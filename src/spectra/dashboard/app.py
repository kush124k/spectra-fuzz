"""FastAPI dashboard application with WebSocket live updates."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    campaign_state: Any = None,
    update_queue: asyncio.Queue | None = None,
) -> FastAPI:
    """Create the FastAPI dashboard application.

    Args:
        campaign_state: The shared CampaignState object (or None for standalone).
        update_queue: Queue receiving state updates from the campaign manager.
    """
    app = FastAPI(title="spectra-fuzz Dashboard", version="0.1.0")

    # Track connected WebSocket clients
    connected_clients: set[WebSocket] = set()

    # --- Static files ---
    @app.get("/", response_class=HTMLResponse)
    async def index():
        index_file = STATIC_DIR / "index.html"
        return index_file.read_text(encoding="utf-8")

    @app.get("/style.css")
    async def css():
        return FileResponse(STATIC_DIR / "style.css", media_type="text/css")

    @app.get("/app.js")
    async def js():
        return FileResponse(STATIC_DIR / "app.js", media_type="application/javascript")

    # --- REST API ---
    @app.get("/api/state")
    async def get_state():
        if campaign_state is not None:
            return campaign_state.to_dict() if hasattr(campaign_state, "to_dict") else {}
        return {"status": "no campaign running"}

    @app.get("/api/crashes")
    async def get_crashes():
        if campaign_state is not None and hasattr(campaign_state, "crash_reports"):
            return [
                {
                    "crash_id": r.crash_id,
                    "target": r.target_name,
                    "bug_class": r.bug_class,
                    "severity": r.severity,
                    "summary": r.summary,
                    "analyzed": r.analyzed,
                }
                for r in campaign_state.crash_reports
            ]
        return []

    @app.get("/api/divergences")
    async def get_divergences():
        # Would be populated from oracle
        return []

    @app.get("/api/budget")
    async def get_budget():
        return {"status": "ok"}

    # --- WebSocket ---
    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws.accept()
        connected_clients.add(ws)
        logger.info("Dashboard client connected (%d total)", len(connected_clients))

        try:
            # Send initial state
            if campaign_state and hasattr(campaign_state, "to_dict"):
                await ws.send_json({"type": "state", "data": campaign_state.to_dict()})

            # Keep connection alive and forward updates
            while True:
                try:
                    # Wait for client messages (keep-alive pings)
                    data = await asyncio.wait_for(ws.receive_text(), timeout=30)
                    if data == "ping":
                        await ws.send_text("pong")
                except asyncio.TimeoutError:
                    # Send periodic state update
                    if campaign_state and hasattr(campaign_state, "to_dict"):
                        await ws.send_json({"type": "state", "data": campaign_state.to_dict()})
        except WebSocketDisconnect:
            pass
        finally:
            connected_clients.discard(ws)
            logger.info("Dashboard client disconnected (%d remaining)", len(connected_clients))

    # --- Background update broadcaster ---
    @app.on_event("startup")
    async def start_broadcaster():
        if update_queue is None:
            return

        async def broadcast_updates():
            while True:
                try:
                    update = await update_queue.get()
                    message = json.dumps({"type": "state", "data": update})
                    disconnected = set()
                    for client in connected_clients:
                        try:
                            await client.send_text(message)
                        except Exception:
                            disconnected.add(client)
                    connected_clients -= disconnected
                except Exception as e:
                    logger.debug("Broadcast error: %s", e)
                    await asyncio.sleep(1)

        asyncio.create_task(broadcast_updates())

    return app
