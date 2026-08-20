"""Gemini API client wrapper with retry, rate-limiting, and budget tracking.

Provides an async interface to Google Gemini with structured output support
(via Pydantic response schemas), automatic retry on transient errors, and
token/cost budget enforcement.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any, TypeVar

from pydantic import BaseModel

from spectra.config import LLMConfig

logger = logging.getLogger(__name__)
T = TypeVar("T", bound=BaseModel)


class BudgetExhausted(Exception):
    """Raised when the LLM API budget has been exceeded."""


class LLMClient:
    """Async wrapper around the Google Gemini API.

    Features:
    - Structured output via Pydantic response schemas
    - Token and call-count budget tracking
    - Rate limiting with sliding window
    - Exponential backoff retry on transient errors
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client: Any = None

        # Budget tracking
        self._calls_this_hour: deque[float] = deque()
        self._tokens_this_hour: deque[tuple[float, int]] = deque()
        self._total_calls: int = 0
        self._total_tokens: int = 0

    def _ensure_client(self) -> Any:
        """Lazily initialize the Gemini client."""
        if self._client is None:
            from google import genai
            self._client = genai.Client(api_key=self._config.api_key)
        return self._client

    def _prune_budget_window(self) -> None:
        """Remove entries older than 1 hour from sliding windows."""
        cutoff = time.time() - 3600
        while self._calls_this_hour and self._calls_this_hour[0] < cutoff:
            self._calls_this_hour.popleft()
        while self._tokens_this_hour and self._tokens_this_hour[0][0] < cutoff:
            self._tokens_this_hour.popleft()

    def _check_budget(self) -> None:
        """Raise BudgetExhausted if limits are exceeded."""
        self._prune_budget_window()

        if len(self._calls_this_hour) >= self._config.budget.max_calls_per_hour:
            raise BudgetExhausted(
                f"Call limit reached: {len(self._calls_this_hour)}/{self._config.budget.max_calls_per_hour} calls/hour"
            )

        total_tokens = sum(t for _, t in self._tokens_this_hour)
        if total_tokens >= self._config.budget.max_tokens_per_hour:
            raise BudgetExhausted(
                f"Token limit reached: {total_tokens}/{self._config.budget.max_tokens_per_hour} tokens/hour"
            )

    def _record_usage(self, tokens: int) -> None:
        now = time.time()
        self._calls_this_hour.append(now)
        self._tokens_this_hour.append((now, tokens))
        self._total_calls += 1
        self._total_tokens += tokens

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        prompt: str,
        *,
        model: str | None = None,
        response_schema: type[T] | None = None,
        temperature: float = 0.7,
        max_retries: int = 3,
        system_instruction: str = "",
    ) -> T | str:
        """Generate content from the Gemini API.

        If ``response_schema`` is provided (a Pydantic model class), the
        response is parsed and validated into that schema.  Otherwise the
        raw text response is returned.
        """
        self._check_budget()

        client = self._ensure_client()
        model_name = model or self._config.fast_model

        config: dict[str, Any] = {
            "temperature": temperature,
        }

        if response_schema is not None:
            config["response_mime_type"] = "application/json"
            config["response_schema"] = response_schema

        contents = prompt

        last_error: Exception | None = None
        for attempt in range(max_retries):
            try:
                # Run the synchronous SDK call in a thread to avoid blocking
                response = await asyncio.to_thread(
                    client.models.generate_content,
                    model=model_name,
                    contents=contents,
                    config={
                        **config,
                        **({"system_instruction": system_instruction} if system_instruction else {}),
                    },
                )

                # Extract token usage
                tokens_used = 0
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    tokens_used = getattr(response.usage_metadata, "total_token_count", 0) or 0
                self._record_usage(tokens_used)

                logger.debug(
                    "Gemini response: model=%s, tokens=%d, attempt=%d",
                    model_name, tokens_used, attempt + 1,
                )

                # Parse structured response
                if response_schema is not None:
                    if hasattr(response, "parsed") and response.parsed is not None:
                        return response.parsed
                    # Fallback: manually parse the JSON text
                    import json
                    text = response.text or ""
                    data = json.loads(text)
                    return response_schema.model_validate(data)
                else:
                    return response.text or ""

            except BudgetExhausted:
                raise
            except Exception as e:
                last_error = e
                wait = 2 ** attempt
                logger.warning(
                    "Gemini API error (attempt %d/%d): %s — retrying in %ds",
                    attempt + 1, max_retries, e, wait,
                )
                await asyncio.sleep(wait)

        raise RuntimeError(f"Gemini API failed after {max_retries} retries: {last_error}")

    async def generate_fast(self, prompt: str, **kwargs: Any) -> Any:
        """Generate using the fast (cheaper) model."""
        return await self.generate(prompt, model=self._config.fast_model, **kwargs)

    async def generate_deep(self, prompt: str, **kwargs: Any) -> Any:
        """Generate using the deep (more capable) model."""
        return await self.generate(prompt, model=self._config.deep_model, **kwargs)

    # ------------------------------------------------------------------
    # Budget introspection
    # ------------------------------------------------------------------

    @property
    def budget_status(self) -> dict[str, Any]:
        """Current budget usage snapshot."""
        self._prune_budget_window()
        total_tokens = sum(t for _, t in self._tokens_this_hour)
        return {
            "calls_this_hour": len(self._calls_this_hour),
            "max_calls_per_hour": self._config.budget.max_calls_per_hour,
            "tokens_this_hour": total_tokens,
            "max_tokens_per_hour": self._config.budget.max_tokens_per_hour,
            "total_calls": self._total_calls,
            "total_tokens": self._total_tokens,
            "budget_remaining_pct": max(
                0.0,
                100.0 * (1 - len(self._calls_this_hour) / self._config.budget.max_calls_per_hour),
            ),
        }
