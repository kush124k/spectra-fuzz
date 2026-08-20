/* ==========================================================================
   spectra-fuzz Dashboard — Client-side JavaScript
   Real-time WebSocket state, Chart.js coverage/speed graphs, crash/div feeds.
   ========================================================================== */

(() => {
    "use strict";

    // ─── WebSocket ──────────────────────────────────────────────────────────
    const WS_URL = `ws://${location.host}/ws`;
    let ws = null;
    let reconnectTimer = null;
    let reconnectAttempts = 0;

    // ─── State ──────────────────────────────────────────────────────────────
    const coverageHistory = [];
    const execSpeedHistory = [];
    const crashEntries = [];
    const divEntries = [];
    const mutationEntries = [];
    const MAX_HISTORY = 300;

    // ─── Charts ─────────────────────────────────────────────────────────────
    let coverageChart = null;
    let execSpeedChart = null;

    const CHART_DEFAULTS = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400, easing: "easeOutQuart" },
        interaction: { mode: "index", intersect: false },
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: "rgba(17, 24, 39, 0.95)",
                titleColor: "#f1f5f9",
                bodyColor: "#94a3b8",
                borderColor: "rgba(99, 102, 241, 0.3)",
                borderWidth: 1,
                cornerRadius: 8,
                padding: 10,
                titleFont: { family: "'Inter', sans-serif", weight: "600" },
                bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
            },
        },
        scales: {
            x: {
                display: true,
                grid: { color: "rgba(255,255,255,0.03)" },
                ticks: { color: "#64748b", font: { size: 10, family: "'JetBrains Mono', monospace" }, maxTicksLimit: 8 },
            },
            y: {
                display: true,
                grid: { color: "rgba(255,255,255,0.03)" },
                ticks: { color: "#64748b", font: { size: 10, family: "'JetBrains Mono', monospace" } },
                beginAtZero: true,
            },
        },
    };

    function initCharts() {
        const coverageCtx = document.getElementById("coverage-chart").getContext("2d");
        coverageChart = new Chart(coverageCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Edges Covered",
                    data: [],
                    borderColor: "#22d3ee",
                    backgroundColor: "rgba(34, 211, 238, 0.05)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: "#22d3ee",
                }],
            },
            options: { ...CHART_DEFAULTS },
        });

        const execCtx = document.getElementById("execspeed-chart").getContext("2d");
        execSpeedChart = new Chart(execCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Exec/s",
                    data: [],
                    borderColor: "#818cf8",
                    backgroundColor: "rgba(129, 140, 248, 0.05)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: "#818cf8",
                }],
            },
            options: { ...CHART_DEFAULTS },
        });
    }

    // ─── DOM Helpers ────────────────────────────────────────────────────────
    const $ = (id) => document.getElementById(id);

    function formatNumber(n) {
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
        if (n >= 1_000) return (n / 1_000).toFixed(1) + "K";
        return n.toLocaleString();
    }

    function formatTime(seconds) {
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
    }

    function timeLabel(seconds) {
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        return `${m}:${String(s).padStart(2, "0")}`;
    }

    // ─── State Update ───────────────────────────────────────────────────────
    function updateState(data) {
        // Runtime
        $("runtime").textContent = formatTime(data.runtime_seconds || 0);

        // Stats cards
        $("total-execs").textContent = formatNumber(data.total_execs || 0);
        $("execs-per-sec").textContent = `${(data.execs_per_sec || 0).toFixed(0)} exec/s`;

        const covPct = data.coverage_pct || 0;
        $("coverage-pct").textContent = covPct.toFixed(1) + "%";
        $("coverage-edges").textContent = `${formatNumber(data.covered_edges || 0)} / ${formatNumber(data.total_edges || 0)} edges`;

        $("unique-crashes").textContent = data.unique_crashes || 0;
        $("total-divergences").textContent = data.divergences_total || 0;
        $("div-bugs").textContent = `${data.divergences_bugs || 0} bugs confirmed`;
        $("llm-calls").textContent = data.llm_calls || 0;
        $("llm-seeds").textContent = `${data.llm_seeds_generated || 0} seeds generated`;

        // Mutation stats
        $("mut-seeds").textContent = data.llm_seeds_generated || 0;
        $("mut-hits").textContent = data.llm_seeds_hit || 0;
        const hitRate = data.llm_seeds_generated > 0
            ? ((data.llm_seeds_hit || 0) / data.llm_seeds_generated * 100).toFixed(1)
            : "0";
        $("mut-rate").textContent = hitRate + "%";

        // Status badge
        const badge = $("status-badge");
        const statusText = $("status-text");
        statusText.textContent = data.status || "running";
        badge.classList.toggle("error", data.status === "error");

        // Coverage chart
        const ts = data.runtime_seconds || 0;
        coverageHistory.push({ t: ts, v: data.covered_edges || 0 });
        if (coverageHistory.length > MAX_HISTORY) coverageHistory.shift();

        coverageChart.data.labels = coverageHistory.map((p) => timeLabel(p.t));
        coverageChart.data.datasets[0].data = coverageHistory.map((p) => p.v);
        coverageChart.update("none");

        // Exec speed chart
        execSpeedHistory.push({ t: ts, v: data.execs_per_sec || 0 });
        if (execSpeedHistory.length > MAX_HISTORY) execSpeedHistory.shift();

        execSpeedChart.data.labels = execSpeedHistory.map((p) => timeLabel(p.t));
        execSpeedChart.data.datasets[0].data = execSpeedHistory.map((p) => p.v);
        execSpeedChart.update("none");

        // Animate stat cards on value change
        animateCard("card-execs");
        if (data.unique_crashes > 0) animateCard("card-crashes");
        if (data.divergences_total > 0) animateCard("card-divergences");
    }

    function animateCard(id) {
        const el = $(id);
        if (!el) return;
        el.style.transition = "box-shadow 0.3s";
        el.style.boxShadow = "0 0 20px rgba(99, 102, 241, 0.15)";
        setTimeout(() => { el.style.boxShadow = ""; }, 600);
    }

    // ─── Crash Feed ─────────────────────────────────────────────────────────
    function loadCrashes() {
        fetch("/api/crashes")
            .then((r) => r.json())
            .then((crashes) => {
                if (!crashes || crashes.length === 0) return;

                const feed = $("crash-feed");
                feed.innerHTML = "";
                $("crash-count-badge").textContent = crashes.length;

                crashes.forEach((c) => {
                    const entry = document.createElement("div");
                    entry.className = "crash-entry";
                    entry.innerHTML = `
                        <div class="crash-entry-header">
                            <span class="crash-entry-title">${escapeHtml(c.bug_class || "unknown")}</span>
                            <span class="severity-badge severity-${c.severity || "medium"}">${c.severity || "?"}</span>
                        </div>
                        <div class="crash-entry-summary">${escapeHtml(c.summary || "Analysis pending...")}</div>
                        <div class="crash-entry-meta">
                            <span>target: ${escapeHtml(c.target || "?")}</span>
                            <span>id: ${escapeHtml(c.crash_id || "?").substring(0, 30)}</span>
                        </div>
                    `;
                    feed.appendChild(entry);
                });
            })
            .catch(() => {});
    }

    // ─── Utilities ──────────────────────────────────────────────────────────
    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    // ─── Toast ──────────────────────────────────────────────────────────────
    function showToast(message, type = "") {
        const toast = $("connection-toast");
        const msg = $("toast-message");
        msg.textContent = message;
        toast.className = "toast visible" + (type ? ` ${type}` : "");
        setTimeout(() => { toast.classList.remove("visible"); }, 3000);
    }

    // ─── WebSocket Connection ───────────────────────────────────────────────
    function connect() {
        if (ws && ws.readyState <= WebSocket.OPEN) return;

        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            reconnectAttempts = 0;
            $("status-text").textContent = "connected";
            $("status-badge").classList.remove("error");
            showToast("Connected to spectra-fuzz", "success");

            // Start ping/keep-alive
            setInterval(() => {
                if (ws.readyState === WebSocket.OPEN) ws.send("ping");
            }, 25000);
        };

        ws.onmessage = (event) => {
            if (event.data === "pong") return;

            try {
                const msg = JSON.parse(event.data);
                if (msg.type === "state") {
                    updateState(msg.data);
                } else if (msg.type === "crash") {
                    loadCrashes();
                }
            } catch (e) {
                console.warn("Failed to parse WS message:", e);
            }
        };

        ws.onclose = () => {
            $("status-text").textContent = "disconnected";
            $("status-badge").classList.add("error");
            scheduleReconnect();
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    function scheduleReconnect() {
        if (reconnectTimer) return;
        const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
        reconnectAttempts++;
        reconnectTimer = setTimeout(() => {
            reconnectTimer = null;
            connect();
        }, delay);
    }

    // ─── Initialization ────────────────────────────────────────────────────
    document.addEventListener("DOMContentLoaded", () => {
        initCharts();
        connect();

        // Periodic crash/divergence polling (supplements WebSocket)
        setInterval(loadCrashes, 10000);
    });
})();
