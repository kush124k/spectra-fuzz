"""Campaign manager — the main orchestration loop.

This is the heart of spectra-fuzz. It coordinates:
- AFL++ engine instances (one per target)
- Coverage monitoring and plateau detection
- Crash collection and LLM analysis
- Differential oracle checks
- LLM-guided seed generation and injection
- Strategy reviews
- Dashboard updates via WebSocket
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from spectra.campaign.corpus import CorpusManager, SeedOrigin
from spectra.campaign.scheduler import LLMScheduler, LLMTaskType
from spectra.config import SpectraConfig
from spectra.engine.afl import AFLEngine
from spectra.engine.coverage import PlateauDetector
from spectra.llm.analyzer import CrashAnalyzer
from spectra.llm.mutator import LLMMutator
from spectra.llm.strategist import StrategyAdvisor

logger = logging.getLogger(__name__)
console = Console()


class CampaignState:
    """Mutable campaign state shared across the orchestration loop."""

    def __init__(self) -> None:
        self.start_time: float = 0.0
        self.total_execs: int = 0
        self.execs_per_sec: float = 0.0
        self.unique_crashes: int = 0
        self.unique_hangs: int = 0
        self.covered_edges: int = 0
        self.total_edges: int = 0
        self.corpus_size: int = 0
        self.llm_calls: int = 0
        self.llm_seeds_generated: int = 0
        self.llm_seeds_hit: int = 0
        self.divergences_total: int = 0
        self.divergences_bugs: int = 0
        self.divergences_ambig: int = 0
        self.crash_reports: list = []
        self.bug_classes: list[str] = []
        self.running: bool = True
        self.status_message: str = "initializing"

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime_seconds": time.time() - self.start_time,
            "total_execs": self.total_execs,
            "execs_per_sec": self.execs_per_sec,
            "unique_crashes": self.unique_crashes,
            "covered_edges": self.covered_edges,
            "total_edges": self.total_edges,
            "coverage_pct": (self.covered_edges / self.total_edges * 100) if self.total_edges > 0 else 0,
            "corpus_size": self.corpus_size,
            "llm_calls": self.llm_calls,
            "llm_seeds_generated": self.llm_seeds_generated,
            "llm_seeds_hit": self.llm_seeds_hit,
            "divergences_total": self.divergences_total,
            "divergences_bugs": self.divergences_bugs,
            "status": self.status_message,
        }


class CampaignManager:
    """Main campaign orchestration loop.

    Coordinates AFL++ instances, coverage monitoring, LLM agents,
    and the differential oracle in a single async event loop.
    """

    def __init__(self, config: SpectraConfig, llm_enabled: bool = True) -> None:
        self._config = config
        self._llm_enabled = llm_enabled
        self._state = CampaignState()

        # Components (initialized in run())
        self._engines: dict[str, AFLEngine] = {}
        self._plateau_detectors: dict[str, PlateauDetector] = {}
        self._corpus: CorpusManager | None = None
        self._scheduler: LLMScheduler | None = None
        self._crash_analyzer: CrashAnalyzer | None = None
        self._mutator: LLMMutator | None = None
        self._strategist: StrategyAdvisor | None = None
        self._oracle: Any = None  # DifferentialOracle
        self._dashboard_queue: asyncio.Queue | None = None

    async def run(self) -> None:
        """Execute the full fuzzing campaign."""
        self._state.start_time = time.time()
        output_dir = Path(self._config.campaign.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        console.print("\n[bold cyan]═══ Initializing Campaign ═══[/bold cyan]\n")

        # --- Initialize corpus ---
        corpus_dir = output_dir / "corpus"
        self._corpus = CorpusManager(corpus_dir)
        seeds_dir = Path(self._config.targets.seeds.directory)
        n_seeds = self._corpus.load_initial_seeds(seeds_dir)
        console.print(f"  [green]✓[/green] Loaded {n_seeds} initial seeds")

        # --- Initialize engines ---
        for target in self._config.targets.binaries:
            engine = AFLEngine(self._config.engine)
            self._engines[target.name] = engine
            self._plateau_detectors[target.name] = PlateauDetector(
                threshold_seconds=self._config.llm.triggers.plateau_threshold_seconds
            )
            console.print(f"  [green]✓[/green] Registered engine for target: [cyan]{target.name}[/cyan]")

        # --- Initialize LLM components ---
        if self._llm_enabled:
            self._scheduler = LLMScheduler(self._config.llm)
            self._crash_analyzer = CrashAnalyzer(self._config.llm)
            self._mutator = LLMMutator(self._config.llm, protocol_name="HTTP/1.1")
            self._strategist = StrategyAdvisor(self._config.llm)
            console.print("  [green]✓[/green] LLM integration enabled")
        else:
            console.print("  [yellow]○[/yellow] LLM integration disabled")

        # --- Initialize differential oracle ---
        if self._config.differential.enabled and len(self._config.targets.binaries) >= 2:
            from spectra.differential.oracle import DifferentialOracle
            self._oracle = DifferentialOracle(
                config=self._config.differential,
                llm_config=self._config.llm if self._llm_enabled else None,
            )
            for target in self._config.targets.binaries:
                self._oracle.register_target(
                    target.name,
                    Path(target.path),
                    target.args,
                )
            console.print("  [green]✓[/green] Differential oracle enabled")

        # --- Initialize dashboard ---
        self._dashboard_queue = asyncio.Queue()
        dashboard_task = None
        if self._config.dashboard.enabled:
            dashboard_task = asyncio.create_task(self._run_dashboard())
            console.print(
                f"  [green]✓[/green] Dashboard at "
                f"[link=http://{self._config.dashboard.host}:{self._config.dashboard.port}]"
                f"http://{self._config.dashboard.host}:{self._config.dashboard.port}[/link]"
            )

        # --- Start AFL++ instances ---
        console.print("\n[bold cyan]═══ Starting Fuzzing Engines ═══[/bold cyan]\n")
        self._state.status_message = "starting engines"

        for target in self._config.targets.binaries:
            engine = self._engines[target.name]
            target_output = output_dir / target.name
            try:
                await engine.start(
                    target=Path(target.path),
                    target_args=target.args,
                    corpus=corpus_dir,
                    output=target_output,
                )
                console.print(f"  [green]✓[/green] AFL++ started for [cyan]{target.name}[/cyan]")
            except Exception as e:
                console.print(f"  [red]✗[/red] Failed to start AFL++ for {target.name}: {e}")
                logger.exception("Engine start failed for %s", target.name)

        # --- Main loop ---
        console.print("\n[bold cyan]═══ Campaign Running ═══[/bold cyan]\n")
        self._state.status_message = "running"

        try:
            await self._main_loop()
        except asyncio.CancelledError:
            pass
        finally:
            # Shutdown
            self._state.status_message = "shutting down"
            console.print("\n[bold cyan]═══ Shutting Down ═══[/bold cyan]\n")

            for name, engine in self._engines.items():
                await engine.stop()
                console.print(f"  [green]✓[/green] Stopped engine for {name}")

            if self._oracle:
                self._oracle.close()

            if dashboard_task:
                dashboard_task.cancel()
                try:
                    await dashboard_task
                except asyncio.CancelledError:
                    pass

            # Export results to disk
            self._export_results(output_dir)

            # Print final summary
            self._print_summary()

    async def _main_loop(self) -> None:
        """The core polling loop that orchestrates all components."""
        duration = self._config.campaign.duration_seconds
        poll_interval = self._config.campaign.poll_interval_seconds
        iteration = 0

        while self._state.running:
            iteration += 1
            elapsed = time.time() - self._state.start_time

            # Check campaign duration
            if elapsed >= duration:
                console.print("\n[yellow]Campaign duration reached.[/yellow]")
                break

            # --- Step 1: Poll AFL++ stats ---
            await self._poll_stats()

            # --- Step 2: Check for new crashes ---
            await self._check_crashes()

            # --- Step 3: Check coverage plateaus ---
            await self._check_plateaus()

            # --- Step 4: Run differential oracle ---
            if self._oracle and iteration % 10 == 0:
                await self._check_divergences()

            # --- Step 5: Strategy review ---
            if self._llm_enabled and self._scheduler:
                if self._scheduler.should_invoke(LLMTaskType.STRATEGY_REVIEW):
                    await self._run_strategy_review()

            # --- Step 6: Push dashboard update ---
            await self._push_dashboard_update()

            # --- Step 7: Log periodic status ---
            if iteration % 12 == 0:  # every ~60 seconds at 5s polling
                self._log_status()

            await asyncio.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Step implementations
    # ------------------------------------------------------------------

    async def _poll_stats(self) -> None:
        """Read stats from all AFL++ instances and update campaign state."""
        total_execs = 0
        total_eps = 0.0
        total_crashes = 0
        total_hangs = 0
        max_covered = 0
        max_total = 0

        for name, engine in self._engines.items():
            if not await engine.is_running():
                continue

            try:
                stats = await engine.get_stats()
                total_execs += stats.execs_done
                total_eps += stats.execs_per_sec
                total_crashes += stats.unique_crashes
                total_hangs += stats.unique_hangs

                # Coverage from bitmap
                coverage = await engine.get_coverage()
                if coverage.covered_edges > max_covered:
                    max_covered = coverage.covered_edges
                    max_total = coverage.total_edges

                # Update plateau detector
                detector = self._plateau_detectors.get(name)
                if detector:
                    detector.update(coverage)

                # Check if AFL++ is productive (finding edges on its own)
                if self._scheduler:
                    productive = stats.last_new_find_seconds < 30
                    self._scheduler.set_afl_productive(productive)

            except Exception as e:
                logger.debug("Failed to poll stats for %s: %s", name, e)

        self._state.total_execs = total_execs
        self._state.execs_per_sec = total_eps
        self._state.unique_crashes = total_crashes
        self._state.unique_hangs = total_hangs
        self._state.covered_edges = max_covered
        self._state.total_edges = max_total
        if self._corpus:
            self._state.corpus_size = self._corpus.total_seeds

    async def _check_crashes(self) -> None:
        """Collect new crashes from all engines and analyze via LLM."""
        for name, engine in self._engines.items():
            try:
                new_crashes = await engine.get_new_crashes()
                for crash in new_crashes:
                    logger.info(
                        "New crash in %s: %s (signal=%d)",
                        name, crash.crash_id, crash.signal,
                    )

                    if not self._llm_enabled or not self._crash_analyzer or not self._scheduler:
                        continue

                    if not self._scheduler.should_invoke(LLMTaskType.CRASH_ANALYSIS):
                        continue

                    # Reproduce to get stack trace — we need the trace
                    # populated before we can send to the analyzer
                    target_cfg = next(
                        (t for t in self._config.targets.binaries if t.name == name), None
                    )
                    if not target_cfg:
                        logger.warning(
                            "Cannot reproduce crash %s: no target config for '%s'",
                            crash.crash_id, name,
                        )
                        continue

                    trace = await engine.reproduce_crash(
                        crash, Path(target_cfg.path), target_cfg.args
                    )
                    if not trace:
                        logger.warning(
                            "Crash %s reproduced but yielded no stack trace",
                            crash.crash_id,
                        )

                    crash = CrashInfo(
                        crash_id=crash.crash_id,
                        file_path=crash.file_path,
                        target_name=crash.target_name,
                        input_data=crash.input_data,
                        stack_trace=trace,
                        signal=crash.signal,
                        timestamp=crash.timestamp,
                    )

                    # Analyze via LLM
                    self._scheduler.record_call(LLMTaskType.CRASH_ANALYSIS)
                    self._state.llm_calls += 1
                    report = await self._crash_analyzer.analyze_crash_info(crash)
                    self._state.crash_reports.append(report)

                    if report.bug_class and report.bug_class not in self._state.bug_classes:
                        self._state.bug_classes.append(report.bug_class)

                    # Inject suggested seeds
                    suggested = self._crash_analyzer.get_suggested_seeds(report)
                    if suggested and self._corpus:
                        added = self._corpus.add_seeds_batch(
                            suggested, SeedOrigin.LLM_CRASH,
                            rationale=f"crash-followup: {report.bug_class}",
                        )
                        self._state.llm_seeds_generated += added

                        # Also inject into all AFL++ instances
                        for eng in self._engines.values():
                            await eng.inject_seeds(suggested)

            except Exception as e:
                logger.error("Error checking crashes for %s: %s", name, e)

    async def _check_plateaus(self) -> None:
        """Detect coverage plateaus and trigger LLM mutation generation."""
        if not self._llm_enabled or not self._mutator or not self._scheduler:
            return

        for name, detector in self._plateau_detectors.items():
            if not detector.is_plateau:
                continue

            if not self._scheduler.should_invoke(LLMTaskType.PLATEAU_MUTATION):
                continue

            logger.info(
                "Coverage plateau detected for %s (%.0fs since last edge)",
                name, detector.seconds_since_new_edge,
            )

            # Get current coverage for context
            engine = self._engines.get(name)
            if not engine:
                continue

            coverage = await engine.get_coverage()
            recent = self._corpus.get_seed_data(10) if self._corpus else []

            # Generate seeds via LLM
            self._scheduler.record_call(LLMTaskType.PLATEAU_MUTATION)
            self._state.llm_calls += 1

            seeds = await self._mutator.generate_seeds(
                coverage=coverage,
                plateau_seconds=detector.seconds_since_new_edge,
                recent_inputs=recent,
            )

            if seeds:
                self._state.llm_seeds_generated += len(seeds)

                # Inject into corpus and all engines
                if self._corpus:
                    self._corpus.add_seeds_batch(
                        seeds, SeedOrigin.LLM_GENERATED,
                        rationale="plateau-breaking mutation",
                    )

                for eng in self._engines.values():
                    await eng.inject_seeds(seeds)

                # Reset plateau detector to allow re-detection
                detector.reset_plateau()

                console.print(
                    f"  [magenta]⚡[/magenta] Injected {len(seeds)} LLM seeds "
                    f"for [cyan]{name}[/cyan] (plateau-break)"
                )

    async def _check_divergences(self) -> None:
        """Run differential oracle on recent queue entries."""
        if not self._oracle or not self._corpus:
            return

        # Pick a few recent seeds to check differentially
        recent = self._corpus.get_recent_seeds(5)
        for seed_entry in recent:
            try:
                divs = await self._oracle.check_divergence(seed_entry.data, auto_triage=True)
                for div in divs:
                    self._state.divergences_total += 1
                    if div.classification.value == "bug":
                        self._state.divergences_bugs += 1
                    elif div.classification.value == "spec_ambiguity":
                        self._state.divergences_ambig += 1

                    console.print(
                        f"  [{'red' if div.classification.value == 'bug' else 'yellow'}]"
                        f"⚠ Divergence[/]: {div.target_a.target_name} vs {div.target_b.target_name} "
                        f"[{div.classification.value}]"
                    )
            except Exception as e:
                logger.debug("Divergence check failed: %s", e)

    async def _run_strategy_review(self) -> None:
        """Invoke the LLM strategy advisor for high-level recommendations."""
        if not self._strategist or not self._scheduler:
            return

        self._scheduler.record_call(LLMTaskType.STRATEGY_REVIEW)
        self._state.llm_calls += 1

        mutator_stats = self._mutator.stats if self._mutator else {}
        oracle_stats = self._oracle.stats if self._oracle else {}

        response = await self._strategist.review_campaign(
            runtime_seconds=time.time() - self._state.start_time,
            total_execs=self._state.total_execs,
            execs_per_sec=self._state.execs_per_sec,
            corpus_size=self._state.corpus_size,
            covered_edges=self._state.covered_edges,
            total_edges=self._state.total_edges,
            unique_crashes=self._state.unique_crashes,
            bug_classes=self._state.bug_classes,
            total_divergences=oracle_stats.get("total_divergences", 0),
            confirmed_bugs=oracle_stats.get("confirmed_bugs", 0),
            spec_ambiguities=oracle_stats.get("spec_ambiguities", 0),
            seeds_generated=mutator_stats.get("total_generated", 0),
            seeds_hit_coverage=mutator_stats.get("total_hit_coverage", 0),
        )

        console.print(f"\n  [bold magenta]📊 Strategy Review #{self._strategist.review_count}[/bold magenta]")
        console.print(f"  {response.assessment[:200]}")
        for rec in response.recommendations[:3]:
            console.print(f"  → [{rec.priority}] {rec.strategy}: {rec.description[:100]}")

        if not response.should_continue:
            console.print(f"\n  [yellow]Strategy advisor recommends stopping: {response.stop_reason}[/yellow]")
            self._state.running = False

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    async def _run_dashboard(self) -> None:
        """Run the web dashboard in the background."""
        try:
            import uvicorn

            from spectra.dashboard.app import create_app

            app = create_app(self._state, self._dashboard_queue)
            config = uvicorn.Config(
                app,
                host=self._config.dashboard.host,
                port=self._config.dashboard.port,
                log_level="warning",
            )
            server = uvicorn.Server(config)
            await server.serve()
        except Exception as e:
            logger.error("Dashboard error: %s", e)

    async def _push_dashboard_update(self) -> None:
        """Push a state update to the dashboard WebSocket."""
        if self._dashboard_queue:
            try:
                self._dashboard_queue.put_nowait(self._state.to_dict())
            except asyncio.QueueFull:
                pass  # drop update if queue is full

    # ------------------------------------------------------------------
    # Results Export
    # ------------------------------------------------------------------

    def _export_results(self, output_dir: Path) -> None:
        """Write structured results to disk at campaign end."""
        results_dir = output_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        # Campaign summary
        summary = self._state.to_dict()
        summary["config"] = {
            "campaign_name": self._config.campaign.name,
            "duration_seconds": self._config.campaign.duration_seconds,
            "llm_enabled": self._llm_enabled,
            "targets": [t.name for t in self._config.targets.binaries],
            "differential_enabled": self._config.differential.enabled,
        }
        if self._corpus:
            summary["corpus_stats"] = self._corpus.stats
        if self._scheduler:
            summary["llm_budget_status"] = self._scheduler.budget_status
            summary["llm_roi"] = {
                "total_calls": self._scheduler.roi.total_calls,
                "total_new_edges": self._scheduler.roi.total_new_edges,
                "total_new_crashes": self._scheduler.roi.total_new_crashes,
                "edges_per_call": self._scheduler.roi.edges_per_call,
            }

        summary_path = results_dir / "campaign_results.json"
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2, default=str)
        console.print(f"  [green]✓[/green] Results exported to {summary_path}")

        # Crash reports
        if self._state.crash_reports:
            crash_data = []
            for report in self._state.crash_reports:
                crash_data.append({
                    "crash_id": getattr(report, "crash_id", "unknown"),
                    "target": getattr(report, "target_name", "unknown"),
                    "bug_class": getattr(report, "bug_class", "unknown"),
                    "severity": getattr(report, "severity", "unknown"),
                    "summary": getattr(report, "summary", ""),
                    "root_cause": getattr(report, "root_cause", ""),
                })
            crashes_path = results_dir / "crash_reports.json"
            with open(crashes_path, "w") as f:
                json.dump(crash_data, f, indent=2)
            console.print(f"  [green]✓[/green] {len(crash_data)} crash reports exported")

    # ------------------------------------------------------------------
    # Logging & Summary
    # ------------------------------------------------------------------

    def _log_status(self) -> None:
        elapsed = time.time() - self._state.start_time
        mins = int(elapsed // 60)
        coverage_pct = (
            self._state.covered_edges / self._state.total_edges * 100
            if self._state.total_edges > 0 else 0
        )

        console.print(
            f"  [{mins:3d}m] "
            f"execs={self._state.total_execs:,} "
            f"eps={self._state.execs_per_sec:.0f} "
            f"cov={coverage_pct:.1f}% "
            f"crashes={self._state.unique_crashes} "
            f"divs={self._state.divergences_total} "
            f"llm_calls={self._state.llm_calls} "
            f"seeds={self._state.llm_seeds_generated}"
        )

    def _print_summary(self) -> None:
        """Print final campaign summary."""
        elapsed = time.time() - self._state.start_time
        coverage_pct = (
            self._state.covered_edges / self._state.total_edges * 100
            if self._state.total_edges > 0 else 0
        )

        table = Table(title="Campaign Summary", border_style="green")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Runtime", f"{elapsed:.0f}s ({elapsed/60:.1f}m)")
        table.add_row("Total Executions", f"{self._state.total_execs:,}")
        table.add_row("Exec/sec (avg)", f"{self._state.total_execs / max(elapsed, 1):.0f}")
        table.add_row("Coverage", f"{coverage_pct:.1f}% ({self._state.covered_edges} edges)")
        table.add_row("Unique Crashes", str(self._state.unique_crashes))
        table.add_row("Corpus Size", str(self._state.corpus_size))
        table.add_row("Divergences", f"{self._state.divergences_total} (bugs={self._state.divergences_bugs})")
        table.add_row("LLM Calls", str(self._state.llm_calls))
        table.add_row("LLM Seeds Generated", str(self._state.llm_seeds_generated))
        table.add_row("Bug Classes", ", ".join(self._state.bug_classes) or "(none)")
        console.print(table)


# Import needed in _check_crashes
from spectra.engine.base import CrashInfo
