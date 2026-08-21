#!/usr/bin/env python3
"""Baseline comparison: --no-llm vs --llm on the same target/time budget.

This is the Phase 4 evaluation script — the single most important artifact
in the project.  It runs two identical campaigns back-to-back (or in
parallel on separate output dirs), then diffs the coverage curves and
writes a results/ report with:

  - coverage_over_time.csv for both runs
  - coverage_comparison.png  (matplotlib chart)
  - summary.json             (final numbers + delta)

Usage (from WSL2):

    # Quick 10-minute comparison
    python scripts/benchmark.py --config config/default.toml --duration 600

    # Full 2-hour comparison
    python scripts/benchmark.py --config config/default.toml --duration 7200

    # Use a pre-existing baseline (skip re-running --no-llm)
    python scripts/benchmark.py --config config/default.toml --duration 3600 \
        --baseline-dir results/baseline_20250115_120000
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure project is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
logger = logging.getLogger("benchmark")


# ---------------------------------------------------------------------------
# Coverage sampler — polls AFL++ stats at fixed intervals
# ---------------------------------------------------------------------------

class CoverageSampler:
    """Collects time-series coverage data from a running campaign."""

    def __init__(self, output_dir: Path, sample_interval: float = 10.0) -> None:
        self._output_dir = output_dir
        self._interval = sample_interval
        self._samples: list[dict] = []
        self._running = False

    async def start(self) -> None:
        self._running = True
        start = time.time()
        while self._running:
            elapsed = time.time() - start
            sample = {"elapsed_seconds": round(elapsed, 1)}

            # Find all target output directories
            for target_dir in sorted(self._output_dir.iterdir()):
                if not target_dir.is_dir() or target_dir.name in ("corpus",):
                    continue
                stats = self._read_fuzzer_stats(target_dir / "default" / "fuzzer_stats")
                bitmap = self._read_bitmap_cvg(target_dir / "default" / "fuzz_bitmap")
                queue_count = self._count_queue(target_dir / "default" / "queue")

                sample[f"{target_dir.name}_execs"] = stats.get("execs_done", 0)
                sample[f"{target_dir.name}_eps"] = stats.get("execs_per_sec", 0)
                sample[f"{target_dir.name}_crashes"] = stats.get("saved_crashes", 0)
                sample[f"{target_dir.name}_paths"] = stats.get("corpus_count", queue_count)
                sample[f"{target_dir.name}_bitmap_cvg"] = bitmap
                sample["total_paths"] = sample.get("total_paths", 0) + sample[f"{target_dir.name}_paths"]

            self._samples.append(sample)
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        self._running = False

    def write_csv(self, path: Path) -> None:
        if not self._samples:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        keys = list(self._samples[0].keys())
        # Union all keys across samples
        for s in self._samples:
            for k in s:
                if k not in keys:
                    keys.append(k)
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            for s in self._samples:
                writer.writerow({k: s.get(k, "") for k in keys})

    @property
    def final_paths(self) -> int:
        if not self._samples:
            return 0
        return self._samples[-1].get("total_paths", 0)

    @property
    def final_sample(self) -> dict:
        return self._samples[-1] if self._samples else {}

    @staticmethod
    def _read_fuzzer_stats(path: Path) -> dict:
        result: dict = {}
        if not path.exists():
            return result
        try:
            for line in path.read_text().strip().split("\n"):
                if ":" in line:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip()
                    try:
                        result[key] = float(val) if "." in val else int(val)
                    except ValueError:
                        result[key] = val
        except Exception:
            pass
        return result

    @staticmethod
    def _read_bitmap_cvg(path: Path) -> float:
        if not path.exists():
            return 0.0
        try:
            data = path.read_bytes()
            covered = sum(1 for b in data if b != 0)
            return round(covered / len(data) * 100, 2) if data else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _count_queue(path: Path) -> int:
        if not path.exists():
            return 0
        return len([f for f in path.iterdir() if f.is_file() and not f.name.startswith(".")])


# ---------------------------------------------------------------------------
# Run a single campaign
# ---------------------------------------------------------------------------

async def run_campaign(
    config_path: Path,
    duration: int,
    llm_enabled: bool,
    output_dir: Path,
    sample_interval: float = 10.0,
) -> CoverageSampler:
    """Run a spectra-fuzz campaign and return coverage samples."""
    from spectra.config import load_config
    from spectra.campaign.manager import CampaignManager

    cfg = load_config(config_path)
    cfg.campaign.duration_seconds = duration
    cfg.campaign.output_dir = str(output_dir)
    cfg.dashboard.enabled = False  # no dashboard during benchmarks

    mode = "LLM-augmented" if llm_enabled else "baseline (no-llm)"
    console.print(f"\n[bold cyan]═══ Starting {mode} campaign ({duration}s) ═══[/bold cyan]")
    console.print(f"  Output: {output_dir}")

    # Start coverage sampler
    sampler = CoverageSampler(output_dir, sample_interval)
    sampler_task = asyncio.create_task(sampler.start())

    # Run campaign
    manager = CampaignManager(cfg, llm_enabled=llm_enabled)
    try:
        await manager.run()
    except Exception as e:
        console.print(f"[red]Campaign error: {e}[/red]")
    finally:
        sampler.stop()
        sampler_task.cancel()
        try:
            await sampler_task
        except asyncio.CancelledError:
            pass

    return sampler


# ---------------------------------------------------------------------------
# Generate comparison report
# ---------------------------------------------------------------------------

def generate_comparison_chart(
    baseline_csv: Path,
    llm_csv: Path,
    chart_path: Path,
) -> None:
    """Generate a coverage-over-time comparison chart using matplotlib."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        console.print("[yellow]⚠ matplotlib not installed — skipping chart generation[/yellow]")
        console.print("  Install with: pip install matplotlib")
        return

    def load_csv(path: Path) -> tuple[list[float], list[int]]:
        times, paths = [], []
        with open(path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                times.append(float(row["elapsed_seconds"]))
                paths.append(int(row.get("total_paths", 0)))
        return times, paths

    b_times, b_paths = load_csv(baseline_csv)
    l_times, l_paths = load_csv(llm_csv)

    # Convert to minutes
    b_mins = [t / 60 for t in b_times]
    l_mins = [t / 60 for t in l_times]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor("#0a0e1a")
    ax.set_facecolor("#111827")

    ax.plot(b_mins, b_paths, color="#94a3b8", linewidth=2, label="Baseline (AFL++ only)")
    ax.plot(l_mins, l_paths, color="#22d3ee", linewidth=2, label="LLM-Augmented (spectra-fuzz)")

    # Fill area between to highlight delta
    min_len = min(len(b_paths), len(l_paths))
    if min_len > 0:
        ax.fill_between(
            l_mins[:min_len],
            b_paths[:min_len],
            l_paths[:min_len],
            alpha=0.15,
            color="#22d3ee",
            label="Coverage delta",
        )

    ax.set_xlabel("Time (minutes)", color="#94a3b8", fontsize=12)
    ax.set_ylabel("Corpus Paths (coverage proxy)", color="#94a3b8", fontsize=12)
    ax.set_title("spectra-fuzz: LLM-Augmented vs Baseline Coverage", color="#f1f5f9", fontsize=14, fontweight="bold")
    ax.legend(facecolor="#111827", edgecolor="#374151", labelcolor="#f1f5f9", fontsize=10)
    ax.tick_params(colors="#64748b")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["bottom"].set_color("#374151")
    ax.spines["left"].set_color("#374151")
    ax.grid(True, alpha=0.1, color="#94a3b8")

    chart_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(str(chart_path), dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    console.print(f"  [green]✓[/green] Chart saved: {chart_path}")


def generate_summary(
    baseline_sampler: CoverageSampler,
    llm_sampler: CoverageSampler,
    duration: int,
    results_dir: Path,
) -> dict:
    """Generate and save the comparison summary."""
    b = baseline_sampler.final_sample
    l = llm_sampler.final_sample

    b_paths = baseline_sampler.final_paths
    l_paths = llm_sampler.final_paths
    delta = l_paths - b_paths
    pct_improvement = (delta / max(b_paths, 1)) * 100

    summary = {
        "timestamp": datetime.now().isoformat(),
        "duration_seconds": duration,
        "baseline": {
            "total_paths": b_paths,
            **{k: v for k, v in b.items() if k != "elapsed_seconds"},
        },
        "llm_augmented": {
            "total_paths": l_paths,
            **{k: v for k, v in l.items() if k != "elapsed_seconds"},
        },
        "comparison": {
            "path_delta": delta,
            "improvement_pct": round(pct_improvement, 2),
            "verdict": (
                "LLM-augmented found MORE paths" if delta > 0
                else "Baseline found more or equal paths" if delta <= 0
                else "Equivalent"
            ),
        },
    }

    summary_path = results_dir / "summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Print results table
    console.print("\n")
    table = Table(title="⚡ Benchmark Results", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Baseline", justify="right")
    table.add_column("LLM-Augmented", justify="right")
    table.add_column("Delta", justify="right")

    table.add_row("Corpus Paths", str(b_paths), str(l_paths),
                   f"[{'green' if delta > 0 else 'red'}]{delta:+d}[/]")
    table.add_row("Improvement", "", "",
                   f"[{'green' if pct_improvement > 0 else 'red'}]{pct_improvement:+.1f}%[/]")

    # Per-target crashes
    for key in sorted(b.keys()):
        if key.endswith("_crashes"):
            target = key.replace("_crashes", "")
            b_c = b.get(key, 0)
            l_c = l.get(key, 0)
            table.add_row(f"Crashes ({target})", str(b_c), str(l_c),
                          f"{l_c - b_c:+d}")

    console.print(table)
    console.print(f"\n  Results saved to: [cyan]{results_dir}[/cyan]")

    return summary


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def async_main(args: argparse.Namespace) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = Path("results") / f"benchmark_{timestamp}"
    results_dir.mkdir(parents=True, exist_ok=True)

    config_path = Path(args.config)

    # --- Phase 1: Baseline (--no-llm) ---
    if args.baseline_dir:
        console.print(f"[cyan]Using pre-existing baseline from: {args.baseline_dir}[/cyan]")
        baseline_csv = Path(args.baseline_dir) / "coverage_baseline.csv"
        if not baseline_csv.exists():
            console.print("[red]✗ No coverage_baseline.csv in provided baseline dir[/red]")
            sys.exit(1)
        shutil.copy2(baseline_csv, results_dir / "coverage_baseline.csv")
        baseline_sampler = CoverageSampler(Path(args.baseline_dir))
        # Load samples from CSV
        baseline_sampler._samples = []
        with open(baseline_csv) as f:
            for row in csv.DictReader(f):
                baseline_sampler._samples.append({
                    k: (float(v) if "." in str(v) else int(v)) if v else 0
                    for k, v in row.items()
                })
    else:
        baseline_output = results_dir / "output_baseline"
        baseline_sampler = await run_campaign(
            config_path, args.duration, llm_enabled=False,
            output_dir=baseline_output, sample_interval=args.sample_interval,
        )
        baseline_sampler.write_csv(results_dir / "coverage_baseline.csv")

    # --- Phase 2: LLM-Augmented ---
    llm_output = results_dir / "output_llm"
    llm_sampler = await run_campaign(
        config_path, args.duration, llm_enabled=True,
        output_dir=llm_output, sample_interval=args.sample_interval,
    )
    llm_sampler.write_csv(results_dir / "coverage_llm.csv")

    # --- Phase 3: Comparison ---
    console.print("\n[bold cyan]═══ Generating Comparison Report ═══[/bold cyan]")

    generate_comparison_chart(
        results_dir / "coverage_baseline.csv",
        results_dir / "coverage_llm.csv",
        results_dir / "coverage_comparison.png",
    )

    generate_summary(baseline_sampler, llm_sampler, args.duration, results_dir)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="spectra-fuzz: Baseline vs LLM-Augmented benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick 10-min comparison
  python scripts/benchmark.py --config config/default.toml --duration 600

  # Full 2-hour comparison
  python scripts/benchmark.py --config config/default.toml --duration 7200

  # Re-use existing baseline
  python scripts/benchmark.py --config config/default.toml --duration 3600 \\
      --baseline-dir results/baseline_20250115_120000
        """,
    )
    parser.add_argument("--config", "-c", default="config/default.toml",
                        help="Path to campaign TOML config")
    parser.add_argument("--duration", "-t", type=int, default=3600,
                        help="Duration per run in seconds (default: 3600)")
    parser.add_argument("--sample-interval", type=float, default=10.0,
                        help="Coverage sampling interval in seconds (default: 10)")
    parser.add_argument("--baseline-dir", default=None,
                        help="Path to pre-existing baseline results dir (skip baseline run)")
    args = parser.parse_args()

    console.print(Panel(
        "[bold]spectra-fuzz Benchmark[/bold]\n\n"
        f"Config:     {args.config}\n"
        f"Duration:   {args.duration}s per run ({args.duration/60:.0f} min)\n"
        f"Total time: ~{args.duration * 2 / 60:.0f} min (baseline + LLM)\n"
        f"Baseline:   {'pre-existing' if args.baseline_dir else 'will run fresh'}",
        title="⚡ Phase 4 Evaluation",
        border_style="cyan",
    ))

    asyncio.run(async_main(args))


if __name__ == "__main__":
    main()
