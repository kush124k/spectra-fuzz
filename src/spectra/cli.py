"""spectra-fuzz CLI — command-line interface for managing fuzzing campaigns."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from spectra import __version__
from spectra.config import load_config

console = Console()

BANNER = r"""
   _____ ____  _______________  ___       ____  ________
  / ___// __ \/ ____/ ____/_  |/ _ \    / __ \/ ____/ /
  \__ \/ /_/ / __/ / /     / / /_) /   / /_/ / /   / /
 ___/ / ____/ /___/ /___ _/ / ____/   / ____/ /___/ /___
/____/_/   /_____/\____//___/_/      /_/    \____/_____/
                                       [dim]v{version}[/dim]
   [cyan]LLM-Augmented Differential Fuzzer[/cyan]
"""


@click.group()
@click.version_option(version=__version__, prog_name="spectra-fuzz")
def main() -> None:
    """spectra-fuzz: LLM-augmented differential fuzzer.

    Combines AFL++ coverage-guided fuzzing with Google Gemini for
    crash trace analysis, semantic mutation, and differential comparison.
    """


@main.command()
@click.option(
    "--dir", "-d",
    type=click.Path(),
    default=".",
    help="Directory to initialize the campaign in.",
)
def init(dir: str) -> None:
    """Initialize a new fuzzing campaign directory."""
    import shutil

    target = Path(dir).resolve()
    target.mkdir(parents=True, exist_ok=True)

    # Copy default config if not present
    config_dest = target / "config" / "campaign.toml"
    if not config_dest.exists():
        config_dest.parent.mkdir(parents=True, exist_ok=True)
        default_config = Path(__file__).parent.parent.parent / "config" / "default.toml"
        if default_config.exists():
            shutil.copy2(default_config, config_dest)
            console.print(f"[green]✓[/green] Created config at {config_dest}")
        else:
            console.print("[yellow]⚠[/yellow] Default config template not found, skipping.")

    # Create directory structure
    for subdir in ["output", "seeds", "targets"]:
        (target / subdir).mkdir(parents=True, exist_ok=True)

    # Create .env from template
    env_dest = target / ".env"
    if not env_dest.exists():
        env_example = Path(__file__).parent.parent.parent / ".env.example"
        if env_example.exists():
            shutil.copy2(env_example, env_dest)
            console.print(f"[green]✓[/green] Created .env at {env_dest}")

    console.print(Panel(
        f"Campaign directory initialized at [bold]{target}[/bold]\n\n"
        "Next steps:\n"
        "  1. Edit [cyan]config/campaign.toml[/cyan] with your targets\n"
        "  2. Set your [cyan]GEMINI_API_KEY[/cyan] in [cyan].env[/cyan]\n"
        "  3. Run [cyan]spectra run[/cyan] to start fuzzing",
        title="🎯 spectra-fuzz",
        border_style="green",
    ))


@main.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default="config/default.toml",
    help="Path to campaign TOML config.",
)
@click.option(
    "--duration", "-t",
    type=int,
    default=None,
    help="Override campaign duration in seconds.",
)
@click.option(
    "--no-dashboard",
    is_flag=True,
    default=False,
    help="Disable the web dashboard.",
)
@click.option(
    "--no-llm",
    is_flag=True,
    default=False,
    help="Disable LLM integration (pure AFL++ mode).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate config and exit without fuzzing.",
)
def run(config: str, duration: int | None, no_dashboard: bool, no_llm: bool, dry_run: bool) -> None:
    """Start a fuzzing campaign."""
    console.print(BANNER.format(version=__version__))

    try:
        cfg = load_config(Path(config))
    except Exception as e:
        console.print(f"[red]✗ Config error:[/red] {e}")
        sys.exit(1)

    if duration is not None:
        cfg.campaign.duration_seconds = duration
    if no_dashboard:
        cfg.dashboard.enabled = False

    # Display campaign summary
    table = Table(title="Campaign Configuration", border_style="cyan")
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Campaign", cfg.campaign.name)
    table.add_row("Duration", f"{cfg.campaign.duration_seconds}s")
    table.add_row("Engine", cfg.engine.type)
    table.add_row("WSL Mode", str(cfg.engine.use_wsl))
    table.add_row("Targets", ", ".join(t.name for t in cfg.targets.binaries))
    table.add_row("LLM Provider", cfg.llm.provider if not no_llm else "[dim]disabled[/dim]")
    table.add_row("LLM Fast Model", cfg.llm.fast_model if not no_llm else "[dim]—[/dim]")
    table.add_row("LLM Deep Model", cfg.llm.deep_model if not no_llm else "[dim]—[/dim]")
    table.add_row("Differential", str(cfg.differential.enabled))
    table.add_row("Dashboard", f"http://{cfg.dashboard.host}:{cfg.dashboard.port}" if cfg.dashboard.enabled else "[dim]disabled[/dim]")
    console.print(table)

    if dry_run:
        console.print("\n[green]✓ Dry run — config valid.[/green]")
        return

    # Run the campaign
    from spectra.campaign.manager import CampaignManager

    manager = CampaignManager(cfg, llm_enabled=not no_llm)

    try:
        asyncio.run(manager.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Campaign interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"\n[red]✗ Campaign error:[/red] {e}")
        sys.exit(1)


@main.command()
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default="config/default.toml",
    help="Path to campaign TOML config.",
)
def status(config: str) -> None:
    """Show the status of the current campaign."""
    cfg = load_config(Path(config))
    output_dir = Path(cfg.campaign.output_dir)

    if not output_dir.exists():
        console.print("[yellow]No campaign output found.[/yellow]")
        return

    console.print(Panel(
        f"Campaign: [bold]{cfg.campaign.name}[/bold]\n"
        f"Output:   {output_dir.resolve()}",
        title="📊 Campaign Status",
        border_style="cyan",
    ))

    # Show per-target stats if available
    for target in cfg.targets.binaries:
        stats_file = output_dir / target.name / "default" / "fuzzer_stats"
        if stats_file.exists():
            console.print(f"\n[bold cyan]{target.name}[/bold cyan]")
            text = stats_file.read_text()
            for line in text.strip().split("\n"):
                if any(k in line for k in ["execs_done", "paths_total", "unique_crashes", "stability"]):
                    console.print(f"  {line.strip()}")


@main.command()
@click.argument("crash_id")
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    default="config/default.toml",
    help="Path to campaign TOML config.",
)
def analyze(crash_id: str, config: str) -> None:
    """Deep-dive analysis of a specific crash via LLM."""
    cfg = load_config(Path(config))
    output_dir = Path(cfg.campaign.output_dir)

    # Find the crash file
    crash_file = None
    for target in cfg.targets.binaries:
        candidate = output_dir / target.name / "default" / "crashes" / crash_id
        if candidate.exists():
            crash_file = candidate
            break

    if crash_file is None:
        console.print(f"[red]✗ Crash '{crash_id}' not found in any target output.[/red]")
        sys.exit(1)

    console.print(f"[cyan]Analyzing crash:[/cyan] {crash_file}")

    from spectra.llm.analyzer import CrashAnalyzer

    analyzer = CrashAnalyzer(cfg.llm)
    crash_data = crash_file.read_bytes()

    result = asyncio.run(analyzer.analyze_crash(
        crash_input=crash_data,
        crash_trace="(trace from crash reproduction)",
        target_name=crash_file.parent.parent.parent.name,
    ))

    console.print(Panel(
        result.summary,
        title=f"🔍 Crash Analysis — {result.bug_class}",
        subtitle=f"Severity: {result.severity}",
        border_style="red" if result.severity == "critical" else "yellow",
    ))

    if result.suggested_inputs:
        console.print("\n[bold]Suggested follow-up inputs:[/bold]")
        for i, inp in enumerate(result.suggested_inputs, 1):
            console.print(f"  {i}. {inp.description}")


@main.command()
def dashboard() -> None:
    """Launch the web dashboard standalone."""
    import uvicorn

    from spectra.dashboard.app import create_app

    app = create_app()
    console.print(BANNER.format(version=__version__))
    console.print("[green]Starting dashboard...[/green]")
    uvicorn.run(app, host="127.0.0.1", port=8077)


if __name__ == "__main__":
    main()
