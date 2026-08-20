"""Abstract fuzzing engine interface.

Defines the contract that all fuzzing engine backends (AFL++, libFuzzer, etc.)
must implement.  The rest of spectra-fuzz interacts with engines only through
this interface, keeping the orchestrator engine-agnostic.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class FuzzStats:
    """Snapshot of fuzzing engine statistics."""
    execs_done: int = 0
    execs_per_sec: float = 0.0
    paths_total: int = 0
    paths_found: int = 0
    paths_favored: int = 0
    unique_crashes: int = 0
    unique_hangs: int = 0
    stability: float = 100.0
    corpus_count: int = 0
    last_new_find_seconds: float = 0.0
    run_time_seconds: float = 0.0
    bitmap_cvg: float = 0.0


@dataclasses.dataclass(frozen=True)
class CrashInfo:
    """Metadata for a single crash."""
    crash_id: str
    file_path: Path
    target_name: str
    input_data: bytes = b""
    stack_trace: str = ""
    signal: int = 0
    timestamp: float = 0.0


@dataclasses.dataclass(frozen=True)
class CoverageEdge:
    """A single edge in the coverage map."""
    edge_id: int
    hit_count: int
    source_location: str = ""


@dataclasses.dataclass
class CoverageMap:
    """Coverage bitmap representation."""
    bitmap: bytes = b""
    total_edges: int = 0
    covered_edges: int = 0
    edge_details: list[CoverageEdge] = dataclasses.field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        if self.total_edges == 0:
            return 0.0
        return (self.covered_edges / self.total_edges) * 100.0


class FuzzEngine(ABC):
    """Abstract base class for fuzzing engine backends."""

    @abstractmethod
    async def start(
        self,
        target: Path,
        target_args: list[str],
        corpus: Path,
        output: Path,
        *,
        instance_id: str = "default",
        extra_args: list[str] | None = None,
    ) -> None:
        """Start the fuzzing engine."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the fuzzing engine."""
        ...

    @abstractmethod
    async def is_running(self) -> bool:
        """Check if the engine is still running."""
        ...

    @abstractmethod
    async def inject_seeds(self, seeds: list[bytes]) -> int:
        """Inject new seed inputs into the corpus.

        Returns the number of seeds successfully injected.
        """
        ...

    @abstractmethod
    async def get_stats(self) -> FuzzStats:
        """Read current fuzzing statistics."""
        ...

    @abstractmethod
    async def get_coverage(self) -> CoverageMap:
        """Read the current coverage map."""
        ...

    @abstractmethod
    async def get_new_crashes(self, since_id: str | None = None) -> list[CrashInfo]:
        """Get crash reports newer than the given ID."""
        ...

    @abstractmethod
    async def get_queue_entries(self) -> list[Path]:
        """List all entries in the fuzzing queue/corpus."""
        ...
