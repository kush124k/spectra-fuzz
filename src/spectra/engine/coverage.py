"""Coverage bitmap parsing and analysis.

Reads AFL++ coverage bitmaps (shared-memory dumps), computes edge statistics,
detects coverage plateaus, and identifies uncovered / hot / cold edges.
"""

from __future__ import annotations

import dataclasses
import time
from collections import deque

from spectra.engine.base import CoverageEdge, CoverageMap


# ---------------------------------------------------------------------------
# Bitmap parsing
# ---------------------------------------------------------------------------

# AFL++ default shared-memory bitmap size
AFL_MAP_SIZE = 65536


def parse_coverage_bitmap(raw: bytes, map_size: int = AFL_MAP_SIZE) -> CoverageMap:
    """Parse a raw AFL++ coverage bitmap into a structured CoverageMap.

    The bitmap is an array of uint8 hit-counts, one per edge.  An edge
    with hit_count > 0 has been covered.
    """
    bitmap = raw[:map_size]
    edges: list[CoverageEdge] = []
    covered = 0

    for edge_id, hit_count in enumerate(bitmap):
        if hit_count > 0:
            covered += 1
            edges.append(CoverageEdge(edge_id=edge_id, hit_count=hit_count))

    return CoverageMap(
        bitmap=bitmap,
        total_edges=map_size,
        covered_edges=covered,
        edge_details=edges,
    )


def coverage_diff(old: CoverageMap, new: CoverageMap) -> list[CoverageEdge]:
    """Return edges that are in ``new`` but not in ``old``."""
    if not old.bitmap or not new.bitmap:
        return new.edge_details

    old_set = set()
    for i, b in enumerate(old.bitmap):
        if b > 0:
            old_set.add(i)

    return [e for e in new.edge_details if e.edge_id not in old_set]


def coverage_summary(cov: CoverageMap) -> str:
    """One-line human-readable coverage summary."""
    return (
        f"{cov.covered_edges}/{cov.total_edges} edges covered "
        f"({cov.coverage_pct:.1f}%)"
    )


# ---------------------------------------------------------------------------
# Plateau detector
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CoverageSnapshot:
    """A timestamped coverage observation."""
    timestamp: float
    covered_edges: int
    new_edges: int


class PlateauDetector:
    """Detects when coverage has stopped growing.

    Maintains a sliding window of coverage snapshots and fires a plateau
    event when no new edges have been discovered within the threshold.
    """

    def __init__(self, threshold_seconds: float = 120.0, window_size: int = 100) -> None:
        self._threshold = threshold_seconds
        self._history: deque[CoverageSnapshot] = deque(maxlen=window_size)
        self._last_new_edge_time: float = time.time()
        self._prev_covered: int = 0
        self._plateau_notified: bool = False

    def update(self, coverage: CoverageMap) -> bool:
        """Record a new coverage observation.

        Returns True if a plateau has been detected (only fires once per
        plateau — resets when new edges are found).
        """
        now = time.time()
        new_edges = max(0, coverage.covered_edges - self._prev_covered)

        self._history.append(CoverageSnapshot(
            timestamp=now,
            covered_edges=coverage.covered_edges,
            new_edges=new_edges,
        ))

        if new_edges > 0:
            self._last_new_edge_time = now
            self._prev_covered = coverage.covered_edges
            self._plateau_notified = False
            return False

        # Check if we've been stuck
        stale_seconds = now - self._last_new_edge_time
        if stale_seconds >= self._threshold and not self._plateau_notified:
            self._plateau_notified = True
            return True

        return False

    @property
    def seconds_since_new_edge(self) -> float:
        return time.time() - self._last_new_edge_time

    @property
    def is_plateau(self) -> bool:
        return (time.time() - self._last_new_edge_time) >= self._threshold

    def get_trend(self, last_n: int = 20) -> list[CoverageSnapshot]:
        """Return the last N coverage snapshots for trend analysis."""
        return list(self._history)[-last_n:]

    def reset_plateau(self) -> None:
        """Allow plateau detection to fire again (e.g. after LLM injection)."""
        self._plateau_notified = False
