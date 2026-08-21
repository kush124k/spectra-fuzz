"""Budget-aware LLM invocation scheduler.

Decides *when* to invoke the LLM based on campaign events (crashes, plateaus,
divergences) while respecting API budget limits.  Implements exponential
backoff on repeated plateaus and tracks ROI (coverage gained per LLM call).
"""

from __future__ import annotations

import dataclasses
import logging
import time
from enum import Enum

from spectra.config import LLMConfig

logger = logging.getLogger(__name__)


class LLMTaskType(str, Enum):
    """Types of LLM invocations, in priority order."""
    CRASH_ANALYSIS = "crash_analysis"
    DIVERGENCE_TRIAGE = "divergence_triage"
    PLATEAU_MUTATION = "plateau_mutation"
    STRATEGY_REVIEW = "strategy_review"


# Priority: lower number = higher priority
TASK_PRIORITY: dict[LLMTaskType, int] = {
    LLMTaskType.CRASH_ANALYSIS: 1,
    LLMTaskType.DIVERGENCE_TRIAGE: 2,
    LLMTaskType.PLATEAU_MUTATION: 3,
    LLMTaskType.STRATEGY_REVIEW: 4,
}


@dataclasses.dataclass
class ScheduledTask:
    """An LLM task waiting to be executed."""
    task_type: LLMTaskType
    priority: int
    scheduled_at: float
    context: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ROITracker:
    """Tracks return on investment for LLM calls."""
    total_calls: int = 0
    total_new_edges: int = 0
    total_new_crashes: int = 0
    calls_by_type: dict = dataclasses.field(default_factory=lambda: {t: 0 for t in LLMTaskType})
    edges_by_type: dict = dataclasses.field(default_factory=lambda: {t: 0 for t in LLMTaskType})

    @property
    def edges_per_call(self) -> float:
        return self.total_new_edges / self.total_calls if self.total_calls > 0 else 0


class LLMScheduler:
    """Budget-aware scheduler for LLM invocations.

    Decides when to invoke the LLM based on:
    - Event priority (crashes > divergences > plateaus > strategy)
    - Budget remaining (calls/hour, tokens/hour)
    - Exponential backoff on repeated plateaus
    - AFL++ productivity (suppress LLM when AFL++ is finding edges on its own)
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._roi = ROITracker()

        # Timing
        self._last_call_time: dict[LLMTaskType, float] = {}
        self._plateau_backoff_factor: float = 1.0
        self._last_strategy_review: float = 0.0
        self._calls_this_hour: list[float] = []

        # Suppression: don't call LLM when AFL++ is productive
        self._afl_productive: bool = False

    def should_invoke(self, task_type: LLMTaskType) -> bool:
        """Check whether an LLM call of the given type should proceed.

        Takes into account:
        - Budget limits
        - Minimum intervals between calls of the same type
        - AFL++ productivity (suppress non-critical calls when AFL++ is finding edges)
        - Exponential backoff for plateau mutations
        """
        now = time.time()

        # Prune old calls from the hour window
        self._calls_this_hour = [t for t in self._calls_this_hour if t > now - 3600]

        # Budget check
        if len(self._calls_this_hour) >= self._config.budget.max_calls_per_hour:
            logger.debug("Budget exhausted for this hour (%d calls)", len(self._calls_this_hour))
            return False

        # Type-specific logic
        if task_type == LLMTaskType.CRASH_ANALYSIS:
            # Always analyze crashes if budget allows
            return self._config.triggers.crash_analysis_enabled

        if task_type == LLMTaskType.DIVERGENCE_TRIAGE:
            return self._config.triggers.divergence_triage_enabled

        if task_type == LLMTaskType.PLATEAU_MUTATION:
            # Suppress during productive phases
            if self._afl_productive:
                logger.debug("Suppressing plateau mutation — AFL++ is productive")
                return False

            # Exponential backoff
            last = self._last_call_time.get(LLMTaskType.PLATEAU_MUTATION, 0)
            min_interval = self._config.triggers.plateau_threshold_seconds * self._plateau_backoff_factor
            return not now - last < min_interval

        if task_type == LLMTaskType.STRATEGY_REVIEW:
            interval = self._config.triggers.strategy_review_interval_seconds
            return not now - self._last_strategy_review < interval

        return True

    def record_call(self, task_type: LLMTaskType) -> None:
        """Record that an LLM call was made."""
        now = time.time()
        self._calls_this_hour.append(now)
        self._last_call_time[task_type] = now
        self._roi.total_calls += 1
        self._roi.calls_by_type[task_type] = self._roi.calls_by_type.get(task_type, 0) + 1

        if task_type == LLMTaskType.STRATEGY_REVIEW:
            self._last_strategy_review = now

    def record_result(self, task_type: LLMTaskType, new_edges: int = 0, new_crashes: int = 0) -> None:
        """Record the outcome of an LLM call for ROI tracking."""
        self._roi.total_new_edges += new_edges
        self._roi.total_new_crashes += new_crashes
        self._roi.edges_by_type[task_type] = self._roi.edges_by_type.get(task_type, 0) + new_edges

        # Adjust plateau backoff based on success
        if task_type == LLMTaskType.PLATEAU_MUTATION:
            if new_edges > 0:
                # Successful — reduce backoff (but not below 1x)
                self._plateau_backoff_factor = max(1.0, self._plateau_backoff_factor * 0.5)
                logger.info("Plateau mutation succeeded (%d edges), backoff=%.1f", new_edges, self._plateau_backoff_factor)
            else:
                # Failed — increase backoff (cap at 8x)
                self._plateau_backoff_factor = min(8.0, self._plateau_backoff_factor * 2.0)
                logger.info("Plateau mutation found nothing, backoff=%.1f", self._plateau_backoff_factor)

    def set_afl_productive(self, productive: bool) -> None:
        """Update whether AFL++ is currently finding new edges on its own."""
        if productive != self._afl_productive:
            logger.info("AFL++ productivity: %s", "productive" if productive else "stalled")
        self._afl_productive = productive

    @property
    def roi(self) -> ROITracker:
        return self._roi

    @property
    def budget_status(self) -> dict:
        now = time.time()
        calls = [t for t in self._calls_this_hour if t > now - 3600]
        return {
            "calls_this_hour": len(calls),
            "max_calls_per_hour": self._config.budget.max_calls_per_hour,
            "budget_remaining_pct": max(0, 100 * (1 - len(calls) / self._config.budget.max_calls_per_hour)),
            "plateau_backoff": self._plateau_backoff_factor,
            "afl_productive": self._afl_productive,
            "roi_edges_per_call": self._roi.edges_per_call,
        }
