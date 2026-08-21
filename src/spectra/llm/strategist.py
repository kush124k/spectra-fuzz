"""LLM-powered campaign strategy advisor.

Periodically reviews campaign progress, analyzes coverage trends, and
recommends high-level strategy adjustments (focus areas, configuration
changes, when to stop).
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from spectra.config import LLMConfig
from spectra.llm.client import LLMClient
from spectra.llm.prompts import STRATEGY_REVIEW_PROMPT, SYSTEM_STRATEGY_ADVISOR

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class StrategyRecommendation(BaseModel):
    """A single strategy recommendation."""
    strategy: str = Field(description="Name/title of the recommended strategy")
    description: str = Field(description="Detailed description of what to do")
    priority: str = Field(default="medium", description="Priority: high, medium, low")
    expected_impact: str = Field(default="", description="Expected impact on coverage/bugs")


class StrategyResponse(BaseModel):
    """Structured strategy review from the LLM."""
    assessment: str = Field(description="Overall campaign assessment")
    recommendations: list[StrategyRecommendation] = Field(
        description="2-3 specific strategy recommendations"
    )
    focus_areas: list[str] = Field(
        default_factory=list,
        description="Protocol features to focus on next",
    )
    config_changes: list[str] = Field(
        default_factory=list,
        description="Suggested AFL++ or campaign configuration changes",
    )
    should_continue: bool = Field(
        default=True,
        description="Whether the campaign should continue running",
    )
    stop_reason: str = Field(default="", description="If stopping, why?")


# ---------------------------------------------------------------------------
# Strategist
# ---------------------------------------------------------------------------

class StrategyAdvisor:
    """High-level campaign strategy advisor.

    Reviews campaign progress periodically and recommends adjustments
    based on coverage trends, crash patterns, and mutation effectiveness.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client = LLMClient(config)
        self._previous_strategies: list[str] = []
        self._review_count: int = 0

    async def review_campaign(
        self,
        runtime_seconds: float,
        total_execs: int,
        execs_per_sec: float,
        corpus_size: int,
        covered_edges: int,
        total_edges: int,
        unique_crashes: int,
        bug_classes: list[str],
        total_divergences: int,
        confirmed_bugs: int,
        spec_ambiguities: int,
        seeds_generated: int,
        seeds_hit_coverage: int,
        coverage_trend: str = "",
    ) -> StrategyResponse:
        """Perform a strategy review of the current campaign.

        Returns a StrategyResponse with recommendations for what to do next.
        """
        self._review_count += 1

        # Format runtime
        hours = int(runtime_seconds // 3600)
        minutes = int((runtime_seconds % 3600) // 60)
        runtime_str = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"

        coverage_pct = (covered_edges / total_edges * 100) if total_edges > 0 else 0
        seed_hit_rate = (seeds_hit_coverage / seeds_generated * 100) if seeds_generated > 0 else 0

        previous_str = "\n".join(
            f"- {s}" for s in self._previous_strategies[-10:]
        ) if self._previous_strategies else "(none yet — first review)"

        prompt = STRATEGY_REVIEW_PROMPT.format(
            runtime_str=runtime_str,
            total_execs=total_execs,
            execs_per_sec=execs_per_sec,
            corpus_size=corpus_size,
            covered_edges=covered_edges,
            total_edges=total_edges,
            coverage_pct=coverage_pct,
            trend_minutes=10,
            coverage_trend=coverage_trend or "(not enough data yet)",
            unique_crashes=unique_crashes,
            bug_classes=", ".join(bug_classes) if bug_classes else "(none yet)",
            total_divergences=total_divergences,
            confirmed_bugs=confirmed_bugs,
            spec_ambiguities=spec_ambiguities,
            seeds_generated=seeds_generated,
            seeds_hit_coverage=seeds_hit_coverage,
            seed_hit_rate=seed_hit_rate,
            previous_strategies=previous_str,
        )

        logger.info("Running strategy review #%d...", self._review_count)

        try:
            response: StrategyResponse = await self._client.generate(
                prompt,
                model=self._config.fast_model,
                response_schema=StrategyResponse,
                system_instruction=SYSTEM_STRATEGY_ADVISOR,
                temperature=0.5,
            )

            # Record for future context
            for rec in response.recommendations:
                self._previous_strategies.append(
                    f"[Review #{self._review_count}] {rec.strategy}: {rec.description[:100]}"
                )

            logger.info(
                "Strategy review #%d: continue=%s, recommendations=%d",
                self._review_count, response.should_continue, len(response.recommendations),
            )

            return response

        except Exception as e:
            logger.error("Strategy review failed: %s", e)
            return StrategyResponse(
                assessment=f"Review failed: {e}",
                recommendations=[],
                should_continue=True,
            )

    @property
    def review_count(self) -> int:
        return self._review_count

    @property
    def recent_strategies(self) -> list[str]:
        return list(self._previous_strategies[-5:])
