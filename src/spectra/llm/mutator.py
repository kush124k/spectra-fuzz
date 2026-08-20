"""LLM-guided seed mutation engine.

When coverage plateaus, this module constructs context-rich prompts with
coverage gaps and protocol knowledge, asks Gemini to generate new seeds,
validates them, and tracks which LLM seeds led to new coverage (feedback loop).
"""

from __future__ import annotations

import base64
import dataclasses
import logging
import time
from collections import deque

from pydantic import BaseModel, Field

from spectra.config import LLMConfig
from spectra.engine.base import CoverageMap
from spectra.llm.client import LLMClient
from spectra.llm.prompts import MUTATION_GENERATION_PROMPT, SYSTEM_MUTATION_GENERATOR

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class GeneratedSeed(BaseModel):
    """A single LLM-generated seed input."""
    input_base64: str = Field(description="Base64-encoded raw bytes of the test input")
    rationale: str = Field(description="Why this input should trigger new coverage")
    confidence: float = Field(default=0.5, description="Confidence score 0.0–1.0")
    target_feature: str = Field(default="", description="Protocol feature being targeted")


class MutationResponse(BaseModel):
    """Structured response from the mutation generator."""
    seeds: list[GeneratedSeed] = Field(description="Generated seed inputs")
    strategy_notes: str = Field(default="", description="Notes on the mutation strategy used")


# ---------------------------------------------------------------------------
# Mutation tracking
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class MutationRecord:
    """Tracks the outcome of an LLM-generated seed."""
    seed_hash: str
    seed_data: bytes
    rationale: str
    confidence: float
    generated_at: float
    injected: bool = False
    hit_new_coverage: bool = False
    new_edges_found: int = 0


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

class LLMMutator:
    """LLM-guided seed generation for breaking coverage plateaus.

    Maintains a feedback loop: tracks which past seeds hit new coverage
    and uses successful ones as few-shot examples in future prompts.
    """

    def __init__(self, config: LLMConfig, protocol_name: str = "HTTP/1.1") -> None:
        self._config = config
        self._client = LLMClient(config)
        self._protocol = protocol_name

        # Feedback loop state
        self._all_mutations: deque[MutationRecord] = deque(maxlen=1000)
        self._successful_mutations: deque[MutationRecord] = deque(maxlen=50)
        self._total_generated: int = 0
        self._total_hit_coverage: int = 0

    async def generate_seeds(
        self,
        coverage: CoverageMap,
        plateau_seconds: float,
        uncovered_hints: str = "",
        recent_inputs: list[bytes] | None = None,
    ) -> list[bytes]:
        """Generate new seed inputs guided by the current coverage state.

        Args:
            coverage: Current coverage map
            plateau_seconds: Seconds since last new edge
            uncovered_hints: Source code snippets of uncovered branches
            recent_inputs: Recent corpus entries for context

        Returns:
            List of raw bytes for new seed inputs
        """
        n_seeds = self._config.mutation.seeds_per_request

        # Build few-shot examples from successful past mutations
        few_shot = self._build_few_shot_examples()

        # Format recent inputs
        recent_str = ""
        if recent_inputs:
            for i, inp in enumerate(recent_inputs[:5]):
                try:
                    text = inp.decode("ascii", errors="replace")[:200]
                    recent_str += f"\nInput {i+1}:\n{text}\n"
                except Exception:
                    recent_str += f"\nInput {i+1}: ({len(inp)} bytes, binary)\n"

        prompt = MUTATION_GENERATION_PROMPT.format(
            protocol_name=self._protocol,
            total_edges=coverage.total_edges,
            covered_edges=coverage.covered_edges,
            coverage_pct=coverage.coverage_pct,
            plateau_seconds=plateau_seconds,
            uncovered_hints=uncovered_hints or "(no specific hints available)",
            few_shot_examples=few_shot or "(no successful past mutations yet)",
            recent_inputs=recent_str or "(no recent inputs)",
            n_seeds=n_seeds,
        )

        logger.info(
            "Generating %d seeds via LLM (coverage=%.1f%%, plateau=%.0fs)",
            n_seeds, coverage.coverage_pct, plateau_seconds,
        )

        try:
            response: MutationResponse = await self._client.generate(
                prompt,
                response_schema=MutationResponse,
                system_instruction=SYSTEM_MUTATION_GENERATOR,
                temperature=0.9,  # higher temperature for creative mutations
            )
        except Exception as e:
            logger.error("LLM mutation generation failed: %s", e)
            return []

        # Decode and validate seeds
        seeds: list[bytes] = []
        for gen_seed in response.seeds:
            try:
                raw = base64.b64decode(gen_seed.input_base64)

                # Size validation
                if len(raw) > self._config.mutation.max_seed_size_bytes:
                    raw = raw[:self._config.mutation.max_seed_size_bytes]

                if len(raw) == 0:
                    continue

                # Optional format validation
                if self._config.mutation.validate_before_inject:
                    if not self._basic_validate(raw):
                        logger.debug("Seed failed validation: %s", gen_seed.rationale[:80])
                        continue

                seeds.append(raw)

                # Record for tracking
                import hashlib
                seed_hash = hashlib.sha256(raw).hexdigest()[:12]
                record = MutationRecord(
                    seed_hash=seed_hash,
                    seed_data=raw,
                    rationale=gen_seed.rationale,
                    confidence=gen_seed.confidence,
                    generated_at=time.time(),
                )
                self._all_mutations.append(record)
                self._total_generated += 1

            except Exception as e:
                logger.warning("Failed to decode LLM seed: %s", e)

        logger.info(
            "Generated %d valid seeds from %d LLM proposals (strategy: %s)",
            len(seeds), len(response.seeds), response.strategy_notes[:100],
        )

        return seeds

    def record_coverage_hit(self, seed_data: bytes, new_edges: int) -> None:
        """Record that an LLM-generated seed triggered new coverage.

        This feeds back into the few-shot examples for future prompts.
        """
        import hashlib
        target_hash = hashlib.sha256(seed_data).hexdigest()[:12]

        for record in reversed(self._all_mutations):
            if record.seed_hash == target_hash:
                record.hit_new_coverage = True
                record.new_edges_found = new_edges
                self._successful_mutations.append(record)
                self._total_hit_coverage += 1
                logger.info(
                    "LLM seed hit %d new edges: %s",
                    new_edges, record.rationale[:80],
                )
                return

    def _build_few_shot_examples(self) -> str:
        """Build few-shot examples from past successful mutations."""
        examples = list(self._successful_mutations)[-self._config.mutation.few_shot_examples:]
        if not examples:
            return ""

        parts: list[str] = []
        for i, ex in enumerate(examples, 1):
            try:
                text = ex.seed_data.decode("ascii", errors="replace")[:200]
            except Exception:
                text = f"({len(ex.seed_data)} bytes, binary data)"

            parts.append(
                f"Example {i} (hit {ex.new_edges_found} new edges):\n"
                f"  Input: {text}\n"
                f"  Rationale: {ex.rationale}\n"
            )

        return "\n".join(parts)

    def _basic_validate(self, data: bytes) -> bool:
        """Basic validation that a seed looks like plausible protocol input.

        For HTTP: must start with a method or contain recognizable HTTP content.
        Override this for different protocols.
        """
        if len(data) < 3:
            return False

        # For HTTP: check if it starts with a method or response line
        http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                        b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE"]
        http_response = b"HTTP/"

        first_bytes = data[:10].upper()
        if any(first_bytes.startswith(m) for m in http_methods):
            return True
        if first_bytes.startswith(http_response):
            return True

        # Also accept anything with \r\n (protocol-like)
        if b"\r\n" in data or b"\n" in data:
            return True

        # Accept raw binary too (for edge-case testing)
        return True

    @property
    def stats(self) -> dict:
        """Mutation engine statistics."""
        hit_rate = (self._total_hit_coverage / self._total_generated * 100) if self._total_generated > 0 else 0
        return {
            "total_generated": self._total_generated,
            "total_hit_coverage": self._total_hit_coverage,
            "hit_rate_pct": hit_rate,
            "successful_examples": len(self._successful_mutations),
        }
