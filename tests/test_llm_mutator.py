"""Tests for the LLM mutator and scheduler."""

import time

import pytest

from spectra.campaign.scheduler import LLMScheduler, LLMTaskType
from spectra.config import LLMBudget, LLMConfig, LLMMutationConfig, LLMTriggers
from spectra.llm.mutator import LLMMutator, MutationRecord


def make_llm_config(**overrides) -> LLMConfig:
    """Create a test LLM config with sensible defaults."""
    defaults = {
        "provider": "gemini",
        "fast_model": "gemini-2.5-flash",
        "deep_model": "gemini-2.5-pro",
        "api_key_env": "GEMINI_API_KEY",
        "budget": LLMBudget(max_calls_per_hour=10, max_tokens_per_hour=50000),
        "triggers": LLMTriggers(plateau_threshold_seconds=5),
        "mutation": LLMMutationConfig(seeds_per_request=3, max_seed_size_bytes=4096),
    }
    defaults.update(overrides)
    return LLMConfig(**defaults)


class TestLLMScheduler:
    def test_crash_analysis_always_allowed(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)
        assert scheduler.should_invoke(LLMTaskType.CRASH_ANALYSIS) is True

    def test_budget_exhaustion_blocks_calls(self):
        config = make_llm_config(budget=LLMBudget(max_calls_per_hour=2))
        scheduler = LLMScheduler(config)

        scheduler.record_call(LLMTaskType.CRASH_ANALYSIS)
        scheduler.record_call(LLMTaskType.CRASH_ANALYSIS)

        # Budget exhausted
        assert scheduler.should_invoke(LLMTaskType.CRASH_ANALYSIS) is False

    def test_plateau_backoff_increases_on_failure(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)

        # Record a failed plateau mutation
        scheduler.record_call(LLMTaskType.PLATEAU_MUTATION)
        scheduler.record_result(LLMTaskType.PLATEAU_MUTATION, new_edges=0)

        # Backoff should increase
        assert scheduler._plateau_backoff_factor > 1.0

    def test_plateau_backoff_decreases_on_success(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)

        # Increase backoff first
        scheduler._plateau_backoff_factor = 4.0

        # Record a successful mutation
        scheduler.record_call(LLMTaskType.PLATEAU_MUTATION)
        scheduler.record_result(LLMTaskType.PLATEAU_MUTATION, new_edges=5)

        assert scheduler._plateau_backoff_factor < 4.0

    def test_afl_productive_suppresses_plateau(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)

        scheduler.set_afl_productive(True)
        assert scheduler.should_invoke(LLMTaskType.PLATEAU_MUTATION) is False

        scheduler.set_afl_productive(False)
        # Should be allowed again (after threshold passes)

    def test_roi_tracking(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)

        scheduler.record_call(LLMTaskType.PLATEAU_MUTATION)
        scheduler.record_result(LLMTaskType.PLATEAU_MUTATION, new_edges=10)

        scheduler.record_call(LLMTaskType.CRASH_ANALYSIS)
        scheduler.record_result(LLMTaskType.CRASH_ANALYSIS, new_edges=5, new_crashes=1)

        roi = scheduler.roi
        assert roi.total_calls == 2
        assert roi.total_new_edges == 15
        assert roi.total_new_crashes == 1
        assert roi.edges_per_call == pytest.approx(7.5)

    def test_budget_status(self):
        config = make_llm_config()
        scheduler = LLMScheduler(config)
        scheduler.record_call(LLMTaskType.CRASH_ANALYSIS)

        status = scheduler.budget_status
        assert status["calls_this_hour"] == 1
        assert status["budget_remaining_pct"] > 0


class TestLLMMutator:
    def test_basic_validate_http_methods(self):
        config = make_llm_config()
        mutator = LLMMutator(config)

        assert mutator._basic_validate(b"GET / HTTP/1.1\r\n") is True
        assert mutator._basic_validate(b"POST /data HTTP/1.1\r\n") is True
        assert mutator._basic_validate(b"DELETE /item HTTP/1.0\r\n") is True

    def test_basic_validate_rejects_tiny(self):
        config = make_llm_config()
        mutator = LLMMutator(config)
        assert mutator._basic_validate(b"") is False
        assert mutator._basic_validate(b"ab") is False

    def test_basic_validate_accepts_binary_with_newlines(self):
        config = make_llm_config()
        mutator = LLMMutator(config)
        assert mutator._basic_validate(b"\x00\x01\x02\r\n\x03") is True

    def test_record_coverage_hit(self):
        config = make_llm_config()
        mutator = LLMMutator(config)

        # Simulate a generated seed
        seed = b"GET /test HTTP/1.1\r\nHost: test\r\n\r\n"
        import hashlib
        seed_hash = hashlib.sha256(seed).hexdigest()[:12]

        record = MutationRecord(
            seed_hash=seed_hash,
            seed_data=seed,
            rationale="test mutation",
            confidence=0.8,
            generated_at=time.time(),
        )
        mutator._all_mutations.append(record)
        mutator._total_generated = 1

        # Record coverage hit
        mutator.record_coverage_hit(seed, new_edges=5)

        assert len(mutator._successful_mutations) == 1
        assert mutator._total_hit_coverage == 1
        assert mutator.stats["hit_rate_pct"] == pytest.approx(100.0)

    def test_stats_empty(self):
        config = make_llm_config()
        mutator = LLMMutator(config)
        stats = mutator.stats
        assert stats["total_generated"] == 0
        assert stats["hit_rate_pct"] == 0
