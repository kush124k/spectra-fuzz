"""Tests for the differential oracle and output normalization."""

import pytest

from spectra.differential.normalizer import OutputNormalizer
from spectra.differential.oracle import (
    DifferentialOracle,
    DivergenceClass,
    TargetOutput,
)
from spectra.config import DifferentialConfig


class TestOutputNormalizer:
    def test_normalizes_timestamps(self):
        norm = OutputNormalizer()
        text = "Date: 2025-01-15T10:30:00Z\nContent: hello"
        result = norm.normalize(text)
        assert "2025-01-15" not in result
        assert "TIMESTAMP" in result
        assert "hello" in result

    def test_normalizes_memory_addresses(self):
        norm = OutputNormalizer()
        text = "ptr=0x7ffd12345678 value=42"
        result = norm.normalize(text)
        assert "0x7ffd12345678" not in result
        assert "0xADDR" in result
        assert "42" in result

    def test_normalizes_pids(self):
        norm = OutputNormalizer()
        text = "pid=12345 running"
        result = norm.normalize(text)
        assert "12345" not in result
        assert "pid=PID" in result

    def test_user_patterns(self):
        norm = OutputNormalizer(user_patterns=["Server:.*", "X-Request-Id:.*"])
        text = "Server: nginx/1.25\nContent-Type: text/html\nX-Request-Id: abc123"
        result = norm.normalize(text)
        assert "nginx" not in result
        assert "abc123" not in result
        assert "text/html" in result

    def test_whitespace_normalization(self):
        norm = OutputNormalizer()
        text = "  hello  \r\n  world  \r\n\r\n"
        result = norm.normalize(text)
        assert result == "hello\nworld"

    def test_diff_summary_identical(self):
        norm = OutputNormalizer()
        text = "hello\nworld"
        summary = norm.diff_summary(text, text)
        assert "no differences" in summary

    def test_diff_summary_different(self):
        norm = OutputNormalizer()
        summary = norm.diff_summary("hello\nfoo", "hello\nbar")
        assert "Line 2" in summary
        assert "foo" in summary
        assert "bar" in summary


class TestDifferentialOracle:
    def test_outputs_diverge_crash_vs_success(self):
        config = DifferentialConfig(enabled=True, divergence_db=":memory:")
        oracle = DifferentialOracle(config)

        a = TargetOutput("target_a", exit_code=0, stdout="OK", stderr="", runtime_ms=1, crashed=False)
        b = TargetOutput("target_b", exit_code=139, stdout="", stderr="SEGFAULT", runtime_ms=1, crashed=True)

        assert oracle._outputs_diverge(a, b) is True

    def test_outputs_diverge_different_output(self):
        config = DifferentialConfig(enabled=True, divergence_db=":memory:")
        oracle = DifferentialOracle(config)

        a = TargetOutput("target_a", exit_code=0, stdout="STATUS: OK\nMETHOD: GET", stderr="", runtime_ms=1)
        b = TargetOutput("target_b", exit_code=0, stdout="STATUS: OK\nMETHOD: POST", stderr="", runtime_ms=1)

        assert oracle._outputs_diverge(a, b) is True

    def test_outputs_same_after_normalization(self):
        config = DifferentialConfig(enabled=True, ignore_patterns=["Date:.*"], divergence_db=":memory:")
        oracle = DifferentialOracle(config)

        a = TargetOutput("target_a", exit_code=0, stdout="Date: Mon, 01 Jan 2025 00:00:00 GMT\nOK", stderr="", runtime_ms=1)
        b = TargetOutput("target_b", exit_code=0, stdout="Date: Tue, 02 Jan 2025 00:00:00 GMT\nOK", stderr="", runtime_ms=1)

        # After Date: is stripped, both should be "OK"
        assert oracle._outputs_diverge(a, b) is False

    def test_divergence_stats(self):
        config = DifferentialConfig(enabled=True, divergence_db=":memory:")
        oracle = DifferentialOracle(config)

        stats = oracle.stats
        assert stats["total_divergences"] == 0
        assert stats["confirmed_bugs"] == 0
