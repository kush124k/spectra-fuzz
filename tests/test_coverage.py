"""Tests for coverage bitmap parsing and plateau detection."""

import time

import pytest

from spectra.engine.base import CoverageEdge, CoverageMap
from spectra.engine.coverage import (
    PlateauDetector,
    coverage_diff,
    coverage_summary,
    parse_coverage_bitmap,
)


class TestParseCoverageBitmap:
    def test_empty_bitmap(self):
        raw = bytes(256)
        cov = parse_coverage_bitmap(raw, map_size=256)
        assert cov.covered_edges == 0
        assert cov.total_edges == 256
        assert cov.coverage_pct == 0.0

    def test_some_edges_covered(self):
        raw = bytearray(256)
        raw[0] = 1
        raw[10] = 5
        raw[100] = 255
        cov = parse_coverage_bitmap(bytes(raw), map_size=256)
        assert cov.covered_edges == 3
        assert len(cov.edge_details) == 3
        assert cov.edge_details[0].edge_id == 0
        assert cov.edge_details[0].hit_count == 1
        assert cov.edge_details[1].edge_id == 10
        assert cov.edge_details[1].hit_count == 5
        assert cov.edge_details[2].edge_id == 100
        assert cov.edge_details[2].hit_count == 255

    def test_full_coverage(self):
        raw = bytes([1] * 100)
        cov = parse_coverage_bitmap(raw, map_size=100)
        assert cov.covered_edges == 100
        assert cov.coverage_pct == 100.0

    def test_coverage_pct(self):
        raw = bytearray(1000)
        for i in range(250):
            raw[i] = 1
        cov = parse_coverage_bitmap(bytes(raw), map_size=1000)
        assert cov.coverage_pct == pytest.approx(25.0)


class TestCoverageDiff:
    def test_diff_finds_new_edges(self):
        old_bitmap = bytearray(100)
        old_bitmap[0] = 1
        old_bitmap[5] = 1
        old = parse_coverage_bitmap(bytes(old_bitmap), map_size=100)

        new_bitmap = bytearray(100)
        new_bitmap[0] = 1
        new_bitmap[5] = 1
        new_bitmap[10] = 1  # new edge
        new_bitmap[20] = 3  # new edge
        new = parse_coverage_bitmap(bytes(new_bitmap), map_size=100)

        diff = coverage_diff(old, new)
        new_ids = {e.edge_id for e in diff}
        assert 10 in new_ids
        assert 20 in new_ids
        assert 0 not in new_ids
        assert 5 not in new_ids


class TestCoverageSummary:
    def test_summary_format(self):
        cov = CoverageMap(
            bitmap=b"",
            total_edges=1000,
            covered_edges=250,
        )
        s = coverage_summary(cov)
        assert "250/1000" in s
        assert "25.0%" in s


class TestPlateauDetector:
    def test_no_plateau_initially(self):
        detector = PlateauDetector(threshold_seconds=2.0)
        cov = CoverageMap(total_edges=100, covered_edges=10)
        assert detector.update(cov) is False

    def test_growth_resets_plateau(self):
        detector = PlateauDetector(threshold_seconds=0.1)
        cov1 = CoverageMap(total_edges=100, covered_edges=10)
        detector.update(cov1)

        time.sleep(0.15)

        # Growing coverage should not trigger plateau
        cov2 = CoverageMap(total_edges=100, covered_edges=15)
        assert detector.update(cov2) is False
        assert not detector.is_plateau

    def test_plateau_fires_once(self):
        detector = PlateauDetector(threshold_seconds=0.05)
        cov = CoverageMap(total_edges=100, covered_edges=10)
        detector.update(cov)

        time.sleep(0.1)

        # Same coverage → plateau
        result = detector.update(cov)
        assert result is True

        # Should not fire again
        result = detector.update(cov)
        assert result is False

    def test_reset_allows_refire(self):
        detector = PlateauDetector(threshold_seconds=0.05)
        cov = CoverageMap(total_edges=100, covered_edges=10)
        detector.update(cov)

        time.sleep(0.1)
        detector.update(cov)  # fires plateau

        detector.reset_plateau()
        time.sleep(0.1)

        result = detector.update(cov)
        assert result is True
