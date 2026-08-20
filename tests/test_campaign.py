"""Tests for campaign corpus management."""

import tempfile
from pathlib import Path

import pytest

from spectra.campaign.corpus import CorpusManager, SeedOrigin


class TestCorpusManager:
    def test_add_seed(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        added = corpus.add_seed(b"hello world", SeedOrigin.INITIAL)
        assert added is True
        assert corpus.total_seeds == 1

    def test_dedup_by_content(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        corpus.add_seed(b"hello", SeedOrigin.INITIAL)
        added = corpus.add_seed(b"hello", SeedOrigin.LLM_GENERATED)
        assert added is False
        assert corpus.total_seeds == 1

    def test_different_content_adds(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        corpus.add_seed(b"hello", SeedOrigin.INITIAL)
        corpus.add_seed(b"world", SeedOrigin.INITIAL)
        assert corpus.total_seeds == 2

    def test_add_seeds_batch(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        seeds = [b"seed1", b"seed2", b"seed3", b"seed1"]  # seed1 duplicated
        added = corpus.add_seeds_batch(seeds, SeedOrigin.LLM_GENERATED)
        assert added == 3

    def test_stats(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        corpus.add_seed(b"initial1", SeedOrigin.INITIAL)
        corpus.add_seed(b"initial2", SeedOrigin.INITIAL)
        corpus.add_seed(b"llm_seed", SeedOrigin.LLM_GENERATED)

        stats = corpus.stats
        assert stats["total_seeds"] == 3
        assert stats["by_origin"]["initial"] == 2
        assert stats["by_origin"]["llm"] == 1

    def test_record_coverage_hit(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        seed = b"GET / HTTP/1.1\r\n\r\n"
        corpus.add_seed(seed, SeedOrigin.LLM_GENERATED)
        corpus.record_coverage_hit(seed, new_edges=5)

        stats = corpus.stats
        assert stats["llm_hits"] == 1
        assert stats["llm_hit_rate"] == pytest.approx(100.0)

    def test_get_recent_seeds(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        for i in range(20):
            corpus.add_seed(f"seed_{i}".encode(), SeedOrigin.INITIAL)

        recent = corpus.get_recent_seeds(5)
        assert len(recent) == 5

    def test_load_initial_seeds(self, tmp_path):
        seeds_dir = tmp_path / "seeds"
        seeds_dir.mkdir()
        (seeds_dir / "seed1.txt").write_bytes(b"GET /1 HTTP/1.1\r\n\r\n")
        (seeds_dir / "seed2.txt").write_bytes(b"POST /2 HTTP/1.1\r\n\r\n")

        corpus = CorpusManager(tmp_path / "corpus")
        loaded = corpus.load_initial_seeds(seeds_dir)
        assert loaded == 2
        assert corpus.total_seeds == 2

    def test_corpus_files_created(self, tmp_path):
        corpus = CorpusManager(tmp_path / "corpus")
        corpus.add_seed(b"test data", SeedOrigin.INITIAL)

        # Verify file was created in corpus directory
        files = list((tmp_path / "corpus").iterdir())
        assert len(files) == 1
        assert files[0].read_bytes() == b"test data"
