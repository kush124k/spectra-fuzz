"""Differential oracle — runs the same input through multiple targets and compares outputs.

The oracle is the core of differential fuzzing: any divergent behavior between
implementations is a potential bug (or at minimum a spec clarification opportunity).
Divergences are classified, deduplicated, and stored in a SQLite database.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
import sqlite3
import time
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from spectra.config import DifferentialConfig, LLMConfig
from spectra.differential.normalizer import OutputNormalizer
from spectra.llm.client import LLMClient
from spectra.llm.prompts import DIVERGENCE_TRIAGE_PROMPT, SYSTEM_DIVERGENCE_TRIAGER

logger = logging.getLogger(__name__)


class DivergenceClass(str, Enum):
    """Classification of a differential divergence."""
    BUG = "bug"
    SPEC_AMBIGUITY = "spec_ambiguity"
    BENIGN = "benign_difference"
    UNCLASSIFIED = "unclassified"


@dataclasses.dataclass
class TargetOutput:
    """Output from running an input through a single target."""
    target_name: str
    exit_code: int
    stdout: str
    stderr: str
    runtime_ms: float
    crashed: bool = False
    timed_out: bool = False


@dataclasses.dataclass
class Divergence:
    """A detected divergence between two implementations."""
    divergence_id: str
    input_data: bytes
    target_a: TargetOutput
    target_b: TargetOutput
    classification: DivergenceClass = DivergenceClass.UNCLASSIFIED
    explanation: str = ""
    faulty_target: str = ""
    spec_reference: str = ""
    severity: str = "unknown"
    timestamp: float = dataclasses.field(default_factory=time.time)
    llm_triaged: bool = False


# ---------------------------------------------------------------------------
# LLM triage response schema
# ---------------------------------------------------------------------------

class TriageResponse(BaseModel):
    """Structured divergence triage from the LLM."""
    classification: str = Field(description="bug, spec_ambiguity, or benign_difference")
    faulty_target: str = Field(default="unknown", description="Which implementation is wrong")
    spec_reference: str = Field(default="", description="Relevant spec section")
    explanation: str = Field(description="Detailed explanation")
    minimal_reproducer: str = Field(default="", description="Simplified input triggering divergence")


# ---------------------------------------------------------------------------
# Oracle
# ---------------------------------------------------------------------------

class DifferentialOracle:
    """Runs inputs through multiple targets and detects behavioral divergences.

    Workflow:
    1. Execute the same input against all registered targets
    2. Normalize outputs to remove benign differences
    3. Compare outputs pairwise
    4. Classify and store divergences
    5. Optionally triage via LLM
    """

    def __init__(
        self,
        config: DifferentialConfig,
        llm_config: LLMConfig | None = None,
        targets: dict[str, tuple[Path, list[str]]] | None = None,
    ) -> None:
        self._config = config
        self._normalizer = OutputNormalizer(config.ignore_patterns)
        self._targets = targets or {}
        self._divergences: list[Divergence] = []
        self._seen_hashes: set[str] = set()

        # LLM triage client
        self._llm_client: LLMClient | None = None
        if llm_config and config.enabled:
            self._llm_client = LLMClient(llm_config)

        # Database
        self._db_path = Path(config.divergence_db)
        self._db: sqlite3.Connection | None = None
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite divergence database."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self._db_path))
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS divergences (
                divergence_id TEXT PRIMARY KEY,
                input_hex TEXT,
                target_a TEXT,
                target_b TEXT,
                output_a TEXT,
                output_b TEXT,
                classification TEXT,
                explanation TEXT,
                faulty_target TEXT,
                spec_reference TEXT,
                timestamp REAL
            )
        """)
        self._db.commit()

    def register_target(self, name: str, binary_path: Path, args: list[str]) -> None:
        """Register a target implementation for differential comparison."""
        self._targets[name] = (binary_path, args)

    async def run_input(
        self,
        input_data: bytes,
        timeout_seconds: float = 5.0,
    ) -> dict[str, TargetOutput]:
        """Run the same input through all registered targets.

        Returns a dict mapping target name → output.
        """
        import tempfile

        # Write input to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".input") as f:
            f.write(input_data)
            input_path = Path(f.name)

        try:
            results: dict[str, TargetOutput] = {}

            # Run all targets concurrently
            tasks = []
            for name, (binary, args) in self._targets.items():
                tasks.append(self._run_single(name, binary, args, input_path, timeout_seconds))

            outputs = await asyncio.gather(*tasks, return_exceptions=True)

            for (name, _), output in zip(self._targets.items(), outputs):
                if isinstance(output, Exception):
                    results[name] = TargetOutput(
                        target_name=name,
                        exit_code=-1,
                        stdout="",
                        stderr=f"Execution error: {output}",
                        runtime_ms=0,
                        crashed=True,
                    )
                else:
                    results[name] = output

            return results
        finally:
            input_path.unlink(missing_ok=True)

    async def _run_single(
        self,
        name: str,
        binary: Path,
        args: list[str],
        input_path: Path,
        timeout: float,
    ) -> TargetOutput:
        """Execute a single target with the given input."""
        cmd_args = [str(binary)]
        for arg in args:
            if arg == "@@":
                cmd_args.append(str(input_path))
            else:
                cmd_args.append(arg)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            elapsed = (time.monotonic() - start) * 1000

            return TargetOutput(
                target_name=name,
                exit_code=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
                runtime_ms=elapsed,
                crashed=proc.returncode not in (0, None),
            )
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000
            return TargetOutput(
                target_name=name,
                exit_code=-1,
                stdout="",
                stderr="TIMEOUT",
                runtime_ms=elapsed,
                timed_out=True,
            )

    async def check_divergence(
        self,
        input_data: bytes,
        auto_triage: bool = True,
    ) -> list[Divergence]:
        """Run an input and check for divergences between all target pairs.

        Returns a list of detected divergences.
        """
        if len(self._targets) < 2:
            return []

        outputs = await self.run_input(input_data)
        target_names = list(outputs.keys())
        new_divergences: list[Divergence] = []

        # Pairwise comparison
        for i in range(len(target_names)):
            for j in range(i + 1, len(target_names)):
                a_name = target_names[i]
                b_name = target_names[j]
                a_out = outputs[a_name]
                b_out = outputs[b_name]

                if self._outputs_diverge(a_out, b_out):
                    div_hash = self._divergence_hash(input_data, a_name, b_name)
                    if div_hash in self._seen_hashes:
                        continue
                    self._seen_hashes.add(div_hash)

                    div = Divergence(
                        divergence_id=div_hash,
                        input_data=input_data,
                        target_a=a_out,
                        target_b=b_out,
                    )

                    # LLM triage
                    if auto_triage and self._llm_client and self._config.enabled:
                        div = await self._triage_divergence(div)

                    self._divergences.append(div)
                    self._store_divergence(div)
                    new_divergences.append(div)

                    logger.info(
                        "Divergence detected: %s vs %s [%s] — %s",
                        a_name, b_name, div.classification.value,
                        div.explanation[:100] if div.explanation else "unclassified",
                    )

        return new_divergences

    def _outputs_diverge(self, a: TargetOutput, b: TargetOutput) -> bool:
        """Check if two outputs are materially different."""
        # Always flag if one crashed and the other didn't
        if a.crashed != b.crashed:
            return True
        if a.timed_out != b.timed_out:
            return True

        # Normalize and compare
        a_normalized = self._normalizer.normalize(a.stdout)
        b_normalized = self._normalizer.normalize(b.stdout)

        if a_normalized != b_normalized:
            return True

        # Check exit codes
        if a.exit_code != b.exit_code:
            return True

        return False

    def _divergence_hash(self, input_data: bytes, a_name: str, b_name: str) -> str:
        """Compute a deduplication hash for a divergence."""
        h = hashlib.sha256()
        h.update(input_data)
        h.update(a_name.encode())
        h.update(b_name.encode())
        return h.hexdigest()[:16]

    async def _triage_divergence(self, div: Divergence) -> Divergence:
        """Use the LLM to triage a divergence."""
        if not self._llm_client:
            return div

        # Format input
        try:
            input_ascii = div.input_data.decode("ascii")
            input_hex = ""
            input_ascii_section = f"### Input as ASCII\n```\n{input_ascii[:1000]}\n```"
        except (UnicodeDecodeError, ValueError):
            input_hex = div.input_data[:256].hex()
            input_ascii_section = ""

        prompt = DIVERGENCE_TRIAGE_PROMPT.format(
            protocol_name="HTTP/1.1",
            input_hex=input_hex or div.input_data[:256].hex(),
            input_ascii_section=input_ascii_section,
            target_a_name=div.target_a.target_name,
            output_a=div.target_a.stdout[:2000],
            target_b_name=div.target_b.target_name,
            output_b=div.target_b.stdout[:2000],
            spec_context="RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1)",
        )

        try:
            response: TriageResponse = await self._llm_client.generate(
                prompt,
                response_schema=TriageResponse,
                system_instruction=SYSTEM_DIVERGENCE_TRIAGER,
                temperature=0.3,
            )

            div.classification = DivergenceClass(response.classification)
            div.explanation = response.explanation
            div.faulty_target = response.faulty_target
            div.spec_reference = response.spec_reference
            div.llm_triaged = True

        except Exception as e:
            logger.warning("LLM triage failed: %s", e)

        return div

    def _store_divergence(self, div: Divergence) -> None:
        """Store a divergence in the SQLite database."""
        if self._db is None:
            return

        self._db.execute(
            """INSERT OR REPLACE INTO divergences
               (divergence_id, input_hex, target_a, target_b,
                output_a, output_b, classification, explanation,
                faulty_target, spec_reference, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                div.divergence_id,
                div.input_data.hex(),
                div.target_a.target_name,
                div.target_b.target_name,
                div.target_a.stdout[:5000],
                div.target_b.stdout[:5000],
                div.classification.value,
                div.explanation,
                div.faulty_target,
                div.spec_reference,
                div.timestamp,
            ),
        )
        self._db.commit()

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        total = len(self._divergences)
        bugs = sum(1 for d in self._divergences if d.classification == DivergenceClass.BUG)
        ambig = sum(1 for d in self._divergences if d.classification == DivergenceClass.SPEC_AMBIGUITY)
        benign = sum(1 for d in self._divergences if d.classification == DivergenceClass.BENIGN)
        return {
            "total_divergences": total,
            "confirmed_bugs": bugs,
            "spec_ambiguities": ambig,
            "benign_differences": benign,
            "unclassified": total - bugs - ambig - benign,
        }

    @property
    def divergences(self) -> list[Divergence]:
        return list(self._divergences)

    def close(self) -> None:
        if self._db:
            self._db.close()
