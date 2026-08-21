"""LLM-powered crash trace analyzer.

Takes crash inputs + sanitizer traces, sends them to Gemini for deep analysis,
and returns structured crash reports with root cause, severity, and follow-up
seed suggestions.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import logging

from pydantic import BaseModel, Field

from spectra.config import LLMConfig
from spectra.engine.base import CrashInfo
from spectra.llm.client import LLMClient
from spectra.llm.prompts import CRASH_ANALYSIS_PROMPT, SYSTEM_CRASH_ANALYZER

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Response schemas (Pydantic models for structured Gemini output)
# ---------------------------------------------------------------------------

class SuggestedInput(BaseModel):
    """A follow-up input suggested by the LLM."""
    input_base64: str = Field(description="Base64-encoded raw bytes of the suggested input")
    description: str = Field(description="Why this input might trigger a related bug")
    target_path: str = Field(default="", description="Code path this input is designed to reach")


class CrashAnalysisResponse(BaseModel):
    """Structured crash analysis from the LLM."""
    bug_class: str = Field(description="Bug classification (e.g., heap-buffer-overflow, use-after-free)")
    root_cause: str = Field(description="Detailed root cause explanation")
    severity: str = Field(description="Severity level: critical, high, medium, or low")
    summary: str = Field(description="One-line summary of the vulnerability")
    suggested_inputs: list[SuggestedInput] = Field(
        default_factory=list,
        description="3-5 follow-up inputs to find related bugs",
    )
    exploitability_notes: str = Field(default="", description="Notes on exploitability")


# ---------------------------------------------------------------------------
# Crash report (internal representation)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class CrashReport:
    """Complete crash report combining raw data with LLM analysis."""
    crash_id: str
    crash_hash: str
    target_name: str
    input_data: bytes
    stack_trace: str
    signal: int

    # LLM analysis results
    bug_class: str = "unknown"
    root_cause: str = ""
    severity: str = "unknown"
    summary: str = ""
    suggested_inputs: list[SuggestedInput] = dataclasses.field(default_factory=list)
    exploitability_notes: str = ""
    analyzed: bool = False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CrashAnalyzer:
    """Analyzes crash traces using the Gemini API.

    Deduplicates crashes by stack hash, enriches with source context,
    and produces structured CrashReport objects.
    """

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client = LLMClient(config)
        self._analyzed_hashes: dict[str, CrashReport] = {}

    def _compute_crash_hash(self, crash: CrashInfo) -> str:
        """Compute a deduplication hash from crash trace + signal."""
        h = hashlib.sha256()
        h.update(crash.stack_trace.encode("utf-8", errors="replace"))
        h.update(str(crash.signal).encode())
        return h.hexdigest()[:16]

    def _format_input_hex(self, data: bytes, max_bytes: int = 512) -> str:
        """Format input data as a hex dump for the prompt."""
        truncated = data[:max_bytes]
        lines = []
        for i in range(0, len(truncated), 16):
            chunk = truncated[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
        if len(data) > max_bytes:
            lines.append(f"... ({len(data) - max_bytes} more bytes)")
        return "\n".join(lines)

    def _format_input_ascii(self, data: bytes, max_bytes: int = 1024) -> str:
        """Try to render the input as ASCII text if it's printable."""
        try:
            text = data[:max_bytes].decode("ascii")
            if all(c.isprintable() or c in "\r\n\t" for c in text):
                return text
        except (UnicodeDecodeError, ValueError):
            pass
        return ""

    async def analyze_crash(
        self,
        crash_input: bytes,
        crash_trace: str,
        target_name: str,
        source_context: str = "",
        crash_id: str = "",
        signal: int = 0,
    ) -> CrashReport:
        """Analyze a single crash using the LLM.

        Returns a structured CrashReport with root cause analysis,
        severity rating, and suggested follow-up inputs.
        """
        # Build the crash info
        crash = CrashInfo(
            crash_id=crash_id or "manual",
            file_path=None,  # type: ignore
            target_name=target_name,
            input_data=crash_input,
            stack_trace=crash_trace,
            signal=signal,
        )

        crash_hash = self._compute_crash_hash(crash)

        # Check dedup cache
        if crash_hash in self._analyzed_hashes:
            logger.info("Crash %s already analyzed (hash=%s)", crash_id, crash_hash)
            return self._analyzed_hashes[crash_hash]

        # Build the prompt
        hex_dump = self._format_input_hex(crash_input)
        ascii_text = self._format_input_ascii(crash_input)
        ascii_section = f"### Input as ASCII\n```\n{ascii_text}\n```" if ascii_text else ""

        prompt = CRASH_ANALYSIS_PROMPT.format(
            target_name=target_name,
            crash_input_hex=hex_dump,
            crash_input_ascii_section=ascii_section,
            stack_trace=crash_trace or "(no trace available — input only)",
            source_context=source_context or "(source context not available)",
        )

        logger.info("Analyzing crash %s (hash=%s) via LLM...", crash_id, crash_hash)

        try:
            response: CrashAnalysisResponse = await self._client.generate(
                prompt,
                model=self._config.deep_model,  # use the deep model for crash analysis
                response_schema=CrashAnalysisResponse,
                system_instruction=SYSTEM_CRASH_ANALYZER,
                temperature=0.3,  # lower temperature for factual analysis
            )

            report = CrashReport(
                crash_id=crash_id,
                crash_hash=crash_hash,
                target_name=target_name,
                input_data=crash_input,
                stack_trace=crash_trace,
                signal=signal,
                bug_class=response.bug_class,
                root_cause=response.root_cause,
                severity=response.severity,
                summary=response.summary,
                suggested_inputs=response.suggested_inputs,
                exploitability_notes=response.exploitability_notes,
                analyzed=True,
            )
        except Exception as e:
            logger.error("LLM crash analysis failed: %s", e)
            report = CrashReport(
                crash_id=crash_id,
                crash_hash=crash_hash,
                target_name=target_name,
                input_data=crash_input,
                stack_trace=crash_trace,
                signal=signal,
                summary=f"Analysis failed: {e}",
            )

        self._analyzed_hashes[crash_hash] = report
        return report

    async def analyze_crash_info(self, crash: CrashInfo, source_context: str = "") -> CrashReport:
        """Convenience wrapper that takes a CrashInfo object."""
        return await self.analyze_crash(
            crash_input=crash.input_data,
            crash_trace=crash.stack_trace,
            target_name=crash.target_name,
            source_context=source_context,
            crash_id=crash.crash_id,
            signal=crash.signal,
        )

    def get_suggested_seeds(self, report: CrashReport) -> list[bytes]:
        """Extract raw seed bytes from a crash report's suggested inputs."""
        seeds: list[bytes] = []
        for suggestion in report.suggested_inputs:
            try:
                raw = base64.b64decode(suggestion.input_base64)
                seeds.append(raw)
            except Exception as e:
                logger.warning("Failed to decode suggested input: %s", e)
        return seeds

    @property
    def analyzed_count(self) -> int:
        return len(self._analyzed_hashes)

    @property
    def reports(self) -> dict[str, CrashReport]:
        return dict(self._analyzed_hashes)
