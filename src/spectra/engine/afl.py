"""AFL++ fuzzing engine integration.

Manages AFL++ processes, reads stats/crashes/queue from the filesystem,
and injects LLM-generated seeds into the corpus.  Supports running via
WSL2 on Windows hosts.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import time
from pathlib import Path, PurePosixPath

from spectra.config import EngineConfig
from spectra.engine.base import CoverageMap, CrashInfo, FuzzEngine, FuzzStats

logger = logging.getLogger(__name__)


def _win_to_wsl_path(win_path: Path) -> str:
    """Convert a Windows path to a WSL path (e.g. C:\\foo → /mnt/c/foo)."""
    drive = win_path.drive.rstrip(":").lower()
    rest = win_path.as_posix().split(":", 1)[1] if ":" in str(win_path) else str(win_path)
    return f"/mnt/{drive}{rest}"


class AFLEngine(FuzzEngine):
    """AFL++ subprocess manager.

    Starts ``afl-fuzz`` as a child process (optionally through WSL2),
    monitors its output directory for stats/crashes/coverage, and
    injects new seeds by writing files to the queue directory.
    """

    def __init__(self, config: EngineConfig) -> None:
        self._config = config
        self._process: asyncio.subprocess.Process | None = None
        self._output_dir: Path | None = None
        self._corpus_dir: Path | None = None
        self._target_name: str = ""
        self._instance_id: str = "default"
        self._start_time: float = 0.0
        self._known_crashes: set[str] = set()
        self._seed_counter: int = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(
        self,
        target: Path,
        target_args: list[str],
        corpus: Path,
        output: Path,
        *,
        instance_id: str = "default",
        extra_args: list[str] | None = None,
    ) -> None:
        self._output_dir = output
        self._corpus_dir = corpus
        self._target_name = target.stem
        self._instance_id = instance_id
        self._start_time = time.time()

        corpus.mkdir(parents=True, exist_ok=True)
        output.mkdir(parents=True, exist_ok=True)

        # Build the afl-fuzz command
        cmd_parts: list[str] = []

        if self._config.use_wsl:
            cmd_parts.extend(["wsl.exe"])
            if self._config.wsl_distro:
                cmd_parts.extend(["-d", self._config.wsl_distro])
            cmd_parts.append("--")

        cmd_parts.append(self._config.binary)

        # Input/output directories
        if self._config.use_wsl:
            cmd_parts.extend(["-i", _win_to_wsl_path(corpus)])
            cmd_parts.extend(["-o", _win_to_wsl_path(output)])
        else:
            cmd_parts.extend(["-i", str(corpus)])
            cmd_parts.extend(["-o", str(output)])

        # Power schedule
        cmd_parts.extend(["-p", self._config.power_schedule])

        # Instance naming
        if instance_id == "default":
            cmd_parts.extend(["-M", "default"])
        else:
            cmd_parts.extend(["-S", instance_id])

        # Extra arguments
        if extra_args:
            cmd_parts.extend(extra_args)
        if self._config.extra_args:
            cmd_parts.extend(self._config.extra_args)

        # Target binary and its arguments
        cmd_parts.append("--")
        if self._config.use_wsl:
            cmd_parts.append(_win_to_wsl_path(target))
        else:
            cmd_parts.append(str(target))
        cmd_parts.extend(target_args)

        logger.info("Starting AFL++: %s", " ".join(cmd_parts))

        env = os.environ.copy()
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_NO_UI"] = "1"  # we have our own dashboard
        env["AFL_AUTORESUME"] = "1"

        self._process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        logger.info("AFL++ started (PID=%s) for target '%s'", self._process.pid, self._target_name)

    async def stop(self) -> None:
        if self._process is not None and self._process.returncode is None:
            logger.info("Stopping AFL++ (PID=%s)", self._process.pid)
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=10)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
            logger.info("AFL++ stopped.")

    async def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def get_stats(self) -> FuzzStats:
        stats_file = self._output_dir / self._instance_id / "fuzzer_stats"
        if not stats_file.exists():
            return FuzzStats()

        text = stats_file.read_text(errors="replace")
        values: dict[str, str] = {}
        for line in text.strip().split("\n"):
            if ":" in line:
                key, _, val = line.partition(":")
                values[key.strip()] = val.strip()

        def _float(key: str, default: float = 0.0) -> float:
            try:
                return float(values.get(key, default))
            except (ValueError, TypeError):
                return default

        def _int(key: str, default: int = 0) -> int:
            try:
                return int(values.get(key, default))
            except (ValueError, TypeError):
                return default

        # Calculate time since last new path
        last_find = _float("last_find", self._start_time)
        elapsed = time.time() - last_find if last_find > 0 else 0

        return FuzzStats(
            execs_done=_int("execs_done"),
            execs_per_sec=_float("execs_per_sec_last"),
            paths_total=_int("corpus_count", _int("paths_total")),
            paths_found=_int("paths_found"),
            paths_favored=_int("paths_favored"),
            unique_crashes=_int("saved_crashes", _int("unique_crashes")),
            unique_hangs=_int("saved_hangs", _int("unique_hangs")),
            stability=_float("stability", 100.0),
            corpus_count=_int("corpus_count"),
            last_new_find_seconds=elapsed,
            run_time_seconds=time.time() - self._start_time,
            bitmap_cvg=_float("bitmap_cvg"),
        )

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------

    async def get_coverage(self) -> CoverageMap:
        """Read the AFL++ coverage bitmap.

        AFL++ writes per-edge hit counts to the shared memory bitmap.
        We read the ``fuzz_bitmap`` file (if available) from the output dir.
        """
        from spectra.engine.coverage import parse_coverage_bitmap

        bitmap_file = self._output_dir / self._instance_id / "fuzz_bitmap"
        if not bitmap_file.exists():
            # Try plot_data for coverage percentage
            return CoverageMap()

        bitmap_data = bitmap_file.read_bytes()
        return parse_coverage_bitmap(bitmap_data)

    # ------------------------------------------------------------------
    # Crashes
    # ------------------------------------------------------------------

    async def get_new_crashes(self, since_id: str | None = None) -> list[CrashInfo]:
        crashes_dir = self._output_dir / self._instance_id / "crashes"
        if not crashes_dir.exists():
            return []

        new_crashes: list[CrashInfo] = []
        for crash_file in sorted(crashes_dir.iterdir()):
            if crash_file.name == "README.txt" or crash_file.name.startswith("."):
                continue

            crash_id = crash_file.name
            if crash_id in self._known_crashes:
                continue

            self._known_crashes.add(crash_id)
            input_data = crash_file.read_bytes()
            stack_hash = hashlib.sha256(input_data).hexdigest()[:16]

            # Try to extract signal from filename (AFL++ format: id:NNNNNN,sig:NN,...)
            signal = 0
            sig_match = re.search(r"sig:(\d+)", crash_id)
            if sig_match:
                signal = int(sig_match.group(1))

            new_crashes.append(CrashInfo(
                crash_id=crash_id,
                file_path=crash_file,
                target_name=self._target_name,
                input_data=input_data,
                signal=signal,
                timestamp=crash_file.stat().st_mtime,
                stack_trace="",  # populated later by reproducer
            ))

        return new_crashes

    # ------------------------------------------------------------------
    # Queue / Corpus
    # ------------------------------------------------------------------

    async def get_queue_entries(self) -> list[Path]:
        queue_dir = self._output_dir / self._instance_id / "queue"
        if not queue_dir.exists():
            return []
        return sorted(
            p for p in queue_dir.iterdir()
            if p.is_file() and not p.name.startswith(".")
        )

    async def inject_seeds(self, seeds: list[bytes]) -> int:
        """Write new seeds into the AFL++ queue directory.

        Seeds are written with a naming convention that lets us track
        their provenance (LLM-generated vs AFL++-mutated).
        """
        queue_dir = self._output_dir / self._instance_id / "queue"
        queue_dir.mkdir(parents=True, exist_ok=True)

        injected = 0
        for seed_data in seeds:
            self._seed_counter += 1
            seed_hash = hashlib.sha256(seed_data).hexdigest()[:8]
            # Use underscores instead of colons for Windows compatibility
            filename = f"id_llm_{self._seed_counter:06d}_src_spectra_hash_{seed_hash}"
            seed_path = queue_dir / filename

            if not seed_path.exists():
                seed_path.write_bytes(seed_data)
                injected += 1
                logger.debug("Injected LLM seed: %s (%d bytes)", filename, len(seed_data))

        logger.info("Injected %d/%d LLM seeds for target '%s'", injected, len(seeds), self._target_name)
        return injected

    # ------------------------------------------------------------------
    # Crash reproduction
    # ------------------------------------------------------------------

    async def reproduce_crash(self, crash: CrashInfo, target: Path, target_args: list[str]) -> str:
        """Re-run a crash input to capture the ASAN/UBSAN stack trace.

        Returns the combined stdout+stderr output.
        """
        import tempfile

        # Write crash input to a temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".crash") as f:
            f.write(crash.input_data)
            input_path = Path(f.name)

        try:
            # Build command, replacing @@ with the input file path
            args = [str(target)]
            for arg in target_args:
                if arg == "@@":
                    args.append(str(input_path) if not self._config.use_wsl else _win_to_wsl_path(input_path))
                else:
                    args.append(arg)

            cmd: list[str] = []
            if self._config.use_wsl:
                cmd.extend(["wsl.exe"])
                if self._config.wsl_distro:
                    cmd.extend(["-d", self._config.wsl_distro])
                cmd.append("--")
                args[0] = _win_to_wsl_path(target)

            cmd.extend(args)

            env = os.environ.copy()
            env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=1:print_stacktrace=1"

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                stdout, stderr = b"", b"TIMEOUT during crash reproduction"

            return (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
        finally:
            input_path.unlink(missing_ok=True)
