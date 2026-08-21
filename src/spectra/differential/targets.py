"""Target binary management — building, health-checking, and configuring targets."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from spectra.config import EngineConfig, TargetBinary

logger = logging.getLogger(__name__)


class TargetManager:
    """Manages fuzzing target binaries.

    Handles building targets with AFL++ instrumentation, verifying
    they work correctly, and managing their lifecycle.
    """

    def __init__(self, engine_config: EngineConfig) -> None:
        self._engine_config = engine_config
        self._targets: dict[str, TargetBinary] = {}
        self._built: set[str] = set()

    def register(self, target: TargetBinary) -> None:
        """Register a target binary configuration."""
        self._targets[target.name] = target

    async def build(self, name: str) -> bool:
        """Build a target with AFL++ instrumentation.

        Uses the target's ``build_cmd`` if specified.
        Returns True if the build succeeded.
        """
        target = self._targets.get(name)
        if not target or not target.build_cmd:
            logger.info("No build command for target '%s', assuming pre-built.", name)
            self._built.add(name)
            return True

        logger.info("Building target '%s': %s", name, target.build_cmd)

        cmd_parts = target.build_cmd.split()

        # Optionally run through WSL
        if self._engine_config.use_wsl:
            wsl_cmd = ["wsl.exe"]
            if self._engine_config.wsl_distro:
                wsl_cmd.extend(["-d", self._engine_config.wsl_distro])
            wsl_cmd.append("--")
            wsl_cmd.extend(cmd_parts)
            cmd_parts = wsl_cmd

        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            logger.info("Target '%s' built successfully.", name)
            self._built.add(name)
            return True
        else:
            logger.error(
                "Build failed for '%s' (exit %d):\n%s",
                name, proc.returncode, stderr.decode("utf-8", errors="replace"),
            )
            return False

    async def build_all(self) -> bool:
        """Build all registered targets. Returns True if all succeeded."""
        results = await asyncio.gather(
            *(self.build(name) for name in self._targets),
            return_exceptions=True,
        )
        return all(r is True for r in results)

    async def health_check(self, name: str, test_input: bytes = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n") -> bool:
        """Verify a target binary runs and exits cleanly on a simple input."""
        target = self._targets.get(name)
        if not target:
            return False

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".test") as f:
            f.write(test_input)
            test_path = Path(f.name)

        try:
            binary = Path(target.path)
            args = [str(binary)]
            for arg in target.args:
                if arg == "@@":
                    args.append(str(test_path))
                else:
                    args.append(arg)

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=5.0)
            except TimeoutError:
                proc.kill()
                logger.warning("Health check timed out for '%s'", name)
                return False

            healthy = proc.returncode == 0
            if healthy:
                logger.info("Health check passed for '%s'", name)
            else:
                logger.warning("Health check failed for '%s' (exit %d)", name, proc.returncode)
            return healthy
        finally:
            test_path.unlink(missing_ok=True)

    def get_binary_path(self, name: str) -> Path:
        """Get the resolved binary path for a target."""
        target = self._targets.get(name)
        if not target:
            raise ValueError(f"Unknown target: {name}")
        return Path(target.path)

    def get_args(self, name: str) -> list[str]:
        """Get the command-line arguments for a target."""
        target = self._targets.get(name)
        if not target:
            raise ValueError(f"Unknown target: {name}")
        return list(target.args)

    @property
    def target_names(self) -> list[str]:
        return list(self._targets.keys())

    @property
    def all_built(self) -> bool:
        return self._built == set(self._targets.keys())
