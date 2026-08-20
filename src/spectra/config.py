"""Configuration management for spectra-fuzz campaigns.

Loads campaign configuration from TOML files, validates with Pydantic,
and merges with environment variable overrides.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

if sys.version_info >= (3, 12):
    import tomllib
else:
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class SanitizerConfig(BaseModel):
    """Compiler sanitizer flags for target instrumentation."""
    asan: bool = True
    ubsan: bool = True
    msan: bool = False


class EngineConfig(BaseModel):
    """AFL++ engine configuration."""
    type: Literal["afl++"] = "afl++"
    binary: str = "afl-fuzz"
    use_wsl: bool = True
    wsl_distro: str = ""
    instances_per_target: int = 1
    extra_args: list[str] = Field(default_factory=lambda: ["-t", "1000"])
    power_schedule: str = "explore"
    sanitizers: SanitizerConfig = Field(default_factory=SanitizerConfig)


class TargetBinary(BaseModel):
    """A single fuzzing target binary."""
    name: str
    path: str
    args: list[str] = Field(default_factory=lambda: ["@@"])
    build_cmd: str = ""


class SeedsConfig(BaseModel):
    """Seed corpus configuration."""
    directory: str = "./seeds"


class TargetsConfig(BaseModel):
    """All fuzzing targets for differential comparison."""
    binaries: list[TargetBinary] = Field(default_factory=list)
    seeds: SeedsConfig = Field(default_factory=SeedsConfig)

    @field_validator("binaries")
    @classmethod
    def need_at_least_one_target(cls, v: list[TargetBinary]) -> list[TargetBinary]:
        if not v:
            raise ValueError("At least one target binary must be configured")
        return v


class LLMBudget(BaseModel):
    """API usage budget limits."""
    max_calls_per_hour: int = 200
    max_tokens_per_hour: int = 500_000
    max_cost_usd_per_hour: float = 5.0


class LLMTriggers(BaseModel):
    """When to invoke the LLM during a campaign."""
    plateau_threshold_seconds: int = 120
    crash_analysis_enabled: bool = True
    divergence_triage_enabled: bool = True
    strategy_review_interval_seconds: int = 600


class LLMMutationConfig(BaseModel):
    """LLM mutation generation parameters."""
    seeds_per_request: int = 10
    max_seed_size_bytes: int = 8192
    few_shot_examples: int = 5
    validate_before_inject: bool = True


class LLMConfig(BaseModel):
    """LLM integration configuration."""
    provider: Literal["gemini"] = "gemini"
    fast_model: str = "gemini-2.5-flash"
    deep_model: str = "gemini-2.5-pro"
    api_key_env: str = "GEMINI_API_KEY"
    budget: LLMBudget = Field(default_factory=LLMBudget)
    triggers: LLMTriggers = Field(default_factory=LLMTriggers)
    mutation: LLMMutationConfig = Field(default_factory=LLMMutationConfig)

    @property
    def api_key(self) -> str:
        """Resolve the API key from the environment."""
        key = os.environ.get(self.api_key_env, "")
        if not key:
            raise ValueError(
                f"Environment variable {self.api_key_env} is not set. "
                f"Get a key at https://aistudio.google.com/"
            )
        return key


class DifferentialConfig(BaseModel):
    """Differential oracle configuration."""
    enabled: bool = True
    comparison_mode: Literal["raw", "semantic", "normalized"] = "semantic"
    ignore_patterns: list[str] = Field(default_factory=list)
    divergence_db: str = "./output/divergences.db"


class DashboardConfig(BaseModel):
    """Web dashboard configuration."""
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8077
    auto_open_browser: bool = True


class CampaignMeta(BaseModel):
    """Top-level campaign metadata."""
    name: str = "unnamed-campaign"
    duration_seconds: int = 3600
    poll_interval_seconds: int = 5
    output_dir: str = "./output"


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

class SpectraConfig(BaseModel):
    """Root configuration model for a spectra-fuzz campaign."""
    campaign: CampaignMeta = Field(default_factory=CampaignMeta)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    differential: DifferentialConfig = Field(default_factory=DifferentialConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: Path | str) -> SpectraConfig:
    """Load and validate a campaign configuration from a TOML file.

    Environment variables prefixed with ``SPECTRA_`` override corresponding
    config fields (see ``.env.example`` for the mapping).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "rb") as f:
        raw = tomllib.load(f)

    config = SpectraConfig.model_validate(raw)

    # --- Environment overrides ---
    env_overrides: dict[str, tuple[str, type]] = {
        "SPECTRA_LLM_FAST_MODEL": ("llm.fast_model", str),
        "SPECTRA_LLM_DEEP_MODEL": ("llm.deep_model", str),
        "SPECTRA_LLM_MAX_CALLS_PER_HOUR": ("llm.budget.max_calls_per_hour", int),
        "SPECTRA_LLM_MAX_TOKENS_PER_HOUR": ("llm.budget.max_tokens_per_hour", int),
        "SPECTRA_WSL_DISTRO": ("engine.wsl_distro", str),
        "SPECTRA_DASHBOARD_HOST": ("dashboard.host", str),
        "SPECTRA_DASHBOARD_PORT": ("dashboard.port", int),
    }

    for env_var, (dotpath, typ) in env_overrides.items():
        val = os.environ.get(env_var)
        if val is not None:
            parts = dotpath.split(".")
            obj = config
            for part in parts[:-1]:
                obj = getattr(obj, part)
            setattr(obj, parts[-1], typ(val))

    return config
