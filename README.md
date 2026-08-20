# spectra-fuzz

**LLM-Augmented Differential Fuzzer** — combines AFL++ coverage-guided fuzzing with Google Gemini for crash trace analysis, semantic mutation generation, and coverage plateau breaking.

> Differential fuzzing + LLM intelligence. Not just random bit-flipping — semantically-aware protocol fuzzing that reads your crash traces and proposes targeted mutations.

## What makes this different?

Traditional fuzzers mutate inputs randomly. spectra-fuzz adds an LLM feedback loop:

```
AFL++ finds crash → LLM analyzes root cause → LLM generates targeted follow-up inputs
AFL++ coverage stalls → LLM reads uncovered branches → LLM crafts inputs to reach them
Two implementations disagree → LLM triages: bug vs spec ambiguity vs benign
```

The differential aspect means we fuzz **multiple implementations** of the same protocol (e.g., `llhttp` vs `picohttpparser`) and use divergent behavior as a bug signal — catching logic errors that would never cause a crash.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    spectra-fuzz                      │
│                                                      │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ AFL++    │  │ Gemini API   │  │ Differential  │   │
│  │ Engine   │──│ LLM Layer    │──│ Oracle        │   │
│  │ Manager  │  │              │  │               │   │
│  └──────────┘  │ • Crash      │  │ • Run same    │   │
│       │        │   Analyzer   │  │   input thru  │   │
│       │        │ • Mutation   │  │   all targets │   │
│       │        │   Generator  │  │ • Normalize & │   │
│       ▼        │ • Strategy   │  │   compare     │   │
│  ┌──────────┐  │   Advisor    │  │ • Classify    │   │
│  │ Coverage │  └──────────────┘  │   divergences │   │
│  │ Monitor  │         │          └──────────────┘    │
│  │ Plateau  │         ▼                              │
│  │ Detector │  ┌──────────────┐                      │
│  └──────────┘  │ Campaign     │                      │
│       │        │ Orchestrator │                      │
│       ▼        └──────────────┘                      │
│  ┌──────────┐         │                              │
│  │ Web      │◄────────┘                              │
│  │ Dashboard│  Live coverage, crashes, divergences   │
│  └──────────┘                                        │
└──────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Python 3.11+**
- **WSL2** with AFL++ installed (`sudo apt install aflplusplus` or build from source)
- **Google Gemini API key** from [AI Studio](https://aistudio.google.com/)

### Installation

```bash
# Clone and install
cd spectra-fuzz
pip install -e ".[dev]"

# Set your API key
cp .env.example .env
# Edit .env and set GEMINI_API_KEY=your-key-here
```

### Build Example Targets (in WSL2)

```bash
# Install dependencies
sudo apt install libllhttp-dev

# Fetch picohttpparser
cd targets/http_parsers
make deps
make all
```

### Run a Campaign

```bash
# Initialize campaign directory
spectra init

# Start fuzzing with LLM integration
spectra run --config config/default.toml

# Start fuzzing WITHOUT LLM (pure AFL++ baseline for comparison)
spectra run --config config/default.toml --no-llm

# Dry run (validate config)
spectra run --config config/default.toml --dry-run
```

### Dashboard

The web dashboard launches automatically at `http://127.0.0.1:8077` showing:
- 📊 Real-time coverage timeline with LLM seed injection markers
- 💥 Live crash feed with LLM-generated root cause analysis
- 🔀 Divergence inspector with spec-reference triage
- 🧠 Mutation log tracking which LLM seeds hit new coverage
- ⚡ Execution speed and campaign statistics

### Analyze a Specific Crash

```bash
spectra analyze id:000001,sig:11,src:... --config config/default.toml
```

## Key Components

| Component | Description |
|-----------|-------------|
| **Engine** (`engine/`) | AFL++ subprocess management, coverage bitmap parsing, plateau detection |
| **LLM** (`llm/`) | Gemini client with budget tracking, crash analyzer, mutation generator, strategy advisor |
| **Differential** (`differential/`) | Multi-target oracle, output normalization, divergence SQLite database |
| **Campaign** (`campaign/`) | Main orchestration loop, corpus management, budget-aware LLM scheduler |
| **Dashboard** (`dashboard/`) | FastAPI + WebSocket real-time dashboard with Chart.js visualizations |

## LLM Agents

### 1. Crash Analyzer
Reads ASAN/UBSAN traces + source context → structured report with bug class, root cause, severity, and follow-up seed suggestions.

### 2. Mutation Generator
When coverage plateaus, constructs context-rich prompts with coverage gaps and protocol knowledge. Uses a **feedback loop**: successful past mutations become few-shot examples for future prompts.

### 3. Divergence Triager
Classifies differential divergences as **bug** (one implementation is wrong), **spec ambiguity** (both arguably correct), or **benign** (cosmetic difference). Cites relevant RFC sections.

### 4. Strategy Advisor
Periodic high-level campaign review. Recommends focus areas, configuration changes, and when to stop.

## Configuration

See `config/default.toml` for all options. Key settings:

```toml
[llm.triggers]
plateau_threshold_seconds = 120  # trigger LLM after 2min without new edges
crash_analysis_enabled = true    # auto-analyze every new unique crash
strategy_review_interval_seconds = 600  # strategy review every 10 minutes

[llm.budget]
max_calls_per_hour = 200         # API call limit
max_tokens_per_hour = 500000     # token budget
```

## Testing

```bash
pytest tests/ -v
```

## Research Context

This project draws from several lines of active research:

- **ChatAFL** — LLM-guided protocol fuzzing using RFC knowledge
- **FuzzGPT** — Historical bug-driven seed generation
- **WhiteFox** — Dual-agent compiler fuzzing with source-code analysis
- **Semantic-Aware Fuzzing** — Microservices integration of LLMs with AFL++

The key innovation in spectra-fuzz is combining **differential fuzzing** (comparing multiple implementations) with **LLM triage** (automatically classifying divergences using protocol spec knowledge) — addressing the "smart oracle" problem that makes differential fuzzing practical at scale.

## License

MIT
