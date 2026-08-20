"""Prompt templates for LLM-guided fuzzing.

All prompts are carefully engineered for structured output. Each prompt
includes: role context, task description, input data, output format, and
few-shot examples where applicable.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# System instructions
# ---------------------------------------------------------------------------

SYSTEM_CRASH_ANALYZER = """\
You are an expert vulnerability researcher and binary analyst. Your task is to
analyze crash traces from a fuzzing campaign and provide structured reports.

You have deep expertise in:
- Memory safety vulnerabilities (buffer overflows, use-after-free, double-free)
- Integer overflow/underflow and type confusion bugs
- Protocol parsing vulnerabilities (HTTP, TLS, DNS)
- ASAN/UBSAN/MSAN sanitizer output interpretation
- Root cause analysis from stack traces

Always be precise and specific. Reference exact function names, line numbers,
and variable names from the trace when available."""

SYSTEM_MUTATION_GENERATOR = """\
You are an expert fuzzing engineer specializing in protocol-aware mutation.
Your task is to generate new test inputs that maximize code coverage by
targeting specific uncovered branches in the target program.

You understand:
- Network protocol specifications (HTTP/1.1 RFC 9110, TLS 1.3, DNS)
- Edge cases in protocol parsers (chunked encoding, pipelining, malformed headers)
- How to craft inputs that trigger specific code paths
- The balance between syntactic validity and boundary-value exploration

Generate inputs that are creative, diverse, and likely to trigger new code paths.
Each input should target a specific hypothesis about the program's behavior."""

SYSTEM_DIVERGENCE_TRIAGER = """\
You are an expert software analyst specializing in differential testing.
Your task is to analyze behavioral divergences between multiple implementations
of the same protocol specification.

You can distinguish between:
- True bugs (one implementation is incorrect per the spec)
- Specification ambiguities (both behaviors are arguably correct)
- Benign differences (cosmetic variations like whitespace or ordering)
- Implementation-defined behavior (spec explicitly allows variation)

Always cite the relevant specification section when classifying a divergence."""

SYSTEM_STRATEGY_ADVISOR = """\
You are a fuzzing campaign strategist. Your task is to analyze the current
state of a fuzzing campaign and recommend high-level strategy adjustments.

You understand:
- Coverage-guided fuzzing dynamics (exploration vs exploitation)
- When and why coverage plateaus occur
- Protocol feature coverage analysis
- Resource allocation between targets
- When to shift focus between different protocol features"""


# ---------------------------------------------------------------------------
# Crash analysis prompts
# ---------------------------------------------------------------------------

CRASH_ANALYSIS_PROMPT = """\
## Crash Trace Analysis

Analyze the following crash from target **{target_name}**:

### Input that caused the crash
```
{crash_input_hex}
```

{crash_input_ascii_section}

### Sanitizer Output / Stack Trace
```
{stack_trace}
```

### Source Code Context (around crash location)
```c
{source_context}
```

### Task
1. Identify the **bug class** (e.g., heap-buffer-overflow, stack-buffer-overflow,
   use-after-free, integer-overflow, null-dereference, etc.)
2. Explain the **root cause** — what sequence of events led to this crash?
3. Rate the **severity** (critical / high / medium / low) based on exploitability
4. Suggest **3-5 related inputs** that might trigger similar bugs via different
   code paths or trigger more severe variants of this bug
5. Provide a brief **one-line summary** of the vulnerability"""


CRASH_FOLLOWUP_PROMPT = """\
Based on your previous analysis of the {bug_class} vulnerability, generate
{n_seeds} new test inputs designed to:

1. Trigger the same vulnerable code path with different input patterns
2. Find related vulnerabilities in nearby code (adjacent functions, similar parsers)
3. Escalate severity (e.g., if this was a read overflow, try to get a write overflow)

Each input should be a valid (or near-valid) {protocol_name} message that
specifically targets the vulnerability pattern you identified.

Previous crash input was:
```
{original_input}
```"""


# ---------------------------------------------------------------------------
# Mutation generation prompts
# ---------------------------------------------------------------------------

MUTATION_GENERATION_PROMPT = """\
## Coverage-Guided Seed Generation

You are generating new fuzzing seeds for an **{protocol_name}** parser.
The goal is to reach **uncovered code branches** that the fuzzer hasn't hit yet.

### Current Coverage Status
- Total edges: {total_edges}
- Covered edges: {covered_edges} ({coverage_pct:.1f}%)
- Time since last new edge: {plateau_seconds:.0f} seconds

### Uncovered Branch Hints
The following source code regions have NOT been reached by fuzzing yet:
```c
{uncovered_hints}
```

### Successful Past Mutations (few-shot examples)
These LLM-generated inputs successfully triggered new coverage:
{few_shot_examples}

### Recently Explored Inputs
These are some recent inputs in the corpus (for context, don't duplicate):
```
{recent_inputs}
```

### Task
Generate exactly **{n_seeds}** new {protocol_name} test inputs as a JSON array.

For each input:
1. Encode the raw bytes as a **base64** string
2. Provide a brief **rationale** explaining what branch/feature this targets
3. Estimate a **confidence** score (0.0–1.0) that this will trigger new coverage

Focus on:
- Edge cases in {protocol_name} parsing (malformed headers, boundary values)
- Rare protocol features (chunked encoding, trailers, 100-continue)
- Integer boundary values in length fields
- Unusual character encodings and escaping
- Protocol state transitions that are hard to reach"""


# ---------------------------------------------------------------------------
# Divergence triage prompts
# ---------------------------------------------------------------------------

DIVERGENCE_TRIAGE_PROMPT = """\
## Differential Divergence Analysis

Two implementations of **{protocol_name}** produced different outputs for the
same input. Analyze whether this is a bug, spec ambiguity, or benign difference.

### Input
```
{input_hex}
```
{input_ascii_section}

### Output from {target_a_name}
```
{output_a}
```

### Output from {target_b_name}
```
{output_b}
```

### Relevant Specification Context
{spec_context}

### Task
1. **Classification**: Is this a bug, spec_ambiguity, or benign_difference?
2. **Faulty target**: If this is a bug, which implementation is wrong? (or "unknown")
3. **Spec reference**: Which section of the spec is relevant?
4. **Explanation**: Detailed explanation of why you classified it this way
5. **Minimal reproducer**: Simplify the input to the minimum that triggers the divergence"""


# ---------------------------------------------------------------------------
# Strategy advisor prompts
# ---------------------------------------------------------------------------

STRATEGY_REVIEW_PROMPT = """\
## Fuzzing Campaign Strategy Review

Review the current fuzzing campaign state and recommend strategy adjustments.

### Campaign Statistics
- **Runtime**: {runtime_str}
- **Total executions**: {total_execs:,}
- **Executions/sec**: {execs_per_sec:.0f}
- **Corpus size**: {corpus_size}
- **Coverage**: {covered_edges}/{total_edges} edges ({coverage_pct:.1f}%)

### Coverage Trend (last {trend_minutes} minutes)
{coverage_trend}

### Crashes Found
- **Total unique crashes**: {unique_crashes}
- **Bug classes found**: {bug_classes}

### Divergences Found
- **Total divergences**: {total_divergences}
- **Confirmed bugs**: {confirmed_bugs}
- **Spec ambiguities**: {spec_ambiguities}

### LLM Mutations Performance
- **Seeds generated**: {seeds_generated}
- **Seeds that hit new coverage**: {seeds_hit_coverage}
- **Hit rate**: {seed_hit_rate:.1f}%

### Previously Tried Strategies
{previous_strategies}

### Task
1. **Assessment**: How is the campaign performing? Are we making progress?
2. **Recommended strategies**: List 2-3 specific strategies to try next
3. **Focus areas**: Which protocol features should we target?
4. **Configuration changes**: Should we adjust AFL++ settings, power schedule, etc.?
5. **Stop recommendation**: Should we continue or has this campaign reached diminishing returns?"""
