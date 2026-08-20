"""Output normalization for differential comparison.

Strips known-benign differences (timestamps, PIDs, addresses, etc.) from
target outputs before comparison, reducing false-positive divergences.
"""

from __future__ import annotations

import re


class OutputNormalizer:
    """Normalizes program output by stripping known-variable fields.

    Applies a chain of normalization rules:
    1. User-configured ignore patterns (from config TOML)
    2. Built-in patterns for common variable fields
    3. Whitespace normalization
    """

    # Built-in patterns that almost always differ between runs
    BUILTIN_PATTERNS: list[tuple[str, str]] = [
        # Memory addresses (e.g., 0x7ffd1234abcd)
        (r"0x[0-9a-fA-F]{6,16}", "0xADDR"),
        # Process IDs
        (r"\bpid[=: ]+\d+\b", "pid=PID"),
        # Timestamps in various formats
        (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?", "TIMESTAMP"),
        (r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", "TIMESTAMP"),
        # Microsecond/nanosecond durations
        (r"\d+\.?\d*\s*(?:ms|µs|ns|us)\b", "DURATION"),
    ]

    def __init__(self, user_patterns: list[str] | None = None) -> None:
        self._compiled_user: list[re.Pattern] = []
        self._compiled_builtin: list[tuple[re.Pattern, str]] = []

        # Compile user patterns
        if user_patterns:
            for pat in user_patterns:
                try:
                    self._compiled_user.append(re.compile(pat))
                except re.error:
                    pass  # silently skip invalid patterns

        # Compile built-in patterns
        for pat, replacement in self.BUILTIN_PATTERNS:
            try:
                self._compiled_builtin.append((re.compile(pat), replacement))
            except re.error:
                pass

    def normalize(self, text: str) -> str:
        """Apply all normalization rules to the given text.

        Returns the normalized text for comparison.
        """
        result = text

        # Apply user patterns (remove matching lines entirely)
        for pattern in self._compiled_user:
            result = pattern.sub("", result)

        # Apply built-in patterns (replace with placeholders)
        for pattern, replacement in self._compiled_builtin:
            result = pattern.sub(replacement, result)

        # Normalize whitespace
        result = self._normalize_whitespace(result)

        return result

    @staticmethod
    def _normalize_whitespace(text: str) -> str:
        """Normalize whitespace: collapse runs, strip trailing, normalize line endings."""
        # Normalize line endings
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        # Strip leading and trailing whitespace from lines
        lines = [line.strip() for line in text.split("\n")]
        # Remove empty lines at start/end
        while lines and not lines[0]:
            lines.pop(0)
        while lines and not lines[-1]:
            lines.pop()
        return "\n".join(lines)

    def diff_summary(self, text_a: str, text_b: str) -> str:
        """Generate a human-readable diff summary between two normalized outputs."""
        norm_a = self.normalize(text_a)
        norm_b = self.normalize(text_b)

        lines_a = norm_a.split("\n")
        lines_b = norm_b.split("\n")

        diffs: list[str] = []
        max_lines = max(len(lines_a), len(lines_b))

        for i in range(min(max_lines, 50)):  # limit diff output
            la = lines_a[i] if i < len(lines_a) else ""
            lb = lines_b[i] if i < len(lines_b) else ""
            if la != lb:
                diffs.append(f"  Line {i+1}:")
                diffs.append(f"    A: {la[:120]}")
                diffs.append(f"    B: {lb[:120]}")

        if not diffs:
            return "(no differences after normalization)"

        if max_lines > 50:
            diffs.append(f"  ... and {max_lines - 50} more lines")

        return "\n".join(diffs)
