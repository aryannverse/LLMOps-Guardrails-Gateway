"""Stage 1 - Deterministic PII sanitisation engine.

Compiled regular expressions plus checksum validators (Luhn for payment cards,
Verhoeff for Aadhaar) replace sensitive entities with typed placeholders such as
<REDACTED_EMAIL>. This runs before any neural inference, so raw PII never reaches
the classifier, the telemetry log or the external LLM provider.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Callable, Optional

# Verhoeff checksum tables (dihedral group D5) used by Aadhaar numbers.
_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def _digits(s: str) -> list[int]:
    return [int(c) for c in s if c.isdigit()]


def luhn_ok(s: str) -> bool:
    total = 0
    for i, n in enumerate(reversed(_digits(s))):
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def verhoeff_ok(s: str) -> bool:
    c = 0
    for i, n in enumerate(reversed(_digits(s))):
        c = _D[c][_P[i % 8][n]]
    return c == 0


def phone_ok(s: str) -> bool:
    return 10 <= len(_digits(s)) <= 15


# Order matters: high-precision patterns run first so that, for example, a card
# number is never half-consumed by the looser phone pattern.
_RULES: list[tuple[str, re.Pattern, Optional[Callable[[str], bool]]]] = [
    ("API_KEY", re.compile(r"\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}|gsk_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
                           r"|gh[pousr]_[A-Za-z0-9]{36,}|xox[abprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35}"
                           r"|hf_[A-Za-z0-9]{30,})"), None),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b"), None),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ \-]?){12,18}\d\b"), luhn_ok),
    ("AADHAAR", re.compile(r"\b[2-9]\d{3}[ \-]?\d{4}[ \-]?\d{4}\b"), verhoeff_ok),
    ("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("PAN", re.compile(r"\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b"), None),
    ("PHONE", re.compile(r"(?<![\w+])(?:\+\d{1,3}[ .\-]?(?:\(?\d{1,4}\)?[ .\-]?){1,4}\d{2,4}"
                         r"|\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}"
                         r"|[6-9]\d{4}[ \-]?\d{5})(?!\w)"), phone_ok),
]


def redact(text: str) -> tuple[str, Counter]:
    """Return (sanitised_text, Counter of redacted entity types)."""
    counts: Counter = Counter()
    for label, pattern, validator in _RULES:
        def _replace(m: re.Match, label: str = label, validator=validator) -> str:
            if validator is not None and not validator(m.group()):
                return m.group()
            counts[label] += 1
            return f"<REDACTED_{label}>"
        text = pattern.sub(_replace, text)
    return text, counts
