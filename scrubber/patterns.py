"""Regex detectors for structured PII and secrets. No model needed."""

import re

# Order matters: longer / more specific patterns first.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("SECRET_HEX", re.compile(r"(?<![0-9a-fA-Fx])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    ("ETH_ADDRESS", re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])")),
    ("API_KEY", re.compile(
        r"\b(?:sk-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}"
        r"|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}"
        r"|AIza[0-9A-Za-z_\-]{35})\b")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ \-]?){12,18}\d\b")),
    ("PHONE", re.compile(
        r"(?<![\w+])(?:\+\d{1,3}[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\w)")),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

# `password: hunter2`, `api_key=abc123` -> scrub only the value.
ASSIGNMENT = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token"
    r"|private[_\-]?key|mnemonic|seed[_\-]?phrase)\b\s*[:=]\s*[\"']?([^\s\"']{4,})")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find(text: str) -> list[tuple[str, str]]:
    """Return (type, value) pairs found in text."""
    found: list[tuple[str, str]] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for m in ASSIGNMENT.finditer(text):
        a, b = m.span(1)
        if free(a, b):
            taken.append((a, b))
            found.append(("SECRET", m.group(1)))

    for kind, pat in PATTERNS:
        for m in pat.finditer(text):
            a, b = m.span()
            if not free(a, b):
                continue
            if kind == "CREDIT_CARD" and not _luhn_ok(m.group()):
                continue
            taken.append((a, b))
            found.append((kind, m.group()))
    return found
