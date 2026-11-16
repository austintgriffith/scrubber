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


def find(text: str, medical: bool = False) -> list[tuple[str, str]]:
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

    for kind, pat in PATTERNS + (MEDICAL if medical else []):
        for m in pat.finditer(text):
            a, b = m.span()
            if not free(a, b):
                continue
            if kind == "CREDIT_CARD" and not _luhn_ok(m.group()):
                continue
            taken.append((a, b))
            found.append((kind, m.group()))
    return found


# ---- medical mode: ported from pii-sanitizer (research/pii-sanitizer/pipeline.py) ----
# HIPAA Safe Harbor also counts dates tied to a person and ages over 89.
_ONES = "first second third fourth fifth sixth seventh eighth ninth".split()
DAY_WORDS = "(?i:" + "|".join(sorted(
    _ONES + "tenth eleventh twelfth thirteenth fourteenth fifteenth sixteenth seventeenth eighteenth "
    "nineteenth twentieth thirtieth".split() + [f"{t}[- ]?{o}" for t in ("twenty", "thirty") for o in _ONES],
    key=len, reverse=True)) + r")\b"

MEDICAL: list[tuple[str, re.Pattern]] = [(k, re.compile(p)) for k, p in [
    ("URL", r"https?://\S+"),
    ("DATE", r"\b\d{1,2}/\d{1,2}/\d{2,4}\b"),
    ("DATE", r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2}(?:st|nd|rd|th)?(?:,? \d{4})?\b"),
    ("DATE", r"\b(?:\d{1,2}(?:st|nd|rd|th)?|" + DAY_WORDS + r") of (?i:(?:last |next |this )?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*)\b(?:,? \d{4})?"),
    # 12.04.1948, 3-4-22, OCR'd 12.o4.1948 (three parts, so 120/80 is safe)
    ("DATE", r"\b[\dOo]{1,2}[./-][\dOo]{1,2}[./-](?:19|20)?\d\d\b"),
    # A month or holiday alone. "May" only next to a number. \b so "Marchetti" keeps "March".
    ("DATE", r"\b(?i:January|February|March|April|June|July|August|September|Sept?|October|November|December"
             r"|Christmas|Xmas|Thanksgiving|Halloween|Easter|Hanukkah|Passover|Ramadan|Labor Day|Memorial Day"
             r"|New Year'?s(?: Eve| Day)?|Fourth of July|Valentine'?s Day"
             r"|(?:Jan|Feb|Mar|Apr|Jun|Jul|Aug|Oct|Nov|Dec)\.?(?=[ ']\d))\b"
             r"(?:,?\s+(?:the\s+)?(?:\d{1,2}(?:st|nd|rd|th)?\b|" + DAY_WORDS + r"))?(?:,?\s+'?(?:\d{4}|\d{2})\b)?"),
    ("DATE", r"\bMay,? (?:\d{1,2}(?:st|nd|rd|th)?\b|(?:19|20)\d\d\b)"),
    ("DATE", r"\b(?:born|b\.|DOB:?)\s*(?:in\s+)?(?:18\d\d|19[0-3]\d)\b"),  # birth year = age 90+
    # IDs before ZIP: ZIP used to eat "12345" out of "12345-JS" and leave "-JS".
    ("ID_NUMBER", r"\b(?=[A-Z0-9-]*\d)(?=[A-Z0-9-]*[A-Z])[A-Z0-9-]{6,}\b"),
    ("ZIP", r"(?<![\w-])\d{5}(?:-\d{4})?(?![\w-])"),
    ("ID_NUMBER", r"\b\d{3,}-[A-Za-z]+-\d{3,}\b"),
    ("ID_NUMBER", r"\b\d{2}-\d{4}-\d{3}-[A-Z0-9]\b"),
    ("AGE", r"\b(?:9\d|1[01]\d)[- ]?(?:year[- ]old|yo\b|y/o|yrs?\b|years\b)"),
    ("AGE", r"(?:(?<=\bage )|(?<=\bage: )|(?<=\baged )|(?<=\bturns )|(?<=\bturning ))(?:9\d|1[01]\d)\b"),
    ("AGE", r"(?:(?<=\bhe's )|(?<=\bshe's )|(?<=\bI'm )|(?<=\bturned )|(?<=\bso ))(?:9\d|1[01]\d)\b(?![./]\d| ?(?:%|mg|kg|lb|mm|bpm))"),
    ("AGE", r"\b(?:ninety|one hundred|a hundred)(?:[- ]\w+)?(?=[- ](?:years?|yo|next|this)\b)"),
]]
