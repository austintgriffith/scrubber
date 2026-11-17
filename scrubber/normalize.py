"""Rewrite a (scrubbed) prompt in a neutral voice so it can't be tied to its author by style.

Code blocks and inline code are pulled out first and put back after, untouched.
If the rewrite drops or invents a placeholder, it retries, then falls back to light cleanup.
"""

import re
import unicodedata

from . import local_llm

FENCE = re.compile(r"```.*?```", re.DOTALL)
INLINE = re.compile(r"`[^`\n]+`")
TOKEN = re.compile(r"\[[A-Z][A-Z_]*_\d+\]")


NAMES = ("monday tuesday wednesday thursday friday saturday sunday january february march "
         "april june july august september october november december").split()


def _stash(text: str) -> tuple[str, dict[str, str]]:
    code: dict[str, str] = {}

    def sub(m: re.Match) -> str:
        key = f"[CODE_{len(code) + 1}]"
        code[key] = m.group(0)
        return key

    return INLINE.sub(sub, FENCE.sub(sub, text)), code


def _unstash(text: str, code: dict[str, str]) -> str:
    for key, block in code.items():
        text = text.replace(key, block)
    return text


def light_clean(text: str) -> str:
    """Deterministic cleanup. Code blocks are left alone."""
    text, code = _stash(text)
    text = _clean_prose(text)
    return _unstash(text, code)


def _clean_prose(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(str.maketrans({"‘": "'", "’": "'", "“": '"', "”": '"',
                                         "–": "-", "—": "-", "…": "..."}))
    text = "".join(c for c in text if unicodedata.category(c) != "So")  # emoji / symbols
    text = re.sub(r"([!?.])\1+", r"\1", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r" +\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = re.sub(r"\bi\b(?=[ ',.!?])", "I", text)
    text = re.sub(r"\b(" + "|".join(NAMES) + r")\b", lambda m: m.group(1).capitalize(), text)
    # Capitalize the first letter of each sentence / line.
    text = re.sub(r"(^|[.!?]\s+|\n\s*)([a-z])", lambda m: m.group(1) + m.group(2).upper(), text)
    return text.strip()


def normalize(text: str, backend: "local_llm.Backend", tries: int = 2, prompt: str | None = None) -> str:
    prose, code = _stash(text)
    want = sorted(TOKEN.findall(prose))

    out = None
    for _ in range(tries):
        cand = local_llm.rewrite(prose, backend, prompt=prompt)
        if sorted(TOKEN.findall(cand)) == want:
            out = cand
            break
    if out is None:
        out = prose  # model kept mangling tokens; don't risk it
    return _unstash(_clean_prose(out), code)
