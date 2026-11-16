"""Find names and other free-text PII with a local Ollama model.

Text sent here never leaves the machine, so cloud-backed Ollama models are refused.
"""

import json
import os
import re
import urllib.request

PLACEHOLDER = re.compile(r"\[[A-Z][A-Z_]*_\d+\]")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

TYPES = ["PERSON", "ORG", "LOCATION", "PROJECT", "ID_NUMBER", "OTHER_PII"]

SYSTEM = """You find private information in text so it can be redacted before the text is sent to a third party.

Return every span that names or identifies:
- PERSON: a real person's name, nickname, or username/handle
- ORG: a private company, team, client, or organization
- LOCATION: a street address, city, neighborhood, or specific place tied to someone
- PROJECT: an internal or confidential project, product codename, or deal name
- ID_NUMBER: account numbers, case numbers, license/passport numbers, employee IDs
- OTHER_PII: dates of birth, medical details tied to a person, or anything else that identifies someone

Do NOT return:
- generic words, roles, or job titles ("the CEO", "my lawyer")
- well-known technologies, programming languages, public protocols, or software (Python, Ethereum, React, Linux)
- anything already redacted like [PERSON_1] or [EMAIL_2]
- anything in the KEEP list

Copy each span exactly as it appears in the text, character for character. Return each distinct span once."""

SCHEMA = {
    "type": "object",
    "properties": {
        "entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "type": {"type": "string", "enum": TYPES},
                },
                "required": ["text", "type"],
            },
        }
    },
    "required": ["entities"],
}


def check_local(model: str) -> None:
    if "cloud" in model.lower():
        raise ValueError(
            f"{model!r} is an Ollama cloud model; it would send raw text off this machine. "
            "Pick a local model.")


def _chunks(text: str, size: int = 6000) -> list[str]:
    if len(text) <= size:
        return [text]
    out, cur = [], ""
    for para in text.split("\n"):
        if len(cur) + len(para) + 1 > size and cur:
            out.append(cur)
            cur = ""
        cur += para + "\n"
    if cur:
        out.append(cur)
    return out


def find(text: str, model: str, keep: list[str], timeout: float = 300) -> list[tuple[str, str]]:
    """Return (type, value) pairs. Values not literally in the text are dropped."""
    check_local(model)
    found: list[tuple[str, str]] = []
    keep_note = "KEEP list (never return these): " + (", ".join(keep) if keep else "(empty)")
    for chunk in _chunks(text):
        body = {
            "model": model,
            "stream": False,
            "think": False,
            "format": SCHEMA,
            "options": {"temperature": 0, "num_ctx": 16384},
            "messages": [
                {"role": "system", "content": SYSTEM + "\n\n" + keep_note},
                {"role": "user", "content": "TEXT:\n" + chunk},
            ],
        }
        req = urllib.request.Request(
            OLLAMA_URL + "/api/chat",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = json.loads(r.read())["message"]["content"]
        try:
            ents = json.loads(content).get("entities", [])
        except json.JSONDecodeError:
            continue
        for e in ents:
            val = (e.get("text") or "").strip()
            kind = e.get("type") or "OTHER_PII"
            if len(val) < 2 or val not in chunk:  # drop hallucinated spans
                continue
            if PLACEHOLDER.search(val):  # already redacted
                continue
            found.append((kind if kind in TYPES else "OTHER_PII", val))
    return found
