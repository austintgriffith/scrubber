"""Exit check: ask Sage (Levanto's yes/no model, in a TEE on NEAR AI) whether scrubbed text
still has identifiers, before it leaves. Ported from pii-sanitizer (research/pii-sanitizer).

What was learned there (LEARNINGS.md):
- One "is this clean?" question misses leaks. Ask one tag per identifier type.
- Short rules beat long rules. Placeholder labels matter: use [PERSON_n], not [NAME_n].
- Fail closed: if Sage can't answer, treat the text as flagged.
"""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("SAGE_BASE_URL", "https://sage.levanto.ai")
GATE = 0.5

PREAMBLE = ("Placeholders in square brackets like [PERSON_1] or [DATE_1] are already "
            "redacted and are fine. ")

# Cut long-note false alarms 6/40 -> 0/40 with no missed leaks. Keep it short.
RULES = (
    "These are NOT identifiers: diseases, signs, scores, procedures, instruments or syndromes "
    "named after a person or place (Lou Gehrig's disease, Parkinson's, Lyme disease, Whipple, "
    "Babinski, Apgar); drug and device brand names; a famous person the patient only talks about; "
    "ordinary words like hope, will, grant, mark, may; hospital units (4 West, MICU); years "
    "alone, holidays, seasons; vitals and dose ratios like 120/80. "
    "These ARE identifiers even if the same word is a disease or common word: a person's name "
    "used as a name (Mr. Parkinson, daughter Hope, son Will Grant), the patient's own name even "
    "if a celebrity shares it, a town the patient lives in, initials, nicknames. ")

# Wording is tested; change it only with a bench run (research/pii-sanitizer/bench.py).
TAGS = {
    "name": "name: a name, nickname or initials used to refer to the "
            "patient, a relative or another private person; not a [PLACEHOLDER]; not a disease, "
            "sign, procedure, drug or famous person merely mentioned",
    "date": "date: any written date or month tied to the patient (07/15/2022, Jan 10, "
            "November 2022, last December, Christmas), or an age over 89; a year alone, or 'last week', is fine",
    "contact": "contact: phone, fax, email, URL or IP address",
    "number": "number: SSN, MRN, account, member, license, plate or device serial",
    "place": "place: street address, ZIP, town/city, or a hospital or clinic "
             "name or abbreviation; a state alone is fine",
    "unique": "unique: employer, a public or one-of-a-kind role (mayor, only X in town), "
              "a named event or disaster they were in, a named pet, a tattoo, or photo that singles the person out",
    # Without this, "Patient Selena Gomez (no relation)" buried in a long note scored 0.001.
    "self": "self: the patient's or writer's own name written out as who they are "
            "(after 'Patient', 'Pt', 'Mr.', 'Ms.', 'I'm', 'my name is', or as a sign-off), "
            "even if a celebrity has the same name",
}


def _key() -> str:
    if os.environ.get("SAGE_API_KEY"):
        return os.environ["SAGE_API_KEY"]
    f = Path.home() / "sage" / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if line.startswith("SAGE_API_KEY="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError("no SAGE_API_KEY (env or ~/sage/.env)")


def _post(path: str, body: dict) -> dict:
    req = urllib.request.Request(BASE + path, json.dumps(body).encode(), {
        "Authorization": f"Bearer {_key()}", "Content-Type": "application/json",
        "User-Agent": "scrubber/0.1"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (502, 503, 504) or attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))
    raise RuntimeError("unreachable")


def scores(text: str, tags: list[str]) -> dict[str, float]:
    r = _post("/decide", {"content": {"kind": "text", "value": text}, "question": {
        "kind": "tags", "id": "phi", "tags": [{"id": t, "name": TAGS[t]} for t in tags],
        "instructions": PREAMBLE + RULES + "Tag each kind of identifier that is still present in plain text."}})
    return {t["id"]: t["probability"] for t in r["result"]["tags"]}


def flagged(text: str, tags: list[str]) -> list[str]:
    """Tag ids Sage still sees. Fails closed: any error counts as flagged."""
    if not text.strip():
        return []
    try:
        per = scores(text, tags)
    except Exception as e:
        return [f"sage-error: {e}"]
    return [t for t in tags if per.get(t) is None or per[t] >= GATE]
