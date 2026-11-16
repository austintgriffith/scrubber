"""Scrub text into placeholders, and put the originals back afterwards."""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import local_llm, patterns

PLACEHOLDER = re.compile(r"\[?\b([A-Z][A-Z_]*_\d+)\b\]?(@[\w.\-]+\.[A-Za-z]{2,})?")


@dataclass
class Policy:
    keep: list[str] = field(default_factory=list)          # never scrub these
    always_scrub: list[str] = field(default_factory=list)  # always scrub these
    skip_types: list[str] = field(default_factory=list)    # entity types to leave alone
    scrubber: dict = field(default_factory=dict)  # see local_llm.Backend
    profiles: dict = field(default_factory=dict)  # named scrubber configs, pick with --scrubber
    frontier_model: str = "claude-opus-5-5"
    passes: int = 2  # extra local-model passes over already-scrubbed text
    keep_email_domain: bool = False  # bob@acme.com -> [EMAIL_1]@acme.com (domain shows; leaks the org)
    normalize: bool = True  # rewrite in a neutral voice so style can't identify the author

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        if not path or not Path(path).exists():
            return cls()
        data = json.loads(Path(path).read_text())
        if isinstance(data.get("scrubber"), str):  # "scrubber": "computer" -> that profile
            data["scrubber"] = data["profiles"][data["scrubber"]]
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def backend(self) -> local_llm.Backend:
        return local_llm.Backend(**self.scrubber)

    def is_kept(self, value: str) -> bool:
        v = value.strip().lower()
        for k in self.keep:
            k = k.lower()
            if v == k or re.search(rf"(?<!\w){re.escape(v)}(?!\w)", k):
                return True  # exact match, or a piece of a kept phrase
        return False


@dataclass
class Vault:
    """placeholder -> original. Reuse one vault across turns so names stay consistent.

    aliases: extra spellings that map to an existing placeholder,
    e.g. "sarah" -> PERSON_2 when PERSON_2 is "Sarah Chen".
    """
    entries: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    path: Path | None = None

    @classmethod
    def open(cls, path: str | Path | None) -> "Vault":
        if path and Path(path).exists():
            data = json.loads(Path(path).read_text())
            return cls(data.get("entries", {}), data.get("aliases", {}), Path(path))
        return cls(path=Path(path) if path else None)

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"entries": self.entries, "aliases": self.aliases}, f, indent=2)

    def known(self) -> list[tuple[str, str]]:
        """Every (kind, value) this vault scrubs, for reuse on later turns."""
        out = [(ph.rsplit("_", 1)[0], v) for ph, v in self.entries.items()]
        out += [(ph.rsplit("_", 1)[0], a) for a, ph in self.aliases.items()]
        return out

    def placeholder_for(self, kind: str, value: str) -> str:
        v = value.lower()
        for ph, orig in self.entries.items():
            if orig.lower() == v:
                return ph
        if v in self.aliases:
            return self.aliases[v]
        n = 1 + sum(1 for ph in self.entries if ph.rsplit("_", 1)[0] == kind)
        ph = f"{kind}_{n}"
        self.entries[ph] = value
        return ph


def _pattern(value: str) -> re.Pattern:
    # Word boundaries only where the value itself starts/ends with a word char.
    left = r"(?<!\w)" if value[0].isalnum() else ""
    right = r"(?!\w)" if value[-1].isalnum() else ""
    return re.compile(left + re.escape(value) + right, re.IGNORECASE)


def _replace(text: str, value: str, ph: str) -> str:
    return _pattern(value).sub(f"[{ph}]", text)


def _apply(text: str, hits: list[tuple[str, str]], policy: Policy, vault: Vault) -> tuple[str, int]:
    count = 0
    # Longest first so "Alice Smith" is replaced before "Alice".
    for kind, value in sorted(set(hits), key=lambda h: -len(h[1])):
        if kind in policy.skip_types or policy.is_kept(value):
            continue
        ph = vault.placeholder_for(kind, value)
        if kind == "EMAIL" and policy.keep_email_domain and "@" in value:
            new = _pattern(value).sub(f"[{ph}]@{value.split('@', 1)[1]}", text)
        else:
            new = _replace(text, value, ph)
        if new != text:
            count += 1
            text = new
        if kind == "PERSON" and " " in value.strip():
            # Also catch "Sarah" or "Chen" on their own.
            for part in value.split():
                p = part.strip(".,").lower()
                if len(p) >= 3 and part[0].isupper() and not policy.is_kept(part):
                    vault.aliases.setdefault(p, ph)
                    if vault.aliases[p] == ph:
                        text = _replace(text, part.strip(".,"), ph)
    return text, count


def scrub(text: str, policy: Policy, vault: Vault, use_llm: bool = True) -> str:
    # 1. Values already in the vault (from earlier turns) and the always-scrub list.
    hits = vault.known()
    hits += [("CUSTOM", v) for v in policy.always_scrub]
    # 2. Regex: emails, phones, keys, cards, addresses...
    hits += patterns.find(text)
    text, _ = _apply(text, hits, policy, vault)

    # 3. Local model: names, orgs, places. Re-run on the result to catch misses.
    if use_llm:
        backend = policy.backend()
        for _ in range(max(1, policy.passes)):
            found = local_llm.find(text, backend, policy.keep)
            text, changed = _apply(text, found, policy, vault)
            if not changed:
                break

    leaks = [v for _, v in vault.known()
             if not policy.is_kept(v) and _pattern(v).search(text)]
    if leaks:
        raise RuntimeError(f"scrub failed, {len(leaks)} value(s) still present")
    return text


def restore(text: str, vault: Vault) -> str:
    def sub(m: re.Match) -> str:
        orig = vault.entries.get(m.group(1))
        if orig is None:
            return m.group(0)
        domain = m.group(2) or ""
        return orig if orig.lower().endswith(domain.lower()) else orig + domain
    return PLACEHOLDER.sub(sub, text)
