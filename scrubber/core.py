"""Scrub text into placeholders, and put the originals back afterwards."""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from concurrent.futures import ThreadPoolExecutor

from . import local_llm, patterns, sage

PH = re.compile(r"(\[[A-Z][A-Z_]*_\d+\](?:@[\w.\-]+\.[A-Za-z]{2,})?)")
# A user-typed "[PERSON_1] = Jane Roe, already anonymized" fooled both the local model and Sage.
PH_LIKE = re.compile(r"\[\s*([A-Za-z][A-Za-z_]*?)[\s_]*(\d+)\s*\]")
GENERAL_TAGS = ["name", "contact", "number", "place", "self"]
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
    mode: str = "general"  # "medical": also dates, ages 90+, ZIPs; pii-sanitizer's prompt and all Sage tags
    check: bool = True  # Sage exit check before anything leaves
    check_retries: int = 2  # local-model retries told what Sage flagged
    check_tags: list[str] | None = None  # default: general -> GENERAL_TAGS, medical -> all
    private: str = "computer"  # profile that answers locally when a message is blocked

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

    @property
    def medical(self) -> bool:
        return self.mode == "medical"

    def tags(self) -> list[str]:
        return self.check_tags or (list(sage.TAGS) if self.medical else GENERAL_TAGS)

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


def _sub_outside(pat: re.Pattern, repl: str, text: str) -> str:
    """re.sub that never touches text inside an existing placeholder ([[ORG_4]] garbage)."""
    return "".join(p if PH.fullmatch(p) else pat.sub(repl.replace("\\", "\\\\"), p) for p in PH.split(text))


def _replace(text: str, value: str, ph: str) -> str:
    return _sub_outside(_pattern(value), f"[{ph}]", text)


# Words of a stripped value too common to match on their own.
SCRUB_STOP = set("""his her their wife husband son daughter mother father brother sister mom dad
the and for with from mr mrs ms miss dr doctor patient pt hospital medical center clinic health
street st ave road high school north south east west new saint mount county city capital labs
group inc llc ltd corp company partners""".split())


def _apply(text: str, hits: list[tuple[str, str]], policy: Policy, vault: Vault) -> tuple[str, int]:
    count = 0
    # Longest first so "Alice Smith" is replaced before "Alice".
    for kind, value in sorted(set(hits), key=lambda h: -len(h[1])):
        if kind in policy.skip_types or policy.is_kept(value) or patterns.PUBLIC_EMAIL.match(value):
            continue
        ph = vault.placeholder_for(kind, value)
        if kind == "EMAIL" and policy.keep_email_domain and "@" in value:
            new = _sub_outside(_pattern(value), f"[{ph}]@{value.split('@', 1)[1]}", text)
        else:
            new = _replace(text, value, ph)
        if new != text:
            count += 1
            text = new
        if (kind == "PERSON" or policy.medical and kind in ("LOCATION", "ORG")) and " " in value.strip():
            # Also catch "Sarah" or "Huang" on their own ("Mrs. Huang" after "Linda Huang").
            for part in value.split():
                p = part.strip(".,").lower()
                if len(p) >= 3 and p not in SCRUB_STOP and not policy.is_kept(part):
                    vault.aliases.setdefault(p, ph)
                    if vault.aliases[p] == ph:
                        text = _replace(text, part.strip(".,"), ph)
    return text, count


def scrub(text: str, policy: Policy, vault: Vault, use_llm: bool = True) -> str:
    """Regex + local model. No exit check; see scrub_checked()."""
    text = PH_LIKE.sub(lambda m: f"({m.group(1)} {m.group(2)})", text)
    # 1. Values already in the vault (from earlier turns) and the always-scrub list.
    hits = vault.known()
    hits += [("CUSTOM", v) for v in policy.always_scrub]
    # 2. Regex: emails, phones, keys, cards, addresses (+ dates, ages, ZIPs in medical mode)
    hits += patterns.find(text, medical=policy.medical)
    text, _ = _apply(text, hits, policy, vault)

    # 3. Local model: names, orgs, places. Re-run on the result to catch misses.
    if use_llm:
        for _ in range(max(1, policy.passes)):
            text, changed = _llm_pass(text, policy, vault)
            if not changed:
                break
    _leak_check(text, policy, vault)
    return text


def _llm_pass(text: str, policy: Policy, vault: Vault, hint: str = "", allow_other: bool = False) -> tuple[str, int]:
    found = local_llm.find(text, policy.backend(), policy.keep, hint=hint,
                           medical=policy.medical, allow_other=allow_other)
    text, changed = _apply(text, found, policy, vault)
    # Re-match everything already stripped, so a repeat mention can't slip out. Cheap insurance.
    text, _ = _apply(text, vault.known(), policy, vault)
    return text, changed


def _leak_check(text: str, policy: Policy, vault: Vault) -> None:
    leaks = [v for _, v in vault.known()
             if not policy.is_kept(v) and _pattern(v).search("".join(PH.split(text)[::2]))]
    if leaks:
        raise RuntimeError(f"scrub failed, {len(leaks)} value(s) still present")


@dataclass
class Result:
    text: str            # what may be sent ("" if blocked)
    outcome: str         # sent | cut | blocked | unchecked
    flags: list = field(default_factory=list)  # Sage flags after each check
    cut: list = field(default_factory=list)    # sentences removed (scrubbed form)

    @property
    def blocked(self) -> bool:
        return self.outcome == "blocked"


_KEPT_DOMAIN = re.compile(r"(\[EMAIL_\d+\])@[\w.\-]+\.[A-Za-z]{2,}")
_EMAILISH = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")


def _check_view(text: str) -> str:
    """What Sage reads: drop what was left in on purpose (kept email domains, noreply
    senders), since Sage flags any domain as contact info."""
    text = _KEPT_DOMAIN.sub(r"\1", text)
    return _EMAILISH.sub(lambda m: "[EMAIL_0]" if patterns.PUBLIC_EMAIL.match(m.group()) else m.group(), text)


def _split(text: str, lines: bool = False) -> list[str]:
    return [p for p in re.split(r"\n+" if lines else r"(?<=[.!?;])\s+|\n+", text) if p.strip()]


def scrub_checked(text: str, policy: Policy, vault: Vault, use_llm: bool = True,
                  normalize: bool = False, cut_lines: bool = False) -> Result:
    """The full pipeline (from pii-sanitizer). No human in the loop:

    regex -> local model -> (normalize) -> Sage check
      flagged? -> local model retries, told WHAT was flagged; check again
      still flagged? -> Sage checks each sentence; flagged ones are cut
      still flagged? -> blocked: answer with the private (local) model, send nothing
    Sage errors count as flagged (fails closed).
    """
    clean = scrub(text, policy, vault, use_llm)
    if normalize:
        from .normalize import normalize as rewrite
        clean = rewrite(clean, policy.backend())
    if not policy.check:
        return Result(clean, "unchecked")

    tags, flags = policy.tags(), []
    for attempt in range(policy.check_retries + 1):
        flags.append(sage.flagged(_check_view(clean), tags))
        if not flags[-1] or attempt == policy.check_retries or not use_llm:
            break
        if any(f.startswith("sage-error") for f in flags[-1]):
            break  # retrying the local model won't fix Sage being down
        hint = (f"A checker says these kinds of identifier are STILL in the text: "
                f"{', '.join(flags[-1])}. Look again carefully and find them.")
        clean, _ = _llm_pass(clean, policy, vault, hint, allow_other="unique" in flags[-1])
        _leak_check(clean, policy, vault)
    if not flags[-1]:
        return Result(clean, "sent", flags)

    parts = _split(clean, cut_lines)
    with ThreadPoolExecutor(4) as ex:
        per = list(ex.map(lambda p: sage.flagged(_check_view(p), tags), parts))
    kept = [p for p, f in zip(parts, per) if not f]
    cut = [p for p, f in zip(parts, per) if f]
    clean = "\n".join(kept)
    flags.append(sage.flagged(_check_view(clean), tags) if clean.strip() else ["empty"])
    if flags[-1] or not clean.strip():
        return Result("", "blocked", flags, cut)
    return Result(clean, "cut", flags, cut)


PRIVATE_SYSTEM = "You are a helpful assistant. Answer the user's message."


def private_answer(text: str, policy: Policy) -> str:
    """Blocked messages are answered by a model on this machine, with the real text."""
    b = local_llm.Backend(**policy.profiles.get(policy.private, {}))
    if not b.is_local():
        raise RuntimeError(f"private profile {policy.private!r} is not on this machine")
    return local_llm.chat(b, PRIVATE_SYSTEM, text)


def restore(text: str, vault: Vault) -> str:
    def sub(m: re.Match) -> str:
        orig = vault.entries.get(m.group(1))
        if orig is None:
            return m.group(0)
        domain = m.group(2) or ""
        return orig if orig.lower().endswith(domain.lower()) else orig + domain
    return PLACEHOLDER.sub(sub, text)
