"""Run the scrubber's full pipeline on pii-sanitizer's test sets and count leaks.

  uv run python bench/run.py [raw|redteam|redteam2|redteam3] [limit] [--model qwen3:8b] [--mode medical]

raw: 50 fake medical notes. redteamN: chat messages written to beat the stripper.
"Sent with PHI" is the number that matters. Read every leak by hand: word matching overcounts.
"""
import argparse
import json
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESEARCH = ROOT / "research" / "pii-sanitizer"
sys.path.insert(0, str(RESEARCH))
sys.path.insert(0, str(ROOT))

from scrubber.core import Policy, Vault, scrub_checked  # noqa: E402


def load(name):
    if name == "raw":
        from raw_cases import RAW
        return RAW
    import os
    os.environ["REDTEAM"] = str(RESEARCH / "data" / "redteam" / f"chats{name[7:]}.jsonl")
    import redteam
    redteam.PATH = os.environ["REDTEAM"]
    return redteam.load()


def residual(text, must_go):
    return [s for s in must_go if re.search(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(s), text, re.I)]


def words_lost(raw, final, must_go):
    phi = {w.lower() for s in must_go for w in re.findall(r"\w+", s)}
    a = Counter(w for w in re.findall(r"\w+", raw) if w.lower() not in phi and len(w) > 1)
    b = Counter(re.findall(r"\w+", final))
    return [w for w, n in a.items() for _ in range(max(0, n - b[w]))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("set", nargs="?", default="raw")
    ap.add_argument("limit", nargs="?", type=int)
    ap.add_argument("--model", default=None)
    ap.add_argument("--mode", default="medical")
    a = ap.parse_args()

    policy = Policy.load(ROOT / "policy.json")
    policy.mode = a.mode
    policy.check_tags = None
    if a.model:
        policy.scrubber = {"kind": "ollama", "model": a.model}
    cases = load(a.set)[: a.limit]

    def one(case):
        cid, kind, raw, must_go = case
        t0 = time.time()
        try:
            r = scrub_checked(raw, policy, Vault())
            out = {"outcome": r.outcome, "final": r.text, "flags": r.flags, "cut": r.cut}
        except Exception as e:
            out = {"outcome": "error", "final": "", "flags": [str(e)], "cut": []}
        return {"id": cid, "kind": kind, "raw": raw, "must_go": must_go, **out,
                "left": residual(out["final"], must_go), "lost": words_lost(raw, out["final"], must_go),
                "s": time.time() - t0}

    with ThreadPoolExecutor(4) as ex:
        rows = list(ex.map(one, cases))
    out = ROOT / "bench" / "results" / f"{a.set}-{a.mode}-{policy.scrubber.get('model')}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=1))

    n, sent = len(rows), [r for r in rows if r["outcome"] in ("sent", "cut", "unchecked")]
    c = Counter(r["outcome"] for r in rows)
    print(f"{a.set}, {n} cases, mode {a.mode}, model {policy.scrubber.get('model')} -> {out.name}")
    print(f"  outcomes: {dict(c)}")
    print(f"  SENT with PHI still in it: {sum(bool(r['left']) for r in sent)}/{len(sent)}")
    print(f"  useful words lost: {sum(len(r['lost']) for r in rows)}  top: "
          f"{Counter(w for r in rows for w in r['lost']).most_common(12)}")
    print(f"  median seconds/case: {sorted(r['s'] for r in rows)[n // 2]:.1f}")
    for r in rows:
        if r["left"] and r["outcome"] != "blocked" or r["outcome"] == "error":
            print(f"  LEAK {r['id']} {r['outcome']}: {r['left']} {r['flags'][-1:] }")


if __name__ == "__main__":
    main()
