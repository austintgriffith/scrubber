"""Find junk in your Gmail inbox without Claude seeing who your mail is from.

Reads the visible inbox rows from your real browser (clawd-browser bridge), scrubs
them on this machine, asks `claude -p` which rows are junk, and prints the result.
Read only: it does not archive, label, or delete anything.

  CLAWD_BROWSER_URL=http://<host>:8765/k/<token> uv run python examples/junk_mail.py --tab 123
  add --real to show real senders/subjects (default shows only what Claude saw)
"""

import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

from scrubber.core import Policy, Vault, restore, scrub
from scrubber.web import POLICY_PATH, load_env, run_claude

ROWS_JS = (Path(__file__).parent / "gmail_rows.js").read_text()

ASK = """Below are rows from my email inbox. Names, addresses, and other private details were replaced with placeholders like [PERSON_1]; sender domains are kept.

For each row decide:
- junk: marketing, promotions, newsletters, cold sales outreach, spam, scams, phishing, automated notifications that need no action
- keep: anything from a real person writing to me, work threads, receipts or security alerts I may need, calendar invites

Reply with only a JSON array, one object per row, in order: [{"i": <row number>, "verdict": "junk" | "keep", "reason": "<under 10 words>"}]

ROWS:
"""


def bridge(base: str, cmd: str, args: dict) -> dict:
    req = urllib.request.Request(base.rstrip("/") + "/cmd", data=json.dumps({"cmd": cmd, "args": args}).encode())
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.load(r)
    if not d.get("ok"):
        raise RuntimeError(d.get("error"))
    return d["result"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bridge", default=os.environ.get("CLAWD_BROWSER_URL"))
    ap.add_argument("--tab", type=int, help="Gmail tab id (default: active tab)")
    ap.add_argument("--real", action="store_true", help="show real senders/subjects in the output")
    ap.add_argument("--limit", type=int, default=100)
    a = ap.parse_args()
    if not a.bridge:
        sys.exit("set --bridge or CLAWD_BROWSER_URL")
    load_env()

    args = {"code": ROWS_JS} | ({"tab_id": a.tab} if a.tab else {})
    res = bridge(a.bridge, "eval", args)
    rows = (res.get("value") if isinstance(res, dict) else res)[: a.limit]
    print(f"{len(rows)} rows read. Scrubbing locally...", file=sys.stderr)

    lines = [f"#{r['i']} | {'UNREAD | ' if r['unread'] else ''}From: {r['from_name']} <{r['from_email']}>"
             f" | Subject: {r['subject']} | {r['snippet']}" for r in rows]
    policy = Policy.load(POLICY_PATH)
    policy.keep_email_domain = True
    vault = Vault()
    clean = scrub("\n".join(lines), policy, vault)
    clean_lines = {int(m.group(1)): line for line in clean.splitlines() if (m := re.match(r"#(\d+) \|", line))}

    print("Asking Claude...", file=sys.stderr)
    raw, _ = run_claude(ASK + clean, None)
    verdicts = json.loads(raw[raw.index("["): raw.rindex("]") + 1])

    junk = [v for v in verdicts if v.get("verdict") == "junk"]
    print(f"\n{len(junk)} of {len(rows)} look like junk:\n")
    for v in junk:
        line = clean_lines.get(v["i"], f"#{v['i']}")
        if a.real:
            line = restore(line, vault)
        print(f"{line[:160]}\n    -> {v.get('reason', '')}")
    print(f"\n({len(vault.entries)} private values were scrubbed before Claude saw anything)")


if __name__ == "__main__":
    main()
