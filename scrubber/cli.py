"""
scrub scrub  "text"        show scrubbed text + mapping (nothing leaves the machine)
scrub ask    "text"        scrub -> Claude -> restore names in the reply
scrub restore "text"       put originals back using a session vault
Text can also come from stdin.
"""

import argparse
import json
import sys
from pathlib import Path

from .core import Policy, Vault, private_answer, restore, scrub_checked

HOME = Path.home() / ".scrubber"


def main() -> None:
    ap = argparse.ArgumentParser(prog="scrub", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["scrub", "ask", "restore"])
    ap.add_argument("text", nargs="?")
    ap.add_argument("--policy", default="policy.json", help="JSON policy file (default ./policy.json)")
    ap.add_argument("--session", help="name of a vault to reuse across turns (~/.scrubber/sessions)")
    ap.add_argument("--scrubber", help="scrubber profile name from policy.json, e.g. computer, phone, sage")
    ap.add_argument("--frontier", help="Claude model (overrides policy)")
    ap.add_argument("--no-llm", action="store_true", help="regex + lists only, skip the local model")
    ap.add_argument("--show-map", action="store_true", help="scrub: print placeholder -> real value (humans only)")
    ap.add_argument("--json", action="store_true", help="scrub: print {text, outcome, cut} as JSON")
    ap.add_argument("--cut-lines", action="store_true", help="check cuts flagged lines, not sentences (lists, inboxes)")
    ap.add_argument("--keep-email-domain", action="store_true", help="bob@acme.com -> [EMAIL_1]@acme.com")
    ap.add_argument("--no-check", action="store_true", help="skip the Sage exit check")
    ap.add_argument("--raw-style", action="store_true", help="skip style normalizing (keep your wording)")
    ap.add_argument("--show", action="store_true", help="ask: also print what was sent to Claude")
    a = ap.parse_args()

    text = a.text if a.text is not None else sys.stdin.read()
    policy = Policy.load(a.policy)
    if a.scrubber:
        policy.scrubber = policy.profiles[a.scrubber]
    if a.frontier:
        policy.frontier_model = a.frontier
    vault = Vault.open(HOME / "sessions" / f"{a.session}.json" if a.session else None)

    if a.cmd == "restore":
        print(restore(text, vault))
        return

    if a.no_check:
        policy.check = False
    if a.keep_email_domain:
        policy.keep_email_domain = True
    norm = policy.normalize and not a.raw_style and not a.no_llm
    res = scrub_checked(text, policy, vault, use_llm=not a.no_llm, normalize=norm, cut_lines=a.cut_lines)
    vault.save()
    clean = res.text
    if policy.normalize and not a.raw_style and a.no_llm:
        from .normalize import light_clean
        clean = light_clean(clean)
    print(f"[check: {res.outcome}" + (f", cut {len(res.cut)} sentence(s)" if res.cut else "")
          + (f", flags {res.flags}" if res.outcome != "sent" and res.flags else "") + "]", file=sys.stderr)

    if a.cmd == "scrub" and a.json:
        print(json.dumps({"text": clean, "outcome": res.outcome, "cut": len(res.cut),
                          "session": a.session}))
        return
    if a.cmd == "scrub":
        print(clean)
        if a.show_map:  # real values: only for a human at the terminal, never for an agent
            print("\n--- mapping (local only) ---", file=sys.stderr)
            print(json.dumps(vault.entries, indent=2), file=sys.stderr)
        return

    if res.blocked:
        print("[blocked: answered by the local model, nothing sent]", file=sys.stderr)
        print(private_answer(text, policy))
        return
    from .frontier import ask
    if a.show:
        print("--- sent to Claude ---\n" + clean + "\n----------------------", file=sys.stderr)
    reply = ask([{"role": "user", "content": clean}], policy.frontier_model)
    print(restore(reply, vault))


if __name__ == "__main__":
    main()
