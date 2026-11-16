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

from .core import Policy, Vault, restore, scrub

HOME = Path.home() / ".scrubber"


def main() -> None:
    ap = argparse.ArgumentParser(prog="scrub", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["scrub", "ask", "restore"])
    ap.add_argument("text", nargs="?")
    ap.add_argument("--policy", default="policy.json", help="JSON policy file (default ./policy.json)")
    ap.add_argument("--session", help="name of a vault to reuse across turns (~/.scrubber/sessions)")
    ap.add_argument("--model", help="local Ollama model (overrides policy)")
    ap.add_argument("--frontier", help="Claude model (overrides policy)")
    ap.add_argument("--no-llm", action="store_true", help="regex + lists only, skip the local model")
    ap.add_argument("--raw-style", action="store_true", help="skip style normalizing (keep your wording)")
    ap.add_argument("--show", action="store_true", help="ask: also print what was sent to Claude")
    a = ap.parse_args()

    text = a.text if a.text is not None else sys.stdin.read()
    policy = Policy.load(a.policy)
    if a.model:
        policy.local_model = a.model
    if a.frontier:
        policy.frontier_model = a.frontier
    vault = Vault.open(HOME / "sessions" / f"{a.session}.json" if a.session else None)

    if a.cmd == "restore":
        print(restore(text, vault))
        return

    clean = scrub(text, policy, vault, use_llm=not a.no_llm)
    vault.save()
    if policy.normalize and not a.raw_style:
        from .normalize import light_clean, normalize
        clean = light_clean(clean) if a.no_llm else normalize(clean, policy.local_model)

    if a.cmd == "scrub":
        print(clean)
        print("\n--- mapping (local only) ---", file=sys.stderr)
        print(json.dumps(vault.entries, indent=2), file=sys.stderr)
        return

    from .frontier import ask
    if a.show:
        print("--- sent to Claude ---\n" + clean + "\n----------------------", file=sys.stderr)
    reply = ask([{"role": "user", "content": clean}], policy.frontier_model)
    print(restore(reply, vault))


if __name__ == "__main__":
    main()
