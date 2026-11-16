"""Local chat page: you -> scrubber -> `claude -p` -> restore -> you.

Run:  uv run scrub-chat        then open http://127.0.0.1:8788
Only listens on 127.0.0.1.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Policy, Vault, restore, scrub
from .frontier import SYSTEM
from .normalize import normalize

HOME = Path.home() / ".scrubber"
WORKDIR = HOME / "workdir"  # empty dir so the agent can't read your files
PORT = int(os.environ.get("SCRUB_PORT", "8788"))
CLAUDE = shlex.split(os.environ.get("CLAUDE_CMD", "claude"))
POLICY_PATH = os.environ.get("SCRUB_POLICY", str(Path(__file__).resolve().parent.parent / "policy.json"))

chats: dict[str, dict] = {}  # chat id -> {"vault": Vault, "claude_session": str | None}


def load_env() -> None:
    """Read ~/.scrubber/.env (KEY=VALUE lines). Keep tokens there, never in the repo."""
    f = HOME / ".env"
    if f.exists():
        for line in f.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def claude_env() -> dict:
    env = dict(os.environ)
    if env.get("CLAUDE_CODE_OAUTH_TOKEN"):
        # Use the subscription token; these would override it.
        for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            env.pop(k, None)
    return env


def run_claude(prompt: str, session: str | None) -> tuple[str, str]:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    cmd = CLAUDE + ["-p", "--output-format", "json", "--append-system-prompt", SYSTEM]
    if session:
        cmd += ["--resume", session]
    r = subprocess.run(cmd, input=prompt, capture_output=True, text=True, cwd=WORKDIR, timeout=900,
                       env=claude_env())
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        raise RuntimeError((r.stderr or r.stdout or "claude failed").strip()[:500])
    if data.get("is_error"):
        raise RuntimeError(data.get("result") or "claude error")
    return data.get("result", ""), data.get("session_id")


def handle_chat(body: dict) -> dict:
    policy = Policy.load(POLICY_PATH)
    profile = body.get("scrubber")
    if profile:
        policy.scrubber = policy.profiles[profile]
    cid = body.get("chat") or str(uuid.uuid4())
    chat = chats.setdefault(cid, {
        "vault": Vault.open(HOME / "sessions" / f"web-{cid}.json"), "claude_session": None})

    clean = scrub(body["text"], policy, chat["vault"])
    if policy.normalize:
        clean = normalize(clean, policy.backend())
    chat["vault"].save()

    raw, chat["claude_session"] = run_claude(clean, chat["claude_session"])
    return {"chat": cid, "sent": clean, "raw": raw, "reply": restore(raw, chat["vault"])}


def _session_vault(name: str | None) -> Vault:
    if name and not re.fullmatch(r"[\w\-]{1,64}", name):
        raise ValueError("session must be letters, digits, - or _")
    return Vault.open(HOME / "sessions" / f"api-{name}.json" if name else None)


def handle_scrub(body: dict) -> dict:
    """POST /api/scrub {text, session?, scrubber?, normalize?, keep_email_domain?}
    -> {text, session}. Pass the same session to /api/restore."""
    policy = Policy.load(POLICY_PATH)
    if body.get("scrubber"):
        policy.scrubber = policy.profiles[body["scrubber"]]
    if "keep_email_domain" in body:
        policy.keep_email_domain = bool(body["keep_email_domain"])
    session = body.get("session") or uuid.uuid4().hex[:12]
    vault = _session_vault(session)
    clean = scrub(body["text"], policy, vault)
    if body.get("normalize", False):
        clean = normalize(clean, policy.backend())
    vault.save()
    return {"text": clean, "session": session}


def handle_restore(body: dict) -> dict:
    """POST /api/restore {text, session} -> {text}"""
    return {"text": restore(body["text"], _session_vault(body["session"]))}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/profiles":
            p = Policy.load(POLICY_PATH)
            raw = json.loads(Path(POLICY_PATH).read_text())
            default = raw.get("scrubber") if isinstance(raw.get("scrubber"), str) else None
            self._send(200, json.dumps({"profiles": list(p.profiles), "default": default}).encode(),
                       "application/json")
            return
        page = (Path(__file__).parent / "chat.html").read_bytes()
        self._send(200, page, "text/html; charset=utf-8")

    def do_POST(self):
        if self.path not in ("/chat", "/api/scrub", "/api/restore"):
            return self._send(404, b"", "text/plain")
        # Block cross-site requests from other pages in your browser.
        origin = self.headers.get("Origin", "")
        if origin and origin not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
            return self._send(403, b"bad origin", "text/plain")
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        try:
            out = {"/chat": handle_chat, "/api/scrub": handle_scrub,
                   "/api/restore": handle_restore}[self.path](body)
            self._send(200, json.dumps(out).encode(), "application/json")
        except Exception as e:  # show the error in the page
            self._send(500, json.dumps({"error": str(e)}).encode(), "application/json")

    def log_message(self, *a):  # keep prompts out of the terminal log
        pass


def main() -> None:
    load_env()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"scrub chat on http://127.0.0.1:{PORT}", file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
