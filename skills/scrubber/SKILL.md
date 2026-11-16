---
name: scrubber
description: Remove private info (names, emails, phones, keys, addresses) from text on this machine before you read it or send it to a model. Use for email triage or any task over someone's private data. Repo ~/scrubber.
---

# scrubber

Scrubs text on this machine. Names and private details become placeholders like
`[PERSON_1]`, `[ORG_2]`, `[EMAIL_3]@acme.com`. A local model (Ollama) finds them;
Sage (a checker model) checks before the text leaves; whatever it flags is cut or blocked.

## The one rule

**Never read the raw text yourself.** You are a frontier model too: if raw email
or chat text lands in your context, it has already leaked. Pipe it from its source
straight into the scrubber, and read only what comes out.

- Fetch into a file or pipe. Don't `cat`, `head` or print the raw data.
- Print only counts or lengths when checking that a fetch worked.
- Never use `--show-map` or `--real`. Those print real values; they are for a human at a terminal.
- Don't write raw or restored text into a repo, a log, or a message to anyone.

## Needs

- Ollama running with `qwen3:14b` (or the `local_model` in `~/scrubber/policy.json`).
- Sage key: `SAGE_API_KEY` or `~/sage/.env`. Without it every message is blocked (fails closed).
- For the junk example only: `claude` logged in, or `CLAUDE_CODE_OAUTH_TOKEN=...` in `~/.scrubber/.env`.

## Scrub some text

```sh
cd ~/scrubber
some-command-that-outputs-private-text \
  | uv run scrub scrub --session triage-$(date +%F) --json --cut-lines --keep-email-domain --raw-style
```

Prints one JSON line: `{"text": <scrubbed>, "outcome": ..., "cut": <n lines cut>, "session": ...}`.

- `outcome`: `sent` (clean), `cut` (some lines removed), `blocked` (`text` is empty: do nothing with it), `unchecked` (`--no-check`).
- `--session NAME`: same name -> same placeholders across calls. Mappings stay in `~/.scrubber/sessions/` (mode 600).
- `--cut-lines`: for lists (one email per line). Without it, sentences are cut.
- `--keep-email-domain`: keeps `@domain` (helps spot junk; shows the sender's company).
- `--raw-style`: skip rewording. Use it for data like emails; rewording is for the user's own writing.
- Takes ~1 min per 30 rows. Run it in the background for big inboxes.

Over HTTP instead (when `uv run scrub-chat` is running): `POST 127.0.0.1:8788/api/scrub`
with `{"text", "session", "keep_email_domain", "cut_lines"}`; same fields back.

## Email triage recipe (Gmail via clawd-browser)

Ready-made: `examples/junk_mail.py` reads the visible inbox rows, scrubs them, asks
Claude which are junk, and prints JSON with **scrubbed** rows only:

```sh
cd ~/scrubber
CLAWD_BROWSER_URL=<bridge base url> uv run python examples/junk_mail.py --tab <gmail tab id> --json
# -> [{"i": 12, "verdict": "junk", "reason": "Black Friday promo", "row": "#12 | From: [ORG_3] <[EMAIL_4]@e.store.com> | ..."}]
```

To do the triage yourself instead of asking Claude:

1. Pull rows with the bridge `eval` and `examples/gmail_rows.js`, write them to a temp file
   as `#<i> | From: name <email> | Subject: ... | snippet` lines. Don't print the file.
2. Scrub the file with the command above (`--cut-lines --keep-email-domain --raw-style --json`).
3. Read only the JSON `text`. Decide per row.
4. Act by row number `i` (the `i`-th visible `tr.zA` in the inbox). You never need the real name to archive or label a row.
5. Ask the user before archiving, deleting, or sending anything.

Rows Sage cut are missing from the output: leave those for the user.

## If something fails

- `scrub failed, N value(s) still present`: the scrubber stopped itself; nothing was sent. Retry or skip.
- `blocked` with `sage-error`: Sage is down. Don't fall back to sending raw text. Tell the user.
- Ollama not running: start it (`ollama serve`) or tell the user.
