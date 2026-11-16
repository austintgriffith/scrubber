# scrubber

Scrub private info from a prompt on your machine, send the clean prompt to Claude, then put the real values back in the reply.

```
your prompt ─► regex (emails, phones, keys, cards, ETH addresses)
            ─► local Ollama model (people, orgs, places, project names)
            ─► keep-list check (names you want Claude to see)
            ─► style normalize (local model rewrites in a neutral voice)
            ─► Claude (sees [PERSON_1], [ORG_1], ...)
            ─► restore placeholders ─► reply
```

The mapping stays local (`~/.scrubber/sessions/<name>.json`, mode 600).

## Use

```bash
uv sync
uv run scrub scrub "Email Sarah Chen at Northwind about Project Falcon"   # see what would be sent
uv run scrub ask   "Email Sarah Chen at Northwind about Project Falcon"   # full round trip
uv run scrub ask --session acme "..."   # reuse placeholders across turns
uv run scrub scrub --no-llm "..."       # regex + lists only, instant
```

`ask` needs `ANTHROPIC_API_KEY` (or an `ant auth login` profile). Ollama must be running.

## Style normalizing

Even with names gone, your writing style can identify you (slang, emoji, typos, sign-offs). This matters when prompts go through a mixer like zkllmapi: anonymous payment doesn't help if your prompts read like you.

So after scrubbing, the local model rewrites the prompt in plain neutral English, keeping the meaning. Code blocks and `inline code` are never touched. If the rewrite drops or adds a placeholder, it retries once, then falls back to fixed-rule cleanup only (emoji, smart quotes, repeated punctuation, capitalization).

Turn off per call with `--raw-style`, or set `"normalize": false` in the policy.

## Policy (`policy.json`)

- `keep`: names never scrubbed (public projects, public people, your own brand). Parts of a kept phrase are kept too ("Vitalik" from "Vitalik Buterin").
- `always_scrub`: words always scrubbed, even if the model misses them (codenames, client names).
- `skip_types`: entity types to leave alone, e.g. `["LOCATION"]`.
- `scrubber`: which profile does the scrubbing. Pick per call with `--scrubber phone`.
- `profiles`: scrubber models. `kind` is `ollama`, `openai` (any OpenAI-style server: phone app, LM Studio, Sage) or `anthropic`. Anything not on this machine needs `"remote": true`, because it sees raw text.
- `normalize`: rewrite prompts in a neutral voice (default true).
- `passes`: how many times the local model re-checks the scrubbed text.

## Library

```python
from scrubber.core import Policy, Vault, scrub, restore
policy, vault = Policy.load("policy.json"), Vault()
clean = scrub(text, policy, vault)
...send clean anywhere...
original = restore(reply, vault)
```

## Tests

`uv run python -m unittest discover -s tests`
