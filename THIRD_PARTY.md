# Third-party code

This project is GPL-3.0 (see `LICENSE`). It includes code under other licenses:

- `research/pii-sanitizer/` and the Sage check, medical regexes and prompt in
  `scrubber/sage.py`, `scrubber/patterns.py`, `scrubber/local_llm.py`, `scrubber/core.py`:
  from [clawdbotatg/pii-sanitizer](https://github.com/clawdbotatg/pii-sanitizer), MIT
  (`research/pii-sanitizer/LICENSE`).
- Credential patterns in `scrubber/patterns.py` (auth header, bearer, URL password,
  query secret, home dir, public email rules): from
  [huggingface/safeagents](https://github.com/huggingface/safeagents), Apache-2.0,
  Copyright 2026-present the HuggingFace Inc. team.
- Dependency [atif-scan](https://pypi.org/project/atif-scan/), Apache-2.0.
