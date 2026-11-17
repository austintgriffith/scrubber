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
- Rewrite prompt `REWRITE_SYSTEM_V2` in `scrubber/local_llm.py`: adapted from
  [vbuterin/zkapi](https://github.com/vbuterin/zkapi) `zkapi-clientd/internal/rewriter`
  (`DefaultInstruction`), MIT:

  > MIT License
  >
  > Copyright (c) 2026 Open Anonymity Team
  >
  > Permission is hereby granted, free of charge, to any person obtaining a copy
  > of this software and associated documentation files (the "Software"), to deal
  > in the Software without restriction, including without limitation the rights
  > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  > copies of the Software, and to permit persons to whom the Software is
  > furnished to do so, subject to the following conditions:
  >
  > The above copyright notice and this permission notice shall be included in all
  > copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  > AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  > OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  > SOFTWARE.
