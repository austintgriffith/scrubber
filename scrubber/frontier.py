"""Send already-scrubbed text to Claude."""

import anthropic

SYSTEM = (
    "Some names and private details in the user's message were replaced with placeholders "
    "like [PERSON_1], [ORG_2], or [EMAIL_1]. Treat each placeholder as the real value it "
    "stands for. When you refer to one, write the placeholder exactly as given, brackets "
    "included, so it can be swapped back. Do not guess what the real values are."
)


def ask(messages: list[dict], model: str, effort: str = "medium") -> str:
    client = anthropic.Anthropic()
    with client.beta.messages.stream(
        model=model,
        max_tokens=64000,
        system=SYSTEM,
        messages=messages,
        thinking={"type": "adaptive"},
        output_config={"effort": effort},
        # If the model declines, the API retries on a fallback model in the same call.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
    ) as stream:
        msg = stream.get_final_message()
    if msg.stop_reason == "refusal":
        raise RuntimeError("Claude declined the request")
    return "".join(b.text for b in msg.content if b.type == "text")
