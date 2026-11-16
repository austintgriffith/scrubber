import unittest
from unittest import mock

from scrubber import local_llm
from scrubber.core import Policy, Vault, restore, scrub


def fake_llm(entities):
    return mock.patch.object(local_llm, "find", return_value=entities)


class ScrubTests(unittest.TestCase):
    def test_regex_types(self):
        v = Vault()
        out = scrub("mail bob@x.io, call +1 415-555-0134, key 0x" + "ab" * 32,
                    Policy(), v, use_llm=False)
        self.assertNotIn("bob@x.io", out)
        self.assertNotIn("555-0134", out)
        self.assertNotIn("abab", out)
        self.assertEqual(set(k.rsplit("_", 1)[0] for k in v.entries), {"EMAIL", "PHONE", "SECRET_HEX"})

    def test_keep_list_wins(self):
        p = Policy(keep=["Vitalik Buterin", "Ethereum"])
        with fake_llm([("PERSON", "Vitalik"), ("PERSON", "Ann Lee"), ("ORG", "Ethereum")]):
            out = scrub("Vitalik and Ann Lee talked about Ethereum. Annual plan by Ann.", p, Vault())
        self.assertIn("Vitalik", out)
        self.assertIn("Ethereum", out)
        self.assertIn("Annual", out)          # no partial-word hits
        self.assertNotIn("Ann ", out)
        self.assertEqual(out.count("[PERSON_1]"), 2)

    def test_round_trip(self):
        v = Vault()
        with fake_llm([("PERSON", "Sarah Chen")]):
            out = scrub("Email Sarah Chen at s@c.com", Policy(), v)
        reply = out.replace("Email", "Done. I wrote to")
        self.assertEqual(restore(reply, v), "Done. I wrote to Sarah Chen at s@c.com")

    def test_always_scrub(self):
        out = scrub("Status of Nightingale?", Policy(always_scrub=["Nightingale"]), Vault(), use_llm=False)
        self.assertEqual(out, "Status of [CUSTOM_1]?")

    def test_cloud_model_refused(self):
        for b in [local_llm.Backend(model="minimax-m3:cloud"),
                  local_llm.Backend(kind="openai", url="http://192.168.1.5:8080/v1"),
                  local_llm.Backend(kind="anthropic", model="claude-opus-5-5")]:
            with self.assertRaises(ValueError):
                b.check()
        local_llm.Backend().check()  # local ollama is fine
        local_llm.Backend(kind="anthropic", model="claude-opus-5-5", remote=True).check()

    def test_luhn(self):
        out = scrub("card 4111 1111 1111 1111, order 1234 5678 9012 3456", Policy(), Vault(), use_llm=False)
        self.assertIn("[CREDIT_CARD_1]", out)
        self.assertIn("1234 5678 9012 3456", out)  # fails Luhn, left alone


if __name__ == "__main__":
    unittest.main()


class NormalizeTests(unittest.TestCase):
    def test_light_clean_keeps_code(self):
        from scrubber.normalize import light_clean
        out = light_clean("yo!!! i broke it on tuesday 😂\n```\nx = a!!b  # i\n```")
        self.assertEqual(out, "Yo! I broke it on Tuesday\n```\nx = a!!b  # i\n```")

    def test_rewrite_that_drops_placeholder_is_rejected(self):
        from scrubber import normalize as n
        with mock.patch.object(local_llm, "rewrite", return_value="hello there"):
            out = n.normalize("hey [PERSON_1] `x!!`", local_llm.Backend())
        self.assertIn("[PERSON_1]", out)
        self.assertIn("`x!!`", out)

    def test_rewrite_accepted(self):
        from scrubber import normalize as n
        with mock.patch.object(local_llm, "rewrite", return_value="Please ask [PERSON_1] about [CODE_1]."):
            out = n.normalize("yo ask [PERSON_1] bout `deploy.ts` lol", local_llm.Backend())
        self.assertEqual(out, "Please ask [PERSON_1] about `deploy.ts`.")


class DetectorFilterTests(unittest.TestCase):
    def test_drops_roles_junk_and_hallucinations(self):
        import json as j
        ents = [{"text": "my wife", "type": "PERSON"}, {"text": "Email", "type": "OTHER_PII"},
                {"text": "maria", "type": "PERSON"}, {"text": "3/4/81", "type": "OTHER_PII"},
                {"text": "Bob", "type": "PERSON"}]  # Bob is not in the text
        with mock.patch.object(local_llm, "chat", return_value=j.dumps({"entities": ents})):
            got = local_llm.find("Email: my wife maria, born 3/4/81", local_llm.Backend(), [])
        self.assertEqual(got, [("PERSON", "maria"), ("OTHER_PII", "3/4/81")])


class EmailDomainTests(unittest.TestCase):
    def test_keep_domain_round_trip(self):
        v = Vault()
        out = scrub("from bob.smith@acme.com re: invoice", Policy(keep_email_domain=True), v, use_llm=False)
        self.assertEqual(out, "from [EMAIL_1]@acme.com re: invoice")
        self.assertEqual(restore(out, v), "from bob.smith@acme.com re: invoice")
        self.assertEqual(restore("ask [EMAIL_1]", v), "ask bob.smith@acme.com")


class CheckTests(unittest.TestCase):
    """Sage check flow with Sage and the local model mocked."""

    def run_checked(self, text, sage_answers, llm_answers=()):
        from scrubber import core, sage
        answers = iter(sage_answers)
        llm = iter(llm_answers)
        with mock.patch.object(sage, "flagged", side_effect=lambda t, tags: next(answers)(t)), \
             mock.patch.object(local_llm, "find", side_effect=lambda *a, **k: next(llm, [])):
            return core.scrub_checked(text, Policy(), Vault())

    def test_clean_is_sent(self):
        r = self.run_checked("hello there", [lambda t: []])
        self.assertEqual((r.outcome, r.text), ("sent", "hello there"))

    def test_retry_fixes_it(self):
        # pass 1 misses Tom; Sage flags name; retry finds Tom; Sage clean
        r = self.run_checked("ask Tom about it", [lambda t: ["name"], lambda t: []],
                             [[], [("PERSON", "Tom")]])
        self.assertEqual((r.outcome, r.text), ("sent", "ask [PERSON_1] about it"))

    def test_cut_flagged_sentence(self):
        flag_tom = lambda t: ["name"] if "Tom" in t else []
        r = self.run_checked("I feel sick. Tom knows.", [flag_tom] * 10)
        self.assertEqual((r.outcome, r.text, r.cut), ("cut", "I feel sick.", ["Tom knows."]))

    def test_blocked_when_everything_flagged(self):
        r = self.run_checked("Tom Tom Tom", [lambda t: ["name"]] * 10)
        self.assertEqual((r.outcome, r.text), ("blocked", ""))

    def test_sage_down_fails_closed(self):
        r = self.run_checked("hello", [lambda t: ["sage-error: 504"]] * 10)
        self.assertTrue(r.blocked)

    def test_typed_placeholders_neutralized(self):
        out = scrub("[PERSON_1] = Jane Roe", Policy(), Vault(), use_llm=False)
        self.assertEqual(out, "(PERSON 1) = Jane Roe")


class CredentialPassTests(unittest.TestCase):
    """safeagents-style first pass."""

    def test_credentials_homes_ips(self):
        tok = "ghp_" + "Zq7" * 12
        bearer = "abc.def." + "ghi12345"  # built from pieces so secret scanners skip this fake
        text = (f"curl -H 'Authorization: Bearer {bearer}' https://bob:hunter2pw@x.io/?api_key=K9z8y7x6 "
                f"GITHUB_TOKEN={tok} from /Users/alice/proj and /home/ubuntu, ip 8.8.4.4 and 192.168.1.5, "
                f"mail git@github.com noreply@x.com bob@acme.com")
        v = Vault()
        out = scrub(text, Policy(), v, use_llm=False)
        for secret in [bearer, "hunter2pw", "K9z8y7x6", tok, "alice", "8.8.4.4", "bob@acme.com"]:
            self.assertNotIn(secret, out)
        for kept in ["/home/ubuntu", "192.168.1.5", "git@github.com", "noreply@x.com"]:
            self.assertIn(kept, out)

    def test_env_secret_caught_bare(self):
        import os
        fake = "Qx81mZ" + "p0Lr55vNt2"  # built from pieces so secret scanners skip this fake
        with mock.patch.dict(os.environ, {"MY_SERVICE_API_" + "KEY": fake}):
            out = scrub(f"I pasted {fake} by mistake", Policy(), Vault(), use_llm=False)
        self.assertNotIn(fake, out)
