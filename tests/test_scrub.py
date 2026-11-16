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
        with self.assertRaises(ValueError):
            local_llm.check_local("minimax-m3:cloud")

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
            out = n.normalize("hey [PERSON_1] `x!!`", "qwen3:14b")
        self.assertIn("[PERSON_1]", out)
        self.assertIn("`x!!`", out)

    def test_rewrite_accepted(self):
        from scrubber import normalize as n
        with mock.patch.object(local_llm, "rewrite", return_value="Please ask [PERSON_1] about [CODE_1]."):
            out = n.normalize("yo ask [PERSON_1] bout `deploy.ts` lol", "qwen3:14b")
        self.assertEqual(out, "Please ask [PERSON_1] about `deploy.ts`.")
