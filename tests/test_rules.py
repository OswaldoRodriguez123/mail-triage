import unittest
from pathlib import Path

from mail_triage.evidence import from_message
from mail_triage.rules import RuleSet
from tests import fixtures

DATA = Path(__file__).resolve().parents[1] / "mail_triage" / "rules" / "data"


class RulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = RuleSet.load(DATA)

    def verdict(self, fixture, **kwargs):
        return self.rules.evaluate(from_message(fixture), **kwargs)

    def test_netflix_is_deleted(self):
        v = self.verdict(fixtures.netflix_phish())
        self.assertEqual(v.bucket, "delete")
        self.assertGreaterEqual(v.score, 0.85)
        self.assertTrue(v.fraud_signal)

    def test_random_sender_is_review_not_delete(self):
        v = self.verdict(fixtures.soda_random())
        self.assertEqual(v.bucket, "review")
        self.assertFalse(v.fraud_signal)

    def test_promo_is_never_deleted_even_from_new_domain(self):
        v = self.verdict(fixtures.promo_newsletter())
        self.assertEqual(v.bucket, "review")

    def test_allowlisted_domain_never_deletes(self):
        v = self.verdict(fixtures.netflix_phish(), allow_domains={"brainstormingyourliiife.net"})
        self.assertEqual(v.bucket, "review")

    def test_veto_does_not_rescue_auth_failure(self):
        v = self.verdict(fixtures.netflix_phish(), allow_domains={"brainstormingyourliiife.net"})
        self.assertNotEqual(v.bucket, "rescue")

    def test_blocked_domain_forces_delete(self):
        v = self.verdict(fixtures.promo_newsletter(), block_domains={"shop.test"})
        self.assertEqual(v.bucket, "delete")

    def test_transactional_mail_is_rescued(self):
        v = self.verdict(fixtures.sanitized_receipt())
        self.assertEqual(v.bucket, "rescue")

    def test_vivo_phishing_has_fraud_signal(self):
        v = self.verdict(fixtures.vivo_pt())
        self.assertTrue(v.fraud_signal)
        self.assertIn(v.bucket, {"delete", "review"})

    def test_new_domain_adds_reason(self):
        v = self.rules.evaluate(from_message(fixtures.soda_random()), domain_age_days=5)
        self.assertIn("dominio nuevo", v.reasons)
        self.assertEqual(v.bucket, "review")


if __name__ == "__main__":
    unittest.main()
