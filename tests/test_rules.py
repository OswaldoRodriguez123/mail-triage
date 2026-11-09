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


    def test_obfuscated_brand_from_foreign_domain_is_deleted(self):
        # Brand claimed in display name via invisible chars, sent from unrelated domain.
        msg = {
            "id": "m_obf",
            "internetMessageId": "<m_obf@example.test>",
            "subject": "Your request to change phone number on your account is now pending review.",
            "from": {"emailAddress": {"name": "C\U000e0139o\U000e0139i\U000e0139n\U000e0139b\U000e0139a\U000e0139s\U000e0139e Support", "address": "bz@lyglj.com"}},
            "body": {"content": "Dear Customer, your account has a pending request."},
            "receivedDateTime": "2026-11-06T10:00:00Z",
            "hasAttachments": False,
            "internetMessageHeaders": [{"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=pass"}],
        }
        from mail_triage.evidence import from_message
        ev = from_message(msg)
        v = self.rules.evaluate(ev, allow_domains=frozenset(), block_domains=frozenset(), domain_age_days=100)
        self.assertEqual(v.bucket, "delete")
        self.assertIn("marca suplantada desde dominio ajeno", v.reasons)

    def test_brand_in_subject_only_from_foreign_domain_stays_review(self):
        # Brand mentioned in subject but not in display name -> no mismatch bonus.
        msg = {
            "id": "m_subj",
            "internetMessageId": "<m_subj@example.test>",
            "subject": "Coinbase account update",
            "from": {"emailAddress": {"name": "Newsletter", "address": "news@example.com"}},
            "body": {"content": "Check your Coinbase account."},
            "receivedDateTime": "2026-11-06T10:00:00Z",
            "hasAttachments": False,
            "internetMessageHeaders": [{"name": "Authentication-Results", "value": "spf=pass; dkim=pass; dmarc=pass"}],
        }
        from mail_triage.evidence import from_message
        ev = from_message(msg)
        v = self.rules.evaluate(ev, allow_domains=frozenset(), block_domains=frozenset(), domain_age_days=100)
        # Brand in subject adds 0.35 but no mismatch bonus -> review band.
        self.assertEqual(v.bucket, "review")
        self.assertNotIn("marca suplantada desde dominio ajeno", v.reasons)

if __name__ == "__main__":
    unittest.main()
