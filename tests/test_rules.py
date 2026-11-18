import unittest
from pathlib import Path

from mail_triage.evidence import from_message
from mail_triage.rules import RuleSet
from tests import fixtures

DATA = Path(__file__).resolve().parents[1] / "mail_triage" / "rules" / "data"


def _fake_message(name, address, subject, body):
    return {
        "id": "m_brand", "internetMessageId": "<m_brand@example.test>",
        "subject": subject,
        "from": {"emailAddress": {"name": name, "address": address}},
        "body": {"content": body}, "hasAttachments": False,
        "internetMessageHeaders": [{"name": "Authentication-Results",
                                    "value": "spf=pass; dkim=pass; dmarc=pass"}],
    }


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

    def test_lookalike_domain_containing_brand_is_deleted(self):
        v = self.verdict(_fake_message("Coinbase", "no-reply@coinbase-security.xyz",
                                       "Accion requerida", "Verifica tu cuenta en coinbase-security.xyz"))
        self.assertEqual(v.bucket, "delete")
        self.assertIn("marca suplantada desde dominio ajeno", v.reasons)

    def test_official_brand_domain_is_not_mismatch(self):
        v = self.verdict(_fake_message("Coinbase", "no-reply@coinbase.com",
                                       "Your transaction receipt", "Receipt attached"))
        self.assertNotIn("marca suplantada desde dominio ajeno", v.reasons)

    def test_brand_display_name_from_free_mail_is_mismatch(self):
        v = self.verdict(_fake_message("Coinbase", "recovery@gmail.com",
                                       "Accion requerida", "Verifica tu cuenta"))
        self.assertIn("marca suplantada desde dominio ajeno", v.reasons)
        self.assertEqual(v.bucket, "delete")

    def test_generic_bank_word_is_not_a_brand(self):
        v = self.verdict(_fake_message("Banco Falabella", "contacto@cl.bancofalabella.com",
                                       "Acompana a tus seres queridos", "Hola"))
        self.assertNotIn("marca suplantada", v.reasons)

    def test_brand_only_in_body_is_review_with_body_reason(self):
        v = self.verdict(_fake_message("Notificaciones", "billing@mailer-service.com",
                                       "Tienes una recompensa pendiente",
                                       "Reclama tu recompensa de Coinbase aqui: https://claim-reward.top/r"))
        self.assertEqual(v.bucket, "review")
        self.assertIn("marca mencionada en el cuerpo", v.reasons)

    def test_brand_in_body_from_official_domain_is_not_penalized(self):
        v = self.verdict(_fake_message("Notificaciones", "no-reply@coinbase.com",
                                       "Novedades de la semana",
                                       "Coinbase lanza una funcion nueva."))
        self.assertNotIn("marca mencionada en el cuerpo", v.reasons)

    def test_newsletter_mentioning_brand_with_auth_failure_is_not_deleted(self):
        msg = _fake_message("Crypto Weekly", "news@mailer-service.com",
                            "Weekly crypto digest",
                            "Coinbase sube hoy. Act now before prices change: "
                            "https://coinbase.com/prices")
        msg["internetMessageHeaders"] = [{"name": "Authentication-Results",
                                          "value": "spf=fail smtp.mailfrom=mailer-service.com"}]
        v = self.verdict(msg)
        self.assertEqual(v.bucket, "review")
        self.assertIn("marca mencionada en el cuerpo", v.reasons)

if __name__ == "__main__":
    unittest.main()
