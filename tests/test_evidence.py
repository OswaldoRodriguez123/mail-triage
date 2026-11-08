import unittest

from correo_limpio.evidence import from_message, parse_auth_results, registrable_domain
from tests import fixtures


class EvidenceTest(unittest.TestCase):
    def test_netflix_impersonation_fields(self):
        ev = from_message(fixtures.netflix_phish())
        self.assertEqual(ev.from_domain, "brainstormingyourliiife.net")
        self.assertEqual(ev.brand, "netflix")
        self.assertTrue(ev.auth.failed)
        self.assertIn("netflix-verify.test", ev.link_domains)

    def test_random_sender_detected(self):
        ev = from_message(fixtures.soda_random())
        self.assertTrue(ev.random_sender)
        self.assertIsNone(ev.brand)

    def test_portuguese_detected(self):
        ev = from_message(fixtures.vivo_pt())
        self.assertEqual(ev.language, "pt")

    def test_missing_headers_are_unknown(self):
        msg = fixtures.cloud_billing()
        msg.pop("internetMessageHeaders")
        ev = from_message(msg)
        self.assertEqual(ev.auth.dmarc, "unknown")
        self.assertEqual(ev.reply_to_domain, None)

    def test_malformed_sender_does_not_crash(self):
        msg = fixtures.travel_empty()
        msg["from"]["emailAddress"]["address"] = "<>"
        ev = from_message(msg)
        self.assertEqual(ev.from_domain, "")
        self.assertEqual(ev.subject[:4], "Take")

    def test_parse_auth_results(self):
        result = parse_auth_results([
            {"name": "Authentication-Results",
             "value": "spf=fail smtp.mailfrom=x.test; dkim=none; dmarc=fail header.from=x.test"}
        ])
        self.assertEqual((result.spf, result.dkim, result.dmarc), ("fail", "none", "fail"))
        self.assertTrue(result.failed)

    def test_registrable_domain_handles_compound_suffix(self):
        self.assertEqual(registrable_domain("mail.banco.com.mx"), "banco.com.mx")
        self.assertEqual(registrable_domain("a.b.example.test"), "example.test")


if __name__ == "__main__":
    unittest.main()
