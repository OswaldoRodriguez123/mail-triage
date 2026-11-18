import unittest

from mail_triage.evidence import (
    find_brand,
    from_message,
    is_brand_domain,
    normalize_for_matching,
    parse_auth_results,
    registrable_domain,
)
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


    def test_normalize_strips_invisible_chars(self):
        text = "C\U000e0139oinbase Support"
        self.assertEqual(normalize_for_matching(text), "Coinbase Support")

    def test_normalize_maps_homoglyphs(self):
        # Cyrillic С (U+0421) -> C, і (U+0456) -> i, е (U+0435) -> e
        text = "\u0421\u043e\u0456nbase"
        self.assertEqual(normalize_for_matching(text), "Coinbase")

    def test_find_brand_detects_obfuscated_coinbase(self):
        # Invisible chars between letters
        text = "C\U000e0139o\U000e0139i\U000e0139n\U000e0139b\U000e0139a\U000e0139s\U000e0139e Support"
        self.assertEqual(find_brand(text, frozenset(["coinbase"])), "coinbase")

    def test_find_brand_detects_homoglyph_coinbase(self):
        # Cyrillic lookalikes
        text = "\u0421o\u0456nb\u0430se"
        self.assertEqual(find_brand(text, frozenset(["coinbase"])), "coinbase")

    def test_find_brand_returns_none_for_clean_text(self):
        self.assertIsNone(find_brand("Hello world", frozenset(["coinbase"])))


class BrandDomainTest(unittest.TestCase):
    SUFFIXES = frozenset({"co.uk", "com.mx"})
    BAD_TLDS = frozenset({"xyz", "top"})

    def test_accepts_official_domain_and_subdomains(self):
        self.assertTrue(is_brand_domain("coinbase.com", "coinbase", self.SUFFIXES, self.BAD_TLDS))
        self.assertTrue(is_brand_domain("mail.coinbase.com", "coinbase", self.SUFFIXES, self.BAD_TLDS))
        self.assertTrue(is_brand_domain("coinbase.co.uk", "coinbase", self.SUFFIXES, self.BAD_TLDS))

    def test_rejects_lookalike_domains(self):
        self.assertFalse(is_brand_domain("coinbase-security.xyz", "coinbase", self.SUFFIXES, self.BAD_TLDS))
        self.assertFalse(is_brand_domain("coinbase.com.evil.tld", "coinbase", self.SUFFIXES, self.BAD_TLDS))
        self.assertFalse(is_brand_domain("coinbase.xyz", "coinbase", self.SUFFIXES, self.BAD_TLDS))

    def test_accepts_extra_official_domains(self):
        self.assertTrue(is_brand_domain("amazon.com.mx", "amazon", self.SUFFIXES, self.BAD_TLDS,
                                        ("amazon.com.mx",)))


if __name__ == "__main__":
    unittest.main()
