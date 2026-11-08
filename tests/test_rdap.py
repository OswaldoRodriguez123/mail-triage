import unittest

from mail_triage.rdap import domain_age_days


class RdapTest(unittest.TestCase):
    def test_parses_registration_date(self):
        def fetch(url):
            return {"events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}]}
        age = domain_age_days("new.test", fetch=fetch, today="2026-11-07")
        self.assertEqual(age, 6)

    def test_failure_returns_none(self):
        def fetch(url):
            raise OSError("offline")
        self.assertIsNone(domain_age_days("new.test", fetch=fetch, today="2026-11-07"))


if __name__ == "__main__":
    unittest.main()
