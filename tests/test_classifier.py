import unittest

from correo_limpio.classifier import ClefClient, ClefDecision, refine
from correo_limpio.evidence import from_message
from correo_limpio.http import HttpResponse
from correo_limpio.rules import Verdict
from tests import fixtures


class FakeHttp:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, headers, body))
        return self.response


def clef_response(fraud, expected, category):
    return HttpResponse(200, {"result": {"answers": {
        "fraude": {"probability": fraud},
        "esperado": {"probability": expected},
        "categoria": {"choice": category, "probabilities": {category: 0.9}},
    }}}, "")


class ClassifierTest(unittest.TestCase):
    def test_request_shape(self):
        http = FakeHttp(clef_response(0.1, 0.8, "notificacion_legitima"))
        client = ClefClient(http, "acct", "tok")
        client.evaluate(from_message(fixtures.sanitized_receipt()))
        method, url, headers, body = http.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/accounts/acct/ai/run/@cf/cloudflare/clef-flash"))
        self.assertEqual(headers["Authorization"], "Bearer tok")
        self.assertEqual(body["model"], "clef-flash")
        self.assertEqual(set(body["questions"]), {"fraude", "esperado", "categoria"})
        self.assertNotIn("body", body["state"])

    def test_fraud_high_deletes(self):
        d = ClefDecision("fraude", 0.95, 0.1, {})
        self.assertEqual(refine(Verdict(0.4, "review", (), False), d).bucket, "delete")

    def test_expected_high_rescues(self):
        d = ClefDecision("notificacion_legitima", 0.1, 0.8, {})
        self.assertEqual(refine(Verdict(0.2, "review", (), False), d).bucket, "rescue")

    def test_promo_never_deletes_or_rescues(self):
        d = ClefDecision("promocion", 0.1, 0.9, {})
        self.assertEqual(refine(Verdict(0.2, "review", (), False), d).bucket, "review")

    def test_error_returns_none(self):
        http = FakeHttp(HttpResponse(429, {"success": False}, ""))
        self.assertIsNone(ClefClient(http, "acct", "tok").evaluate(from_message(fixtures.soda_random())))

    def test_existing_delete_is_not_downgraded(self):
        d = ClefDecision("notificacion_legitima", 0.1, 0.9, {})
        self.assertEqual(refine(Verdict(1.0, "delete", (), True), d).bucket, "delete")


if __name__ == "__main__":
    unittest.main()
