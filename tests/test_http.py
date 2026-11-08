import unittest

from mail_triage.http import HttpResponse, UrllibHttp


class HttpTest(unittest.TestCase):
    def test_response_parses_json(self):
        r = HttpResponse(200, {"ok": True}, '{"ok": true}')
        self.assertTrue(r.json["ok"])


if __name__ == "__main__":
    unittest.main()
