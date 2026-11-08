import unittest

from correo_limpio.auth import Auth, AuthError, DeviceCode
from correo_limpio.http import HttpResponse
from correo_limpio.keychain import MemoryStore


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, body, form))
        return self.responses.pop(0)


class AuthTest(unittest.TestCase):
    def test_login_stores_refresh_token(self):
        http = FakeHttp([
            HttpResponse(200, {"device_code": "dc", "user_code": "ABCD",
                               "verification_uri": "https://microsoft.com/devicelogin",
                               "interval": 5, "expires_in": 900}, ""),
            HttpResponse(400, {"error": "authorization_pending"}, ""),
            HttpResponse(200, {"access_token": "at", "refresh_token": "rt"}, ""),
        ])
        secrets = MemoryStore()
        auth = Auth(http, secrets, client_id="cid", sleep=lambda _: None)
        code = auth.start_login()
        self.assertEqual(code.user_code, "ABCD")
        auth.wait_for_login(code)
        self.assertEqual(secrets.get("refresh-token"), "rt")

    def test_access_token_refreshes_and_caches(self):
        http = FakeHttp([
            HttpResponse(200, {"access_token": "at", "refresh_token": "rt2"}, ""),
        ])
        secrets = MemoryStore({"refresh-token": "rt1"})
        auth = Auth(http, secrets, client_id="cid", sleep=lambda _: None)
        self.assertEqual(auth.access_token(), "at")
        self.assertEqual(auth.access_token(), "at")
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(secrets.get("refresh-token"), "rt2")

    def test_invalid_grant_raises(self):
        http = FakeHttp([HttpResponse(400, {"error": "invalid_grant"}, "")])
        auth = Auth(http, MemoryStore({"refresh-token": "rt1"}), client_id="cid", sleep=lambda _: None)
        with self.assertRaises(AuthError):
            auth.access_token()


if __name__ == "__main__":
    unittest.main()
