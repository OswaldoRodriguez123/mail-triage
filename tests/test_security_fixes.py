import hashlib
import io
import json
import os
import stat
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from mail_triage.graph import GraphClient, GraphError
from mail_triage.http import MAX_BODY_BYTES, HttpError, HttpResponse, UrllibHttp, _StripAuthRedirectHandler
from mail_triage.keychain import MacKeychain
from mail_triage.rdap import domain_age_days
from mail_triage.report import ReportItem, build_report, load, save
from mail_triage.store import Store
import mail_triage.cli as cli
from types import SimpleNamespace


def item(n=1, bucket="delete", message_id="m1"):
    return ReportItem(n, message_id, "Asunto", "Remitente <x@y.test>", "y.test",
                      bucket, 0.9, ("marca suplantada",), None)


SECRET = b"k" * 32


class KeyedDigestTest(unittest.TestCase):
    def test_roundtrip_with_secret(self):
        with TemporaryDirectory() as tmp:
            report, code = build_report([item()], False, "rules", secret=SECRET)
            save(report, Path(tmp))
            loaded = load(report.run_id, Path(tmp), secret=SECRET)
            self.assertTrue(loaded.code_matches(code))

    def test_attacker_recomputed_unkeyed_digest_is_rejected(self):
        # A local attacker who can write the runs dir can recompute the old
        # unkeyed sha256 digest, but not the keyed HMAC.
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules", secret=SECRET)
            path = save(report, Path(tmp))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["items"][0]["bucket"] = "rescue"
            canonical = "\n".join(
                f"{i['n']}|{i['message_id']}|{i['bucket']}|{i['score']}"
                for i in data["items"]
            )
            data["digest"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load(report.run_id, Path(tmp), secret=SECRET)

    def test_wrong_key_is_rejected(self):
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules", secret=SECRET)
            save(report, Path(tmp))
            with self.assertRaises(ValueError):
                load(report.run_id, Path(tmp), secret=b"x" * 32)

    def test_secret_never_written_to_disk(self):
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules", secret=SECRET)
            path = save(report, Path(tmp))
            self.assertNotIn(SECRET.hex(), path.read_text(encoding="utf-8"))


class RunIdTraversalTest(unittest.TestCase):
    def test_absolute_run_id_rejected(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                load("/etc/passwd", Path(tmp), secret=SECRET)

    def test_dotdot_run_id_rejected(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                load("../../outside", Path(tmp), secret=SECRET)

    def test_cli_helper_rejects_bad_run_id(self):
        with TemporaryDirectory() as tmp:
            ctx = SimpleNamespace(cfg=SimpleNamespace(state_dir=tmp), plan_secret=SECRET)
            self.assertIsNone(cli._load_report(ctx, "../../outside"))
            self.assertIsNone(cli._load_report(ctx, "/abs/path"))
            self.assertIsNone(cli._load_report(ctx, "corrida inexistente"))


class PrivateFilePermsTest(unittest.TestCase):
    def test_report_files_and_dirs_are_owner_only(self):
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules", secret=SECRET)
            path = save(report, Path(tmp) / "runs")
            dir_mode = stat.S_IMODE(os.stat(path.parent).st_mode)
            json_mode = stat.S_IMODE(os.stat(path).st_mode)
            csv_mode = stat.S_IMODE(os.stat(path.parent / "report.csv").st_mode)
            self.assertEqual(dir_mode, 0o700)
            self.assertEqual(json_mode, 0o600)
            self.assertEqual(csv_mode, 0o600)

    def test_state_db_is_owner_only(self):
        with TemporaryDirectory() as tmp:
            db = Path(tmp) / "state.db"
            Store(db).init()
            self.assertEqual(stat.S_IMODE(os.stat(db).st_mode), 0o600)


class _FakeRawResponse:
    def __init__(self, raw: bytes, headers=None, status=200):
        self._raw = raw
        self.headers = headers or {}
        self.status = status

    def read(self, n=-1):
        if n is None or n < 0:
            return self._raw
        return self._raw[:n]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeOpener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout=None):
        return self.response


class HttpCapTest(unittest.TestCase):
    def _run_with(self, response):
        with mock.patch("mail_triage.http._OPENER", _FakeOpener(response)):
            return UrllibHttp().request("GET", "https://graph.microsoft.com/x")

    def test_oversized_body_fails_closed(self):
        raw = b"a" * (MAX_BODY_BYTES + 10)
        with self.assertRaises(HttpError):
            self._run_with(_FakeRawResponse(raw))

    def test_oversized_content_length_rejected_before_read(self):
        response = _FakeRawResponse(b"", headers={"Content-Length": str(MAX_BODY_BYTES + 1)})
        with self.assertRaises(HttpError):
            self._run_with(response)

    def test_body_at_cap_is_accepted(self):
        raw = b'{"ok": true}'
        response = self._run_with(_FakeRawResponse(raw, headers={"Content-Length": str(len(raw))}))
        self.assertTrue(response.json["ok"])


class RedirectAuthStripTest(unittest.TestCase):
    def _redirect(self, newurl):
        handler = _StripAuthRedirectHandler()
        req = urllib.request.Request(
            "https://graph.microsoft.com/origin",
            headers={"Authorization": "Bearer tok"},
        )
        return handler.redirect_request(req, None, 302, "Found", {}, newurl)

    def test_cross_origin_redirect_drops_authorization(self):
        new_req = self._redirect("https://evil.example.com/collect")
        self.assertIsNone(new_req.headers.get("Authorization"))

    def test_same_origin_redirect_keeps_authorization(self):
        new_req = self._redirect("https://graph.microsoft.com/elsewhere")
        self.assertEqual(new_req.headers.get("Authorization"), "Bearer tok")


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, body))
        return self.responses.pop(0)


class GraphUrlGuardTest(unittest.TestCase):
    def client(self, responses):
        self.http = FakeHttp(responses)
        return GraphClient(self.http, token_provider=lambda: "token")

    def test_move_quotes_message_id(self):
        g = self.client([HttpResponse(200, {}, "")])
        g.move("AAAA/bb?$top=1#frag", "deleteditems")
        _, url, _ = self.http.calls[0]
        self.assertIn("AAAA%2Fbb%3F%24top%3D1%23frag", url)

    def test_non_graph_next_link_is_never_fetched(self):
        g = self.client([
            HttpResponse(200, {"value": [{"id": "1"}],
                               "@odata.nextLink": "https://evil.example.com/steal"}, ""),
        ])
        with self.assertRaises(GraphError):
            list(g.iter_messages("junkemail", max_items=10, skip_ids=set()))
        self.assertEqual(len(self.http.calls), 1)

    def test_http_scheme_next_link_rejected(self):
        g = self.client([
            HttpResponse(200, {"value": [],
                               "@odata.nextLink": "http://graph.microsoft.com/v1.0/next"}, ""),
        ])
        with self.assertRaises(GraphError):
            list(g.iter_messages("junkemail", max_items=10, skip_ids=set()))

    def test_relative_next_link_rejected(self):
        g = self.client([
            HttpResponse(200, {"value": [], "@odata.nextLink": "next"}, ""),
        ])
        with self.assertRaises(GraphError):
            list(g.iter_messages("junkemail", max_items=10, skip_ids=set()))

    def test_absolute_url_off_graph_host_rejected(self):
        g = self.client([])
        with self.assertRaises(GraphError):
            g.get("https://evil.example.com/me")
        self.assertEqual(self.http.calls, [])


class RdapInjectionTest(unittest.TestCase):
    def test_domain_with_url_chars_never_reaches_fetch(self):
        called = []

        def fetch(url):
            called.append(url)
            return {}

        self.assertIsNone(domain_age_days("a/b@c?d.com", fetch=fetch, today="2026-11-07"))
        self.assertEqual(called, [])

    def test_plain_domain_is_encoded_and_fetched(self):
        called = []

        def fetch(url):
            called.append(url)
            return {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}

        self.assertIsNotNone(domain_age_days("Example.COM.", fetch=fetch, today="2026-11-07"))
        self.assertEqual(called, ["https://rdap.org/domain/example.com"])


class DigestCoversWholeReportTest(unittest.TestCase):
    def _forge(self, tmp, mutate):
        report, _ = build_report([item()], False, "rules", secret=SECRET)
        path = save(report, Path(tmp))
        data = json.loads(path.read_text(encoding="utf-8"))
        mutate(data)
        path.write_text(json.dumps(data), encoding="utf-8")
        return report.run_id, path

    def test_extended_expiry_is_rejected(self):
        with TemporaryDirectory() as tmp:
            run_id, _ = self._forge(
                tmp, lambda d: d.update(expires_at="2999-01-01T00:00:00+00:00")
            )
            with self.assertRaises(ValueError):
                load(run_id, Path(tmp), secret=SECRET)

    def test_flipped_metadata_is_rejected(self):
        with TemporaryDirectory() as tmp:
            for mutation in (
                lambda d: d.update(has_more=True),
                lambda d: d.update(mode="clef"),
                lambda d: d.update(run_id="forged-run-id"),
            ):
                run_id, _ = self._forge(tmp, mutation)
                with self.assertRaises(ValueError):
                    load(run_id, Path(tmp), secret=SECRET)

    def test_edited_domain_and_reasons_are_rejected(self):
        with TemporaryDirectory() as tmp:
            def mutate(d):
                d["items"][0]["domain"] = "evil.test"
                d["items"][0]["reasons"] = ["clef: legítimo"]
            run_id, _ = self._forge(tmp, mutate)
            with self.assertRaises(ValueError):
                load(run_id, Path(tmp), secret=SECRET)

    def test_untampered_report_still_loads(self):
        with TemporaryDirectory() as tmp:
            report, code = build_report([item()], False, "rules", secret=SECRET)
            save(report, Path(tmp))
            loaded = load(report.run_id, Path(tmp), secret=SECRET)
            self.assertTrue(loaded.code_matches(code))


class RedirectBodyTest(unittest.TestCase):
    def _request(self, url, data=None, method=None):
        return urllib.request.Request(
            url,
            data=data,
            headers={"Authorization": "Bearer tok", "Content-Type": "application/json"},
            method=method,
        )

    def _redirect(self, req, newurl, code=307):
        handler = _StripAuthRedirectHandler()
        return handler.redirect_request(req, None, code, "Redirect", {}, newurl)

    def test_cross_origin_post_with_body_is_refused(self):
        req = self._request(
            "https://graph.microsoft.com/start",
            data=b'{"refresh_token":"secret"}',
            method="POST",
        )
        self.assertIsNone(self._redirect(req, "https://evil.example.com/collect"))

    def test_cross_origin_get_redirect_still_drops_authorization(self):
        req = self._request("https://graph.microsoft.com/start", method="GET")
        new_req = self._redirect(req, "https://evil.example.com/collect", code=302)
        self.assertIsNone(new_req.headers.get("Authorization"))

    def test_port_change_counts_as_cross_origin(self):
        req = self._request("https://graph.microsoft.com/start", method="GET")
        new_req = self._redirect(req, "https://graph.microsoft.com:444/collect", code=302)
        self.assertIsNone(new_req.headers.get("Authorization"))

    def test_same_origin_redirect_keeps_authorization(self):
        req = self._request("https://graph.microsoft.com/start", method="GET")
        new_req = self._redirect(req, "https://graph.microsoft.com:443/elsewhere", code=302)
        self.assertEqual(new_req.headers.get("Authorization"), "Bearer tok")


class GraphUrlGuardPortTest(unittest.TestCase):
    def client(self, responses):
        self.http = FakeHttp(responses)
        return GraphClient(self.http, token_provider=lambda: "token")

    def test_same_host_different_port_next_link_rejected(self):
        g = self.client([
            HttpResponse(200, {"value": [{"id": "1"}],
                               "@odata.nextLink": "https://graph.microsoft.com:444/v1.0/next"}, ""),
        ])
        with self.assertRaises(GraphError):
            list(g.iter_messages("junkemail", max_items=10, skip_ids=set()))
        self.assertEqual(len(self.http.calls), 1)

    def test_same_host_explicit_default_port_next_link_accepted(self):
        g = self.client([
            HttpResponse(200, {"value": [{"id": "1"}],
                               "@odata.nextLink": "https://graph.microsoft.com:443/v1.0/next"}, ""),
            HttpResponse(200, {"value": [{"id": "2"}]}, ""),
        ])
        messages, _ = g.list_junk(max_items=10, skip_ids=set())
        self.assertEqual([m["id"] for m in messages], ["1", "2"])


class KeychainStdinTest(unittest.TestCase):
    def test_secret_goes_via_stdin_not_argv(self):
        run = mock.Mock(return_value=mock.Mock(stdout=b"", stderr=b"", returncode=0))
        store = MacKeychain(run=run)
        store.set("refresh-token", "sekret-value-123")
        args, kwargs = run.call_args
        argv = args[0]
        self.assertNotIn("sekret-value-123", argv)
        self.assertEqual(kwargs.get("input"), b"sekret-value-123\nsekret-value-123\n")


if __name__ == "__main__":
    unittest.main()
