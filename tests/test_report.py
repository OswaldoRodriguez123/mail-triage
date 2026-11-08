import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.report import ReportItem, build_report, load, render, save


def item(n=1, bucket="delete"):
    return ReportItem(n, "m1", "Confirm Your Renewal 🚩", "Netflix <x@y.test>", "y.test",
                      bucket, 0.9, ("marca suplantada", "auth fail"), None)


class ReportTest(unittest.TestCase):
    def test_code_matches_and_expires(self):
        now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
        report, code = build_report([item()], False, "rules", now=now)
        self.assertTrue(report.code_matches(code, now=now))
        self.assertFalse(report.code_matches(code, now=now + timedelta(minutes=61)))
        self.assertFalse(report.code_matches("ZZZZZZ", now=now))

    def test_save_and_load_roundtrip(self):
        with TemporaryDirectory() as tmp:
            report, code = build_report([item()], True, "clef")
            save(report, Path(tmp))
            loaded = load(report.run_id, Path(tmp))
            self.assertEqual(loaded.items[0].subject, "Confirm Your Renewal 🚩")
            self.assertTrue(loaded.code_matches(code))
            self.assertTrue(loaded.has_more)

    def test_tampered_report_is_rejected(self):
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules")
            path = save(report, Path(tmp))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["items"][0]["bucket"] = "rescue"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load(report.run_id, Path(tmp))

    def test_render_contains_reason_and_number(self):
        report, _ = build_report([item()], False, "rules")
        text = render(report)
        self.assertIn("1.", text)
        self.assertIn("marca suplantada", text)
        self.assertIn("borrar", text.lower())


if __name__ == "__main__":
    unittest.main()
