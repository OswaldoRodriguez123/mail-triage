import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from mail_triage.store import Store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.store.init()

    def tearDown(self):
        self.tmp.cleanup()

    def add_feedback(self, run, msg, domain, verdict):
        self.store.record_decision(run, 1, msg, "a@b.test", domain, verdict, "x", "feedback", "2026-01-01")

    def test_three_distinct_feedback_promotes(self):
        for i in range(3):
            self.add_feedback(f"run{i}", f"msg{i}", "spam.test", "block")
        self.assertTrue(self.store.promote("spam.test", "block"))
        self.assertEqual(self.store.rules()["spam.test"], "block")
        self.assertEqual(self.store.rule_sources()["spam.test"], "auto")

    def test_purge_rows_do_not_promote(self):
        for i in range(3):
            self.store.record_decision(f"run{i}", 1, f"msg{i}", "a@b.test", "spam.test",
                                       "delete", "x", "purge", "2026-01-01")
        self.assertFalse(self.store.promote("spam.test", "block"))

    def test_same_message_twice_does_not_promote(self):
        for i in range(3):
            self.add_feedback("run1", "msg1", "spam.test", "block")
        self.assertFalse(self.store.promote("spam.test", "block"))

    def test_undo_degrades_auto_rule(self):
        self.store.upsert_rule("spam.test", "block", "auto")
        self.store.degrade_auto("spam.test")
        self.assertNotIn("spam.test", self.store.rules())

    def test_inbox_domains_replace(self):
        self.store.replace_inbox_domains({"a.test", "b.test"}, "2026-01-01")
        self.assertEqual(self.store.inbox_domains(), {"a.test", "b.test"})
        self.store.replace_inbox_domains({"c.test"}, "2026-01-02")
        self.assertEqual(self.store.inbox_domains(), {"c.test"})

    def test_clef_verdict_cache_roundtrip(self):
        self.store.cache_clef_verdict("a.test", "fraude", 0.9, 0.1, "2026-01-01T00:00:00+00:00")
        row = self.store.get_clef_verdict("a.test")
        self.assertEqual(row["category"], "fraude")
        self.assertAlmostEqual(row["fraud"], 0.9)

    def test_clef_verdict_cache_expires_by_scan_days(self):
        self.store.mark_scan_day("2026-01-01", "2026-01-01T10:00:00+00:00")
        self.store.cache_clef_verdict("a.test", "fraude", 0.9, 0.1, "2026-01-01T10:00:00+00:00")
        for day in ("2026-02-01", "2026-03-01", "2026-03-02", "2026-03-03"):
            self.store.mark_scan_day(day, f"{day}T10:00:00+00:00")
        self.assertIsNotNone(self.store.get_clef_verdict("a.test", 4))
        self.store.mark_scan_day("2026-03-04", "2026-03-04T10:00:00+00:00")
        self.assertIsNone(self.store.get_clef_verdict("a.test", 4))

    def test_same_day_runs_count_once(self):
        self.store.mark_scan_day("2026-01-01", "2026-01-01T08:00:00+00:00")
        self.store.cache_clef_verdict("a.test", "fraude", 0.9, 0.1, "2026-01-01T08:00:00+00:00")
        self.store.mark_scan_day("2026-01-01", "2026-01-01T20:00:00+00:00")
        self.store.mark_scan_day("2026-01-02", "2026-01-02T08:00:00+00:00")
        self.assertIsNotNone(self.store.get_clef_verdict("a.test", 1))


if __name__ == "__main__":
    unittest.main()
