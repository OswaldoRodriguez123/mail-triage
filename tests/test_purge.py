import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.config import Config
from correo_limpio.graph import GraphError
from correo_limpio.purge import Selection, feedback, parse_selection, purge, undo
from correo_limpio.report import ReportItem, build_report
from correo_limpio.store import Store


class FakeGraph:
    def __init__(self):
        self.moves = []
        self.fail_ids = set()
        self.fail_status = 404

    def move(self, message_id, destination):
        if message_id in self.fail_ids:
            raise GraphError(self.fail_status, "nope")
        self.moves.append((message_id, destination))


class PurgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(Path(self.tmp.name), Path(self.tmp.name), client_id="cid")
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.store.init()
        items = [
            ReportItem(1, "m1", "a", "x@y.test", "y.test", "delete", 0.9, (), None),
            ReportItem(2, "m2", "b", "x@y.test", "y.test", "delete", 0.9, (), None),
            ReportItem(3, "m3", "c", "x@y.test", "y.test", "rescue", 0.1, (), None),
            ReportItem(4, "m4", "d", "x@y.test", "y.test", "delete", 0.9, (), None),
        ]
        self.report, self.code = build_report(items, False, "rules")
        self.report_expires = self.report.expires_at
        self.graph = FakeGraph()

    def test_wrong_code_moves_nothing(self):
        result = purge(self.cfg, self.graph, self.store, self.report, "WRONG",
                       Selection(delete={1}, rescue=set()))
        self.assertEqual(self.graph.moves, [])
        self.assertEqual(result.moved, [])

    def test_expired_code_moves_nothing(self):
        later = self.report_expires + timedelta(minutes=1)
        purge(self.cfg, self.graph, self.store, self.report, self.code,
              Selection(delete={1}, rescue=set()), now=later)
        self.assertEqual(self.graph.moves, [])

    def test_subset_moves_only_selected(self):
        purge(self.cfg, self.graph, self.store, self.report, self.code,
              Selection(delete={1}, rescue={3}))
        self.assertEqual(self.graph.moves, [("m1", "deleteditems"), ("m3", "inbox")])

    def test_empty_selection_raises(self):
        with self.assertRaises(ValueError):
            purge(self.cfg, self.graph, self.store, self.report, self.code,
                  Selection(set(), set()))

    def test_missing_message_reports_skipped_and_continues(self):
        self.graph.fail_ids = {"m1"}
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1, 2}, rescue=set()))
        self.assertEqual(result.moved, [(2, "deleteditems")])
        self.assertEqual(result.failed, [(1, "404")])

    def test_three_consecutive_failures_abort(self):
        self.graph.fail_ids = {"m1", "m2", "m3", "m4"}
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1, 2, 3, 4}, rescue=set()))
        self.assertTrue(result.aborted)

    def test_non_404_error_counts_as_failure(self):
        self.graph.fail_ids = {"m1"}
        self.graph.fail_status = 503
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1}, rescue=set()))
        self.assertEqual(result.failed, [(1, "503")])

    def test_undo_message_only(self):
        undo(self.cfg, self.graph, self.store, self.report, message_n=2)
        self.assertEqual(self.graph.moves, [("m2", "junkemail")])

    def test_feedback_keep_creates_allow_rule(self):
        feedback(self.cfg, self.graph, self.store, self.report, 1, "allow", rescue=True)
        self.assertEqual(self.store.rules()["y.test"], "allow")
        self.assertIn(("m1", "inbox"), self.graph.moves)

    def test_parse_selection_ranges(self):
        self.assertEqual(parse_selection("1,3-4", None, None), Selection({1, 3, 4}, set()))


if __name__ == "__main__":
    unittest.main()
