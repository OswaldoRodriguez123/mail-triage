import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.evidence import from_message
from correo_limpio.rules import RuleSet
from correo_limpio.store import Store
from tests import fixtures

DATA = Path(__file__).resolve().parents[1] / "correo_limpio" / "rules" / "data"


class RulesFixTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = RuleSet.load(DATA)

    def test_non_allowlisted_low_score_ignores_nonempty_inbox(self):
        v = self.rules.evaluate(from_message(fixtures.cloud_billing()), allow_domains={"unrelated.test"})
        self.assertEqual(v.bucket, "review")

    def test_veto_blocks_delete_but_allows_rescue_when_clean(self):
        v = self.rules.evaluate(from_message(fixtures.cloud_billing()), allow_domains={"cloudprovider.test"})
        self.assertNotEqual(v.bucket, "delete")

    def test_vetoed_high_score_stays_review_not_delete(self):
        v = self.rules.evaluate(from_message(fixtures.netflix_phish()), allow_domains={"brainstormingyourliiife.net"})
        self.assertEqual(v.bucket, "review")


class ClassifierFixTest(unittest.TestCase):
    def test_locked_veto_not_upgraded_to_delete(self):
        from correo_limpio.classifier import ClefDecision, refine
        from correo_limpio.rules import Verdict
        d = ClefDecision("fraude", 0.99, 0.01, {})
        self.assertEqual(refine(Verdict(0.4, "review", ("dominio permitido",), False), d).bucket, "review")

    def test_locked_promo_not_upgraded_to_delete_or_rescue(self):
        from correo_limpio.classifier import ClefDecision, refine
        from correo_limpio.rules import Verdict
        d1 = ClefDecision("fraude", 0.99, 0.01, {})
        d2 = ClefDecision("notificacion_legitima", 0.01, 0.95, {})
        self.assertEqual(refine(Verdict(0.2, "review", ("promoción",), False), d1).bucket, "review")
        self.assertEqual(refine(Verdict(0.2, "review", ("promoción",), False), d2).bucket, "review")


class StoreFixTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.store.init()

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, run, msg):
        self.store.record_decision(run, 1, msg, "a@b.test", "spam.test", "block", "x", "feedback", "2026-01-01")

    def test_same_run_different_messages_do_not_promote(self):
        for i in range(3):
            self.add("run1", f"msg{i}")
        self.assertFalse(self.store.promote("spam.test", "block"))


class CliFixTest(unittest.TestCase):
    def test_purge_invalid_code_returns_2(self):
        from correo_limpio import cli
        from correo_limpio.report import ReportItem, build_report
        import io
        from contextlib import redirect_stdout, redirect_stderr
        from unittest import mock

        items = [ReportItem(1, "m1", "a", "x@y.test", "y.test", "delete", 0.9, (), None)]
        report, _ = build_report(items, False, "rules")
        from pathlib import Path
        from types import SimpleNamespace

        with mock.patch.object(cli, "build_context") as ctx, \
             mock.patch.object(cli, "load", return_value=report):
            ctx.return_value = SimpleNamespace(cfg=SimpleNamespace(state_dir=Path("/tmp")))
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = cli.main(["purge", "--run", report.run_id, "--code", "WRONGC", "--delete", "1"])
            self.assertEqual(rc, 2)
            self.assertIn("inválido", err.getvalue().lower() + out.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
