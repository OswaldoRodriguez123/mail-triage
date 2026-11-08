import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.classifier import ClefDecision
from correo_limpio.config import Config
from correo_limpio.pipeline import scan
from correo_limpio.rules import RuleSet
from tests import fixtures

DATA = Path(__file__).resolve().parents[1] / "correo_limpio" / "rules" / "data"


class FakeGraph:
    def __init__(self, messages):
        self.messages = list(messages)
        self.moves = []

    def list_junk(self, max_items, skip_ids):
        selected = [m for m in self.messages if m["id"] not in skip_ids]
        if max_items:
            selected = selected[:max_items]
        return selected, False

    def inbox_domains(self, lookback_days):
        return set()

    def move(self, message_id, destination):
        self.moves.append((message_id, destination))


class FakeStore:
    def __init__(self):
        self.seen = {}
        self.decisions = set()
        self.domain_ages = {}
        self.inbox = set()

    def reviewed_ids(self):
        return {message_id for message_id, bucket in self.seen.items() if bucket == "review"}

    def decided_ids(self):
        return set(self.decisions)

    def record_seen(self, message_id, run_id, bucket, seen_at):
        self.seen[message_id] = bucket

    def replace_inbox_domains(self, domains, seen_at):
        self.inbox = set(domains)

    def inbox_domains(self):
        return set(self.inbox)

    def rules(self):
        return {}

    def get_domain_age(self, domain):
        return self.domain_ages.get(domain, (None, None))

    def cache_domain_age(self, domain, created, checked_at):
        self.domain_ages[domain] = (created, checked_at)


class FakeClef:
    def __init__(self):
        self.calls = 0

    def evaluate(self, ev):
        self.calls += 1
        return ClefDecision("notificacion_legitima", 0.1, 0.1, {})


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cfg = Config(self.root / "config", self.root / "state", client_id="cid")
        self.rules = RuleSet.load(DATA)
        self.graph = FakeGraph([
            fixtures.netflix_phish(),
            fixtures.soda_random(),
            fixtures.cloud_billing(),
            fixtures.vivo_pt(),
            fixtures.medicare(),
            fixtures.travel_empty(),
            fixtures.promo_newsletter(),
            fixtures.sanitized_receipt(),
        ])
        self.store = FakeStore()
        self.clef = FakeClef()

    def scan(self, **kwargs):
        return scan(self.cfg, self.graph, self.store, self.rules, self.clef, **kwargs)

    def test_scan_buckets_reference_fixtures(self):
        report, code = self.scan()
        by_subject = {i.subject: i.bucket for i in report.items}
        self.assertEqual(by_subject["The 14X baking soda ritual ending suddenly 🚩❗"], "review")
        self.assertEqual(by_subject["Last Chance: Confirm Your Renewal"], "delete")

    def test_scan_is_read_only(self):
        self.scan()
        self.assertEqual(self.graph.moves, [])

    def test_reviewed_are_skipped_unless_requested(self):
        self.scan()
        report2, _ = self.scan()
        self.assertNotIn("50% off this week", [i.subject for i in report2.items])
        report3, _ = self.scan(include_reviewed=True)
        self.assertIn("50% off this week", [i.subject for i in report3.items])

    def test_delete_candidate_not_purged_reappears(self):
        self.scan()
        report2, _ = self.scan()
        self.assertIn("Last Chance: Confirm Your Renewal", [i.subject for i in report2.items])

    def test_clef_only_refines_review_band(self):
        self.scan()
        self.assertEqual(self.clef.calls, 4)  # 8 fixtures - 2 delete/rescue - 1 promo locked

    def test_duplicate_message_ids_counted_once(self):
        self.graph.messages = [fixtures.netflix_phish(), fixtures.netflix_phish()]
        report, _ = self.scan()
        self.assertEqual(len(report.items), 1)


if __name__ == "__main__":
    unittest.main()
