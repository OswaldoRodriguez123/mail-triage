import unittest
from pathlib import Path

from correo_limpio.evidence import from_message
from correo_limpio.rules import RuleSet

DATA = Path(__file__).resolve().parents[1] / "correo_limpio" / "rules" / "data"


def msg(subject, name, address, body, auth="spf=pass smtp.mailfrom=x.test; dkim=pass; dmarc=pass header.from=x.test"):
    return {
        "id": "m",
        "internetMessageId": "<m@example.test>",
        "subject": subject,
        "from": {"emailAddress": {"name": name, "address": address}},
        "body": {"content": body},
        "receivedDateTime": "2026-11-06T10:00:00Z",
        "hasAttachments": False,
        "internetMessageHeaders": [{"name": "Authentication-Results", "value": auth}],
    }


class RescueGuardTest(unittest.TestCase):
    """Live-mailbox regressions: low score alone must never rescue."""

    @classmethod
    def setUpClass(cls):
        cls.rules = RuleSet.load(DATA)

    def test_urgency_blocks_rescue(self):
        ev = from_message(msg(
            "❌FINAL NOTICE❌", "🔴McAfee", "no-reply@wavevidfsta.surf",
            "Your subscription expires today. https://mcafee-check.test/now",
        ))
        v = self.rules.evaluate(ev, allow_domains={"wavevidfsta.surf"})
        self.assertNotEqual(v.bucket, "rescue")

    def test_foreign_language_blocks_rescue_even_with_code_word(self):
        ev = from_message(msg(
            "Desenrola Brasil: Acordo liberado",
            "Aviso Desenrola Brasil",
            "alerta@desenrolabrasil984234.com",
            "Pagamento via PIX disponível para regularização imediata. Código: 761448918. "
            "Acesse https://desenrola.test/pix",
        ))
        v = self.rules.evaluate(ev, allow_domains={"desenrolabrasil984234.com"})
        self.assertNotEqual(v.bucket, "rescue")

    def test_promo_plural_blocks_rescue(self):
        ev = from_message(msg(
            "Psst...Un código secreto solo para ti 😏",
            "Cinemark Promociones",
            "cinemarknews@cinemarknews.cinemark.cl",
            "Canjea tu código en https://cinemark.test/codigo",
        ))
        v = self.rules.evaluate(ev, allow_domains={"cinemarknews.cinemark.cl"})
        self.assertNotEqual(v.bucket, "rescue")

    def test_plain_receipt_still_rescues(self):
        ev = from_message(msg(
            "Your receipt from Store",
            "Store Receipts",
            "receipts@store.test",
            "Thanks for your order. Your receipt is attached.",
        ))
        self.assertEqual(self.rules.evaluate(ev).bucket, "rescue")


if __name__ == "__main__":
    unittest.main()
