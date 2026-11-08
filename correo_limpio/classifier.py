from dataclasses import dataclass

from correo_limpio.evidence import Evidence
from correo_limpio.http import HttpClient
from correo_limpio.rules import Verdict

MODEL = "@cf/cloudflare/clef-flash"
DEFAULT_BASE = "https://api.cloudflare.com/client/v4"

DELETE_FRAUD_PROB = 0.90
RESCUE_EXPECTED_PROB = 0.70
RESCUE_MAX_FRAUD_PROB = 0.30
PROMO_CATEGORIES = frozenset({"promocion", "boletin"})


@dataclass(frozen=True)
class ClefDecision:
    category: str
    fraud_prob: float
    expected_prob: float
    raw: dict


class ClefClient:
    def __init__(
        self,
        http: HttpClient,
        account_id: str,
        token: str,
        base: str = DEFAULT_BASE,
    ) -> None:
        self._http = http
        self._account_id = account_id
        self._token = token
        self._base = base.rstrip("/")

    def evaluate(self, ev: Evidence) -> ClefDecision | None:
        try:
            response = self._http.request(
                "POST",
                f"{self._base}/accounts/{self._account_id}/ai/run/{MODEL}",
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Content-Type": "application/json",
                },
                body={
                    "model": "clef-flash",
                    "state": _state(ev),
                    "questions": _questions(),
                },
            )
            if response.status != 200:
                return None
            answers = response.json["result"]["answers"]
            return ClefDecision(
                category=_category(answers.get("categoria")),
                fraud_prob=_probability(answers.get("fraude")),
                expected_prob=_probability(answers.get("esperado")),
                raw=answers,
            )
        except Exception:
            return None


def refine(verdict: Verdict, decision: ClefDecision | None) -> Verdict:
    if verdict.bucket != "review" or decision is None:
        return verdict
    if decision.fraud_prob >= DELETE_FRAUD_PROB:
        return Verdict(
            max(verdict.score, DELETE_FRAUD_PROB),
            "delete",
            verdict.reasons + ("clef: fraude",),
            True,
        )
    if decision.category in PROMO_CATEGORIES:
        return verdict
    if (
        decision.expected_prob >= RESCUE_EXPECTED_PROB
        and decision.fraud_prob < RESCUE_MAX_FRAUD_PROB
    ):
        return Verdict(
            verdict.score,
            "rescue",
            verdict.reasons + ("clef: esperado",),
            verdict.fraud_signal,
        )
    return verdict


def _state(ev: Evidence) -> dict:
    return {
        "from": ev.from_address,
        "from_name": ev.from_name,
        "from_domain": ev.from_domain,
        "subject": ev.subject,
        "text": ev.text,
        "link_domains": list(ev.link_domains),
        "auth": {"spf": ev.auth.spf, "dkim": ev.auth.dkim, "dmarc": ev.auth.dmarc},
        "language": ev.language,
        "random_sender": ev.random_sender,
        "brand": ev.brand,
    }


def _questions() -> dict:
    return {
        "fraude": {
            "type": "noul",
            "question": "¿Es un intento de fraude o suplantación?",
        },
        "esperado": {
            "type": "noul",
            "question": "¿El destinatario probablemente espera o necesita este correo?",
        },
        "categoria": {
            "type": "choice",
            "question": "¿Qué tipo de correo es?",
            "choices": [
                "fraude",
                "phishing",
                "promocion",
                "boletin",
                "notificacion_legitima",
                "persona",
            ],
        },
    }


def _probability(answer) -> float:
    if isinstance(answer, (int, float)):
        return float(answer)
    if not isinstance(answer, dict):
        return 0.0
    if "probability" in answer:
        try:
            return float(answer["probability"])
        except (TypeError, ValueError):
            return 0.0
    probabilities = answer.get("probabilities")
    if isinstance(probabilities, dict) and probabilities:
        if "yes" in probabilities:
            try:
                return float(probabilities["yes"])
            except (TypeError, ValueError):
                return 0.0
        try:
            return float(max(probabilities.values(), key=lambda value: float(value)))
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _category(answer) -> str:
    if not isinstance(answer, dict):
        return ""
    if answer.get("choice"):
        return str(answer["choice"])
    probabilities = answer.get("probabilities")
    if isinstance(probabilities, dict) and probabilities:
        try:
            return str(max(probabilities, key=lambda key: float(probabilities[key])))
        except (TypeError, ValueError):
            return ""
    return ""
