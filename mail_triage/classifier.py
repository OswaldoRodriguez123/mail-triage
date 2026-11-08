from dataclasses import dataclass

from mail_triage.evidence import Evidence
from mail_triage.http import HttpClient
from mail_triage.rules import Verdict

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
    if getattr(verdict, "locked", False):
        return verdict
    reasons_text = " ".join(verdict.reasons or ()).lower()
    if "permitido" in reasons_text or "promoci" in reasons_text or "veto" in reasons_text:
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
            "instructions": "¿Es un intento de fraude o suplantación?",
        },
        "esperado": {
            "type": "noul",
            "instructions": "¿El destinatario probablemente espera o necesita este correo?",
        },
        "categoria": {
            "type": "choice",
            "instructions": "¿Qué tipo de correo es?",
            "criteria": {
                "fraude": "Fraude o suplantación de identidad",
                "phishing": "Intento de robar credenciales o datos",
                "promocion": "Promoción comercial o publicidad",
                "boletin": "Boletín o newsletter",
                "notificacion_legitima": "Notificación legítima de un servicio",
                "persona": "Mensaje de una persona real",
            },
        },
    }


def _probability(answer) -> float:
    if isinstance(answer, (int, float)):
        return float(answer)
    if not isinstance(answer, dict):
        return 0.0
    for key in ("probability", "noul"):
        if key in answer:
            try:
                return float(answer[key])
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
