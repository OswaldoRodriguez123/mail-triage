import re
from dataclasses import dataclass
from pathlib import Path

from correo_limpio.evidence import Evidence, find_brand

WEIGHTS = {
    "brand": 0.35,
    "auth_fail": 0.30,
    "random_sender": 0.25,
    "reply_to": 0.20,
    "foreign_link": 0.15,
    "urgency": 0.10,
    "language": 0.10,
    "suspicious_tld": 0.10,
    "new_domain": 0.10,
    "blocked": 0.25,
}

PROMO_WORDS = ("off", "sale", "discount", "newsletter", "unsubscribe", "promo", "boletín", "oferta")
PROMO_SYMBOLS = ("%",)
TRANSACTIONAL_WORDS = (
    "receipt", "invoice", "order", "pedido", "factura", "recibo",
    "verification", "código", "code", "reservation", "booking",
)
NEW_DOMAIN_DAYS = 30
DELETE_THRESHOLD = 0.85
RESCUE_THRESHOLD = 0.30


@dataclass(frozen=True)
class Verdict:
    score: float
    bucket: str
    reasons: tuple[str, ...]
    fraud_signal: bool


class RuleSet:
    def __init__(self, brands, urgency, tlds, suffixes) -> None:
        self.brands = frozenset(brands)
        self.urgency = tuple(urgency)
        self.tlds = frozenset(tlds)
        self.suffixes = frozenset(suffixes)

    @classmethod
    def load(cls, data_dir: Path) -> "RuleSet":
        data_dir = Path(data_dir)
        return cls(
            brands=_read_lines(data_dir / "brands.txt"),
            urgency=_read_lines(data_dir / "urgency.txt"),
            tlds=_read_lines(data_dir / "tlds.txt"),
            suffixes=_read_lines(data_dir / "suffixes.txt"),
        )

    def evaluate(
        self,
        ev: Evidence,
        *,
        allow_domains=frozenset(),
        block_domains=frozenset(),
        domain_age_days: int | None = None,
    ) -> Verdict:
        reasons: list[str] = []
        score = 0.0
        fraud_signal = False

        allowed = _matches(ev.from_domain, allow_domains)
        blocked = _matches(ev.from_domain, block_domains)
        haystack = f"{ev.subject} {ev.text}"
        promo_hint = _contains_any(haystack, PROMO_WORDS) or any(
            symbol in haystack for symbol in PROMO_SYMBOLS
        )
        transactional = _contains_any(haystack, TRANSACTIONAL_WORDS)

        brand = ev.brand or find_brand(f"{ev.from_name} {ev.subject}", self.brands)
        if brand:
            score += WEIGHTS["brand"]
            fraud_signal = True
            reasons.append("marca suplantada")

        if ev.auth.failed:
            score += WEIGHTS["auth_fail"]
            fraud_signal = True
            reasons.append("fallo de autenticación")

        if ev.random_sender:
            score += WEIGHTS["random_sender"]
            reasons.append("remitente aleatorio")

        if ev.reply_to_domain and ev.reply_to_domain != ev.from_domain:
            score += WEIGHTS["reply_to"]
            fraud_signal = True
            reasons.append("reply-to distinto")

        foreign = [domain for domain in ev.link_domains if domain and domain != ev.from_domain]
        if foreign:
            score += WEIGHTS["foreign_link"]
            fraud_signal = True
            reasons.append("enlace a dominio ajeno")

        if _contains_any(haystack, self.urgency):
            score += WEIGHTS["urgency"]
            reasons.append("lenguaje de urgencia")

        if ev.language not in ("es", "en", "unknown"):
            score += WEIGHTS["language"]
            reasons.append("idioma fuera de es/en")

        if self._suspicious_tld(ev):
            score += WEIGHTS["suspicious_tld"]
            fraud_signal = True
            reasons.append("TLD sospechoso")

        if blocked:
            score += WEIGHTS["blocked"]
            fraud_signal = True
            reasons.append("dominio bloqueado")

        if domain_age_days is not None and domain_age_days < NEW_DOMAIN_DAYS:
            score += WEIGHTS["new_domain"]
            reasons.append("dominio nuevo")

        score = round(min(score, 1.0), 2)

        if allowed:
            return Verdict(score, "review", tuple(reasons) or ("dominio permitido",), fraud_signal)
        if blocked:
            return Verdict(1.0, "delete", ("dominio bloqueado",), True)
        if promo_hint:
            return Verdict(score, "review", tuple(reasons) or ("promoción",), fraud_signal)
        if score >= DELETE_THRESHOLD and fraud_signal:
            return Verdict(score, "delete", tuple(reasons), True)
        if score <= RESCUE_THRESHOLD and not ev.auth.failed and (
            allow_domains or transactional
        ):
            return Verdict(score, "rescue", tuple(reasons) or ("correo transaccional",), fraud_signal)
        return Verdict(score, "review", tuple(reasons) or ("sin señales claras",), fraud_signal)

    def _suspicious_tld(self, ev: Evidence) -> bool:
        candidates = [ev.from_domain, *ev.link_domains]
        for domain in candidates:
            if not domain or "." not in domain:
                continue
            if domain.rsplit(".", 1)[-1] in self.tlds:
                return True
        return False


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if line:
            lines.append(line)
    return lines


def _matches(domain: str, domains) -> bool:
    if not domain:
        return False
    for candidate in domains or ():
        candidate = (candidate or "").lower().strip()
        if candidate and (domain == candidate or domain.endswith(f".{candidate}")):
            return True
    return False


def _contains_any(haystack: str, needles) -> bool:
    text = (haystack or "").lower()
    for needle in needles:
        needle = needle.lower()
        if not needle:
            continue
        if re.search(rf"(?<!\w){re.escape(needle)}(?!\w)", text):
            return True
    return False
