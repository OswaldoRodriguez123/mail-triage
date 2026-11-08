from dataclasses import dataclass
from datetime import datetime, timezone

from mail_triage.graph import DELETED, INBOX, JUNK, GraphError

ABORT_AFTER_FAILURES = 3

FREE_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com",
    "outlook.es", "live.com", "live.cl", "msn.com", "yahoo.com", "yahoo.es",
    "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
})

STRONG_FRAUD_REASONS = (
    "marca suplantada",
    "fallo de autenticación",
    "reply-to distinto",
    "tld sospechoso",
    "dominio bloqueado",
    "clef: fraude",
)


@dataclass(frozen=True)
class Selection:
    delete: set[int]
    rescue: set[int]


@dataclass(frozen=True)
class PurgeResult:
    moved: list[tuple[int, str]]
    failed: list[tuple[int, str]]
    aborted: bool


def parse_selection(
    delete: str | None = None,
    rescue: str | None = None,
    groups: list[str] | None = None,
    report=None,
) -> Selection:
    delete_numbers = _parse_numbers(delete)
    rescue_numbers = _parse_numbers(rescue)
    for group in groups or []:
        name = (group or "").strip().lower()
        if name in {"delete", "borrar"}:
            delete_numbers |= _group_numbers(report, "delete")
        elif name in {"rescue", "rescatar"}:
            rescue_numbers |= _group_numbers(report, "rescue")
        else:
            raise ValueError(f"grupo desconocido: {group}")
    return Selection(delete_numbers, rescue_numbers)


def purge(cfg, graph, store, report, code, selection: Selection, now=None) -> PurgeResult:
    if not report.code_matches(code, now):
        return PurgeResult([], [], False)
    if not selection.delete and not selection.rescue:
        raise ValueError("selección vacía")

    now = now or datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    by_n = {item.n: item for item in report.items}
    moved: list[tuple[int, str]] = []
    failed: list[tuple[int, str]] = []
    consecutive = 0

    plan = [(n, DELETED, "delete") for n in sorted(selection.delete)]
    plan += [(n, INBOX, "rescue") for n in sorted(selection.rescue)]

    known_rules = store.rules()
    inbox_domains = store.inbox_domains()

    for n, destination, expected_bucket in plan:
        item = by_n.get(n)
        if item is None or item.bucket != expected_bucket:
            continue
        try:
            graph.move(item.message_id, destination)
        except GraphError as exc:
            failed.append((n, str(exc.status)))
            consecutive += 1
            if consecutive >= ABORT_AFTER_FAILURES:
                return PurgeResult(moved, failed, True)
            continue
        consecutive = 0
        moved.append((n, destination))
        store.record_decision(
            report.run_id,
            n,
            item.message_id,
            item.sender,
            item.domain,
            item.bucket,
            "; ".join(item.reasons),
            "purge",
            now_iso,
        )
        if expected_bucket == "delete":
            _learn_block(store, item, known_rules, inbox_domains)
    return PurgeResult(moved, failed, False)


def undo(cfg, graph, store, report, message_n: int | None = None) -> PurgeResult:
    targets = [item for item in report.items if message_n is None or item.n == message_n]
    moved: list[tuple[int, str]] = []
    failed: list[tuple[int, str]] = []
    for item in targets:
        try:
            graph.move(item.message_id, JUNK)
        except GraphError as exc:
            failed.append((item.n, str(exc.status)))
            continue
        moved.append((item.n, JUNK))
        store.degrade_auto(item.domain)
        store.remove_rule(item.domain, "purge")
    return PurgeResult(moved, failed, False)


def feedback(cfg, graph, store, report, n: int, verdict: str, *, rescue: bool = False) -> str:
    item = next((entry for entry in report.items if entry.n == n), None)
    if item is None:
        raise ValueError(f"no existe el mensaje {n} en la corrida {report.run_id}")

    rule_value = _rule_value(verdict)
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    store.record_decision(
        report.run_id,
        n,
        item.message_id,
        item.sender,
        item.domain,
        rule_value,
        f"feedback {rule_value}",
        "feedback",
        now_iso,
    )
    store.upsert_rule(item.domain, rule_value, "user")
    promoted = store.promote(item.domain, rule_value)

    parts = [f"Regla {rule_value} aplicada a {item.domain}."]
    if promoted:
        parts.append("Tres correcciones coincidentes: la regla ya es automática.")
    if rescue:
        try:
            graph.move(item.message_id, INBOX)
            parts.append(f"Mensaje {n} devuelto a la bandeja.")
        except GraphError as exc:
            parts.append(f"No se pudo mover el mensaje {n} (Graph {exc.status}).")
    return " ".join(parts)


def _learn_block(store, item, known_rules, inbox_domains) -> None:
    domain = (item.domain or "").lower()
    if not domain or _is_free(domain):
        return
    if known_rules.get(domain) in {"allow", "block"}:
        return
    if _matches_domain(domain, inbox_domains):
        return
    reasons = " ".join(item.reasons or ()).lower()
    if not any(marker in reasons for marker in STRONG_FRAUD_REASONS):
        return
    store.upsert_rule(domain, "block", "purge")
    known_rules[domain] = "block"


def _is_free(domain: str) -> bool:
    return _matches_domain(domain, FREE_DOMAINS)


def _matches_domain(domain: str, candidates) -> bool:
    for candidate in candidates or ():
        candidate = (candidate or "").lower().strip()
        if candidate and (domain == candidate or domain.endswith(f".{candidate}")):
            return True
    return False


def _rule_value(verdict: str) -> str:
    name = (verdict or "").strip().lower()
    if name in {"allow", "keep", "rescue"}:
        return "allow"
    if name in {"block", "spam", "delete"}:
        return "block"
    raise ValueError(f"veredicto desconocido: {verdict}")


def _group_numbers(report, bucket: str) -> set[int]:
    if report is None:
        raise ValueError("los grupos requieren el reporte de la corrida")
    return {item.n for item in report.items if item.bucket == bucket}


def _parse_numbers(raw: str | None) -> set[int]:
    numbers: set[int] = set()
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            try:
                first, last = int(start), int(end)
            except ValueError as exc:
                raise ValueError(f"rango inválido: {chunk}") from exc
            if first > last:
                raise ValueError(f"rango inválido: {chunk}")
            numbers.update(range(first, last + 1))
        else:
            try:
                numbers.add(int(chunk))
            except ValueError as exc:
                raise ValueError(f"número inválido: {chunk}") from exc
    return numbers
