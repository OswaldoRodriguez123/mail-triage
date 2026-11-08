from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from correo_limpio.classifier import refine
from correo_limpio.config import Config
from correo_limpio.evidence import from_message
from correo_limpio.report import ReportItem, build_report, save

CLEF_SUMMARY = "{category} fraude={fraud:.2f} esperado={expected:.2f}"


def scan(
    cfg: Config,
    graph,
    store,
    ruleset,
    clef=None,
    rdap=None,
    *,
    include_reviewed: bool = False,
    max_items: int | None = None,
    now: datetime | None = None,
):
    now = now or datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")

    skip = set() if include_reviewed else (store.decided_ids() | store.reviewed_ids())
    messages, has_more = graph.list_junk(max_items or cfg.max_per_run, skip)

    inbox = graph.inbox_domains(cfg.inbox_lookback_days)
    store.replace_inbox_domains(inbox, now_iso)

    messages = _dedupe(messages)
    evidences = [from_message(message) for message in messages]
    ages = _domain_ages(store, rdap, evidences, now)

    rules = store.rules()
    allow_rules = {domain for domain, verdict in rules.items() if verdict == "allow"}
    block_rules = {domain for domain, verdict in rules.items() if verdict == "block"}

    items: list[ReportItem] = []
    clef_used = False
    for ev in evidences:
        verdict = ruleset.evaluate(
            ev,
            allow_domains=inbox | allow_rules,
            block_domains=block_rules,
            domain_age_days=ages.get(ev.from_domain),
        )
        clef_label = None
        protected = _is_protected(verdict)
        if verdict.bucket == "review" and clef is not None and not protected:
            decision = clef.evaluate(ev)
            if decision is not None:
                clef_used = True
                clef_label = CLEF_SUMMARY.format(
                    category=decision.category,
                    fraud=decision.fraud_prob,
                    expected=decision.expected_prob,
                )
                verdict = refine(verdict, decision)
        items.append(
            ReportItem(
                n=len(items) + 1,
                message_id=ev.message_id,
                subject=ev.subject,
                sender=_sender(ev),
                domain=ev.from_domain,
                bucket=verdict.bucket,
                score=verdict.score,
                reasons=verdict.reasons,
                clef=clef_label,
            )
        )

    report, code = build_report(items, has_more, "clef" if clef_used else "rules", now=now)
    save(report, Path(cfg.state_dir) / "runs")
    for item in report.items:
        store.record_seen(item.message_id, report.run_id, item.bucket, now_iso)
    return report, code


def _dedupe(messages) -> list[dict]:
    seen: set[str] = set()
    unique: list[dict] = []
    for message in messages:
        message_id = message.get("id")
        if not message_id or message_id in seen:
            continue
        seen.add(message_id)
        unique.append(message)
    return unique


def _domain_ages(store, rdap, evidences, now: datetime) -> dict[str, int | None]:
    today = now.date()
    ages: dict[str, int | None] = {}
    for ev in evidences:
        domain = ev.from_domain
        if not domain or domain in ages:
            continue
        created, checked = store.get_domain_age(domain)
        if created or checked:
            ages[domain] = _days_since(created, today)
            continue
        if rdap is None:
            ages[domain] = None
            continue
        age = rdap.domain_age_days(domain)
        ages[domain] = age
        created_date = (today - timedelta(days=age)).isoformat() if age is not None else None
        store.cache_domain_age(domain, created_date, now.isoformat(timespec="seconds"))
    return ages


def _days_since(created: str | None, today: date) -> int | None:
    if not created:
        return None
    try:
        return max((today - date.fromisoformat(created[:10])).days, 0)
    except ValueError:
        return None


def _is_protected(verdict) -> bool:
    text = " ".join(getattr(verdict, "reasons", ()) or ()).lower()
    return any(marker in text for marker in ("permitido", "promoci", "veto"))


def _sender(ev) -> str:
    if ev.from_name:
        return f"{ev.from_name} <{ev.from_address}>"
    return ev.from_address
