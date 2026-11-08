from datetime import date, datetime, timezone

from mail_triage.http import UrllibHttp

RDAP_BASE = "https://rdap.org/domain"


def domain_age_days(domain: str, fetch=None, today=None) -> int | None:
    try:
        fetch_json = fetch or _default_fetch
        data = fetch_json(f"{RDAP_BASE}/{domain}")
        if not isinstance(data, dict):
            return None
        registered = None
        for event in data.get("events") or []:
            if (event.get("eventAction") or "").lower() == "registration":
                registered = event.get("eventDate")
                break
        if not registered:
            return None
        registered_on = _as_date(registered)
        reference = _as_date(today) if today is not None else datetime.now(timezone.utc).date()
        if registered_on is None or reference is None:
            return None
        return max((reference - registered_on).days, 0)
    except Exception:
        return None


def _default_fetch(url: str) -> dict:
    response = UrllibHttp().request("GET", url)
    if response.status != 200:
        raise OSError(f"RDAP {response.status}")
    return response.json


def _as_date(value) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None
