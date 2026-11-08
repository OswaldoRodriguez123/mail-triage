import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol


class HttpError(Exception):
    pass


@dataclass(frozen=True)
class HttpResponse:
    status: int
    json: dict
    text: str


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: dict | None = None,
        form: dict | None = None,
        timeout: int = 30,
    ) -> HttpResponse: ...


def _parse_json(text: str) -> dict:
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


class UrllibHttp:
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: dict | None = None,
        form: dict | None = None,
        timeout: int = 30,
    ) -> HttpResponse:
        hdrs = dict(headers or {})
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")

        request = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                text = response.read().decode("utf-8", "replace")
                status = response.status
        except urllib.error.HTTPError as exc:
            text = exc.read().decode("utf-8", "replace")
            status = exc.code
        except (urllib.error.URLError, OSError) as exc:
            raise HttpError(str(exc)) from exc
        return HttpResponse(status, _parse_json(text), text)
