import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Protocol

MAX_BODY_BYTES = 10 * 1024 * 1024


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


def _origin(url: str) -> tuple[str, str, int | None] | None:
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    return parts.scheme.lower(), host, parts.port


def _read_capped(handle) -> str:
    # Read at most MAX_BODY_BYTES + 1 so an oversized body fails closed
    # instead of draining the socket into memory.
    raw = handle.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        raise HttpError(f"respuesta excede el máximo de {MAX_BODY_BYTES} bytes")
    return raw.decode("utf-8", "replace")


def _check_content_length(headers) -> None:
    try:
        length = int(headers.get("Content-Length") or 0)
    except (TypeError, ValueError):
        return  # unknown length: the capped read() is the real boundary
    if length > MAX_BODY_BYTES:
        raise HttpError(f"respuesta excede el máximo de {MAX_BODY_BYTES} bytes")


class _StripAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Drop the Authorization header when a redirect crosses origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        if _origin(newurl) != _origin(req.full_url):
            for store in (new_req.headers, getattr(new_req, "unredirected_hdrs", {})):
                for key in list(store):
                    if key.lower() == "authorization":
                        del store[key]
        return new_req


_OPENER = urllib.request.build_opener(_StripAuthRedirectHandler())


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
            with _OPENER.open(request, timeout=timeout) as response:
                _check_content_length(response.headers)
                text = _read_capped(response)
                status = response.status
        except urllib.error.HTTPError as exc:
            _check_content_length(exc.headers)
            text = _read_capped(exc)
            status = exc.code
        except HttpError:
            raise
        except (urllib.error.URLError, OSError) as exc:
            raise HttpError(str(exc)) from exc
        return HttpResponse(status, _parse_json(text), text)
