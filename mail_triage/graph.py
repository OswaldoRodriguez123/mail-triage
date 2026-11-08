import urllib.parse
from datetime import datetime, timedelta, timezone

from mail_triage.http import HttpClient

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

JUNK = "junkemail"
INBOX = "inbox"
DELETED = "deleteditems"

SELECT_FIELDS = (
    "id,internetMessageId,subject,from,sender,replyTo,receivedDateTime,"
    "bodyPreview,body,internetMessageHeaders,hasAttachments,isRead"
)
PREFER_TEXT = 'outlook.body-content-type="text"'


class GraphError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"Graph {status}: {message}")
        self.status = status


class GraphClient:
    def __init__(self, http: HttpClient, token_provider, base: str = GRAPH_BASE) -> None:
        self._http = http
        self._token_provider = token_provider
        self._base = base.rstrip("/")

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._token_provider()}"}
        if extra:
            headers.update(extra)
        return headers

    def _url(self, path: str, params: dict | None = None) -> str:
        if path.startswith("http"):
            return path
        url = f"{self._base}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        return url

    def get(self, path: str, params: dict | None = None) -> dict:
        response = self._http.request("GET", self._url(path, params), headers=self._headers())
        if not 200 <= response.status < 300:
            raise GraphError(response.status, response.text)
        return response.json

    def post(self, path: str, body: dict) -> dict:
        response = self._http.request(
            "POST", self._url(path), headers=self._headers(), body=body
        )
        if not 200 <= response.status < 300:
            raise GraphError(response.status, response.text)
        return response.json

    def _iter_pages(self, folder: str, page_size: int = 50):
        path = f"/me/mailFolders/{folder}/messages"
        params = {"$select": SELECT_FIELDS, "$top": page_size}
        url: str | None = self._url(path, params)
        while url:
            response = self._http.request(
                "GET", url, headers=self._headers({"Prefer": PREFER_TEXT})
            )
            if not 200 <= response.status < 300:
                raise GraphError(response.status, response.text)
            page = response.json
            yield page
            url = page.get("@odata.nextLink")

    def iter_messages(self, folder, *, max_items, skip_ids, page_size=50):
        yielded = 0
        for page in self._iter_pages(folder, page_size):
            for message in page.get("value", []):
                if message.get("id") in skip_ids:
                    continue
                yield message
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return

    def list_junk(self, max_items, skip_ids) -> tuple[list[dict], bool]:
        messages: list[dict] = []
        for page in self._iter_pages(JUNK):
            for message in page.get("value", []):
                if message.get("id") in skip_ids:
                    continue
                if max_items is not None and len(messages) >= max_items:
                    return messages, True
                messages.append(message)
            if page.get("@odata.nextLink"):
                if max_items is not None and len(messages) >= max_items:
                    return messages, True
                continue
            return messages, False
        return messages, False

    def list_junk_senders(self, page_size: int = 100) -> list[dict]:
        messages: list[dict] = []
        url: str | None = self._url(
            f"/me/mailFolders/{JUNK}/messages",
            {"$select": "id,from", "$top": page_size},
        )
        while url:
            response = self._http.request("GET", url, headers=self._headers())
            if not 200 <= response.status < 300:
                raise GraphError(response.status, response.text)
            page = response.json
            messages.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
        return messages

    def inbox_domains(self, lookback_days: int) -> set[str]:
        from mail_triage.evidence import registrable_domain

        since = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        path = f"/me/mailFolders/{INBOX}/messages"
        params = {
            "$select": "from",
            "$filter": f"receivedDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "$top": 250,
        }
        domains: set[str] = set()
        url: str | None = self._url(path, params)
        senders = 0
        while url and senders < 500:
            response = self._http.request("GET", url, headers=self._headers())
            if not 200 <= response.status < 300:
                raise GraphError(response.status, response.text)
            page = response.json
            for message in page.get("value", []):
                address = (
                    (message.get("from") or {})
                    .get("emailAddress", {})
                    .get("address", "")
                )
                if "@" in address:
                    domain = registrable_domain(address.rsplit("@", 1)[1])
                    if domain:
                        domains.add(domain)
                senders += 1
            url = page.get("@odata.nextLink")
        return domains

    def move(self, message_id: str, destination: str) -> None:
        self.post(f"/me/messages/{message_id}/move", {"destinationId": destination})
