from typing import Protocol

JUNK = "junkemail"
INBOX = "inbox"
DELETED = "deleteditems"


class ProviderError(Exception):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(f"Provider {status}: {message}")
        self.status = status


class MailProvider(Protocol):
    name: str

    def list_junk(self, max_items, skip_ids) -> tuple[list[dict], bool]:
        ...

    def inbox_domains(self, lookback_days: int) -> set[str]:
        ...

    def list_junk_senders(self, page_size: int = 100) -> list[dict]:
        ...

    def move(self, message_id: str, destination: str) -> None:
        ...
