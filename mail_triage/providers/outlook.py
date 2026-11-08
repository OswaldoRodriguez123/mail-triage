from mail_triage.graph import GraphClient, GraphError
from mail_triage.providers.base import ProviderError


class OutlookProvider:
    name = "outlook"

    def __init__(self, graph: GraphClient) -> None:
        self._graph = graph

    def list_junk(self, max_items, skip_ids) -> tuple[list[dict], bool]:
        try:
            return self._graph.list_junk(max_items, skip_ids)
        except GraphError as exc:
            raise ProviderError(exc.status, str(exc)) from exc

    def inbox_domains(self, lookback_days: int) -> set[str]:
        try:
            return self._graph.inbox_domains(lookback_days)
        except GraphError as exc:
            raise ProviderError(exc.status, str(exc)) from exc

    def list_junk_senders(self, page_size: int = 100) -> list[dict]:
        try:
            return self._graph.list_junk_senders(page_size)
        except GraphError as exc:
            raise ProviderError(exc.status, str(exc)) from exc

    def move(self, message_id: str, destination: str) -> None:
        try:
            self._graph.move(message_id, destination)
        except GraphError as exc:
            raise ProviderError(exc.status, str(exc)) from exc
