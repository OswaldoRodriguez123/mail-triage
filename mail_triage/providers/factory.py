from mail_triage.graph import GraphClient
from mail_triage.providers.base import MailProvider
from mail_triage.providers.outlook import OutlookProvider

PROVIDERS = {"outlook": OutlookProvider}


def get_provider(name: str, graph: GraphClient) -> MailProvider:
    cls = PROVIDERS.get((name or "outlook").lower())
    if cls is None:
        raise ValueError(f"proveedor no soportado: {name}")
    return cls(graph)


def list_providers() -> tuple[str, ...]:
    return tuple(PROVIDERS)
