import subprocess
from typing import Protocol

SERVICE = "correo-limpio"

REFRESH_TOKEN = "refresh-token"
CLOUDFLARE_ACCOUNT_ID = "cloudflare-account-id"
CLOUDFLARE_TOKEN = "cloudflare-token"


class SecretStore(Protocol):
    def get(self, name: str) -> str | None: ...

    def set(self, name: str, value: str) -> None: ...

    def delete(self, name: str) -> None: ...


class MemoryStore:
    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._values = dict(initial or {})

    def get(self, name: str) -> str | None:
        return self._values.get(name)

    def set(self, name: str, value: str) -> None:
        self._values[name] = value

    def delete(self, name: str) -> None:
        self._values.pop(name, None)


class MacKeychain:
    def __init__(self, run=subprocess.run) -> None:
        self._run = run

    def _call(self, args: list[str]) -> subprocess.CompletedProcess:
        return self._run(args, capture_output=True, check=False)

    def get(self, name: str) -> str | None:
        try:
            result = self._call(
                ["security", "find-generic-password", "-s", SERVICE, "-a", name, "-w"]
            )
        except FileNotFoundError:
            return None
        if result.returncode != 0:
            return None
        return result.stdout.decode("utf-8").strip()

    def set(self, name: str, value: str) -> None:
        try:
            result = self._call(
                ["security", "add-generic-password", "-U", "-s", SERVICE, "-a", name, "-w", value]
            )
        except FileNotFoundError as exc:
            raise RuntimeError("security CLI no disponible") from exc
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8").strip())

    def delete(self, name: str) -> None:
        try:
            result = self._call(
                ["security", "delete-generic-password", "-s", SERVICE, "-a", name]
            )
        except FileNotFoundError as exc:
            raise RuntimeError("security CLI no disponible") from exc
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8").strip())
