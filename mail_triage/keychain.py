import subprocess
from typing import Protocol

SERVICE = "mail-triage"
LEGACY_SERVICE = "correo-limpio"

REFRESH_TOKEN = "refresh-token"
CLOUDFLARE_ACCOUNT_ID = "cloudflare-account-id"
CLOUDFLARE_TOKEN = "cloudflare-token"
PLAN_HMAC_KEY = "plan-hmac-key"


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
    def __init__(self, run=subprocess.run, services=(SERVICE, LEGACY_SERVICE)) -> None:
        self._run = run
        self._services = tuple(services) or (SERVICE,)

    def _call(self, args: list[str], input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        return self._run(
            args,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=15,
        )

    def get(self, name: str) -> str | None:
        for service in self._services:
            try:
                result = self._call(
                    ["security", "find-generic-password", "-s", service, "-a", name, "-w"]
                )
            except FileNotFoundError:
                return None
            except subprocess.TimeoutExpired:
                return None
            if result.returncode == 0:
                return result.stdout.decode("utf-8").strip()
        return None

    def set(self, name: str, value: str) -> None:
        # `-w` as the last argument makes `security` prompt for the secret on
        # stdin instead of taking it from argv, so the value never shows up in
        # `ps`/sysctl output of any co-resident process. The prompt asks for
        # the value twice (password + retype).
        try:
            result = self._call(
                ["security", "add-generic-password", "-U", "-s", self._services[0], "-a", name, "-w"],
                input_bytes=f"{value}\n{value}\n".encode("utf-8"),
            )
        except FileNotFoundError as exc:
            raise RuntimeError("security CLI no disponible") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("security add-generic-password agotó el tiempo de espera") from exc
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8").strip())

    def delete(self, name: str) -> None:
        try:
            result = self._call(
                ["security", "delete-generic-password", "-s", self._services[0], "-a", name]
            )
        except FileNotFoundError as exc:
            raise RuntimeError("security CLI no disponible") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("security delete-generic-password agotó el tiempo de espera") from exc
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode("utf-8").strip())
