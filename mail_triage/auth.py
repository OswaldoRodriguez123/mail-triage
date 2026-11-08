import time
from dataclasses import dataclass

from mail_triage.keychain import REFRESH_TOKEN, SecretStore

BASE_URL = "https://login.microsoftonline.com"
MAIL_READWRITE = "https://graph.microsoft.com/Mail.ReadWrite"
OFFLINE_ACCESS = "offline_access"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class DeviceCode:
    user_code: str
    verification_uri: str
    device_code: str
    interval: int
    expires_in: int


class Auth:
    def __init__(
        self,
        http,
        secrets: SecretStore,
        client_id: str,
        tenant: str = "consumers",
        scopes: tuple[str, ...] = (MAIL_READWRITE, OFFLINE_ACCESS),
        sleep=time.sleep,
    ) -> None:
        self._http = http
        self._secrets = secrets
        self._client_id = client_id
        self._tenant = tenant
        self._scopes = scopes
        self._sleep = sleep
        self._token: str | None = None

    def _url(self, endpoint: str) -> str:
        return f"{BASE_URL}/{self._tenant}/oauth2/v2.0/{endpoint}"

    def start_login(self) -> DeviceCode:
        response = self._http.request(
            "POST",
            self._url("devicecode"),
            form={"client_id": self._client_id, "scope": " ".join(self._scopes)},
        )
        if response.status != 200:
            raise AuthError(response.json.get("error_description") or response.text)
        data = response.json
        try:
            return DeviceCode(
                user_code=data["user_code"],
                verification_uri=data["verification_uri"],
                device_code=data["device_code"],
                interval=int(data.get("interval", 5)),
                expires_in=int(data.get("expires_in", 900)),
            )
        except KeyError as exc:
            raise AuthError(f"respuesta de devicecode incompleta: {exc}") from exc

    def wait_for_login(self, code: DeviceCode) -> None:
        interval = max(1, code.interval)
        while True:
            response = self._http.request(
                "POST",
                self._url("token"),
                form={
                    "grant_type": DEVICE_CODE_GRANT,
                    "client_id": self._client_id,
                    "device_code": code.device_code,
                },
            )
            if response.status == 200:
                self._store_session(response.json)
                return
            error = response.json.get("error")
            if error == "authorization_pending":
                self._sleep(interval)
                continue
            if error == "slow_down":
                interval += 5
                self._sleep(interval)
                continue
            if error in {"expired_token", "authorization_declined"}:
                raise AuthError(error)
            raise AuthError(response.json.get("error_description") or response.text or error)

    def access_token(self) -> str:
        if self._token is not None:
            return self._token
        refresh = self._secrets.get(REFRESH_TOKEN)
        if not refresh:
            raise AuthError("no hay sesión; ejecuta `mail-triage login`")
        response = self._http.request(
            "POST",
            self._url("token"),
            form={
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "refresh_token": refresh,
            },
        )
        if response.status != 200:
            raise AuthError(response.json.get("error_description") or response.json.get("error") or response.text)
        self._store_session(response.json)
        if self._token is None:
            raise AuthError("respuesta de token sin access_token")
        return self._token

    def _store_session(self, data: dict) -> None:
        token = data.get("access_token")
        if token:
            self._token = token
        rotated = data.get("refresh_token")
        if rotated:
            self._secrets.set(REFRESH_TOKEN, rotated)
