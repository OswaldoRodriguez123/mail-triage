# Correo Limpio Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Un CLI local y una skill de OpenCode que revisan la carpeta No deseados de Hotmail, borran solo fraude/engaño (a la Papelera), rescatan correo legítimo a la Bandeja y aprenden de las correcciones del usuario.

**Architecture:** CLI en Python puro (solo stdlib) sobre Microsoft Graph con OAuth device-code. El motor de reglas deterministas decide la mayoría; Clef-flash de Cloudflare (opcional, tier gratis) opina solo sobre la banda dudosa. Estado y aprendizaje en SQLite; cada corrida produce un reporte con `run_id` y código de confirmación. La skill solo ejecuta cambios después de que el usuario apruebe un subconjunto.

**Tech Stack:** Python 3.14 (stdlib: `urllib`, `sqlite3`, `email`, `tomllib`, `unittest`), Microsoft Graph v1.0, Cloudflare Workers AI (`@cf/cloudflare/clef-flash`), Keychain de macOS, OpenCode skill.

**Spec:** `docs/superpowers/specs/2026-11-07-correo-limpio-design.md`

## Global Constraints

- Solo biblioteca estándar de Python. Ninguna dependencia de `pip`, ni `requests`, ni SDKs.
- Todo el código y los identificadores en inglés; los textos de cara al usuario y la documentación en español.
- Nunca `permanentDelete`. Los únicos destinos de escritura son `deleteditems` y `inbox`; nunca se toca otra carpeta.
- `scan` no modifica el buzón. El único que mueve correos es `purge`/`undo`/`feedback --rescue`, y solo con `--code` válido y selección explícita.
- Tope por defecto: 200 mensajes por corrida. `--all` lo levanta solo si el usuario lo pide.
- Solo fraude/engaño puede ir a `borrar`. Promos y boletines legítimos van como máximo a `revisar`, nunca a `borrar` ni a `rescatar`.
- Un veto (dominio permitido o visto en la Bandeja) impide borrar y no rescata por sí solo.
- Una regla de bloqueo confirmada (usuario o promovida) fuerza `borrar` salvo veto.
- Las reglas `auto` nacen solo de 3 `feedback` explícitos coincidentes en mensajes y corridas distintas. Aprobar un lote no las crea.
- Sin credenciales de Cloudflare, todo funciona en modo reglas; Clef-flash nunca es requisito.
- Secretos únicamente en el Keychain (`refresh-token`, `cloudflare-account-id`, `cloudflare-token`). Nada de secretos en el repo.
- El correo real no se versiona. Los fixtures son sintéticos, construidos con los patrones de la captura.

## Review Focus

Estos son los casos que el spec implica pero ninguna tarea cubre por sí sola; cada uno tiene su test en la tarea que lo posee.

1. **Cabeceras ausentes o malformadas** (`internetMessageHeaders` no viene, `Authentication-Results` roto): el pipeline debe seguir y tratar la autenticación como `unknown`, no reventar. Test en Task 5.
2. **Mensaje movido o borrado entre `scan` y `purge`** (404 de Graph): se reporta como omitido y la corrida continúa. Test en Task 11.
3. **Remitente vacío o `From` malformado** (`<>`, sin `@`): dominio vacío, bucket `revisar`, sin excepción. Test en Task 5.
4. **Asuntos/textos no ASCII, emojis y cadenas largas**: el reporte y el JSON conservan el contenido y no rompen la tabla. Test en Task 9.
5. **Límite de Cloudflare agotado o error transitorio de Graph** (429/503): se cae a modo reglas o se aborta limpiamente con mensaje, sin perder el reporte. Tests en Task 8 y Task 11.

---

### Task 1: Scaffold, configuración y comando `status`

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `correo_limpio/__init__.py`
- Create: `correo_limpio/__main__.py`
- Create: `correo_limpio/config.py`
- Create: `correo_limpio/cli.py`
- Create: `tests/__init__.py`
- Test: `tests/test_config.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `correo_limpio.config.Config` (frozen dataclass): `config_dir: Path`, `state_dir: Path`, `client_id: str | None`, `max_per_run: int`, `inbox_lookback_days: int`, `user_languages: tuple[str, ...]`.
  - `correo_limpio.config.load_config() -> Config`.
  - `correo_limpio.cli.main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing tests**

`tests/test_config.py`:
```python
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from correo_limpio.config import load_config


class ConfigTest(unittest.TestCase):
    def test_defaults_use_xdg_paths(self):
        with TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"HOME": tmp}, clear=False):
            cfg = load_config()
            self.assertEqual(cfg.config_dir, Path(tmp) / ".config" / "correo-limpio")
            self.assertEqual(cfg.state_dir, Path(tmp) / ".local" / "state" / "correo-limpio")
            self.assertEqual(cfg.max_per_run, 200)
            self.assertEqual(cfg.inbox_lookback_days, 90)
            self.assertIsNone(cfg.client_id)


if __name__ == "__main__":
    unittest.main()
```

`tests/test_cli.py`:
```python
import io
import json
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from unittest import mock

from correo_limpio.cli import main


class StatusTest(unittest.TestCase):
    def test_status_prints_json(self):
        with TemporaryDirectory() as tmp, mock.patch.dict("os.environ", {"HOME": tmp}, clear=False):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["status"]), 0)
            data = json.loads(out.getvalue())
            self.assertEqual(data["max_per_run"], 200)
            self.assertIn("config_dir", data)
            self.assertIn("state_dir", data)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_config tests.test_cli -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio'`.

- [ ] **Step 3: Implement**

`pyproject.toml`:
```toml
[project]
name = "correo-limpio"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = []

[project.scripts]
correo-limpio = "correo_limpio.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["correo_limpio*"]

[tool.setuptools.package-data]
correo_limpio = ["rules/data/*.txt"]
```

`.gitignore`:
```
__pycache__/
*.pyc
.venv/
*.db
*.sqlite3
config.toml
runs/
```

`correo_limpio/__init__.py`:
```python
__version__ = "0.1.0"
```

`correo_limpio/__main__.py`:
```python
from correo_limpio.cli import main

raise SystemExit(main())
```

`correo_limpio/config.py`:
```python
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

CONFIG_FILENAME = "config.toml"
DEFAULT_MAX_PER_RUN = 200
DEFAULT_INBOX_LOOKBACK_DAYS = 90


@dataclass(frozen=True)
class Config:
    config_dir: Path
    state_dir: Path
    client_id: str | None
    max_per_run: int = DEFAULT_MAX_PER_RUN
    inbox_lookback_days: int = DEFAULT_INBOX_LOOKBACK_DAYS
    user_languages: tuple[str, ...] = ("es", "en")


def load_config() -> Config:
    home = Path(os.environ.get("HOME", str(Path.home())))
    config_dir = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "correo-limpio"
    state_dir = Path(os.environ.get("XDG_STATE_HOME", home / ".local" / "state")) / "correo-limpio"
    raw = {}
    path = config_dir / CONFIG_FILENAME
    if path.exists():
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return Config(
        config_dir=config_dir,
        state_dir=state_dir,
        client_id=raw.get("client_id") or None,
        max_per_run=int(raw.get("max_per_run", DEFAULT_MAX_PER_RUN)),
        inbox_lookback_days=int(raw.get("inbox_lookback_days", DEFAULT_INBOX_LOOKBACK_DAYS)),
        user_languages=tuple(raw.get("user_languages", ["es", "en"])),
    )
```

`correo_limpio/cli.py`:
```python
import argparse
import json
import sys

from correo_limpio.config import load_config


def _status() -> int:
    cfg = load_config()
    print(json.dumps({
        "config_dir": str(cfg.config_dir),
        "state_dir": str(cfg.state_dir),
        "client_id_present": cfg.client_id is not None,
        "max_per_run": cfg.max_per_run,
        "inbox_lookback_days": cfg.inbox_lookback_days,
    }, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="correo-limpio")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="muestra la configuración y el estado")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "status":
        return _status()
    return 2


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_config tests.test_cli -v`
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml .gitignore correo_limpio tests
git commit -m "feat: scaffold correo-limpio cli and config"
```

---

### Task 2: Keychain de macOS con backend en memoria para tests

**Files:**
- Create: `correo_limpio/keychain.py`
- Modify: `correo_limpio/cli.py` (status muestra credenciales)
- Test: `tests/test_keychain.py`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `SecretStore` (Protocol): `get(name) -> str | None`, `set(name, value) -> None`, `delete(name) -> None`.
  - `MacKeychain(run=subprocess.run)`, servicio `"correo-limpio"`.
  - `MemoryStore(initial: dict[str, str] | None = None)`.
  - Constantes `REFRESH_TOKEN = "refresh-token"`, `CLOUDFLARE_ACCOUNT_ID = "cloudflare-account-id"`, `CLOUDFLARE_TOKEN = "cloudflare-token"`.

- [ ] **Step 1: Write the failing test**

`tests/test_keychain.py`:
```python
import unittest
from unittest import mock

from correo_limpio.keychain import MacKeychain, MemoryStore


class KeychainTest(unittest.TestCase):
    def test_memory_roundtrip(self):
        store = MemoryStore()
        self.assertIsNone(store.get("refresh-token"))
        store.set("refresh-token", "abc")
        self.assertEqual(store.get("refresh-token"), "abc")
        store.delete("refresh-token")
        self.assertIsNone(store.get("refresh-token"))

    def test_mac_keychain_uses_security_cli(self):
        run = mock.Mock(return_value=mock.Mock(stdout=b"secret\n", returncode=0))
        store = MacKeychain(run=run)
        self.assertEqual(store.get("refresh-token"), "secret")
        args = run.call_args.args[0]
        self.assertEqual(args[:3], ["security", "find-generic-password", "-s"])
        self.assertIn("correo-limpio", args)

    def test_mac_keychain_missing_returns_none(self):
        run = mock.Mock(return_value=mock.Mock(stdout=b"", returncode=44))
        self.assertIsNone(MacKeychain(run=run).get("refresh-token"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_keychain -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.keychain'`.

- [ ] **Step 3: Implement**

`correo_limpio/keychain.py` — protocolo, `MemoryStore` y `MacKeychain` usando `security find-generic-password -s correo-limpio -a <name> -w`, `security add-generic-password -U -s ... -a ... -w ...` y `security delete-generic-password`. Si `returncode != 0` en `get`, o si `security` no existe (`FileNotFoundError`), devolver `None`. `set` y `delete` lanzan `RuntimeError` con el stderr si fallan.

En `cli.py`, `_status()` agrega:
```python
"credentials": {
    "graph": MacKeychain().get(REFRESH_TOKEN) is not None,
    "cloudflare": MacKeychain().get(CLOUDFLARE_TOKEN) is not None,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_keychain tests.test_cli -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/keychain.py correo_limpio/cli.py tests/test_keychain.py
git commit -m "feat: store secrets in macos keychain"
```

---

### Task 3: Capa HTTP y OAuth device-code de Microsoft

**Files:**
- Create: `correo_limpio/http.py`
- Create: `correo_limpio/auth.py`
- Test: `tests/test_http.py`
- Test: `tests/test_auth.py`

**Interfaces:**
- Consumes: `SecretStore`, `REFRESH_TOKEN`.
- Produces:
  - `HttpResponse(status: int, json: dict, text: str)`.
  - `HttpClient` Protocol: `request(method, url, headers=None, body=None, form=None, timeout=30) -> HttpResponse`.
  - `UrllibHttp` implementación real.
  - `DeviceCode(user_code, verification_uri, device_code, interval, expires_in)`.
  - `AuthError(Exception)`.
  - `Auth(http, secrets, client_id, tenant="consumers", scopes=(MAIL_READWRITE, OFFLINE_ACCESS), sleep=time.sleep)` con `start_login() -> DeviceCode`, `wait_for_login(code) -> None`, `access_token() -> str`.

- [ ] **Step 1: Write the failing tests**

`tests/test_auth.py`:
```python
import unittest

from correo_limpio.auth import Auth, AuthError, DeviceCode
from correo_limpio.http import HttpResponse
from correo_limpio.keychain import MemoryStore


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, body, form))
        return self.responses.pop(0)


class AuthTest(unittest.TestCase):
    def test_login_stores_refresh_token(self):
        http = FakeHttp([
            HttpResponse(200, {"device_code": "dc", "user_code": "ABCD",
                               "verification_uri": "https://microsoft.com/devicelogin",
                               "interval": 5, "expires_in": 900}, ""),
            HttpResponse(400, {"error": "authorization_pending"}, ""),
            HttpResponse(200, {"access_token": "at", "refresh_token": "rt"}, ""),
        ])
        secrets = MemoryStore()
        auth = Auth(http, secrets, client_id="cid", sleep=lambda _: None)
        code = auth.start_login()
        self.assertEqual(code.user_code, "ABCD")
        auth.wait_for_login(code)
        self.assertEqual(secrets.get("refresh-token"), "rt")

    def test_access_token_refreshes_and_caches(self):
        http = FakeHttp([
            HttpResponse(200, {"access_token": "at", "refresh_token": "rt2"}, ""),
        ])
        secrets = MemoryStore({"refresh-token": "rt1"})
        auth = Auth(http, secrets, client_id="cid", sleep=lambda _: None)
        self.assertEqual(auth.access_token(), "at")
        self.assertEqual(auth.access_token(), "at")
        self.assertEqual(len(http.calls), 1)
        self.assertEqual(secrets.get("refresh-token"), "rt2")

    def test_invalid_grant_raises(self):
        http = FakeHttp([HttpResponse(400, {"error": "invalid_grant"}, "")])
        auth = Auth(http, MemoryStore({"refresh-token": "rt1"}), client_id="cid", sleep=lambda _: None)
        with self.assertRaises(AuthError):
            auth.access_token()


if __name__ == "__main__":
    unittest.main()
```

`tests/test_http.py`:
```python
import unittest

from correo_limpio.http import HttpResponse, UrllibHttp


class HttpTest(unittest.TestCase):
    def test_response_parses_json(self):
        r = HttpResponse(200, {"ok": True}, '{"ok": true}')
        self.assertTrue(r.json["ok"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_auth tests.test_http -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.http'`.

- [ ] **Step 3: Implement**

`http.py`: `UrllibHttp.request` arma `urllib.request.Request`; si `form`, codifica con `urllib.parse.urlencode` y `Content-Type: application/x-www-form-urlencoded`; si `body`, usa JSON. Captura `HTTPError` y devuelve `HttpResponse(status=e.code, json=parsed_or_empty, text=...)`. Errores de red se envuelven en `HttpError`.

`auth.py`: endpoints en `https://login.microsoftonline.com/consumers/oauth2/v2.0/{devicecode,token}`. `start_login` hace `POST devicecode` con `{"client_id", "scope": " ".join(scopes)}`. `wait_for_login` itera: `POST token` con `grant_type=urn:ietf:params:oauth:grant-type:device_code`, `client_id`, `device_code`; en `authorization_pending` duerme `interval`; en `slow_down` suma 5; en éxito guarda `refresh_token` en `secrets.set(REFRESH_TOKEN, ...)`; en `expired_token`/`authorization_declined` lanza `AuthError`. `access_token` devuelve el token en memoria si existe; si no, refresca con `grant_type=refresh_token` y guarda el refresh rotado.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_auth tests.test_http -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/http.py correo_limpio/auth.py tests/test_http.py tests/test_auth.py
git commit -m "feat: add http layer and microsoft device-code auth"
```

---

### Task 4: Cliente de Microsoft Graph

**Files:**
- Create: `correo_limpio/graph.py`
- Test: `tests/test_graph.py`

**Interfaces:**
- Consumes: `HttpClient`, `HttpResponse`.
- Produces:
  - `GraphError(Exception)` con `.status`.
  - `GraphClient(http, token_provider, base="https://graph.microsoft.com/v1.0")`.
  - `get(path, params=None) -> dict`, `post(path, body) -> dict`.
  - `iter_messages(folder, *, max_items, skip_ids, page_size=50) -> Iterator[dict]`.
  - `list_junk(max_items, skip_ids) -> tuple[list[dict], bool]` (mensajes, `has_more`).
  - `inbox_domains(lookback_days) -> set[str]`.
  - `move(message_id, destination) -> None`.
  - Constantes `JUNK = "junkemail"`, `INBOX = "inbox"`, `DELETED = "deleteditems"`.

- [ ] **Step 1: Write the failing test**

`tests/test_graph.py`:
```python
import unittest

from correo_limpio.graph import GraphClient, GraphError, DELETED
from correo_limpio.http import HttpResponse


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, body))
        return self.responses.pop(0)


class GraphTest(unittest.TestCase):
    def client(self, responses):
        self.http = FakeHttp(responses)
        return GraphClient(self.http, token_provider=lambda: "token")

    def test_list_junk_follows_pagination_and_skips_seen(self):
        g = self.client([
            HttpResponse(200, {"value": [{"id": "1"}, {"id": "2"}],
                               "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}, ""),
            HttpResponse(200, {"value": [{"id": "3"}]}, ""),
        ])
        messages, has_more = g.list_junk(max_items=10, skip_ids={"2"})
        self.assertEqual([m["id"] for m in messages], ["1", "3"])
        self.assertFalse(has_more)
        self.assertIn("junkemail", self.http.calls[0][1])

    def test_list_junk_reports_more_at_cap(self):
        g = self.client([HttpResponse(200, {"value": [{"id": "1"}],
                                           "@odata.nextLink": "next"}, "")])
        messages, has_more = g.list_junk(max_items=1, skip_ids=set())
        self.assertEqual(len(messages), 1)
        self.assertTrue(has_more)

    def test_move_posts_destination(self):
        g = self.client([HttpResponse(200, {}, "")])
        g.move("m1", DELETED)
        method, url, body = self.http.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/me/messages/m1/move"))
        self.assertEqual(body, {"destinationId": "deleteditems"})

    def test_http_error_raises_graph_error(self):
        g = self.client([HttpResponse(404, {"error": {"code": "ErrorItemNotFound"}}, "")])
        with self.assertRaises(GraphError) as ctx:
            g.move("gone", DELETED)
        self.assertEqual(ctx.exception.status, 404)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_graph -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.graph'`.

- [ ] **Step 3: Implement**

`GraphClient` usa `Authorization: Bearer` y `prefer: outlook.body-content-type="text"` en listados. `SELECT` incluye `id,internetMessageId,subject,from,sender,replyTo,receivedDateTime,bodyPreview,body,internetMessageHeaders,hasAttachments,isRead`. `inbox_domains` pagina mensajes de la Bandeja con `$select=from` y `$filter=receivedDateTime ge <iso>` (lookback), se detiene a los 500 remitentes, extrae el dominio con `registrable_domain` de `evidence.py` (import local dentro del método para evitar el ciclo) y devuelve el set. `move` hace `POST /me/messages/{id}/move`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_graph -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/graph.py tests/test_graph.py
git commit -m "feat: add microsoft graph client"
```

---

### Task 5: Evidencia por mensaje (cabeceras, enlaces, idioma, remitente)

**Files:**
- Create: `correo_limpio/evidence.py`
- Create: `tests/fixtures.py`
- Test: `tests/test_evidence.py`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `AuthResult(spf="unknown", dkim="unknown", dmarc="unknown")` con `.failed: bool`.
  - `Evidence` (frozen dataclass) con: `message_id`, `internet_message_id`, `subject`, `from_name`, `from_address`, `from_domain`, `reply_to_domain`, `auth`, `text`, `link_domains`, `language`, `has_attachments`, `random_sender`, `brand`, `received`.
  - `from_message(msg: dict) -> Evidence`.
  - `parse_auth_results(headers: list[dict]) -> AuthResult`.
  - `registrable_domain(host: str) -> str`.
  - `is_random_sender(local: str, domain: str) -> bool`.
  - `detect_language(text: str) -> str`.
  - `find_brand(text: str, brands: set[str]) -> str | None`.

- [ ] **Step 1: Write the failing test**

`tests/fixtures.py` con seis mensajes sintéticos: `netflix_phish()`, `soda_random()`, `cloud_billing()`, `vivo_pt()`, `medicare()`, `travel_empty()`, más `promo_newsletter()` y `sanitized_receipt()`. Cada uno es un dict con `id`, `subject`, `from: {emailAddress: {name, address}}`, `body: {content: "..."}`, `internetMessageHeaders: [{name, value}]`.

`tests/test_evidence.py`:
```python
import unittest

from correo_limpio.evidence import from_message, parse_auth_results, registrable_domain
from tests import fixtures


class EvidenceTest(unittest.TestCase):
    def test_netflix_impersonation_fields(self):
        ev = from_message(fixtures.netflix_phish())
        self.assertEqual(ev.from_domain, "brainstormingyourliiife.net")
        self.assertEqual(ev.brand, "netflix")
        self.assertTrue(ev.auth.failed)
        self.assertIn("netflix-verify.test", ev.link_domains)

    def test_random_sender_detected(self):
        ev = from_message(fixtures.soda_random())
        self.assertTrue(ev.random_sender)
        self.assertIsNone(ev.brand)

    def test_portuguese_detected(self):
        ev = from_message(fixtures.vivo_pt())
        self.assertEqual(ev.language, "pt")

    def test_missing_headers_are_unknown(self):
        msg = fixtures.cloud_billing()
        msg.pop("internetMessageHeaders")
        ev = from_message(msg)
        self.assertEqual(ev.auth.dmarc, "unknown")
        self.assertEqual(ev.reply_to_domain, None)

    def test_malformed_sender_does_not_crash(self):
        msg = fixtures.travel_empty()
        msg["from"]["emailAddress"]["address"] = "<>"
        ev = from_message(msg)
        self.assertEqual(ev.from_domain, "")
        self.assertEqual(ev.subject[:4], "Take")

    def test_parse_auth_results(self):
        result = parse_auth_results([
            {"name": "Authentication-Results",
             "value": "spf=fail smtp.mailfrom=x.test; dkim=none; dmarc=fail header.from=x.test"}
        ])
        self.assertEqual((result.spf, result.dkim, result.dmarc), ("fail", "none", "fail"))
        self.assertTrue(result.failed)

    def test_registrable_domain_handles_compound_suffix(self):
        self.assertEqual(registrable_domain("mail.banco.com.mx"), "banco.com.mx")
        self.assertEqual(registrable_domain("a.b.example.test"), "example.test")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_evidence -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.evidence'`.

- [ ] **Step 3: Implement**

`evidence.py`: lee `body.content` (texto plano por el `Prefer`), recorta a 400 caracteres para `text`, extrae URLs con regex y se queda con dominios registrables únicos (máx. 10). `parse_auth_results` busca `spf=`, `dkim=`, `dmarc=` con regex y devuelve `unknown` si no hay cabecera. `is_random_sender` marca verdadero si el localpart tiene ≥ 12 caracteres y (≥ 4 dígitos o relación consonante/vocal > 3) o si el dominio tiene ≥ 20 caracteres sin vocales suficientes. `detect_language` cuenta stopwords de `es`, `en`, `pt`, `it`, `fr`; devuelve la mayor o `"unknown"`. `find_brand` busca marcas como palabra completa en nombre visible + asunto, en minúsculas.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_evidence -v`
Expected: PASS, 7 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/evidence.py tests/fixtures.py tests/test_evidence.py
git commit -m "feat: extract evidence from graph messages"
```

---

### Task 6: Motor de reglas, guardia de fraude y vetos

**Files:**
- Create: `correo_limpio/rules.py`
- Create: `correo_limpio/rdap.py`
- Create: `correo_limpio/rules/data/brands.txt`
- Create: `correo_limpio/rules/data/urgency.txt`
- Create: `correo_limpio/rules/data/tlds.txt`
- Create: `correo_limpio/rules/data/suffixes.txt`
- Test: `tests/test_rules.py`
- Test: `tests/test_rdap.py`

**Interfaces:**
- Consumes: `Evidence`, `AuthResult`, `find_brand`, `registrable_domain`.
- Produces:
  - `Verdict(score: float, bucket: str, reasons: tuple[str, ...], fraud_signal: bool)` con buckets `"delete"`, `"rescue"`, `"review"`.
  - `RuleSet.load(data_dir: Path) -> RuleSet`.
  - `RuleSet.evaluate(ev, *, allow_domains=frozenset(), block_domains=frozenset(), domain_age_days: int | None = None) -> Verdict`.
  - `correo_limpio.rdap.domain_age_days(domain: str, fetch=None) -> int | None`.

- [ ] **Step 1: Write the failing test**

`tests/test_rules.py`:
```python
import unittest
from pathlib import Path

from correo_limpio.evidence import from_message
from correo_limpio.rules import RuleSet
from tests import fixtures

DATA = Path(__file__).resolve().parents[1] / "correo_limpio" / "rules" / "data"


class RulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = RuleSet.load(DATA)

    def verdict(self, fixture, **kwargs):
        return self.rules.evaluate(from_message(fixture), **kwargs)

    def test_netflix_is_deleted(self):
        v = self.verdict(fixtures.netflix_phish())
        self.assertEqual(v.bucket, "delete")
        self.assertGreaterEqual(v.score, 0.85)
        self.assertTrue(v.fraud_signal)

    def test_random_sender_is_review_not_delete(self):
        v = self.verdict(fixtures.soda_random())
        self.assertEqual(v.bucket, "review")
        self.assertFalse(v.fraud_signal)

    def test_promo_is_never_deleted_even_from_new_domain(self):
        v = self.verdict(fixtures.promo_newsletter())
        self.assertEqual(v.bucket, "review")

    def test_allowlisted_domain_never_deletes(self):
        v = self.verdict(fixtures.netflix_phish(), allow_domains={"brainstormingyourliiife.net"})
        self.assertEqual(v.bucket, "review")

    def test_veto_does_not_rescue_auth_failure(self):
        v = self.verdict(fixtures.netflix_phish(), allow_domains={"brainstormingyourliiife.net"})
        self.assertNotEqual(v.bucket, "rescue")

    def test_blocked_domain_forces_delete(self):
        v = self.verdict(fixtures.promo_newsletter(), block_domains={"shop.test"})
        self.assertEqual(v.bucket, "delete")

    def test_transactional_mail_is_rescued(self):
        v = self.verdict(fixtures.sanitized_receipt())
        self.assertEqual(v.bucket, "rescue")

    def test_vivo_phishing_has_fraud_signal(self):
        v = self.verdict(fixtures.vivo_pt())
        self.assertTrue(v.fraud_signal)
        self.assertIn(v.bucket, {"delete", "review"})

    def test_new_domain_adds_reason(self):
        v = self.rules.evaluate(from_message(fixtures.soda_random()), domain_age_days=5)
        self.assertIn("dominio nuevo", v.reasons)
        self.assertEqual(v.bucket, "review")


if __name__ == "__main__":
    unittest.main()
```

`tests/test_rdap.py`:
```python
import unittest

from correo_limpio.rdap import domain_age_days


class RdapTest(unittest.TestCase):
    def test_parses_registration_date(self):
        def fetch(url):
            return {"events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}]}
        age = domain_age_days("new.test", fetch=fetch, today="2026-11-07")
        self.assertEqual(age, 6)

    def test_failure_returns_none(self):
        def fetch(url):
            raise OSError("offline")
        self.assertIsNone(domain_age_days("new.test", fetch=fetch, today="2026-11-07"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_rules -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.rules'`.

- [ ] **Step 3: Implement**

Pesos exactos del spec: marca `+0.35`, auth fail `+0.30`, remitente aleatorio `+0.25`, reply-to distinto `+0.20`, enlace a dominio ajeno `+0.15`, urgencia `+0.10`, idioma fuera de `("es","en")` `+0.10`, TLD sospechoso `+0.10`, dominio con menos de 30 días `+0.10` (solo si `domain_age_days` no es `None`), bloqueo `+0.25`. Señal de fraude si hay cualquiera de: marca suplantada, auth fail, reply-to distinto, enlace ajeno, TLD sospechoso o bloqueo.

Reglas de decisión, en orden:
1. Veto = dominio en `allow_domains`. Nunca `delete`.
2. `block_domains` y sin veto → `delete`, `score=1.0`, razón `"dominio bloqueado"`.
3. `promo_hint` (palabras `off`, `sale`, `discount`, `newsletter`, `unsubscribe`, `promo`, `%`, `boletín`, `oferta`) → máximo `review`, nunca `delete` ni `rescue`.
4. `score >= 0.85` y `fraud_signal` y sin veto → `delete`.
5. `score <= 0.30` y auth no falló y no `promo_hint` y (`allow_domains` o `looks_transactional`) → `rescue`. `looks_transactional` = subject/text con `receipt`, `invoice`, `order`, `pedido`, `factura`, `recibo`, `verification`, `código`, `code`, `reservation`, `booking`.
6. Resto → `review`.

`RuleSet.load` lee los cuatro archivos (una entrada por línea, `#` comentarios, minúsculas). `brands.txt` arranca con al menos: netflix, amazon, paypal, microsoft, apple, google, facebook, instagram, whatsapp, banco, bbva, santander, hsbc, citibanamex, oxxo, mercadolibre, dhl, fedex, ups, vivo, claro, telcel, medicare, coinbase, binance, steam, spotify, disney, uber, rappi, stripe. `urgency.txt`: last chance, expired, confirm your, verify your, parcel, renewal, prize, winner, account suspended, débito, fatura, envío, paquete. `tlds.txt`: zip, mov, top, xyz, click, link, live, shop, work, support, fit, rest. `suffixes.txt`: com.mx, com.br, com.ar, com.co, com.pe, com.es, co.uk, org.mx, gob.mx, com.au.

`rdap.py`: `domain_age_days(domain, fetch=None, today=None) -> int | None`. `fetch` recibe la URL `https://rdap.org/domain/<domain>` y devuelve el JSON; por defecto usa `UrllibHttp`. Busca el evento `registration` en `events`, calcula días contra `today` (ISO o `date`), y devuelve `None` ante cualquier error, dominio sin RDAP o fecha inválida. Nunca lanza.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_rules tests.test_rdap -v`
Expected: PASS, 11 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/rules.py correo_limpio/rdap.py correo_limpio/rules/data tests/test_rules.py tests/test_rdap.py
git commit -m "feat: add deterministic spam rules, vetoes and rdap age signal"
```

---

### Task 7: SQLite, aprendizaje y promoción de reglas

**Files:**
- Create: `correo_limpio/store.py`
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: nada.
- Produces `Store(db_path: Path)` con `init()`, `record_seen(message_id, run_id, bucket, seen_at)`, `reviewed_ids() -> set[str]`, `decided_ids() -> set[str]`, `record_decision(run_id, n, message_id, sender, domain, bucket, reason, source, created_at)`, `decisions_for_run(run_id) -> list[dict]`, `feedback_count(domain, verdict) -> int`, `promote(domain, verdict) -> bool`, `upsert_rule(domain, verdict, source)`, `rules() -> dict[str, str]`, `rule_sources() -> dict[str, str]`, `degrade_auto(domain)`, `replace_inbox_domains(domains, seen_at)`, `inbox_domains() -> set[str]`, `cache_domain_age(domain, created, checked_at)`, `get_domain_age(domain) -> tuple[str | None, str | None]`.

Esquema: `seen(message_id PRIMARY KEY, run_id, bucket, seen_at)`, `decisions(id INTEGER PRIMARY KEY, run_id, n, message_id, sender, domain, bucket, reason, source, created_at)`, `feedback(...)` implícito en `decisions` con `source='feedback'`, `rules(domain PRIMARY KEY, verdict, source, hits, updated_at)`, `inbox_senders(domain PRIMARY KEY, last_seen)`, `domain_age(domain PRIMARY KEY, created, checked_at)`.

- [ ] **Step 1: Write the failing test**

`tests/test_store.py`:
```python
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from correo_limpio.store import Store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.store.init()

    def tearDown(self):
        self.tmp.cleanup()

    def add_feedback(self, run, msg, domain, verdict):
        self.store.record_decision(run, 1, msg, "a@b.test", domain, "review", "x", "feedback", "2026-01-01")

    def test_three_distinct_feedback_promotes(self):
        for i in range(3):
            self.add_feedback(f"run{i}", f"msg{i}", "spam.test", "block")
        self.assertTrue(self.store.promote("spam.test", "block"))
        self.assertEqual(self.store.rules()["spam.test"], "block")
        self.assertEqual(self.store.rule_sources()["spam.test"], "auto")

    def test_purge_rows_do_not_promote(self):
        for i in range(3):
            self.store.record_decision(f"run{i}", 1, f"msg{i}", "a@b.test", "spam.test",
                                       "delete", "x", "purge", "2026-01-01")
        self.assertFalse(self.store.promote("spam.test", "block"))

    def test_same_message_twice_does_not_promote(self):
        for i in range(3):
            self.add_feedback("run1", "msg1", "spam.test", "block")
        self.assertFalse(self.store.promote("spam.test", "block"))

    def test_undo_degrades_auto_rule(self):
        self.store.upsert_rule("spam.test", "block", "auto")
        self.store.degrade_auto("spam.test")
        self.assertNotIn("spam.test", self.store.rules())

    def test_inbox_domains_replace(self):
        self.store.replace_inbox_domains({"a.test", "b.test"}, "2026-01-01")
        self.assertEqual(self.store.inbox_domains(), {"a.test", "b.test"})
        self.store.replace_inbox_domains({"c.test"}, "2026-01-02")
        self.assertEqual(self.store.inbox_domains(), {"c.test"})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_store -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.store'`.

- [ ] **Step 3: Implement**

`promote(domain, verdict)` cuenta `SELECT COUNT(DISTINCT run_id || ':' || message_id) FROM decisions WHERE domain=? AND bucket=? AND source='feedback'`; si ≥ 3, `upsert_rule(domain, verdict, "auto")` y devuelve `True`. `degrade_auto` borra la regla solo si `source='auto'`. `record_seen` usa `INSERT OR REPLACE`. `decided_ids` = `SELECT DISTINCT message_id FROM decisions`. `reviewed_ids` = `SELECT message_id FROM seen WHERE bucket='review'`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_store -v`
Expected: PASS, 5 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/store.py tests/test_store.py
git commit -m "feat: add sqlite store and rule learning"
```

---

### Task 8: Cliente de Clef-flash (Cloudflare Workers AI)

**Files:**
- Create: `correo_limpio/classifier.py`
- Test: `tests/test_classifier.py`

**Interfaces:**
- Consumes: `HttpClient`, `Evidence`, `Verdict`.
- Produces:
  - `ClefDecision(category: str, fraud_prob: float, expected_prob: float, raw: dict)`.
  - `ClefClient(http, account_id, token, base="https://api.cloudflare.com/client/v4")` con `evaluate(ev: Evidence) -> ClefDecision | None`.
  - `refine(verdict: Verdict, decision: ClefDecision | None) -> Verdict`.
  - Constante `MODEL = "@cf/cloudflare/clef-flash"`.

- [ ] **Step 1: Write the failing test**

`tests/test_classifier.py`:
```python
import unittest

from correo_limpio.classifier import ClefClient, ClefDecision, refine
from correo_limpio.evidence import from_message
from correo_limpio.http import HttpResponse
from correo_limpio.rules import Verdict
from tests import fixtures


class FakeHttp:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers=None, body=None, form=None, timeout=30):
        self.calls.append((method, url, headers, body))
        return self.response


def clef_response(fraud, expected, category):
    return HttpResponse(200, {"result": {"answers": {
        "fraude": {"probability": fraud},
        "esperado": {"probability": expected},
        "categoria": {"choice": category, "probabilities": {category: 0.9}},
    }}}, "")


class ClassifierTest(unittest.TestCase):
    def test_request_shape(self):
        http = FakeHttp(clef_response(0.1, 0.8, "notificacion_legitima"))
        client = ClefClient(http, "acct", "tok")
        client.evaluate(from_message(fixtures.sanitized_receipt()))
        method, url, headers, body = http.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/accounts/acct/ai/run/@cf/cloudflare/clef-flash"))
        self.assertEqual(headers["Authorization"], "Bearer tok")
        self.assertEqual(body["model"], "clef-flash")
        self.assertEqual(set(body["questions"]), {"fraude", "esperado", "categoria"})
        self.assertNotIn("body", body["state"])

    def test_fraud_high_deletes(self):
        d = ClefDecision("fraude", 0.95, 0.1, {})
        self.assertEqual(refine(Verdict(0.4, "review", (), False), d).bucket, "delete")

    def test_expected_high_rescues(self):
        d = ClefDecision("notificacion_legitima", 0.1, 0.8, {})
        self.assertEqual(refine(Verdict(0.2, "review", (), False), d).bucket, "rescue")

    def test_promo_never_deletes_or_rescues(self):
        d = ClefDecision("promocion", 0.1, 0.9, {})
        self.assertEqual(refine(Verdict(0.2, "review", (), False), d).bucket, "review")

    def test_error_returns_none(self):
        http = FakeHttp(HttpResponse(429, {"success": False}, ""))
        self.assertIsNone(ClefClient(http, "acct", "tok").evaluate(from_message(fixtures.soda_random())))

    def test_existing_delete_is_not_downgraded(self):
        d = ClefDecision("notificacion_legitima", 0.1, 0.9, {})
        self.assertEqual(refine(Verdict(1.0, "delete", (), True), d).bucket, "delete")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_classifier -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.classifier'`.

- [ ] **Step 3: Implement**

`evaluate` arma `state` como dict con `from`, `from_domain`, `subject`, `text`, `link_domains`, `auth` (spf/dkim/dmarc), `language`, `random_sender`, `brand`. Preguntas: `noul` `fraude`, `noul` `esperado`, `choice` `categoria` con criterios `fraude`, `phishing`, `promocion`, `boletin`, `notificacion_legitima`, `persona`. Parsea `result.answers`; tolera `{"probability": x}` y `{"probabilities": {...}}` para elección. En status ≠ 200, excepción o JSON inválido devuelve `None` (nunca lanza).

`refine`: si el verdict no es `review`, lo devuelve intacto. Si `fraud_prob >= 0.90` → `delete` con razón `"clef: fraude"`. Si categoría en `{"promocion", "boletin"}` → `review`. Si `expected_prob >= 0.70` y `fraud_prob < 0.30` → `rescue`. Si no → `review`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_classifier -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/classifier.py tests/test_classifier.py
git commit -m "feat: add clef-flash classifier with free-tier fallback"
```

---

### Task 9: Reporte de corrida, código de confirmación y exportación

**Files:**
- Create: `correo_limpio/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: nada.
- Produces:
  - `ReportItem(n, message_id, subject, sender, domain, bucket, score, reasons, clef)`.
  - `RunReport(run_id, code_hash, created_at: datetime, expires_at: datetime, digest, items, has_more, mode)` con `code_matches(code, now=None) -> bool`.
  - `build_report(items, has_more, mode, now=None) -> tuple[RunReport, str]` (genera `run_id`, código de 6, su hash y el digest de los items).
  - `render(report) -> str`.
  - `save(report, runs_dir) -> Path`.
  - `load(run_id, runs_dir) -> RunReport` (recalcula el digest y lanza `ValueError` si no coincide).

- [ ] **Step 1: Write the failing test**

`tests/test_report.py`:
```python
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.report import ReportItem, build_report, load, render, save


def item(n=1, bucket="delete"):
    return ReportItem(n, "m1", "Confirm Your Renewal 🚩", "Netflix <x@y.test>", "y.test",
                      bucket, 0.9, ("marca suplantada", "auth fail"), None)


class ReportTest(unittest.TestCase):
    def test_code_matches_and_expires(self):
        now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
        report, code = build_report([item()], False, "rules", now=now)
        self.assertTrue(report.code_matches(code, now=now))
        self.assertFalse(report.code_matches(code, now=now + timedelta(minutes=61)))
        self.assertFalse(report.code_matches("ZZZZZZ", now=now))

    def test_save_and_load_roundtrip(self):
        with TemporaryDirectory() as tmp:
            report, code = build_report([item()], True, "clef")
            save(report, Path(tmp))
            loaded = load(report.run_id, Path(tmp))
            self.assertEqual(loaded.items[0].subject, "Confirm Your Renewal 🚩")
            self.assertTrue(loaded.code_matches(code))
            self.assertTrue(loaded.has_more)

    def test_tampered_report_is_rejected(self):
        with TemporaryDirectory() as tmp:
            report, _ = build_report([item()], False, "rules")
            path = save(report, Path(tmp))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["items"][0]["bucket"] = "rescue"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                load(report.run_id, Path(tmp))

    def test_render_contains_reason_and_number(self):
        report, _ = build_report([item()], False, "rules")
        text = render(report)
        self.assertIn("1.", text)
        self.assertIn("marca suplantada", text)
        self.assertIn("borrar", text.lower())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_report -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.report'`.

- [ ] **Step 3: Implement**

`build_report` usa `secrets.choice` sobre `"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"` para 6 caracteres; guarda `sha256(code).hexdigest()`; `run_id = utcnow.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)`; `created_at` y `expires_at` son `datetime` UTC (`+60min`); `digest = sha256` sobre la representación canónica de los items (`n|message_id|bucket|score`). `code_matches` compara con `hmac.compare_digest` y verifica `now <= expires_at`. `save` escribe `runs/<run_id>/report.json` y `report.csv` (columnas n, bucket, score, sender, domain, subject, reasons) y devuelve la ruta del JSON. `load` lee `report.json`, convierte fechas con `datetime.fromisoformat`, recalcula el digest y lanza `ValueError` si no coincide. `render` arma tabla de ancho fijo con secciones `BORRAR`, `RESCATAR`, `REVISAR`, razón y `[clef: ...]` si aplica.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_report -v`
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/report.py tests/test_report.py
git commit -m "feat: add run report with confirmation code and export"
```

---

### Task 10: Pipeline de `scan` (solo lectura)

**Files:**
- Create: `correo_limpio/pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `Config`, `GraphClient`, `Store`, `RuleSet`, `ClefClient`, `from_message`, `refine`, `build_report`, `domain_age_days`.
- Produces: `scan(cfg, graph, store, ruleset, clef=None, rdap=None, *, include_reviewed=False, max_items=None, now=None) -> tuple[RunReport, str]` (reporte y código en claro).

- [ ] **Step 1: Write the failing test**

`tests/test_pipeline.py` con un `FakeGraph` que devuelve los fixtures, un `FakeStore` en memoria que implementa `reviewed_ids`, `decided_ids`, `record_seen`, `replace_inbox_domains`, `inbox_domains`, `rules` y un `FakeClef`.

```python
def test_scan_buckets_reference_fixtures(self):
    report, code = self.scan()
    by_subject = {i.subject: i.bucket for i in report.items}
    self.assertEqual(by_subject["The 14X baking soda ritual ending suddenly 🚩❗"], "review")
    self.assertEqual(by_subject["Last Chance: Confirm Your Renewal"], "delete")

def test_scan_is_read_only(self):
    self.scan()
    self.assertEqual(self.graph.moves, [])

def test_reviewed_are_skipped_unless_requested(self):
    self.scan()
    report2, _ = self.scan()
    self.assertNotIn("50% off this week", [i.subject for i in report2.items])
    report3, _ = self.scan(include_reviewed=True)
    self.assertIn("50% off this week", [i.subject for i in report3.items])

def test_delete_candidate_not_purged_reappears(self):
    self.scan()
    report2, _ = self.scan()
    self.assertIn("Last Chance: Confirm Your Renewal", [i.subject for i in report2.items])

def test_clef_only_refines_review_band(self):
    self.scan()
    self.assertEqual(self.clef.calls, 5)  # 8 fixtures - 3 delete/rescue

def test_duplicate_message_ids_counted_once(self):
    self.graph.messages = [fixtures.netflix_phish(), fixtures.netflix_phish()]
    report, _ = self.scan()
    self.assertEqual(len(report.items), 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_pipeline -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.pipeline'`.

- [ ] **Step 3: Implement**

`scan`:
1. `skip = set()`; si no `include_reviewed`, `skip = store.decided_ids() | store.reviewed_ids()`.
2. `messages, has_more = graph.list_junk(max_items or cfg.max_per_run, skip)`.
3. `domains = graph.inbox_domains(cfg.inbox_lookback_days)`; `store.replace_inbox_domains(domains, now_iso)`.
4. Resolver edades: para cada dominio único que no esté en `store.get_domain_age`, si `rdap` está disponible, `rdap.domain_age_days(domain)` y `store.cache_domain_age(domain, created, now_iso)`. Construir `ages: dict[str, int | None]`.
5. Deduplicar mensajes por `message_id`, conservando el primero.
6. `allow_rules = {d for d, v in store.rules().items() if v == "allow"}`; `block_rules = {d for d, v in store.rules().items() if v == "block"}`. Para cada mensaje: `ev = from_message(m)`; `v = ruleset.evaluate(ev, allow_domains=domains | allow_rules, block_domains=block_rules, domain_age_days=ages.get(ev.from_domain))`; si `v.bucket == "review"` y `clef`, `v = refine(v, clef.evaluate(ev))`.
7. Construir items con `n` 1..N en orden de llegada, `report, code = build_report(items, has_more, "clef" if clef else "rules")`.
8. `save(report, cfg.state_dir / "runs")`.
9. `store.record_seen` para cada item con `report.run_id` y su bucket.
10. Devolver `(report, code)`.

`clef` debe pasarse solo si hay credenciales; el CLI lo decide.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_pipeline -v`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/pipeline.py tests/test_pipeline.py
git commit -m "feat: add read-only scan pipeline"
```

---

### Task 11: `purge`, `undo` y `feedback`

**Files:**
- Create: `correo_limpio/purge.py`
- Test: `tests/test_purge.py`

**Interfaces:**
- Consumes: todo lo anterior.
- Produces:
  - `Selection(delete: set[int], rescue: set[int])`.
  - `parse_selection(delete: str | None, rescue: str | None, groups: list[str] | None) -> Selection` (acepta `"1,4,7"`, `"1-3"` y grupos `delete`/`rescue`).
  - `PurgeResult(moved: list[tuple[int, str]], failed: list[tuple[int, str]], aborted: bool)`.
  - `purge(cfg, graph, store, report, code, selection, now=None) -> PurgeResult`.
  - `undo(cfg, graph, store, report, message_n=None) -> PurgeResult`.
  - `feedback(cfg, graph, store, report, n, verdict, *, rescue=False) -> str`.

- [ ] **Step 1: Write the failing test**

`tests/test_purge.py`:
```python
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from correo_limpio.config import Config
from correo_limpio.graph import GraphError
from correo_limpio.purge import Selection, feedback, parse_selection, purge, undo
from correo_limpio.report import ReportItem, build_report
from correo_limpio.store import Store


class FakeGraph:
    def __init__(self):
        self.moves = []
        self.fail_ids = set()
        self.fail_status = 404

    def move(self, message_id, destination):
        if message_id in self.fail_ids:
            raise GraphError(self.fail_status, "nope")
        self.moves.append((message_id, destination))


class PurgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = Config(Path(self.tmp.name), Path(self.tmp.name), client_id="cid")
        self.store = Store(Path(self.tmp.name) / "state.db")
        self.store.init()
        items = [
            ReportItem(1, "m1", "a", "x@y.test", "y.test", "delete", 0.9, (), None),
            ReportItem(2, "m2", "b", "x@y.test", "y.test", "delete", 0.9, (), None),
            ReportItem(3, "m3", "c", "x@y.test", "y.test", "rescue", 0.1, (), None),
            ReportItem(4, "m4", "d", "x@y.test", "y.test", "delete", 0.9, (), None),
        ]
        self.report, self.code = build_report(items, False, "rules")
        self.report_expires = self.report.expires_at
        self.graph = FakeGraph()

    def test_wrong_code_moves_nothing(self):
        result = purge(self.cfg, self.graph, self.store, self.report, "WRONG",
                       Selection(delete={1}, rescue=set()))
        self.assertEqual(self.graph.moves, [])
        self.assertEqual(result.moved, [])

    def test_expired_code_moves_nothing(self):
        later = self.report_expires + timedelta(minutes=1)
        purge(self.cfg, self.graph, self.store, self.report, self.code,
              Selection(delete={1}, rescue=set()), now=later)
        self.assertEqual(self.graph.moves, [])

    def test_subset_moves_only_selected(self):
        purge(self.cfg, self.graph, self.store, self.report, self.code,
              Selection(delete={1}, rescue={3}))
        self.assertEqual(self.graph.moves, [("m1", "deleteditems"), ("m3", "inbox")])

    def test_empty_selection_raises(self):
        with self.assertRaises(ValueError):
            purge(self.cfg, self.graph, self.store, self.report, self.code,
                  Selection(set(), set()))

    def test_missing_message_reports_skipped_and_continues(self):
        self.graph.fail_ids = {"m1"}
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1, 2}, rescue=set()))
        self.assertEqual(result.moved, [(2, "deleteditems")])
        self.assertEqual(result.failed, [(1, "404")])

    def test_three_consecutive_failures_abort(self):
        self.graph.fail_ids = {"m1", "m2", "m3", "m4"}
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1, 2, 3, 4}, rescue=set()))
        self.assertTrue(result.aborted)

    def test_non_404_error_counts_as_failure(self):
        self.graph.fail_ids = {"m1"}
        self.graph.fail_status = 503
        result = purge(self.cfg, self.graph, self.store, self.report, self.code,
                       Selection(delete={1}, rescue=set()))
        self.assertEqual(result.failed, [(1, "503")])

    def test_undo_message_only(self):
        undo(self.cfg, self.graph, self.store, self.report, message_n=2)
        self.assertEqual(self.graph.moves, [("m2", "junkemail")])

    def test_feedback_keep_creates_allow_rule(self):
        feedback(self.cfg, self.graph, self.store, self.report, 1, "allow", rescue=True)
        self.assertEqual(self.store.rules()["y.test"], "allow")
        self.assertIn(("m1", "inbox"), self.graph.moves)

    def test_parse_selection_ranges(self):
        self.assertEqual(parse_selection("1,3-4", None, None), Selection({1, 3, 4}, set()))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify they fail**

Run: `python3 -m unittest tests.test_purge -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'correo_limpio.purge'`.

- [ ] **Step 3: Implement**

`purge`:
1. `if not report.code_matches(code, now): return PurgeResult([], [], False)`.
2. `if not selection.delete and not selection.rescue: raise ValueError("selección vacía")`.
3. Para cada `n` de `delete` (bucket `delete`): `graph.move(item.message_id, "deleteditems")`; registrar `store.record_decision(... source="purge")`. Para `rescue` análogo con `inbox`. Si `GraphError` con `status == 404`: `failed.append((n, "404"))`; otros errores también a `failed`; si hay 3 fallos consecutivos → `aborted=True` y parar.

`undo`: para los items del bucket correspondiente (o solo `message_n`), mover a `junkemail` y llamar `store.degrade_auto(domain)`.

`feedback`: registra `store.record_decision(..., source="feedback")`, aplica `store.upsert_rule(domain, "allow"|"block", "user")`, intenta `store.promote(domain, verdict)` (si 3 feedback), y si `rescue` mueve el mensaje a `inbox`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_purge -v`
Expected: PASS, 10 tests.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/purge.py tests/test_purge.py
git commit -m "feat: add purge undo and feedback with code gate"
```

---

### Task 12: Cableado del CLI completo

**Files:**
- Modify: `correo_limpio/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `Auth`, `GraphClient`, `Store`, `RuleSet`, `ClefClient`, `scan`, `purge`, `undo`, `feedback`, `load`, `parse_selection`.
- Produces: `main(argv)` con subcomandos `status`, `login`, `scan`, `purge`, `undo`, `feedback` y códigos de salida 0/1/2.

- [ ] **Step 1: Write the failing tests**

En `tests/test_cli.py`, agregar:
```python
import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from correo_limpio import cli
from correo_limpio.auth import DeviceCode
from correo_limpio.report import build_report


class CliWiringTest(unittest.TestCase):
    def run_main(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            rc = cli.main(argv)
        return rc, out.getvalue()

    def test_purge_requires_code_and_selection(self):
        self.assertEqual(self.run_main(["purge", "--run", "x"])[0], 2)
        self.assertEqual(self.run_main(["purge", "--run", "x", "--code", "ABC123"])[0], 2)

    def test_feedback_requires_verdict(self):
        self.assertEqual(self.run_main(["feedback", "run1", "1"])[0], 2)

    def test_login_prints_device_code(self):
        with TemporaryDirectory() as tmp, \
             mock.patch.object(cli, "load_config") as cfg, \
             mock.patch.object(cli, "Auth") as auth_cls:
            cfg.return_value = SimpleNamespace(
                client_id="cid", config_dir=Path(tmp), state_dir=Path(tmp),
                max_per_run=200, inbox_lookback_days=90, user_languages=("es", "en"))
            auth_cls.return_value.start_login.return_value = DeviceCode(
                "ABCD", "https://microsoft.com/devicelogin", "dc", 5, 900)
            rc, out = self.run_main(["login"])
        self.assertEqual(rc, 0)
        self.assertIn("ABCD", out)
        self.assertIn("devicelogin", out)

    def test_scan_prints_code(self):
        report, code = build_report([], False, "rules")
        with mock.patch.object(cli, "scan", return_value=(report, code)), \
             mock.patch.object(cli, "build_context", return_value=mock.Mock()):
            rc, out = self.run_main(["scan"])
        self.assertEqual(rc, 0)
        self.assertIn(code, out)
        self.assertIn("Código", out)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_cli -v`
Expected: FAIL por subcomandos inexistentes.

- [ ] **Step 3: Implement**

- `build_context(args)` es el único punto que toca Keychain y red: devuelve `(cfg, auth, graph, store, ruleset, clef, rdap)`. Los tests lo parchean; `scan` también se importa como nombre de módulo para poder parchearlo.
- `login`: lee `cfg.client_id`; si falta, imprime los pasos del README y devuelve 2. Si no, `Auth(...).start_login()`, imprime `user_code` y `verification_uri`, llama `wait_for_login`.
- `login --cloudflare`: pide account ID y token por `getpass`/`input`, guarda en Keychain.
- `scan`: acepta `--max`, `--all` (pasa `max_items=None`) y `--include-reviewed`; llama `scan`, imprime `render(report)` y una línea final `Código <code> (válido 60 min)`.
- `purge`: `--run`, `--code`, `--delete`, `--rescue`, `--group` (repetible). Ningún argumento se marca `required` en argparse: `main` valida y devuelve 2 con mensaje en stderr si falta `--code` o la selección. Carga el reporte, parsea selección, ejecuta, imprime resumen.
- `undo`: `--run`, `--message`.
- `feedback`: `--run`, `n`, `--keep`/`--spam`, `--rescue`. Sin veredicto devuelve 2.
- Errores de `AuthError`/`GraphError` → stderr y exit 1.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: PASS, toda la suite.

- [ ] **Step 5: Commit**

```bash
git add correo_limpio/cli.py tests/test_cli.py
git commit -m "feat: wire full cli commands"
```

---

### Task 13: Skill de OpenCode, README e instalación

**Files:**
- Create: `skills/correo-limpio/SKILL.md`
- Create: `README.md`
- Create: `scripts/install-skill.sh`
- Test: `tests/test_skill_doc.py`

**Interfaces:**
- Consumes: CLI `correo-limpio`.
- Produces: skill instalable en `~/.config/opencode/skills/correo-limpio/`.

- [ ] **Step 1: Write the failing test**

```python
import unittest
from pathlib import Path


class SkillDocTest(unittest.TestCase):
    def test_skill_frontmatter_and_safety_rules(self):
        text = Path("skills/correo-limpio/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: correo-limpio", text)
        self.assertIn("description:", text)
        self.assertIn("Nunca ejecutes `purge` sin", text)
        self.assertIn("--code", text)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_skill_doc -v`
Expected: FAIL por archivo inexistente.

- [ ] **Step 3: Implement**

`SKILL.md` con frontmatter (`name`, `description` que dispare con "limpia mi spam", "revisa no deseados", "borra correo basura") y flujo obligatorio: `correo-limpio scan` → mostrar los tres grupos → **pedir confirmación** → `purge --run <id> --code <código> --delete ... --rescue ...` solo con lo aprobado → ofrecer `feedback`/`undo`. Prohibido inventar aprobación, ejecutar por iniciativa propia, o usar `--all` sin pedido explícito.

`README.md`: requisitos, registro en Azure paso a paso (app de cliente público, cuentas personales, `Mail.ReadWrite` + `offline_access`), `correo-limpio login`, Cloudflare opcional, ejemplos de uso, qué hace y qué no, cómo desinstalar/borrar estado.

`scripts/install-skill.sh`: crea el directorio destino y hace `ln -sfn "$(pwd)/skills/correo-limpio" ~/.config/opencode/skills/correo-limpio`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_skill_doc -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skills README.md scripts tests/test_skill_doc.py
git commit -m "docs: add opencode skill and setup guide"
```

---

### Task 14: Verificación real con el buzón (manual)

**Files:**
- Modify: `README.md` (sección "Verificación")

**Interfaces:**
- Consumes: todo.
- Produces: evidencia de que funciona contra Hotmail real.

- [ ] **Step 1: Registrar la app en Azure y hacer login**

Crear la app según el README, con "Allow public client flows", cuentas personales, permisos delegados `Mail.ReadWrite` y `offline_access`. Guardar el `client_id` en `~/.config/correo-limpio/config.toml`. Ejecutar `correo-limpio login` y autorizar en el navegador.

- [ ] **Step 2: Escanear sin tocar nada**

Run: `correo-limpio scan`
Expected: tabla con los tres grupos, código de 6 caracteres, y el sello de modo (`reglas` o `clef`). Ningún movimiento en el buzón.

- [ ] **Step 3: Verificar el criterio con correo real**

Revisar que los ejemplos tipo Netflix/Vivo estén en `BORRAR` o `REVISAR`, que ninguna promo legítima esté en `BORRAR`, y que un remitente de la Bandeja no aparezca en `BORRAR`.

- [ ] **Step 4: Ejecutar un subconjunto y deshacer**

Run: `correo-limpio purge --run <id> --code <código> --delete 1`
Expected: el mensaje 1 se mueve a Papelera. Luego `correo-limpio undo --run <id> --message 1` lo devuelve a No deseados.

- [ ] **Step 5: Documentar y commitear**

Agregar al README el resultado (fecha, modo, cuántos se movieron) sin datos personales. Commit:

```bash
git add README.md
git commit -m "docs: record first live verification"
```
