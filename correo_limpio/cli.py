import argparse
import getpass
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from correo_limpio.auth import Auth, AuthError
from correo_limpio.classifier import ClefClient
from correo_limpio.config import load_config
from correo_limpio.graph import GraphClient, GraphError
from correo_limpio.http import UrllibHttp
from correo_limpio.keychain import (
    CLOUDFLARE_ACCOUNT_ID,
    CLOUDFLARE_TOKEN,
    REFRESH_TOKEN,
    MacKeychain,
)
from correo_limpio.pipeline import scan
from correo_limpio.purge import feedback, parse_selection, purge, undo
from correo_limpio.rdap import domain_age_days
from correo_limpio.report import load, render
from correo_limpio.rules import RuleSet
from correo_limpio.store import Store

SETUP_STEPS = """Falta `client_id` en tu configuración.

1. Registra una app en https://portal.azure.com (cuentas personales).
2. Permisos delegados: Mail.ReadWrite y offline_access.
3. Activa "Allow public client flows".
4. Copia el Application (client) ID en ~/.config/correo-limpio/config.toml:
   client_id = "tu-client-id"
"""


def _status() -> int:
    cfg = load_config()
    keychain = MacKeychain()
    print(json.dumps({
        "config_dir": str(cfg.config_dir),
        "state_dir": str(cfg.state_dir),
        "client_id_present": cfg.client_id is not None,
        "max_per_run": cfg.max_per_run,
        "inbox_lookback_days": cfg.inbox_lookback_days,
        "credentials": {
            "graph": keychain.get(REFRESH_TOKEN) is not None,
            "cloudflare": keychain.get(CLOUDFLARE_TOKEN) is not None,
        },
    }, ensure_ascii=False, indent=2))
    return 0


def build_context(args) -> SimpleNamespace:
    cfg = load_config()
    if not cfg.client_id:
        raise AuthError(SETUP_STEPS)
    keychain = MacKeychain()
    http = UrllibHttp()
    auth = Auth(http, keychain, cfg.client_id)
    store = Store(Path(cfg.state_dir) / "state.db")
    store.init()
    account_id = keychain.get(CLOUDFLARE_ACCOUNT_ID)
    token = keychain.get(CLOUDFLARE_TOKEN)
    clef = ClefClient(http, account_id, token) if account_id and token else None
    return SimpleNamespace(
        cfg=cfg,
        auth=auth,
        graph=GraphClient(http, auth.access_token),
        store=store,
        ruleset=RuleSet.load(Path(__file__).resolve().parent / "rules" / "data"),
        clef=clef,
        rdap=SimpleNamespace(domain_age_days=domain_age_days),
    )


def _login(args) -> int:
    if args.cloudflare:
        account_id = input("Cloudflare account ID: ").strip()
        token = getpass.getpass("API token de Workers AI: ").strip()
        if not account_id or not token:
            print("Faltan datos; no se guardó nada.", file=sys.stderr)
            return 2
        keychain = MacKeychain()
        keychain.set(CLOUDFLARE_ACCOUNT_ID, account_id)
        keychain.set(CLOUDFLARE_TOKEN, token)
        print("Credenciales de Cloudflare guardadas en el Keychain.")
        return 0

    cfg = load_config()
    if not cfg.client_id:
        print(SETUP_STEPS, file=sys.stderr)
        return 2
    auth = Auth(UrllibHttp(), MacKeychain(), cfg.client_id)
    code = auth.start_login()
    print(f"Abre {code.verification_uri} e ingresa el código {code.user_code}.")
    auth.wait_for_login(code)
    print("Sesión guardada en el Keychain.")
    return 0


def _scan(args) -> int:
    context = build_context(args)
    max_items = None if args.all else args.max
    report, code = scan(
        context.cfg,
        context.graph,
        context.store,
        context.ruleset,
        context.clef,
        context.rdap,
        include_reviewed=args.include_reviewed,
        max_items=max_items,
    )
    print(render(report))
    print(f"\nCódigo {code} (válido 60 min)")
    return 0


def _purge(args) -> int:
    if not args.run:
        print("Falta --run.", file=sys.stderr)
        return 2
    if not args.code:
        print("Falta --code (el código de 6 caracteres del reporte).", file=sys.stderr)
        return 2
    if not args.delete and not args.rescue and not args.group:
        print("Falta una selección: --delete, --rescue o --group.", file=sys.stderr)
        return 2

    context = build_context(args)
    report = load(args.run, Path(context.cfg.state_dir) / "runs")
    if not report.code_matches(args.code):
        print("Código inválido o expirado; no se movió nada.", file=sys.stderr)
        return 2
    try:
        selection = parse_selection(args.delete, args.rescue, args.group, report=report)
    except ValueError as exc:
        print(f"Selección inválida: {exc}", file=sys.stderr)
        return 2

    result = purge(context.cfg, context.graph, context.store, report, args.code, selection)
    if not result.moved and not result.failed and not result.aborted:
        print("Código inválido o expirado; no se movió nada.", file=sys.stderr)
        return 2
    print(f"Movidos: {len(result.moved)}. Fallidos: {len(result.failed)}.")
    for number, status in result.failed:
        print(f"  {number}: Graph {status}")
    if result.aborted:
        print("Se detuvo tras 3 fallos consecutivos; el resto no se tocó.", file=sys.stderr)
        return 1
    return 0


def _undo(args) -> int:
    if not args.run:
        print("Falta --run.", file=sys.stderr)
        return 2
    context = build_context(args)
    report = load(args.run, Path(context.cfg.state_dir) / "runs")
    result = undo(context.cfg, context.graph, context.store, report, message_n=args.message)
    print(f"Movidos de vuelta a No deseados: {len(result.moved)}. Fallidos: {len(result.failed)}.")
    for number, status in result.failed:
        print(f"  {number}: Graph {status}")
    return 0 if not result.failed else 1


def _feedback(args) -> int:
    verdict = "allow" if args.keep else "block" if args.spam else None
    if verdict is None:
        print("Indica --keep o --spam.", file=sys.stderr)
        return 2
    context = build_context(args)
    report = load(args.run, Path(context.cfg.state_dir) / "runs")
    try:
        message = feedback(
            context.cfg,
            context.graph,
            context.store,
            report,
            args.n,
            verdict,
            rescue=args.rescue,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(message)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="correo-limpio")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="muestra la configuración y el estado")

    login = sub.add_parser("login", help="autoriza Microsoft Graph o Cloudflare")
    login.add_argument("--cloudflare", action="store_true", help="guarda credenciales de Cloudflare")

    scan_parser = sub.add_parser("scan", help="revisa No deseados sin mover nada")
    scan_parser.add_argument("--max", type=int, default=None, help="máximo de mensajes")
    scan_parser.add_argument("--all", action="store_true", help="ignora el tope")
    scan_parser.add_argument("--include-reviewed", action="store_true",
                             help="vuelve a mostrar los ya marcados como revisar")

    purge_parser = sub.add_parser("purge", help="mueve lo aprobado a Papelera o Bandeja")
    purge_parser.add_argument("--run", help="run_id del reporte")
    purge_parser.add_argument("--code", help="código de confirmación")
    purge_parser.add_argument("--delete", help="números a borrar, ej. 1,4,7 o 1-3")
    purge_parser.add_argument("--rescue", help="números a rescatar")
    purge_parser.add_argument("--group", action="append",
                              help="grupo completo: delete o rescue")

    undo_parser = sub.add_parser("undo", help="devuelve mensajes a No deseados")
    undo_parser.add_argument("--run", help="run_id del reporte")
    undo_parser.add_argument("--message", type=int, help="solo un número")

    feedback_parser = sub.add_parser("feedback", help="corrige la clasificación de un mensaje")
    feedback_parser.add_argument("run")
    feedback_parser.add_argument("n", type=int)
    verdict = feedback_parser.add_mutually_exclusive_group()
    verdict.add_argument("--keep", action="store_true", help="es legítimo")
    verdict.add_argument("--spam", action="store_true", help="es fraude")
    feedback_parser.add_argument("--rescue", action="store_true",
                                 help="devuélvelo a la Bandeja ahora")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            return _status()
        if args.command == "login":
            return _login(args)
        if args.command == "scan":
            return _scan(args)
        if args.command == "purge":
            return _purge(args)
        if args.command == "undo":
            return _undo(args)
        if args.command == "feedback":
            return _feedback(args)
    except (AuthError, GraphError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
