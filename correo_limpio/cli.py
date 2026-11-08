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
