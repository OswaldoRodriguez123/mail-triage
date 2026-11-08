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
