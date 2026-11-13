import csv
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CODE_LENGTH = 6
CODE_TTL = timedelta(minutes=60)

SECTION_TITLES = {
    "delete": "BORRAR",
    "rescue": "RESCATAR",
    "review": "REVISAR",
}


@dataclass(frozen=True)
class ReportItem:
    n: int
    message_id: str
    subject: str
    sender: str
    domain: str
    bucket: str
    score: float
    reasons: tuple[str, ...]
    clef: str | None


@dataclass(frozen=True)
class RunReport:
    run_id: str
    code_hash: str
    created_at: datetime
    expires_at: datetime
    digest: str
    items: tuple[ReportItem, ...]
    has_more: bool
    mode: str
    # Local HMAC key used to sign the plan digest and the confirmation code.
    # Never persisted; reports written to disk stay unsigned until loaded
    # with the same key. When None, falls back to unkeyed sha256 (legacy).
    secret: bytes | None = None

    def code_matches(self, code: str, now: datetime | None = None) -> bool:
        if not code:
            return False
        now = now or datetime.now(timezone.utc)
        if _aware(now) > self.expires_at:
            return False
        return hmac.compare_digest(_hash(code, self.secret), self.code_hash)


def build_report(items, has_more: bool, mode: str, now: datetime | None = None,
                 secret: bytes | None = None):
    now = now or datetime.now(timezone.utc)
    items = tuple(items)
    code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    run_id = f"{now.strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"
    return RunReport(
        run_id=run_id,
        code_hash=_hash(code, secret),
        created_at=now,
        expires_at=now + CODE_TTL,
        digest=_digest(items, secret),
        items=items,
        has_more=has_more,
        mode=mode,
        secret=secret,
    ), code


def render(report: RunReport) -> str:
    lines = [
        f"Corrida {report.run_id} · modo {report.mode}",
        f"Válido hasta {report.expires_at.strftime('%Y-%m-%d %H:%M UTC')}",
    ]
    for bucket in ("delete", "rescue", "review"):
        group = [item for item in report.items if item.bucket == bucket]
        if not group:
            continue
        lines.append("")
        lines.append(f"{SECTION_TITLES[bucket]} ({len(group)})")
        for item in group:
            lines.append(
                f"  {item.n}. [{item.score:.2f}] {item.sender} · {item.domain}"
            )
            lines.append(f"     {item.subject}")
            detail = "; ".join(item.reasons)
            if item.clef:
                detail = f"{detail} [clef: {item.clef}]" if detail else f"[clef: {item.clef}]"
            if detail:
                lines.append(f"     razón: {detail}")
    if report.has_more:
        lines.append("")
        lines.append("Quedaron mensajes fuera del tope de esta corrida.")
    return "\n".join(lines)


def save(report: RunReport, runs_dir: Path) -> Path:
    _mkdir_private(Path(runs_dir))
    directory = Path(runs_dir) / report.run_id
    _mkdir_private(directory)
    json_path = directory / "report.json"
    _write_private(
        json_path,
        json.dumps(_to_dict(report), ensure_ascii=False, indent=2),
    )
    csv_path = directory / "report.csv"
    fd = os.open(csv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["n", "bucket", "score", "sender", "domain", "subject", "reasons"])
        for item in report.items:
            writer.writerow([
                item.n,
                item.bucket,
                item.score,
                item.sender,
                item.domain,
                item.subject,
                "; ".join(item.reasons),
            ])
    return json_path


def load(run_id: str, runs_dir: Path, secret: bytes | None = None) -> RunReport:
    base = Path(runs_dir).resolve()
    if not run_id or Path(run_id).is_absolute() or ".." in Path(run_id).parts:
        raise ValueError("run_id inválido")
    path = (base / run_id / "report.json").resolve()
    if not path.is_relative_to(base):
        raise ValueError("run_id fuera del directorio de corridas")
    data = json.loads(path.read_text(encoding="utf-8"))
    items = tuple(
        ReportItem(
            n=int(raw["n"]),
            message_id=raw["message_id"],
            subject=raw["subject"],
            sender=raw["sender"],
            domain=raw["domain"],
            bucket=raw["bucket"],
            score=float(raw["score"]),
            reasons=tuple(raw.get("reasons") or ()),
            clef=raw.get("clef"),
        )
        for raw in data.get("items", [])
    )
    if not hmac.compare_digest(_digest(items, secret), data.get("digest") or ""):
        raise ValueError("reporte alterado: el digest no coincide")
    return RunReport(
        run_id=data["run_id"],
        code_hash=data["code_hash"],
        created_at=datetime.fromisoformat(data["created_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
        digest=data["digest"],
        items=items,
        has_more=bool(data.get("has_more")),
        mode=data.get("mode", "rules"),
        secret=secret,
    )


def _to_dict(report: RunReport) -> dict:
    # `secret` is deliberately excluded: the key never touches the disk.
    return {
        "run_id": report.run_id,
        "code_hash": report.code_hash,
        "created_at": report.created_at.isoformat(),
        "expires_at": report.expires_at.isoformat(),
        "digest": report.digest,
        "has_more": report.has_more,
        "mode": report.mode,
        "items": [
            {
                "n": item.n,
                "message_id": item.message_id,
                "subject": item.subject,
                "sender": item.sender,
                "domain": item.domain,
                "bucket": item.bucket,
                "score": item.score,
                "reasons": list(item.reasons),
                "clef": item.clef,
            }
            for item in report.items
        ],
    }


def _digest(items, secret: bytes | None = None) -> str:
    canonical = "\n".join(
        f"{item.n}|{item.message_id}|{item.bucket}|{item.score}" for item in items
    )
    return _mac(secret, canonical.encode("utf-8"))


def _hash(code: str, secret: bytes | None = None) -> str:
    return _mac(secret, code.encode("utf-8"))


def _mac(secret: bytes | None, data: bytes) -> str:
    if secret:
        return hmac.new(secret, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _mkdir_private(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
