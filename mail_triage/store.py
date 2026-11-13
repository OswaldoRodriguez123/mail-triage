import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (
    message_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    bucket TEXT NOT NULL,
    seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    n INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    sender TEXT,
    domain TEXT,
    bucket TEXT NOT NULL,
    reason TEXT,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    domain TEXT PRIMARY KEY,
    verdict TEXT NOT NULL,
    source TEXT NOT NULL,
    hits INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS inbox_senders (
    domain TEXT PRIMARY KEY,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_age (
    domain TEXT PRIMARY KEY,
    created TEXT,
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clef_verdicts (
    domain TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    fraud REAL NOT NULL,
    expected REAL NOT NULL,
    checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_days (
    day TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)

    @contextmanager
    def _connection(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            os.chmod(self.path, 0o600)
        except OSError:
            pass  # sqlite will surface a real error below if the file is unusable
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def init(self) -> None:
        with self._connection() as connection:
            connection.executescript(SCHEMA)

    def record_seen(self, message_id: str, run_id: str, bucket: str, seen_at: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO seen(message_id, run_id, bucket, seen_at) VALUES (?, ?, ?, ?)",
                (message_id, run_id, bucket, seen_at),
            )

    def reviewed_ids(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT message_id FROM seen WHERE bucket = 'review'"
            ).fetchall()
        return {row["message_id"] for row in rows}

    def decided_ids(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT DISTINCT message_id FROM decisions"
            ).fetchall()
        return {row["message_id"] for row in rows}

    def record_decision(
        self,
        run_id: str,
        n: int,
        message_id: str,
        sender: str,
        domain: str,
        bucket: str,
        reason: str,
        source: str,
        created_at: str,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO decisions(run_id, n, message_id, sender, domain, bucket, reason, source, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, n, message_id, sender, domain, bucket, reason, source, created_at),
            )

    def decisions_for_run(self, run_id: str) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM decisions WHERE run_id = ? ORDER BY n, id", (run_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def feedback_count(self, domain: str, verdict: str) -> int:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(DISTINCT run_id) AS runs, COUNT(DISTINCT message_id) AS msgs "
                "FROM decisions WHERE domain = ? AND bucket = ? AND source = 'feedback'",
                (domain, verdict),
            ).fetchone()
        if row is None:
            return 0
        return min(int(row["runs"] or 0), int(row["msgs"] or 0))

    def promote(self, domain: str, verdict: str) -> bool:
        if self.feedback_count(domain, verdict) < 3:
            return False
        self.upsert_rule(domain, verdict, "auto")
        return True

    def upsert_rule(self, domain: str, verdict: str, source: str) -> None:
        updated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO rules(domain, verdict, source, hits, updated_at) VALUES (?, ?, ?, 0, ?) "
                "ON CONFLICT(domain) DO UPDATE SET "
                "verdict = excluded.verdict, source = excluded.source, "
                "hits = rules.hits + 1, updated_at = excluded.updated_at",
                (domain, verdict, source, updated_at),
            )

    def rules(self) -> dict[str, str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT domain, verdict FROM rules").fetchall()
        return {row["domain"]: row["verdict"] for row in rows}

    def rule_sources(self) -> dict[str, str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT domain, source FROM rules").fetchall()
        return {row["domain"]: row["source"] for row in rows}

    def degrade_auto(self, domain: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM rules WHERE domain = ? AND source = 'auto'", (domain,)
            )

    def remove_rule(self, domain: str, source: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "DELETE FROM rules WHERE domain = ? AND source = ?", (domain, source)
            )

    def get_clef_verdict(
        self, domain: str, max_scan_days: int | None = None
    ) -> dict | None:
        if not domain:
            return None
        with self._connection() as connection:
            row = connection.execute(
                "SELECT category, fraud, expected, checked_at FROM clef_verdicts WHERE domain = ?",
                (domain,),
            ).fetchone()
            if row is None:
                return None
            if max_scan_days is not None:
                checked_day = (row["checked_at"] or "")[:10]
                later = connection.execute(
                    "SELECT COUNT(*) AS n FROM scan_days WHERE day > ?", (checked_day,)
                ).fetchone()["n"]
                if later > max_scan_days:
                    return None
        return dict(row)

    def mark_scan_day(self, day: str, seen_at: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO scan_days(day, seen_at) VALUES (?, ?)",
                (day, seen_at),
            )

    def cache_clef_verdict(
        self, domain: str, category: str, fraud: float, expected: float, checked_at: str
    ) -> None:
        if not domain:
            return
        with self._connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO clef_verdicts(domain, category, fraud, expected, checked_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (domain, category, fraud, expected, checked_at),
            )

    def replace_inbox_domains(self, domains, seen_at: str) -> None:
        with self._connection() as connection:
            connection.execute("DELETE FROM inbox_senders")
            connection.executemany(
                "INSERT INTO inbox_senders(domain, last_seen) VALUES (?, ?)",
                [(domain, seen_at) for domain in sorted(domains)],
            )

    def inbox_domains(self) -> set[str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT domain FROM inbox_senders").fetchall()
        return {row["domain"] for row in rows}

    def cache_domain_age(self, domain: str, created: str | None, checked_at: str) -> None:
        with self._connection() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO domain_age(domain, created, checked_at) VALUES (?, ?, ?)",
                (domain, created, checked_at),
            )

    def get_domain_age(self, domain: str) -> tuple[str | None, str | None]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT created, checked_at FROM domain_age WHERE domain = ?", (domain,)
            ).fetchone()
        if row is None:
            return (None, None)
        return (row["created"], row["checked_at"])
