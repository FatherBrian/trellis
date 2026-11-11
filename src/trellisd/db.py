"""A tiny database layer: SQLite for tests and demos, Postgres for real use.

Grants and the ledger share one database. Callers write SQL with ``?`` placeholders;
the Postgres connection rewrites them to ``%s``.

URLs:
    sqlite:///path/to/trellis.db   (or just a file path, or ``:memory:``)
    postgresql://user:pass@host:5432/db
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

DEFAULT_URL = "sqlite:///trellisd.db"


class DatabaseError(Exception):
    """Raised when the database cannot be reached or a write fails."""


def is_postgres(url: str) -> bool:
    return url.startswith(("postgres://", "postgresql://"))


class Database:
    """One connection, serialized by a lock. Enough for v0.1's single-process writers."""

    def __init__(self, url: str = DEFAULT_URL) -> None:
        self.url = url
        self.postgres = is_postgres(url)
        self._lock = threading.RLock()
        try:
            if self.postgres:
                import psycopg

                self._conn: Any = psycopg.connect(url, autocommit=False, connect_timeout=5)
            else:
                path = url.removeprefix("sqlite:///").removeprefix("sqlite://")
                self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
                self._conn.execute("PRAGMA journal_mode=WAL")
        except Exception as exc:
            raise DatabaseError(f"cannot open database {redact_url(url)}: {exc}") from exc

    # -- helpers ---------------------------------------------------------------------------

    def _sql(self, sql: str) -> str:
        return sql.replace("?", "%s") if self.postgres else sql

    def close(self) -> None:
        with contextlib.suppress(Exception):  # closing twice is harmless
            self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def transaction(self, lock_table: str | None = None) -> Iterator[Cursor]:
        """Run statements atomically. ``lock_table`` serializes writers on that table."""
        with self._lock:
            cur = Cursor(self, self._conn.cursor())
            try:
                if self.postgres:
                    if lock_table:
                        cur.raw.execute(f"LOCK TABLE {lock_table} IN EXCLUSIVE MODE")
                else:
                    cur.raw.execute("BEGIN IMMEDIATE")
                yield cur
                self._conn.commit()
            except Exception:
                with contextlib.suppress(Exception):
                    self._conn.rollback()
                raise

    def execute_script(self, script: str) -> None:
        with self._lock:
            if self.postgres:
                with self._conn.cursor() as cur:
                    cur.execute(script)
                self._conn.commit()
            else:
                self._conn.executescript(script)

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute(self._sql(sql), tuple(params))
                rows = list(cur.fetchall())
            finally:
                if self.postgres:
                    self._conn.commit()  # end the read transaction
            return rows

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self.transaction() as cur:
            cur.execute(sql, params)


class Cursor:
    def __init__(self, db: Database, raw: Any) -> None:
        self.db = db
        self.raw = raw

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Cursor:
        self.raw.execute(self.db._sql(sql), tuple(params))
        return self

    def fetchone(self) -> tuple[Any, ...] | None:
        row = self.raw.fetchone()
        return tuple(row) if row is not None else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return [tuple(r) for r in self.raw.fetchall()]


def redact_url(url: str) -> str:
    """Hide a password in a database URL before it goes into a message."""
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        creds, host = rest.rsplit("@", 1)
        user = creds.split(":", 1)[0]
        return f"{scheme}://{user}:***@{host}"
    return url
