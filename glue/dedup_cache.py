"""
Dedup Cache — Shared SQLite deduplication layer

Provides a SQLite-backed cache for mapping (resource_arn, check_id) tuples
to CISO Assistant finding IDs. Used by both prowler_mapper.py and
asset_inventory.py to avoid creating duplicate findings.
"""

import os
import sqlite3
from datetime import datetime, timezone


class DedupCache:
    """SQLite cache mapping (resource_arn, check_id) -> CISO finding ID."""

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                resource_arn TEXT NOT NULL,
                check_id     TEXT NOT NULL,
                ciso_id      TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'FAIL',
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                PRIMARY KEY (resource_arn, check_id)
            )
            """
        )
        self.conn.commit()

    def get(self, resource_arn: str, check_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT ciso_id, status, first_seen, last_seen "
            "FROM findings WHERE resource_arn = ? AND check_id = ?",
            (resource_arn, check_id),
        ).fetchone()
        if row:
            return {
                "ciso_id": row[0],
                "status": row[1],
                "first_seen": row[2],
                "last_seen": row[3],
            }
        return None

    def upsert(
        self,
        resource_arn: str,
        check_id: str,
        ciso_id: str,
        status: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO findings (resource_arn, check_id, ciso_id, status, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource_arn, check_id) DO UPDATE SET
                ciso_id   = excluded.ciso_id,
                status    = excluded.status,
                last_seen = excluded.last_seen
            """,
            (resource_arn, check_id, ciso_id, status, now, now),
        )
        self.conn.commit()

    def get_all_failing(self) -> list[dict]:
        """Get all findings currently marked as FAIL."""
        rows = self.conn.execute(
            "SELECT resource_arn, check_id, ciso_id FROM findings WHERE status = 'FAIL'"
        ).fetchall()
        return [
            {"resource_arn": r[0], "check_id": r[1], "ciso_id": r[2]}
            for r in rows
        ]

    def close(self) -> None:
        self.conn.close()
