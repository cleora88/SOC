from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path(os.getenv("SOC_DB_PATH", str(Path(__file__).parent / "soc_alerts.db")))


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                rule_name TEXT,
                event_type TEXT,
                severity INTEGER,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                hostname TEXT,
                destination_port INTEGER,
                protocol TEXT,
                asset_criticality TEXT,
                log_message TEXT,
                raw_event TEXT,
                category TEXT,
                confidence REAL,
                priority TEXT,
                risk_score INTEGER,
                mitre_attack TEXT,
                explanation TEXT,
                recommended_action TEXT,
                processing_ms INTEGER,
                created_at TEXT,
                updated_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyst_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            """
        )
        existing_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        migrations = {
            "model_used": "ALTER TABLE alerts ADD COLUMN model_used TEXT DEFAULT 'rule-fallback'",
            "updated_at": "ALTER TABLE alerts ADD COLUMN updated_at TEXT",
        }
        for column, statement in migrations.items():
            if column not in existing_columns:
                conn.execute(statement)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_priority ON alerts(priority)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)")


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["raw_event"] = json.loads(data.get("raw_event") or "{}")
    return data


def save_alert(alert: dict[str, Any]) -> None:
    payload = dict(alert)
    payload["raw_event"] = json.dumps(payload.get("raw_event") or {})
    payload["updated_at"] = payload.get("updated_at") or payload.get("created_at")
    columns = list(payload.keys())
    placeholders = ", ".join("?" for _ in columns)
    updates = ", ".join(f"{column}=excluded.{column}" for column in columns if column != "id")

    with connect() as conn:
        conn.execute(
            f"""
            INSERT INTO alerts ({", ".join(columns)})
            VALUES ({placeholders})
            ON CONFLICT(id) DO UPDATE SET {updates}
            """,
            [payload[column] for column in columns],
        )


def list_alerts(filters: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    clauses = []
    values: list[Any] = []

    for field in ["priority", "category", "source", "status", "mitre_attack"]:
        if filters.get(field):
            clauses.append(f"{field} = ?")
            values.append(filters[field])

    if filters.get("q"):
        clauses.append(
            "(source_ip LIKE ? OR destination_ip LIKE ? OR username LIKE ? OR hostname LIKE ? OR rule_name LIKE ?)"
        )
        needle = f"%{filters['q']}%"
        values.extend([needle, needle, needle, needle, needle])

    sql = "SELECT * FROM alerts"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC LIMIT ?"
    values.append(limit)

    with connect() as conn:
        return [_decode(row) for row in conn.execute(sql, values).fetchall()]


def get_alert(alert_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _decode(row) if row else None


def update_alert_status(alert_id: str, status: str, updated_at: str) -> dict[str, Any] | None:
    with connect() as conn:
        conn.execute("UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?", (status, updated_at, alert_id))
    return get_alert(alert_id)


def add_note(alert_id: str, note: str, created_at: str) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO analyst_notes (alert_id, note, created_at) VALUES (?, ?, ?)",
            (alert_id, note, created_at),
        )


def get_notes(alert_id: str) -> list[dict[str, Any]]:
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            "SELECT id, note, created_at FROM analyst_notes WHERE alert_id = ? ORDER BY created_at DESC",
            (alert_id,),
        ).fetchall()]


def clear_alerts() -> None:
    with connect() as conn:
        conn.execute("DELETE FROM analyst_notes")
        conn.execute("DELETE FROM alerts")


def stats() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT priority, category, status, COUNT(*) AS count FROM alerts GROUP BY priority, category, status").fetchall()
        total = conn.execute("SELECT COUNT(*) AS count FROM alerts").fetchone()["count"]

    priorities: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    categories: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for row in rows:
        priorities[row["priority"]] = priorities.get(row["priority"], 0) + row["count"]
        categories[row["category"]] = categories.get(row["category"], 0) + row["count"]
        statuses[row["status"]] = statuses.get(row["status"], 0) + row["count"]

    return {"total": total, **priorities, "categories": categories, "statuses": statuses}
