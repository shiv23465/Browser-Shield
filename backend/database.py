
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


DATABASE_PATH = Path(__file__).resolve().parent / "browser_shield.db"


def get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:

        # Existing scan history table
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                modules_checked INTEGER NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)

        # Threat intelligence database
        connection.execute("""
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL UNIQUE,
                indicator_type TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'active',
                added_at TEXT NOT NULL
            )
        """)


def save_scan(report):
    scanned_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scan_history (
                url, status, risk_score,
                modules_checked, scanned_at
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            report["url"],
            report["status"],
            report["risk_score"],
            report["modules_checked"],
            scanned_at,
        ))

        return {
            "id": cursor.lastrowid,
            "scanned_at": scanned_at,
        }


def get_scan_history(limit=50):
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT id, url, status, risk_score,
                   modules_checked, scanned_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def save_threat_intelligence(url, threat_result):
    if not threat_result.get("is_malicious"):
        return None

    now = datetime.now(timezone.utc).isoformat()

    threat_type = threat_result.get("threat", "Malicious URL")
    source = threat_result.get("source", "URLhaus")

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO threat_intelligence (
                indicator,
                indicator_type,
                threat_type,
                source,
                confidence,
                first_seen,
                last_seen,
                status,
                added_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)

            ON CONFLICT(indicator)
            DO UPDATE SET
                threat_type = excluded.threat_type,
                source = excluded.source,
                confidence = excluded.confidence,
                last_seen = excluded.last_seen,
                status = 'active'
        """, (
            url,
            "URL",
            threat_type,
            source,
            100,
            now,
            now,
            "active",
            now,
        ))

        return {
            "indicator": url,
            "source": source,
            "status": "Saved",
        }


def get_threat_intelligence(limit=100):
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM threat_intelligence
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
