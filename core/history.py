"""
WinnyTool - Scan History Manager
Stores and retrieves scan history using SQLite for trend analysis
and historical comparison of diagnostic results.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Optional


# Database path relative to the project root
_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_DB_PATH = os.path.join(_DB_DIR, "scan_history.db")


def _get_connection() -> sqlite3.Connection:
    """Get a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """
    Initialize the scan history database.
    Creates the data directory and tables if they do not exist.
    """
    os.makedirs(_DB_DIR, exist_ok=True)

    conn = _get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                scan_type       TEXT    NOT NULL,
                total_issues    INTEGER NOT NULL DEFAULT 0,
                critical_count  INTEGER NOT NULL DEFAULT 0,
                high_count      INTEGER NOT NULL DEFAULT 0,
                medium_count    INTEGER NOT NULL DEFAULT 0,
                low_count       INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER NOT NULL,
                category  TEXT    NOT NULL,
                issue     TEXT    NOT NULL,
                severity  TEXT    NOT NULL DEFAULT 'info',
                status    TEXT    NOT NULL DEFAULT 'open',
                details   TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        conn.commit()
    finally:
        conn.close()


def save_scan(scan_type: str, results: list[dict]) -> int:
    """
    Save scan results to the database.

    Args:
        scan_type: Type of scan (e.g. "full", "cve", "bsod", "performance").
        results: List of finding dicts, each with keys:
            - category (str): e.g. "CVE", "BSOD", "Performance"
            - issue (str): description of the finding
            - severity (str): "critical", "high", "medium", "low", or "info"
            - status (str, optional): "open", "resolved", "ignored" (default "open")
            - details (str, optional): additional details

    Returns:
        int: The scan_id of the saved scan.
    """
    init_db()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count severities
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in results:
        sev = item.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1

    total = len(results)

    conn = _get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO scans (timestamp, scan_type, total_issues,
               critical_count, high_count, medium_count, low_count)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, scan_type, total,
             counts["critical"], counts["high"], counts["medium"], counts["low"]),
        )
        scan_id = cursor.lastrowid

        for item in results:
            conn.execute(
                """INSERT INTO findings (scan_id, category, issue, severity, status, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    item.get("category", "General"),
                    item.get("issue", ""),
                    item.get("severity", "info").lower(),
                    item.get("status", "open"),
                    item.get("details", ""),
                ),
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def get_scan_history(limit: int = 20) -> list[dict]:
    """
    Retrieve recent scan summaries ordered by most recent first.

    Args:
        limit: Maximum number of scans to return (default 20).

    Returns:
        List of dicts with keys: id, timestamp, scan_type, total_issues,
        critical_count, high_count, medium_count, low_count.
    """
    init_db()

    conn = _get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_scan_details(scan_id: int) -> dict:
    """
    Retrieve full details for a specific scan.

    Args:
        scan_id: The ID of the scan to retrieve.

    Returns:
        Dict with keys:
            - scan: dict of scan summary (or None if not found)
            - findings: list of finding dicts
    """
    init_db()

    conn = _get_connection()
    try:
        scan_row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()

        findings_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
            "CASE severity "
            "  WHEN 'critical' THEN 1 "
            "  WHEN 'high' THEN 2 "
            "  WHEN 'medium' THEN 3 "
            "  WHEN 'low' THEN 4 "
            "  ELSE 5 END",
            (scan_id,),
        ).fetchall()

        return {
            "scan": dict(scan_row) if scan_row else None,
            "findings": [dict(row) for row in findings_rows],
        }
    finally:
        conn.close()


def get_trend_data() -> list[dict]:
    """
    Retrieve trend data showing how issue counts change over time.
    Useful for graphing improvement or regression.

    Returns:
        List of dicts ordered by timestamp, each with:
            timestamp, scan_type, total_issues, critical_count,
            high_count, medium_count, low_count
    """
    init_db()

    conn = _get_connection()
    try:
        rows = conn.execute(
            """SELECT timestamp, scan_type, total_issues,
                      critical_count, high_count, medium_count, low_count
               FROM scans
               ORDER BY timestamp ASC"""
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def clear_history() -> None:
    """Delete all scan history data from the database."""
    init_db()

    conn = _get_connection()
    try:
        conn.executescript("""
            DELETE FROM findings;
            DELETE FROM scans;
            DELETE FROM sqlite_sequence WHERE name IN ('scans', 'findings');
        """)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()

    # Example: save a dummy scan
    dummy_results = [
        {"category": "CVE", "issue": "CVE-2024-0001 detected", "severity": "critical",
         "details": "Outdated driver found"},
        {"category": "Performance", "issue": "High CPU usage", "severity": "medium",
         "details": "Average 85% over 5 min"},
        {"category": "Disk", "issue": "Low disk space on C:", "severity": "high",
         "details": "Only 5 GB remaining"},
    ]

    sid = save_scan("full", dummy_results)
    print(f"Saved scan ID: {sid}")

    history = get_scan_history()
    print(f"Scan history ({len(history)} entries):")
    for s in history:
        print(f"  [{s['id']}] {s['timestamp']} - {s['scan_type']} "
              f"({s['total_issues']} issues)")

    details = get_scan_details(sid)
    print(f"\nDetails for scan {sid}:")
    for f in details["findings"]:
        print(f"  [{f['severity'].upper()}] {f['category']}: {f['issue']}")

    trends = get_trend_data()
    print(f"\nTrend data: {len(trends)} data points")
