"""
database.py — Persists every detected event to a local SQLite database.

Why bother logging instead of just printing to console? Because a real
security tool needs a history you can review later: "was my network
under attack last night while I was asleep?" is a question console
output alone can't answer once the terminal closes.
"""

import sqlite3
from datetime import datetime

import configs


def get_connection():
    conn = sqlite3.connect(configs.DATABASE_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,   -- 'deauth_burst', 'rogue_ap', 'evil_twin'
            ssid TEXT,
            bssid TEXT,
            detail TEXT
        )
    """)
    return conn


def log_event(event_type, ssid=None, bssid=None, detail=None):
    """Insert one detected event into the database."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO events (timestamp, event_type, ssid, bssid, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(timespec="seconds"),
         event_type, ssid, bssid, detail),
    )
    conn.commit()
    conn.close()


def recent_events(limit=20):
    """Fetch the most recent events, newest first — useful for a dashboard later."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT timestamp, event_type, ssid, bssid, detail "
        "FROM events ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows
