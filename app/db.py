import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from .security import hash_password


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('UP','DOWN')),
    latency_ms REAL,
    error TEXT,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_key TEXT NOT NULL,
    attempted_at INTEGER NOT NULL,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_checks_target_time ON checks(target_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_login_source_time ON login_attempts(source_key, attempted_at DESC);
"""


@contextmanager
def connect(db_path):
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path, admin_password):
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                ("admin", hash_password(admin_password), utc_now()),
            )
        count = conn.execute("SELECT COUNT(*) AS c FROM targets").fetchone()["c"]
        if count == 0:
            conn.execute(
                "INSERT INTO targets(name,host,port,enabled,created_at) VALUES(?,?,?,?,?)",
                ("Local Web Service", "127.0.0.1", 5000, 1, utc_now()),
            )


def get_user(db_path, username):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()


def list_targets(db_path):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()


def add_target(db_path, name, host, port):
    with connect(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO targets(name,host,port,enabled,created_at) VALUES(?,?,?,?,?)",
            (name, host, port, 1, utc_now()),
        )
        return cur.lastrowid


def delete_target(db_path, target_id):
    with connect(db_path) as conn:
        conn.execute("DELETE FROM targets WHERE id=?", (target_id,))


def set_target_enabled(db_path, target_id, enabled):
    with connect(db_path) as conn:
        conn.execute("UPDATE targets SET enabled=? WHERE id=?", (int(enabled), target_id))


def get_enabled_targets(db_path):
    with connect(db_path) as conn:
        return conn.execute("SELECT * FROM targets WHERE enabled=1 ORDER BY id").fetchall()


def save_check(db_path, target_id, status, latency_ms, error=None):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO checks(target_id,checked_at,status,latency_ms,error) VALUES(?,?,?,?,?)",
            (target_id, utc_now(), status, latency_ms, error),
        )
        if status == "DOWN":
            conn.execute(
                "INSERT INTO alerts(target_id,severity,message,created_at) VALUES(?,?,?,?)",
                (target_id, "warning", error or "Target is unreachable", utc_now()),
            )


def record_event(db_path, event_type, severity, source_ip, message):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO events(event_type,severity,source_ip,message,created_at) VALUES(?,?,?,?,?)",
            (event_type, severity, source_ip, message, utc_now()),
        )


def dashboard_data(db_path):
    with connect(db_path) as conn:
        targets = conn.execute("""
            SELECT t.*, c.status, c.latency_ms, c.checked_at, c.error
            FROM targets t
            LEFT JOIN checks c ON c.id=(SELECT id FROM checks WHERE target_id=t.id ORDER BY id DESC LIMIT 1)
            ORDER BY t.id DESC
        """).fetchall()
        events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 30").fetchall()
        alerts = conn.execute("SELECT * FROM alerts WHERE acknowledged=0 ORDER BY id DESC LIMIT 20").fetchall()
        total = conn.execute("SELECT COUNT(*) AS c FROM targets").fetchone()["c"]
        up = conn.execute("SELECT COUNT(*) AS c FROM targets t JOIN checks c ON c.id=(SELECT id FROM checks WHERE target_id=t.id ORDER BY id DESC LIMIT 1) WHERE c.status='UP'").fetchone()["c"]
        return targets, events, alerts, total, up


def recent_checks(db_path, target_id, limit=20):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT * FROM checks WHERE target_id=? ORDER BY id DESC LIMIT ?", (target_id, limit)
        ).fetchall()


def acknowledge_alert(db_path, alert_id):
    with connect(db_path) as conn:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))


def login_failures(db_path, source_key, since_epoch):
    with connect(db_path) as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM login_attempts WHERE source_key=? AND attempted_at>=? AND success=0",
            (source_key, since_epoch),
        ).fetchone()["c"]


def record_login_attempt(db_path, source_key, success, attempted_at):
    with connect(db_path) as conn:
        conn.execute(
            "INSERT INTO login_attempts(source_key,attempted_at,success) VALUES(?,?,?)",
            (source_key, attempted_at, int(success)),
        )
