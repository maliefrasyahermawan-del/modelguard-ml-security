import sqlite3
import json
from pathlib import Path
from typing import List, Optional

DB_PATH = Path(__file__).parent.parent / "modelguard.db"


def _get_conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name        TEXT NOT NULL,
            file_path        TEXT NOT NULL,
            file_size        INTEGER NOT NULL,
            sha256           TEXT NOT NULL,
            verdict          TEXT NOT NULL,
            risk_score       INTEGER NOT NULL,
            scan_duration_ms INTEGER NOT NULL,
            scanned_at       TEXT NOT NULL,
            findings_json    TEXT NOT NULL,
            layers_completed TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(result) -> int:
    from src.report import to_dict
    d = to_dict(result)
    conn = _get_conn()
    cur = conn.execute(
        """INSERT INTO scans
           (file_name, file_path, file_size, sha256, verdict, risk_score,
            scan_duration_ms, scanned_at, findings_json, layers_completed)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            d["file_name"], d["file_path"], d["file_size"], d["sha256"],
            d["verdict"], d["risk_score"], d["scan_duration_ms"], d["scanned_at"],
            json.dumps(d["findings"]), json.dumps(d["layers_completed"]),
        ),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def get_scan(scan_id: int) -> Optional[dict]:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return _row_to_dict(row) if row else None


def get_recent_scans(limit: int = 10) -> List[dict]:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["findings"] = json.loads(d["findings_json"])
    d["layers_completed"] = json.loads(d["layers_completed"])
    return d
