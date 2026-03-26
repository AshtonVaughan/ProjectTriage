"""SQLite database layer for hypothesis dedup, findings, and hunt sessions."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    technique TEXT NOT NULL,
    novelty_score REAL DEFAULT 0,
    exploitability_score REAL DEFAULT 0,
    impact_score REAL DEFAULT 0,
    total_score REAL DEFAULT 0,
    status TEXT DEFAULT 'queued',
    outcome TEXT DEFAULT '',
    tested_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hypothesis_id TEXT,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    cvss_score REAL DEFAULT 0,
    description TEXT DEFAULT '',
    reproduction_steps TEXT DEFAULT '',
    validated INTEGER DEFAULT 0,
    report_path TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (hypothesis_id) REFERENCES hypotheses(id)
);

CREATE TABLE IF NOT EXISTS hunt_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    provider TEXT DEFAULT '',
    model TEXT DEFAULT '',
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    completed_at TEXT,
    hypotheses_tested INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    notes TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_hypotheses_target ON hypotheses(target);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
"""


class Database:
    """Simple SQLite interface for Project Triage persistence."""

    def __init__(self, db_path: str | Path = "data/project_triage.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def hypothesis_exists(self, hypothesis_id: str) -> bool:
        """Check if a hypothesis has already been tested (dedup check)."""
        row = self.conn.execute(
            "SELECT 1 FROM hypotheses WHERE id = ?", (hypothesis_id,)
        ).fetchone()
        return row is not None

    def clear_hypotheses_for_target(self, target: str) -> int:
        """Clear all hypotheses for a target to allow regeneration on new sessions."""
        cursor = self.conn.execute(
            "DELETE FROM hypotheses WHERE target = ?", (target,)
        )
        self.conn.commit()
        return cursor.rowcount

    def insert_hypothesis(
        self,
        hypothesis_id: str,
        target: str,
        endpoint: str,
        technique: str,
        scores: dict[str, float] | None = None,
    ) -> None:
        """Record a hypothesis. Skips silently if already exists (dedup)."""
        scores = scores or {}
        try:
            self.conn.execute(
                """INSERT OR IGNORE INTO hypotheses
                   (id, target, endpoint, technique, novelty_score,
                    exploitability_score, impact_score, total_score, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'queued')""",
                (
                    hypothesis_id, target, endpoint, technique,
                    scores.get("novelty", 0),
                    scores.get("exploitability", 0),
                    scores.get("impact", 0),
                    scores.get("total", 0),
                ),
            )
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass  # Already exists, dedup working as intended

    def update_hypothesis(self, hypothesis_id: str, status: str, outcome: str = "") -> None:
        """Mark a hypothesis as tested with its outcome."""
        self.conn.execute(
            "UPDATE hypotheses SET status = ?, outcome = ?, tested_at = ? WHERE id = ?",
            (status, outcome, datetime.now().isoformat(), hypothesis_id),
        )
        self.conn.commit()

    def get_tested_for_target(self, target: str) -> list[str]:
        """Get all hypothesis IDs already tested for a target."""
        rows = self.conn.execute(
            "SELECT id FROM hypotheses WHERE target = ? AND status != 'queued'",
            (target,),
        ).fetchall()
        return [row["id"] for row in rows]

    def insert_finding(
        self,
        target: str,
        title: str,
        severity: str = "medium",
        cvss_score: float = 0,
        description: str = "",
        reproduction_steps: str = "",
        hypothesis_id: str | None = None,
        report_path: str = "",
        validated: bool = False,
    ) -> int:
        """Record a validated finding. Returns the finding ID."""
        cursor = self.conn.execute(
            """INSERT INTO findings
               (hypothesis_id, target, title, severity, cvss_score,
                description, reproduction_steps, validated, report_path)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                hypothesis_id, target, title, severity, cvss_score,
                description, reproduction_steps, int(validated), report_path,
            ),
        )
        self.conn.commit()
        return cursor.lastrowid or 0

    def get_findings_for_target(self, target: str) -> list[dict[str, Any]]:
        """Get all findings for a target."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE target = ? ORDER BY created_at DESC",
            (target,),
        ).fetchall()
        return [dict(row) for row in rows]

    def start_hunt_session(self, target: str, provider: str, model: str) -> int:
        """Record the start of a hunt session."""
        cursor = self.conn.execute(
            "INSERT INTO hunt_sessions (target, provider, model) VALUES (?, ?, ?)",
            (target, provider, model),
        )
        self.conn.commit()
        return cursor.lastrowid or 0

    def end_hunt_session(
        self, session_id: int, hypotheses_tested: int, findings_count: int, notes: str = ""
    ) -> None:
        """Record the end of a hunt session."""
        self.conn.execute(
            """UPDATE hunt_sessions
               SET completed_at = ?, hypotheses_tested = ?, findings_count = ?, notes = ?
               WHERE id = ?""",
            (datetime.now().isoformat(), hypotheses_tested, findings_count, notes, session_id),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
