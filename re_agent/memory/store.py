"""
Memory Store - SQLite-based storage for Playbooks and SelfLessons.

Supports:
- Tag-based lookup (fast exact match)
- Content search (LIKE queries)
- Metadata storage for vector indices
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
from dataclasses import asdict
from typing import Any

from .schema import Playbook, SelfLesson, MemoryEntry


class MemoryStore:
    """SQLite store for memory entries"""

    def __init__(self, db_path: str = "memory.db"):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                source_url TEXT,
                source_name TEXT,
                title TEXT NOT NULL,
                author TEXT,
                pattern_tags TEXT,        -- JSON array
                target_type TEXT,          -- JSON array
                difficulty TEXT,
                signals TEXT,              -- JSON array
                tactic_steps TEXT,         -- JSON array
                tool_recipe TEXT,          -- JSON array of dicts
                code_templates TEXT,       -- JSON array
                pitfalls TEXT,             -- JSON array
                validation TEXT,           -- JSON array
                references_json TEXT,       -- JSON array
                confidence REAL DEFAULT 0.8,
                license_note TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS self_lessons (
                id TEXT PRIMARY KEY,
                challenge_sha256 TEXT NOT NULL,
                solve_status TEXT,          -- solved/unsolved
                verified BOOLEAN,
                winning_solver TEXT,
                input_channel TEXT,
                key_signals TEXT,           -- JSON array
                failed_attempts TEXT,       -- JSON array
                successful_recipe TEXT,     -- JSON array
                generalized_pattern TEXT,
                reusable_tool_calls TEXT,   -- JSON array of dicts
                should_try TEXT,            -- JSON array
                should_avoid TEXT,          -- JSON array
                artifacts TEXT,             -- JSON array
                confidence REAL DEFAULT 0.5,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS memory_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                tag TEXT NOT NULL,
                signal TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_memory_tag ON memory_index(tag);
            CREATE INDEX IF NOT EXISTS idx_memory_entry ON memory_index(entry_id, entry_type);
            CREATE INDEX IF NOT EXISTS idx_playbooks_tags ON playbooks(pattern_tags);
            CREATE INDEX IF NOT EXISTS idx_lessons_sha256 ON self_lessons(challenge_sha256);
        """)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ===== Playbooks =====

    def add_playbook(self, pb: Playbook) -> str:
        pb.created_at = pb.created_at or datetime.now().isoformat()
        self.conn.execute("""
            INSERT OR REPLACE INTO playbooks
            (id, source_url, source_name, title, author, pattern_tags, target_type,
             difficulty, signals, tactic_steps, tool_recipe, code_templates,
             pitfalls, validation, references_json, confidence, license_note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pb.id, pb.source_url, pb.source_name, pb.title, pb.author,
            json.dumps(pb.pattern_tags, ensure_ascii=False),
            json.dumps(pb.target_type, ensure_ascii=False),
            pb.difficulty,
            json.dumps(pb.signals, ensure_ascii=False),
            json.dumps(pb.tactic_steps, ensure_ascii=False),
            json.dumps(pb.tool_recipe, ensure_ascii=False),
            json.dumps(pb.code_templates, ensure_ascii=False),
            json.dumps(pb.pitfalls, ensure_ascii=False),
            json.dumps(pb.validation, ensure_ascii=False),
            json.dumps(pb.references, ensure_ascii=False),
            pb.confidence, pb.license_note, pb.created_at,
        ))
        self.conn.commit()

        # Update index
        for tag in pb.pattern_tags:
            self.conn.execute(
                "INSERT INTO memory_index (entry_id, entry_type, tag) VALUES (?, ?, ?)",
                (pb.id, "playbook", tag)
            )
        for signal in pb.signals:
            self.conn.execute(
                "INSERT INTO memory_index (entry_id, entry_type, tag, signal) VALUES (?, ?, ?, ?)",
                (pb.id, "playbook", signal[:100], signal[:200])
            )
        self.conn.commit()
        return pb.id

    def get_playbook(self, pb_id: str) -> Playbook | None:
        row = self.conn.execute(
            "SELECT * FROM playbooks WHERE id = ?", (pb_id,)
        ).fetchone()
        if not row:
            return None
        return self._row_to_playbook(row)

    def list_playbooks(self, limit: int = 50) -> list[Playbook]:
        rows = self.conn.execute(
            "SELECT * FROM playbooks ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def search_playbooks_by_tag(self, tags: list[str], limit: int = 10) -> list[Playbook]:
        placeholders = ",".join("?" for _ in tags)
        rows = self.conn.execute(
            f"SELECT DISTINCT p.* FROM playbooks p "
            f"JOIN memory_index i ON p.id = i.entry_id "
            f"WHERE i.tag IN ({placeholders}) AND i.entry_type = 'playbook' "
            f"LIMIT ?",
            (*tags, limit)
        ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def search_playbooks_by_content(self, query: str, limit: int = 10) -> list[Playbook]:
        rows = self.conn.execute(
            "SELECT * FROM playbooks WHERE title LIKE ? OR signals LIKE ? LIMIT ?",
            (f"%{query}%", f"%{query}%", limit)
        ).fetchall()
        return [self._row_to_playbook(r) for r in rows]

    def _row_to_playbook(self, row) -> Playbook:
        return Playbook(
            id=row["id"],
            source_url=row["source_url"] or "",
            source_name=row["source_name"] or "",
            title=row["title"],
            author=row["author"],
            pattern_tags=json.loads(row["pattern_tags"] or "[]"),
            target_type=json.loads(row["target_type"] or "[]"),
            difficulty=row["difficulty"],
            signals=json.loads(row["signals"] or "[]"),
            tactic_steps=json.loads(row["tactic_steps"] or "[]"),
            tool_recipe=json.loads(row["tool_recipe"] or "[]"),
            code_templates=json.loads(row["code_templates"] or "[]"),
            pitfalls=json.loads(row["pitfalls"] or "[]"),
            validation=json.loads(row["validation"] or "[]"),
            references=json.loads(row["references_json"] or "[]"),
            confidence=row["confidence"] or 0.8,
            license_note=row["license_note"],
            created_at=row["created_at"] or "",
        )

    # ===== Self Lessons =====

    def add_self_lesson(self, lesson: SelfLesson) -> str:
        lesson.created_at = lesson.created_at or datetime.now().isoformat()
        self.conn.execute("""
            INSERT OR REPLACE INTO self_lessons
            (id, challenge_sha256, solve_status, verified, winning_solver,
             input_channel, key_signals, failed_attempts, successful_recipe,
             generalized_pattern, reusable_tool_calls, should_try, should_avoid,
             artifacts, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            lesson.id, lesson.challenge_sha256,
            "solved" if lesson.solved else "unsolved",
            lesson.verified, lesson.winning_solver,
            lesson.input_channel,
            json.dumps(lesson.key_signals, ensure_ascii=False),
            json.dumps(lesson.failed_attempts, ensure_ascii=False),
            json.dumps(lesson.successful_recipe, ensure_ascii=False),
            lesson.generalized_pattern,
            json.dumps(lesson.reusable_tool_calls, ensure_ascii=False),
            json.dumps(lesson.should_try_earlier_next_time, ensure_ascii=False),
            json.dumps(lesson.should_avoid_next_time, ensure_ascii=False),
            json.dumps(lesson.artifacts, ensure_ascii=False),
            lesson.confidence, lesson.created_at,
        ))
        self.conn.commit()

        for signal in lesson.key_signals:
            self.conn.execute(
                "INSERT INTO memory_index (entry_id, entry_type, tag) VALUES (?, ?, ?)",
                (lesson.id, "self_lesson", signal)
            )
        self.conn.commit()
        return lesson.id

    def get_lessons_by_sha256(self, sha256: str) -> list[SelfLesson]:
        rows = self.conn.execute(
            "SELECT * FROM self_lessons WHERE challenge_sha256 = ?", (sha256,)
        ).fetchall()
        return [self._row_to_lesson(r) for r in rows]

    def get_recent_lessons(self, limit: int = 20) -> list[SelfLesson]:
        rows = self.conn.execute(
            "SELECT * FROM self_lessons ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_lesson(r) for r in rows]

    def _row_to_lesson(self, row) -> SelfLesson:
        return SelfLesson(
            id=row["id"],
            challenge_sha256=row["challenge_sha256"],
            solved=row["solve_status"] == "solved",
            verified=bool(row["verified"]),
            winning_solver=row["winning_solver"],
            input_channel=row["input_channel"],
            key_signals=json.loads(row["key_signals"] or "[]"),
            failed_attempts=json.loads(row["failed_attempts"] or "[]"),
            successful_recipe=json.loads(row["successful_recipe"] or "[]"),
            generalized_pattern=row["generalized_pattern"] or "",
            reusable_tool_calls=json.loads(row["reusable_tool_calls"] or "[]"),
            should_try_earlier_next_time=json.loads(row["should_try"] or "[]"),
            should_avoid_next_time=json.loads(row["should_avoid"] or "[]"),
            artifacts=json.loads(row["artifacts"] or "[]"),
            confidence=row["confidence"] or 0.5,
            created_at=row["created_at"] or "",
        )

    def stats(self) -> dict:
        pb_count = self.conn.execute("SELECT COUNT(*) FROM playbooks").fetchone()[0]
        sl_count = self.conn.execute("SELECT COUNT(*) FROM self_lessons").fetchone()[0]
        solved = self.conn.execute(
            "SELECT COUNT(*) FROM self_lessons WHERE solve_status = 'solved'"
        ).fetchone()[0]
        return {
            "playbooks": pb_count,
            "self_lessons": sl_count,
            "solved_lessons": solved,
        }
