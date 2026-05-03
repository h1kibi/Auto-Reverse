"""
数据库模块 - SQLite 存储函数摘要
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionSummary:
    """函数摘要"""
    id: Optional[int] = None
    sample_sha256: str = ""
    name: str = ""
    address: str = ""
    decompiled_code: str = ""
    summary: str = ""
    behavior_tags: list[str] = field(default_factory=list)
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "sample_sha256": self.sample_sha256,
            "name": self.name,
            "address": self.address,
            "decompiled_code": self.decompiled_code,
            "summary": self.summary,
            "behavior_tags": self.behavior_tags,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


@dataclass
class AnalysisSession:
    """分析会话"""
    id: Optional[int] = None
    sample_sha256: str = ""
    sample_path: str = ""
    file_type: str = ""
    status: str = "pending"
    result_json: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


class Database:
    """SQLite 数据库"""

    def __init__(self, db_path: str = "reverse_agent.db"):
        self.db_path = Path(db_path)
        self.conn = None
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        # 创建表
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS analysis_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_sha256 TEXT NOT NULL,
                sample_path TEXT NOT NULL,
                file_type TEXT,
                status TEXT DEFAULT 'pending',
                result_json TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS function_summaries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample_sha256 TEXT NOT NULL,
                name TEXT NOT NULL,
                address TEXT,
                decompiled_code TEXT,
                summary TEXT,
                behavior_tags TEXT,
                confidence REAL DEFAULT 0.0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_sha256
                ON analysis_sessions(sample_sha256);

            CREATE INDEX IF NOT EXISTS idx_functions_sha256
                ON function_summaries(sample_sha256);

            CREATE INDEX IF NOT EXISTS idx_functions_name
                ON function_summaries(name);
        """)
        self.conn.commit()

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()

    # ========== 分析会话 ==========

    def create_session(self, session: AnalysisSession) -> int:
        """创建分析会话"""
        cursor = self.conn.execute(
            "INSERT INTO analysis_sessions (sample_sha256, sample_path, file_type, status, result_json) VALUES (?, ?, ?, ?, ?)",
            (session.sample_sha256, session.sample_path, session.file_type, session.status, session.result_json)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_session(self, session_id: int) -> Optional[AnalysisSession]:
        """获取分析会话"""
        row = self.conn.execute(
            "SELECT * FROM analysis_sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if row:
            return AnalysisSession(
                id=row["id"],
                sample_sha256=row["sample_sha256"],
                sample_path=row["sample_path"],
                file_type=row["file_type"],
                status=row["status"],
                result_json=row["result_json"],
                created_at=row["created_at"],
            )
        return None

    def get_sessions_by_sha256(self, sha256: str) -> list[AnalysisSession]:
        """根据 SHA256 获取分析会话"""
        rows = self.conn.execute(
            "SELECT * FROM analysis_sessions WHERE sample_sha256 = ? ORDER BY created_at DESC",
            (sha256,)
        ).fetchall()
        return [AnalysisSession(
            id=row["id"],
            sample_sha256=row["sample_sha256"],
            sample_path=row["sample_path"],
            file_type=row["file_type"],
            status=row["status"],
            result_json=row["result_json"],
            created_at=row["created_at"],
        ) for row in rows]

    def update_session_status(self, session_id: int, status: str, result_json: str = None):
        """更新会话状态"""
        if result_json:
            self.conn.execute(
                "UPDATE analysis_sessions SET status = ?, result_json = ? WHERE id = ?",
                (status, result_json, session_id)
            )
        else:
            self.conn.execute(
                "UPDATE analysis_sessions SET status = ? WHERE id = ?",
                (status, session_id)
            )
        self.conn.commit()

    # ========== 函数摘要 ==========

    def add_function_summary(self, func: FunctionSummary) -> int:
        """添加函数摘要"""
        tags_json = json.dumps(func.behavior_tags, ensure_ascii=False)
        cursor = self.conn.execute(
            "INSERT INTO function_summaries (sample_sha256, name, address, decompiled_code, summary, behavior_tags, confidence) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (func.sample_sha256, func.name, func.address, func.decompiled_code, func.summary, tags_json, func.confidence)
        )
        self.conn.commit()
        return cursor.lastrowid

    def get_function_by_name(self, sample_sha256: str, name: str) -> Optional[FunctionSummary]:
        """根据函数名获取摘要"""
        row = self.conn.execute(
            "SELECT * FROM function_summaries WHERE sample_sha256 = ? AND name = ?",
            (sample_sha256, name)
        ).fetchone()
        if row:
            return self._row_to_function(row)
        return None

    def get_function_by_address(self, sample_sha256: str, address: str) -> Optional[FunctionSummary]:
        """根据地址获取函数摘要"""
        row = self.conn.execute(
            "SELECT * FROM function_summaries WHERE sample_sha256 = ? AND address = ?",
            (sample_sha256, address)
        ).fetchone()
        if row:
            return self._row_to_function(row)
        return None

    def get_functions_by_sample(self, sample_sha256: str) -> list[FunctionSummary]:
        """获取样本的所有函数摘要"""
        rows = self.conn.execute(
            "SELECT * FROM function_summaries WHERE sample_sha256 = ? ORDER BY name",
            (sample_sha256,)
        ).fetchall()
        return [self._row_to_function(row) for row in rows]

    def get_functions_by_tag(self, sample_sha256: str, tag: str) -> list[FunctionSummary]:
        """根据行为标签获取函数"""
        rows = self.conn.execute(
            "SELECT * FROM function_summaries WHERE sample_sha256 = ? AND behavior_tags LIKE ?",
            (sample_sha256, f"%{tag}%")
        ).fetchall()
        return [self._row_to_function(row) for row in rows]

    def search_functions(self, sample_sha256: str, keyword: str) -> list[FunctionSummary]:
        """搜索函数"""
        rows = self.conn.execute(
            "SELECT * FROM function_summaries WHERE sample_sha256 = ? AND (name LIKE ? OR summary LIKE ?)",
            (sample_sha256, f"%{keyword}%", f"%{keyword}%")
        ).fetchall()
        return [self._row_to_function(row) for row in rows]

    def get_function_count(self, sample_sha256: str) -> int:
        """获取函数总数"""
        row = self.conn.execute(
            "SELECT COUNT(*) as count FROM function_summaries WHERE sample_sha256 = ?",
            (sample_sha256,)
        ).fetchone()
        return row["count"]

    def _row_to_function(self, row) -> FunctionSummary:
        """将数据库行转换为 FunctionSummary"""
        tags = []
        if row["behavior_tags"]:
            try:
                tags = json.loads(row["behavior_tags"])
            except:
                tags = []

        return FunctionSummary(
            id=row["id"],
            sample_sha256=row["sample_sha256"],
            name=row["name"],
            address=row["address"],
            decompiled_code=row["decompiled_code"],
            summary=row["summary"],
            behavior_tags=tags,
            confidence=row["confidence"],
            created_at=row["created_at"],
        )
