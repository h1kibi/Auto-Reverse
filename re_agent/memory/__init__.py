"""
Memory module - Playbook and SelfLesson storage + retrieval + ingest + quality.
"""

from .schema import Playbook, SelfLesson, MemoryEntry
from .store import MemoryStore
from .retriever import MemoryRetriever
from .ingest import ingest_file, distill_with_llm, ingest_and_distill
from .playbook_import import parse_playbook_markdown
from ..core.evidence_v2 import canonicalize_tag, CANONICAL_TAGS

__all__ = [
    "Playbook", "SelfLesson", "MemoryEntry",
    "MemoryStore", "MemoryRetriever",
    "ingest_file", "distill_with_llm", "ingest_and_distill",
    "parse_playbook_markdown",
    "canonicalize_tag", "CANONICAL_TAGS",
]
