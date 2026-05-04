"""
Memory Ingest & Distill - Article-to-Playbook pipeline.

Flow:
  fetch article (URL or file)
    -> HTML/Markdown -> clean text
    -> LLM distill -> Playbook JSON
    -> schema validation
    -> dedup / tag normalization
    -> store in MemoryStore
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from .schema import Playbook
from .store import MemoryStore


def ingest_file(
    path: Path,
    store: MemoryStore,
    source_name: str = "manual",
    source_url: str = "",
) -> Playbook | None:
    """Ingest a Markdown or JSON article file into a Playbook."""

    content = path.read_text(encoding="utf-8")
    ext = path.suffix.lower()

    if ext == ".json":
        try:
            data = json.loads(content)
            pb = Playbook(
                id=data.get("id", f"pb_{uuid.uuid4().hex[:12]}"),
                source_url=source_url or data.get("source_url", ""),
                source_name=source_name,
                title=data.get("title", path.stem),
                author=data.get("author"),
                pattern_tags=data.get("pattern_tags", []),
                target_type=data.get("target_type", []),
                difficulty=data.get("difficulty"),
                signals=data.get("signals", []),
                tactic_steps=data.get("tactic_steps", []),
                tool_recipe=data.get("tool_recipe", []),
                code_templates=data.get("code_templates", []),
                pitfalls=data.get("pitfalls", []),
                validation=data.get("validation", []),
                references=data.get("references", []),
                confidence=data.get("confidence", 0.8),
            )
        except (json.JSONDecodeError, KeyError):
            return None
    else:
        # Markdown / plaintext -> extract title + heuristic tags
        title = path.stem.replace("_", " ").replace("-", " ")
        # Simple keyword extraction for tags
        text_lower = content.lower()
        tags = []
        for tag in ["z3", "angr", "xor", "base64", "strcmp", "upx", "anti_debug",
                     "elf", "pe", "go", "rust", "crackme", "ctf"]:
            if tag in text_lower:
                tags.append(tag)

        pb = Playbook(
            id=f"pb_{uuid.uuid4().hex[:12]}",
            source_url=source_url,
            source_name=source_name,
            title=title,
            pattern_tags=tags,
            tactic_steps=_extract_steps(content),
            references=[source_url] if source_url else [str(path)],
            confidence=0.5,
        )

    store.add_playbook(pb)
    return pb


def distill_with_llm(
    raw_text: str,
    source_url: str = "",
    source_name: str = "",
) -> dict | None:
    """Use LLM to distill raw article text into a structured Playbook JSON."""

    import os
    try:
        from ..llm import LLMFactory, ChatMessage
    except ImportError:
        return None

    api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    prompt = f"""Distill this CTF reverse engineering writeup into a playbook JSON.

Source: {source_name} ({source_url})

Article:
{raw_text[:6000]}

Output EXACTLY this JSON structure:
{{
  "title": "concise title",
  "pattern_tags": ["z3","xor","angr","elf" etc],
  "target_type": ["elf","pe","go","rust" etc],
  "difficulty": "easy|medium|hard",
  "signals": ["what indicators suggest this playbook applies?"],
  "tactic_steps": ["step 1...","step 2..."],
  "tool_recipe": [{{"tool":"...","target":"..."}}],
  "pitfalls": ["common mistakes"],
  "validation": ["how to verify"],
  "confidence": 0.8
}}

Rules:
- Extract REUSABLE patterns, not challenge-specific details.
- Signals should be OBSERVABLE before solving (imports, strings, file type).
- Tool recipe should list concrete tools with targets.
- Do NOT include the actual flag value.
- Output ONLY valid JSON, no markdown fences."""

    provider = "mimo" if os.getenv("MIMO_API_KEY") else "openai"
    client = LLMFactory.create(provider, api_key=api_key)

    try:
        resp = client.chat(
            [ChatMessage(role="user", content=prompt)],
            temperature=0.2, max_tokens=2000,
        )
        text = resp.content.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)
        return json.loads(text)
    except Exception:
        return None


def ingest_and_distill(
    path: Path,
    store: MemoryStore,
    source_url: str = "",
    source_name: str = "",
    use_llm: bool = False,
) -> Playbook | None:
    """Full ingest pipeline: file -> (optional LLM distill) -> Playbook -> store."""

    if use_llm:
        raw = path.read_text(encoding="utf-8")
        distilled = distill_with_llm(raw, source_url, source_name)
        if distilled:
            pb = Playbook(
                id=f"pb_{uuid.uuid4().hex[:12]}",
                source_url=source_url,
                source_name=source_name,
                title=distilled.get("title", path.stem),
                pattern_tags=distilled.get("pattern_tags", []),
                target_type=distilled.get("target_type", []),
                difficulty=distilled.get("difficulty"),
                signals=distilled.get("signals", []),
                tactic_steps=distilled.get("tactic_steps", []),
                tool_recipe=distilled.get("tool_recipe", []),
                pitfalls=distilled.get("pitfalls", []),
                validation=distilled.get("validation", []),
                references=[source_url] if source_url else [str(path)],
                confidence=distilled.get("confidence", 0.8),
            )
            store.add_playbook(pb)
            return pb
        return None

    return ingest_file(path, store, source_name, source_url)


def _extract_steps(text: str) -> list[str]:
    """Extract numbered/list steps from markdown text as tactic steps."""
    steps: list[str] = []
    bullet = re.compile(r"^\s*(?:\d+[\.\)]\s*|[-*]\s+)(.+)$", re.MULTILINE)
    for m in bullet.finditer(text):
        step = m.group(1).strip()
        if 10 < len(step) < 200 and not step.startswith("http"):
            steps.append(step)
            if len(steps) >= 15:
                break
    return steps
