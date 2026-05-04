"""
Memory Playbook Import - parse user Markdown experience into structured Playbook.

GPT requirement: YAML frontmatter + Markdown sections -> Playbook JSON.
User experience priority > community articles.
"""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from .schema import Playbook


def parse_playbook_markdown(path: Path) -> Playbook:
    """Parse a Markdown file with optional YAML frontmatter into a Playbook."""
    text = path.read_text(encoding="utf-8", errors="replace")

    # Parse YAML frontmatter
    frontmatter = {}
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1].strip()
            for line in fm_text.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, _, val = line.partition(":")
                    key, val = key.strip(), val.strip()
                    if val.startswith("[") and val.endswith("]"):
                        val = [x.strip().strip('"').strip("'") for x in val[1:-1].split(",")]
                    elif val == "true":
                        val = True
                    elif val == "false":
                        val = False
                    elif val.isdigit():
                        val = int(val)
                    elif "." in val and val.replace(".", "").isdigit():
                        val = float(val)
                    frontmatter[key] = val
            text = parts[2]

    sections = _split_sections(text)
    title = frontmatter.get("title") or _first_heading(text) or path.stem.replace("_", " ").replace("-", " ")
    safe_id = re.sub(r"[^a-z0-9_]", "_", title.lower())[:50]

    return Playbook(
        id=frontmatter.get("id", f"pb_user_{safe_id}_{uuid.uuid4().hex[:8]}"),
        title=title,
        source_name="user",
        pattern_tags=frontmatter.get("tags", _infer_tags(text)),
        target_type=frontmatter.get("target_types", []),
        signals=_parse_list_items(sections.get("signals", "")),
        tactic_steps=_parse_numbered(sections.get("strategy", "")),
        tool_recipe=_parse_tool_list(sections.get("tool recipe", "")),
        pitfalls=_parse_list_items(sections.get("pitfalls", "")),
        validation=_parse_list_items(sections.get("validation", "")),
        code_templates=[],
        references=[],
        confidence=frontmatter.get("confidence", 0.9),
    )


def _split_sections(text: str) -> dict[str, str]:
    """Split markdown into sections by ## headings."""
    sections = {}
    current = "body"
    current_text = []
    for line in text.split("\n"):
        if line.startswith("## "):
            if current_text:
                sections[current] = "\n".join(current_text).strip()
            current = line[3:].strip().lower()
            current_text = []
        else:
            current_text.append(line)
    if current_text:
        sections[current] = "\n".join(current_text).strip()
    return sections


def _first_heading(text: str) -> str | None:
    m = re.search(r"^#\s+(.+)", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def _infer_tags(text: str) -> list[str]:
    tags = []
    low = text.lower()
    for tag in ["z3", "angr", "xor", "base64", "strcmp", "memcmp", "upx",
                 "anti_debug", "elf", "pe", "go", "rust", "stdin", "argv"]:
        if tag in low:
            tags.append(tag)
    return tags


def _parse_list_items(text: str) -> list[str]:
    items = []
    for m in re.finditer(r"^\s*[-*]\s+(.+)", text, re.MULTILINE):
        item = m.group(1).strip()
        if item and len(item) > 3:
            items.append(item)
    return items


def _parse_numbered(text: str) -> list[str]:
    items = []
    for m in re.finditer(r"^\s*\d+[\.\)]\s+(.+)", text, re.MULTILINE):
        item = m.group(1).strip()
        if item and len(item) > 3:
            items.append(item)
    return items


def _parse_tool_list(text: str) -> list[dict]:
    """Parse tool recipe: either JSON block or bulleted key: value pairs."""
    try:
        import json
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            return json.loads(text[start:end + 1])
    except Exception:
        pass
    # Fallback: parse bulleted list
    tools = []
    for m in re.finditer(r"^\s*[-*]\s+([\w_]+)\s*:\s*(.+)", text, re.MULTILINE):
        name = m.group(1).strip()
        params_str = m.group(2).strip()
        try:
            params = json.loads(params_str)
        except Exception:
            params = {"raw": params_str}
        tools.append({"tool": name, "params": params})
    return tools
