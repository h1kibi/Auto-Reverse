"""
Evidence Graph - unified evidence tracking for reverse analysis.

v2: Auto-enriches from R2/Ghidra analysis artifacts.
"""

from dataclasses import dataclass, field
from pathlib import Path
import json
from typing import Any

from ..schema import AnalysisResult, ArtifactType


@dataclass
class EvidenceRef:
    """Reference to a piece of evidence"""
    id: str
    kind: str
    artifact_id: str | None = None
    location: str | None = None
    excerpt: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class Observation:
    """An observation made during analysis"""
    id: str
    run_id: str
    tool: str
    kind: str
    summary: str
    evidence_ids: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    raw_excerpt: str | None = None
    error: str | None = None


@dataclass
class FunctionNode:
    """Function evidence node"""
    id: str
    address: int
    name: str
    size: int | None = None
    tags: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    xrefs_from: list[str] = field(default_factory=list)
    xrefs_to: list[str] = field(default_factory=list)
    decompile_artifact: str | None = None


@dataclass
class StringNode:
    """String evidence node"""
    id: str
    value: str
    address: int | None = None
    encoding: str | None = None
    xrefs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class ImportNode:
    """Import evidence node"""
    name: str
    library: str | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class DynamicEvent:
    """Dynamic tracing event"""
    id: str
    kind: str
    timestamp_ms: int | None = None
    function: str | None = None
    args: list[str] = field(default_factory=list)
    result: str | None = None
    evidence_artifact: str | None = None


class EvidenceGraph:
    """Unified evidence graph for reverse analysis"""

    def __init__(self, run_id: str = ""):
        self.run_id = run_id
        self.functions: list[FunctionNode] = []
        self.strings: list[StringNode] = []
        self.imports: list[ImportNode] = []
        self.dynamic_events: list[DynamicEvent] = []
        self.observations: list[Observation] = []

    # ── mutations ──

    def add_function(self, fn: FunctionNode) -> None:
        self.functions.append(fn)

    def add_string(self, s: StringNode) -> None:
        self.strings.append(s)

    def add_import(self, imp: ImportNode) -> None:
        self.imports.append(imp)

    def add_dynamic_event(self, event: DynamicEvent) -> None:
        self.dynamic_events.append(event)

    def add_observation(self, obs: Observation) -> None:
        self.observations.append(obs)

    # ── queries ──

    def get_xref_targets_for_strings(self, patterns: list[str]) -> set[int]:
        targets: set[int] = set()
        for s in self.strings:
            for pat in patterns:
                if pat.lower() in s.value.lower():
                    for xref in s.xrefs:
                        try:
                            targets.add(int(xref, 16))
                        except ValueError:
                            pass
        return targets

    def get_functions_by_tag(self, tag: str) -> list[FunctionNode]:
        return [fn for fn in self.functions if tag in fn.tags]

    def get_strings_by_tag(self, tag: str) -> list[StringNode]:
        return [s for s in self.strings if tag in s.tags]

    # ── builders ──

    @classmethod
    def from_profile(cls, profile) -> "EvidenceGraph":
        """Build evidence graph from ChallengeProfile (lightweight)"""
        graph = cls(run_id=profile.sha256)

        for i, s in enumerate(profile.strings):
            tags = []
            s_low = s.lower()
            if any(p in s_low for p in ("correct", "success", "congrat", "you win")):
                tags.append("success")
            if any(p in s_low for p in ("wrong", "fail", "invalid", "try again")):
                tags.append("failure")
            if any(p in s_low for p in ("flag{", "ctf{", "picoctf")):
                tags.append("flag_like")
            graph.add_string(StringNode(id=f"str_{i}", value=s, tags=tags))

        for i, imp in enumerate(profile.imports):
            tags = []
            low = imp.lower()
            if any(k in low for k in ("strcmp", "memcmp", "strncmp")):
                tags.append("comparison")
            if any(k in low for k in ("scanf", "fgets", "read", "getchar")):
                tags.append("input")
            graph.add_import(ImportNode(name=imp, tags=tags))

        return graph

    @classmethod
    def from_analysis(cls, result: AnalysisResult) -> "EvidenceGraph":
        """Build evidence graph enriched with R2/Ghidra xref data"""
        sha = result.sample.sha256
        graph = cls(run_id=sha)  # start empty with real run_id

        for tr in result.tool_results:
            for art in tr.artifacts:
                graph._ingest_artifact(art, tr.tool)

        # Also enrich from profile-level data
        from ..ctf.profiler import build_profile
        try:
            profile = build_profile(result)
            light = cls.from_profile(profile)
            for fn in light.functions:
                if not any(f.address == fn.address for f in graph.functions):
                    graph.add_function(fn)
            for s in light.strings:
                if not any(st.value == s.value for st in graph.strings):
                    graph.add_string(s)
            for imp in light.imports:
                if not any(i.name == imp.name for i in graph.imports):
                    graph.add_import(imp)
        except Exception:
            pass

        return graph

    def _ingest_artifact(self, art, tool_name: str) -> None:
        """Ingest a single tool artifact into the evidence graph"""
        art_path = Path(art.path) if hasattr(art, 'path') else None
        if not art_path or not art_path.exists():
            return

        art_type = art.type.value if hasattr(art.type, 'value') else str(art.type)

        try:
            content = art_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return

        if "functions" in art_path.name.lower() or art_type == "functions":
            self._ingest_functions(content, tool_name, art_path)
        elif "strings" in art_path.name.lower() or art_type == "strings":
            self._ingest_strings_file(content, tool_name, art_path)
        elif "imports" in art_path.name.lower() or art_type == "imports":
            self._ingest_imports_file(content, tool_name, art_path)

    def _ingest_functions(self, content: str, tool: str, path: Path) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        items = data if isinstance(data, list) else data.get("functions", [])
        for item in items:
            if not isinstance(item, dict):
                continue
            addr = item.get("address") or item.get("offset") or item.get("addr")
            name = item.get("name", "?")
            if addr is not None:
                try:
                    addr_int = int(addr, 16) if isinstance(addr, str) else int(addr)
                except (ValueError, TypeError):
                    continue
                tags = self._tag_function(name, "")
                self.add_function(FunctionNode(
                    id=f"fn_{tool}_{addr_int:x}",
                    address=addr_int, name=name,
                    size=item.get("size"),
                    tags=tags,
                ))

    def _ingest_strings_file(self, content: str, tool: str, path: Path) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = []

        items = data if isinstance(data, list) else []
        for item in items:
            if isinstance(item, str):
                self._add_string_node(item, tool)
            elif isinstance(item, dict):
                val = item.get("string") or item.get("value") or ""
                if val:
                    self._add_string_node(val, tool, item.get("address"))

    def _ingest_imports_file(self, content: str, tool: str, path: Path) -> None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return

        items = data if isinstance(data, list) else []
        for item in items:
            if isinstance(item, str):
                self._add_import_node(item, tool)
            elif isinstance(item, dict):
                name = item.get("name") or item.get("function") or ""
                lib = item.get("libname") or item.get("library")
                if name:
                    self._add_import_node(name, tool, lib)

    def _add_string_node(self, value: str, tool: str, address=None) -> None:
        val = value.strip()
        if not val or len(val) < 3:
            return
        if any(s.value == val for s in self.strings):
            return
        tags = self._tag_string(val)
        self.add_string(StringNode(
            id=f"str_{tool}_{len(self.strings)}",
            value=val, address=address, tags=tags,
        ))

    def _add_import_node(self, name: str, tool: str, library=None) -> None:
        name = name.strip()
        if not name:
            return
        if any(i.name == name for i in self.imports):
            return
        tags = self._tag_import(name)
        self.add_import(ImportNode(name=name, library=library, tags=tags))

    @staticmethod
    def _tag_function(name: str, code: str) -> list[str]:
        tags = []
        low = (name + " " + code).lower()
        key_map = {
            "network": ["socket", "connect", "send", "recv", "http", "url"],
            "crypto": ["encrypt", "decrypt", "aes", "rsa", "hash", "md5", "sha", "cipher", "key", "xor"],
            "file": ["open", "read", "write", "create", "delete", "file"],
            "comparison": ["check", "verify", "validate", "auth", "strcmp", "memcmp", "compare"],
            "input": ["scanf", "fgets", "read(", "getchar", "gets(", "argv"],
        }
        for tag, keywords in key_map.items():
            if any(k in low for k in keywords):
                tags.append(tag)
        return tags

    @staticmethod
    def _tag_string(value: str) -> list[str]:
        tags = []
        low = value.lower()
        if any(p in low for p in ("correct", "success", "congrat", "you win", "well done")):
            tags.append("success")
        if any(p in low for p in ("wrong", "fail", "invalid", "try again", "nope")):
            tags.append("failure")
        if any(p in low for p in ("flag{", "ctf{", "picoctf{")):
            tags.append("flag_like")
        if any(p in low for p in ("base64", "hex", "xor", "rot13")):
            tags.append("encoding")
        return tags

    @staticmethod
    def _tag_import(name: str) -> list[str]:
        tags = []
        low = name.lower()
        if any(k in low for k in ("strcmp", "memcmp", "strncmp")):
            tags.append("comparison")
        if any(k in low for k in ("scanf", "fgets", "read", "getchar", "gets")):
            tags.append("input")
        if any(k in low for k in ("socket", "connect", "send", "recv")):
            tags.append("network")
        if any(k in low for k in ("ptrace", "isdebuggerpresent")):
            tags.append("anti_debug")
        return tags
