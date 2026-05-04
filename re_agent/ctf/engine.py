"""
SolveEngine - Unified solve orchestration.

Unifies three execution modes:
1. Fixed pipeline (DeterministicPlanner)
2. Agent-tools (local tool runtime)
3. Agent (OpenAI Brain loop)

All share SolveState and SolveEngine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.policy import ExecutionPolicy
from ..memory.retriever import MemoryRetriever
from ..memory.store import MemoryStore
from .models import ChallengeProfile, Candidate, SolverRun, SolveResult
from ..core.evidence import EvidenceGraph
from .strategy import StrategyPlan, PlanStep, DeterministicPlanner, LLMPlanner, PlanMerger
from .validator import FlagValidator
from .solve_config import SolveConfig


@dataclass
class SolveState:
    """Immutable-ish solve state snapshot"""
    run_id: str
    sample_path: Path
    profile: ChallengeProfile | None = None
    evidence: Any = None  # EvidenceGraph
    memory_hits: list[dict] = field(default_factory=list)
    plan: StrategyPlan = field(default_factory=StrategyPlan)
    solver_runs: list[SolverRun] = field(default_factory=list)
    candidates: list[dict] = field(default_factory=list)
    verifications: list[dict] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    completed: bool = False
    solved: bool = False
    winning_candidate: dict | None = None


class SolveEngine:
    """Unified solve orchestrator"""

    def __init__(
        self,
        planner: DeterministicPlanner | None = None,
        validator: FlagValidator | None = None,
        memory_store: MemoryStore | None = None,
        policy: ExecutionPolicy | None = None,
    ):
        self.planner = planner or DeterministicPlanner()
        self.validator = validator or FlagValidator()
        self.memory_store = memory_store
        self.memory_retriever = MemoryRetriever(memory_store) if memory_store else None
        self.policy = policy or ExecutionPolicy()

    def solve(
        self,
        sample_path: Path,
        config: SolveConfig,
        llm_planner: bool = False,
    ) -> SolveResult:
        """Execute a full solve with the configured planner"""
        from ..pipeline import run_analysis
        from ..core.evidence import EvidenceGraph as EG
        from .profiler import build_profile

        analysis = run_analysis(
            sample_path=str(sample_path),
            output_dir=str(config.output_dir or "artifacts"),
            skip_ghidra=config.skip_ghidra,
        )

        profile = build_profile(analysis)
        evidence = EG.from_analysis(analysis)

        memory_hits = []
        if config.enable_memory and self.memory_retriever:
            try:
                memory_hits = self.memory_retriever.retrieve_for_profile(
                    _profile_dict(profile), top_k=5
                )
            except Exception:
                pass

        base = self.planner.build(profile)
        llm_plan = None
        if llm_planner and config.enable_llm_planner:
            llm = LLMPlanner()
            llm_plan = llm.build(profile, memory_hits)
        plan = PlanMerger().merge(base, llm_plan, config.max_total_seconds)

        # ... (rest delegated to pipeline)
        from .pipeline import solve_challenge
        result = solve_challenge(
            sample_path=str(sample_path),
            output_dir=str(config.output_dir or "artifacts"),
            flag_regex=config.flag_regex,
            skip_ghidra=config.skip_ghidra,
            timeout=config.max_total_seconds,
            validate=config.verify,
            enable_memory=config.enable_memory,
            enable_llm_planner=config.enable_llm_planner,
            write_reflection=config.write_reflection,
        )
        return result

    def step(self, state: SolveState, action: PlanStep) -> SolveState:
        """Execute one plan step against current state"""
        return state  # Stub - extended by agent loops


class Mode:
    QUICK = "quick"
    DEEP = "deep"
    SOLVE = "solve"
    INVESTIGATE = "investigate"
    API_REVERSE = "api_reverse"


def auto_route_mode(profile) -> str:
    """OGhidra-style: auto-route based on profile signals."""
    if not profile:
        return Mode.SOLVE

    signals = (getattr(profile, "tags", []) +
               getattr(profile, "comparison_hints", []) +
               getattr(profile, "encoding_hints", []))

    # Deep investigation needed
    if any(s in str(signals) for s in ["anti_debug", "packed", "stripped"]):
        return Mode.DEEP
    if getattr(profile, "protections", []):
        return Mode.DEEP

    # Simple scan sufficient
    if getattr(profile, "solver_hints", []) == ["static_flag"]:
        return Mode.QUICK

    return Mode.SOLVE


MODE_TOOLS: dict[str, list[str]] = {
    Mode.QUICK: ["file", "strings", "readelf", "r2_lite"],
    Mode.DEEP: ["ghidra", "r2", "angr", "z3"],
    Mode.SOLVE: ["static_flag", "encoding", "dynamic_trace", "z3_extractor", "angr_path"],
    Mode.INVESTIGATE: ["decompile_function", "read_artifact_range", "list_artifacts", "rank_functions"],
    Mode.API_REVERSE: ["export_analysis", "abi_inference", "harness_generation"],
}


def _profile_dict(profile) -> dict:
    return {
        "file_type": getattr(profile, "file_type", ""),
        "architecture": getattr(profile, "architecture", ""),
        "tags": getattr(profile, "tags", []),
        "input_channels": getattr(profile, "input_channels", []),
        "comparison_hints": getattr(profile, "comparison_hints", []),
        "crypto_hints": getattr(profile, "crypto_hints", []),
        "encoding_hints": getattr(profile, "encoding_hints", []),
        "protections": getattr(profile, "protections", []),
        "solver_hints": getattr(profile, "solver_hints", []),
        "success_strings": getattr(profile, "success_strings", []),
        "failure_strings": getattr(profile, "failure_strings", []),
    }
