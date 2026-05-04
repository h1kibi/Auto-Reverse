"""
CTF Reverse 求解模块

Includes: profiler, strategy planner, solver pipeline, validator,
constraint extraction loop, learning reports, and agent tools.
"""

from .models import (
    ChallengeProfile, FlagCandidate, Candidate, SolverRun,
    SolveResult, EvidenceRef,
)
from .pipeline import solve_challenge
from .profiler import build_profile
from .validator import FlagValidator, OutputOracle, ValidationResult, OracleResult
from .strategy import (
    DeterministicPlanner, LLMPlanner, PlanMerger,
    StrategyPlan, PlanStep,
)
from .constraints_loop import (
    llm_propose_constraints, repair_constraints_with_llm,
    validate_candidate_full,
)
from .solve_config import SolveConfig
from .learning import generate_learning_report

__all__ = [
    "ChallengeProfile", "FlagCandidate", "Candidate", "SolverRun",
    "SolveResult", "EvidenceRef",
    "solve_challenge", "build_profile",
    "FlagValidator", "OutputOracle", "ValidationResult", "OracleResult",
    "DeterministicPlanner", "LLMPlanner", "PlanMerger",
    "StrategyPlan", "PlanStep",
    "llm_propose_constraints", "repair_constraints_with_llm",
    "validate_candidate_full", "SolveConfig",
    "generate_learning_report",
]
