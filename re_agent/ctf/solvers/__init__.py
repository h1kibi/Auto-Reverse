"""
CTF Solver registry.
"""

from .static_flag import StaticFlagSolver
from .encoding import EncodingSolver
from .z3_constraints import Z3ConstraintSolver
from .z3_extractor import Z3ExtractorSolver
from .angr_path import AngrPathSolver
from .dynamic_trace import DynamicTraceSolver
from .brute_force import BruteForceSolver
from .patcher import PatcherSolver

__all__ = [
    "StaticFlagSolver",
    "EncodingSolver",
    "Z3ConstraintSolver",
    "Z3ExtractorSolver",
    "AngrPathSolver",
    "DynamicTraceSolver",
    "BruteForceSolver",
    "PatcherSolver",
]
