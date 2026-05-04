"""
Z3 约束求解器

从 constraints.json 读取约束，用 Z3 求解 flag
"""

import json
from pathlib import Path
from typing import Any

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class Z3ConstraintSolver(BaseSolver):
    """Z3 约束求解器"""

    name = "z3_constraints"

    def score(self, ctx: SolverContext) -> float:
        constraints_path = ctx.output_dir / "constraints.json"
        return 0.9 if constraints_path.exists() else 0.0

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        path = ctx.output_dir / "constraints.json"
        if not path.exists():
            return []

        try:
            import z3  # noqa: F401
        except ImportError:
            return []

        spec = json.loads(path.read_text(encoding="utf-8"))
        flag = solve_constraint_spec(spec)

        if not flag:
            return []

        return [FlagCandidate(
            value=flag,
            source=self.name,
            confidence=0.9,
            evidence=[f"solved constraints from {path}"],
        )]


def solve_constraint_spec(spec: dict[str, Any]) -> str | None:
    """求解约束规范"""
    try:
        from z3 import BitVec, Solver, sat
    except ImportError:
        return None

    length = int(spec["length"])
    prefix = spec.get("prefix", "")
    suffix = spec.get("suffix", "")

    xs = [BitVec(f"x{i}", 8) for i in range(length)]
    s = Solver()

    # 可打印字符约束
    for x in xs:
        s.add(x >= 0x20, x <= 0x7e)

    # 前缀约束
    for i, ch in enumerate(prefix.encode()):
        s.add(xs[i] == ch)

    # 后缀约束
    if suffix:
        off = length - len(suffix)
        for i, ch in enumerate(suffix.encode()):
            s.add(xs[off + i] == ch)

    # 自定义约束
    for c in spec.get("constraints", []):
        lhs = _expr(c["left"], xs)
        rhs = _expr(c["right"], xs)
        op = c.get("op", "==")

        if op == "==":
            s.add(lhs == rhs)
        elif op == "!=":
            s.add(lhs != rhs)
        elif op == "<":
            s.add(lhs < rhs)
        elif op == "<=":
            s.add(lhs <= rhs)
        elif op == ">":
            s.add(lhs > rhs)
        elif op == ">=":
            s.add(lhs >= rhs)

    if s.check() != sat:
        return None

    m = s.model()
    return bytes([m.eval(x).as_long() for x in xs]).decode("utf-8", errors="replace")


def _expr(node: Any, xs: list):
    """解析表达式节点，兼容三种格式:

    1. legacy string: "x[0]"
    2. extractor dict: {"var": 0}, {"const": 42}
    3. op dict (args): {"op": "xor", "args": [{"var": 0}, 18]}
    4. op dict (left/right): {"op": "xor", "left": {"var": 0}, "right": 18}
    """
    from z3 import LShR

    if isinstance(node, int):
        return node

    if isinstance(node, str):
        import re
        # legacy: "x[0]"
        m = re.fullmatch(r"x\[(\d+)\]", node)
        if m:
            return xs[int(m.group(1))]
        if node.startswith("0x"):
            return int(node, 16)
        return int(node)

    if isinstance(node, dict):
        # {"var": 0}  (from z3_extractor)
        if "var" in node:
            return xs[int(node["var"])]

        # {"const": 42}
        if "const" in node:
            return int(node["const"])

        op = node.get("op")
        if not op:
            raise ValueError(f"expression dict missing op/var/const: {node}")

        # args style: {"op":"xor","args":[{"var":0},18]}
        if "args" in node:
            args = [_expr(a, xs) for a in node["args"]]
        # left/right style: {"op":"xor","left":{"var":0},"right":18}
        else:
            args = [
                _expr(node["left"], xs),
                _expr(node["right"], xs),
            ]

        if op == "add":
            return args[0] + args[1]
        if op == "sub":
            return args[0] - args[1]
        if op == "xor":
            return args[0] ^ args[1]
        if op == "and":
            return args[0] & args[1]
        if op == "or":
            return args[0] | args[1]
        if op == "mul":
            return args[0] * args[1]
        if op == "shl":
            return args[0] << args[1]
        if op == "shr":
            return LShR(args[0], args[1])

        raise ValueError(f"unsupported op: {op}")

    raise TypeError(f"unsupported expression node: {node!r}")
