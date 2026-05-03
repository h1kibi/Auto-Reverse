"""
angr 符号执行求解器

通过符号执行找到到达 success 分支的输入
"""

import re
from pathlib import Path

from .base import BaseSolver, SolverContext
from ..models import FlagCandidate


class AngrPathSolver(BaseSolver):
    """angr 符号执行求解器"""

    name = "angr_path"

    def score(self, ctx: SolverContext) -> float:
        """ELF/PE 且有 success string 时值得尝试"""
        if ctx.profile.file_type.upper() in {"ELF", "PE"} and ctx.profile.success_strings:
            return 0.85
        return 0.3

    def solve(self, ctx: SolverContext) -> list[FlagCandidate]:
        """执行符号执行求解"""
        try:
            import angr
            import claripy
        except ImportError:
            return []

        binary = str(ctx.profile.sample_path)
        project = angr.Project(binary, auto_load_libs=False)

        # 查找 success/failure 地址
        find_addrs = _find_string_xrefs(project, ctx.profile.success_strings)
        avoid_addrs = _find_string_xrefs(project, ctx.profile.failure_strings)

        if not find_addrs:
            return []

        # 创建符号输入
        max_len = 64
        sym = claripy.BVS("flag", max_len * 8)

        state = project.factory.entry_state(
            args=[binary, sym],
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )

        # 约束为可打印字符
        for b in sym.chop(8):
            state.solver.add(b >= 0x20)
            state.solver.add(b <= 0x7e)

        simgr = project.factory.simgr(state)

        try:
            simgr.explore(
                find=list(find_addrs)[:8],
                avoid=list(avoid_addrs)[:16],
                timeout=ctx.timeout,
            )
        except Exception:
            return []

        candidates: list[FlagCandidate] = []
        regex = re.compile(ctx.flag_regex, re.IGNORECASE)

        for found in simgr.found[:3]:
            try:
                raw = found.solver.eval(sym, cast_to=bytes)
                raw = raw.split(b"\x00", 1)[0]
                text = raw.decode("utf-8", errors="replace")

                m = regex.search(text)
                value = m.group(0) if m else text.strip()

                if value:
                    candidates.append(FlagCandidate(
                        value=value,
                        source=self.name,
                        confidence=0.88 if m else 0.7,
                        evidence=[
                            f"reached success address: {[hex(a) for a in list(find_addrs)[:4]]}",
                            f"avoided failure address: {[hex(a) for a in list(avoid_addrs)[:4]]}",
                        ],
                    ))
            except Exception:
                continue

        return candidates


def _find_string_xrefs(project, strings: list[str]) -> set[int]:
    """查找字符串引用地址（启发式）"""
    out = set()
    if not strings:
        return out

    for s in strings[:10]:
        bs = s.encode(errors="ignore")
        if not bs:
            continue

        for obj in project.loader.all_objects:
            try:
                data = obj.memory.load(obj.min_addr, obj.max_addr - obj.min_addr)
            except Exception:
                continue

            idx = data.find(bs)
            if idx < 0:
                continue

            str_addr = obj.min_addr + idx

            # 简单启发式：查找引用该地址的代码
            try:
                cfg = project.analyses.CFGFast(normalize=True)
                for func in cfg.kb.functions.values():
                    for block in func.blocks:
                        if hex(str_addr).encode() in block.bytes:
                            out.add(block.addr)
            except Exception:
                pass

    return out
