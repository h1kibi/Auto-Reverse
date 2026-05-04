"""
LLM Reverse Runtime - experimental Brain loop.

GPT requirement: first version minimal, 4 actions only, max 5 steps.
Does NOT modify existing solve pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..core.observation import normalize_tool_result
from ..ctf.solvers.base import SolverContext
from ..ctf.validator import FlagValidator
from ..brain.actions import BrainResult, BrainAction
from ..brain.context import BrainContext
from ..brain.policy import PolicyGate, RuntimePolicy


class LLMReverseRuntime:
    def __init__(self, brain, tool_executor, context_builder,
                 max_steps: int = 5, policy: RuntimePolicy | None = None):
        self.brain = brain
        self.tool_executor = tool_executor
        self.context_builder = context_builder
        self.max_steps = max_steps
        self.gate = PolicyGate(policy)
        self.policy = policy or RuntimePolicy()

    def run(self, state: dict) -> dict:
        """Simple loop: context -> plan -> execute -> validate. Max 5 steps."""
        for step_idx in range(self.max_steps):
            ctx = self._build_context(state, step_idx)

            result = self.brain.plan(ctx)
            state.setdefault("llm_trace", []).append({
                "step": step_idx,
                "context": ctx.model_dump(),
                "brain_result": result.model_dump(),
            })

            if not result.actions or result.stop_reason:
                state["stop_reason"] = result.stop_reason or "no_actions"
                break

            action_count = 0
            for action in result.actions:
                if action_count >= self.policy.max_actions_per_step:
                    break

                if not self.gate.allow(action):
                    state.setdefault("rejected_actions", []).append(action.model_dump())
                    continue

                obs = self._dispatch_action(state, action)
                state.setdefault("observations", []).append(obs.model_dump())
                action_count += 1

                # Check for verified candidate
                for cand in obs.candidates:
                    if cand.get("verified") or cand.get("accepted"):
                        state["solved"] = True
                        state["winning_candidate"] = cand
                        return state

        return state

    def _build_context(self, state: dict, step_idx: int) -> BrainContext:
        return self.context_builder.build(
            state=state,
            evidence_brief=state.get("evidence_brief", {}),
            memory_hits=state.get("memory_hits", []),
            context_bundles=state.get("context_bundles", []),
            previous_observations=state.get("observations", [])[-5:],
        )

    def _dispatch_action(self, state: dict, action: BrainAction):
        """Execute a single BrainAction through existing tool/solver executors."""
        tool_name = action.name or ""
        params = action.params or {}

        if action.kind == "run_solver":
            return self._run_solver(state, tool_name, params)
        elif action.kind == "run_tool":
            return self._run_tool(state, tool_name, params)
        elif action.kind == "propose_candidate":
            return self._validate_candidate(state, params)
        elif action.kind == "request_context":
            return self._handle_request_context(state, params)
        else:
            return normalize_tool_result("unknown", {
                "summary": f"Unsupported action kind: {action.kind}",
                "status": "skipped",
            })

    def _handle_request_context(self, state: dict, params: dict) -> "RuntimeObservation":
        """Progressive Disclosure: LLM requests more context, system provides it."""
        from ..core.observation import RuntimeObservation
        function = params.get("function") or params.get("target", "")
        if not function:
            return RuntimeObservation(tool="request_context", status="skipped",
                summary="No function/target specified for context request")

        # Build context bundle on demand
        from .context_bundle import build_context_bundle
        profile = state.get("profile")
        out_dir = Path(state.get("output_dir", "artifacts"))
        bundle = build_context_bundle(function, profile, None, out_dir)

        state.setdefault("context_bundles", []).append(bundle.model_dump())

        return RuntimeObservation(
            tool="request_context",
            status="ok",
            summary=f"Context bundle for {function}",
            structured=bundle.model_dump(),
            evidence_ids=getattr(bundle, "evidence_ids", []),
        )

    def _run_solver(self, state: dict, name: str, params: dict) -> "RuntimeObservation":
        from ..core.observation import RuntimeObservation
        try:
            from ..ctf.pipeline import SOLVER_MAP
            from ..ctf.solvers.base import SolverContext
            if name not in SOLVER_MAP:
                return RuntimeObservation(tool=name, status="skipped",
                    summary=f"Unknown solver: {name}")
            solver = SOLVER_MAP[name]()
            profile = state.get("profile")
            out_dir = state.get("output_dir", Path("artifacts"))
            ctx = SolverContext(profile=profile, output_dir=Path(out_dir))
            raw = []
            for c in solver.solve(ctx):
                raw.append({"value": c.value, "source": c.source,
                            "confidence": c.confidence, "evidence": c.evidence})
            return RuntimeObservation(tool=name, status="ok",
                summary=f"{name}: {len(raw)} candidate(s)",
                candidates=raw, risk="executes_sample")
        except Exception as e:
            return RuntimeObservation(tool=name, status="error",
                summary=f"{name} failed: {e}", error=str(e))

    def _run_tool(self, state: dict, name: str, params: dict) -> "RuntimeObservation":
        from ..core.observation import RuntimeObservation
        try:
            from ..ctf.tools import build_default_ctf_registry, ArtifactStore, ToolExecutor
            sample_path = state.get("sample_path", "")
            out_dir = state.get("output_dir", "artifacts")
            store = ArtifactStore(Path(out_dir))
            registry = build_default_ctf_registry(store)
            executor = ToolExecutor(registry, store)
            if name not in registry.names():
                return RuntimeObservation(tool=name, status="skipped",
                    summary=f"Unknown tool: {name}")
            raw = executor.execute(name, {**params, "sample_path": str(sample_path)})
            return normalize_tool_result(name, raw)
        except Exception as e:
            return RuntimeObservation(tool=name, status="error",
                summary=f"{name} failed: {e}", error=str(e))

    def _validate_candidate(self, state: dict, params: dict) -> "RuntimeObservation":
        from ..core.observation import RuntimeObservation
        candidate = params.get("candidate") or params.get("value", "")
        if not candidate:
            return RuntimeObservation(tool="validate_candidate", status="skipped",
                summary="No candidate provided")
        try:
            sample = Path(state.get("sample_path", ""))
            out_dir = Path(state.get("output_dir", "artifacts"))
            validator = FlagValidator(timeout=10)
            vr = validator.validate(sample, candidate, output_dir=out_dir)
            return RuntimeObservation(tool="validate_candidate", status="ok",
                summary="accepted" if vr.accepted else "rejected",
                candidates=[{"value": candidate, "accepted": vr.accepted,
                             "confidence": vr.confidence, "mode": vr.mode}] if vr.accepted else [],
                structured={"accepted": vr.accepted, "mode": vr.mode,
                            "confidence": vr.confidence, "evidence": vr.evidence})
        except Exception as e:
            return RuntimeObservation(tool="validate_candidate", status="error",
                summary=f"Validation failed: {e}", error=str(e))
