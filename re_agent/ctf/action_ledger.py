"""
Action Ledger - prevent repeating failed actions under same evidence.

hana fix: static_flag failed 5 times → blocked on repeat attempt 2-5.
"""

import hashlib
import json

from .brain.actions import BrainAction


def stable_action_key(action, state: dict) -> str:
    payload = {
        "kind": getattr(action, "kind", action.get("kind", "")),
        "name": getattr(action, "name", action.get("name", "")),
        "sample_sha256": state.get("sample_sha256", ""),
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def was_action_failed(state: dict, action) -> bool:
    key = stable_action_key(action, state)
    return key in state.get("failed_action_keys", set())


def record_action_result(state: dict, action, obs) -> None:
    key = stable_action_key(action, state)
    is_failure = (
        getattr(obs, "status", obs.get("status", "")) in {"error", "timeout"}
        or (getattr(obs, "status", obs.get("status", "")) == "ok"
            and not getattr(obs, "candidates", obs.get("candidates", [])))
    )
    if is_failure:
        state.setdefault("failed_action_keys", set()).add(key)

    state.setdefault("action_history", []).append({
        "key": key,
        "kind": getattr(action, "kind", ""),
        "name": getattr(action, "name", ""),
        "status": getattr(obs, "status", obs.get("status", "")),
    })
