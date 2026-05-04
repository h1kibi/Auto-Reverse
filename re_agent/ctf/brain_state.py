"""
Brain State Machine - limits allowed tools by current state.
"""

from enum import Enum


class BrainState(str, Enum):
    INIT = "INIT"
    PROFILED = "PROFILED"
    EVIDENCE_READY = "EVIDENCE_READY"
    TOOL_RUNNING = "TOOL_RUNNING"
    CANDIDATE_FOUND = "CANDIDATE_FOUND"
    VALIDATED = "VALIDATED"
    UNSOLVED = "UNSOLVED"


def infer_next_state(current: BrainState, tool_name: str, result: dict) -> BrainState:
    data = result.get("data") or {}

    if tool_name == "profile_sample" and result.get("ok", True):
        return BrainState.PROFILED

    if tool_name in {"decode_strings", "crypto_recipe", "decode_e_bytearray_candidates"}:
        candidates = data.get("candidates") or []
        if candidates:
            return BrainState.CANDIDATE_FOUND

    if tool_name in {"rank_functions", "decompile_function", "extract_arrays_from_decompile"}:
        if data.get("found") is not False:
            return BrainState.EVIDENCE_READY

    if tool_name == "validate_candidate":
        if data.get("accepted") is True or data.get("final_verdict") == "solved":
            return BrainState.VALIDATED
        return BrainState.EVIDENCE_READY

    return current


STATE_ALLOWED_TOOLS = {
    BrainState.INIT: {"profile_sample"},
    BrainState.PROFILED: {"detect_packer", "detect_e_language", "decode_strings",
                           "rank_functions", "decompile_function", "read_artifact_range"},
    BrainState.EVIDENCE_READY: {"decode_strings", "crypto_recipe", "extract_e_bytearray",
                                  "decode_e_bytearray_candidates", "find_e_bytearray_refs",
                                  "decompile_function", "rank_functions", "extract_arrays_from_decompile",
                                  "run_python_snippet_sandbox", "run_z3"},
    BrainState.CANDIDATE_FOUND: {"validate_candidate"},
    BrainState.UNSOLVED: {"profile_sample", "detect_packer", "rank_functions"},
}
