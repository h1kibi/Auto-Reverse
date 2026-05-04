"""
API schemas - Pydantic request/response models for the FastAPI server.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    sample_path: str
    skip_ghidra: bool = False


class AnalyzeResponse(BaseModel):
    status: str
    sample_sha256: str
    report_path: str = ""
    report_url: str = ""
    function_count: int = 0
    message: str = ""


class SolveRequest(BaseModel):
    sample_path: str
    flag_regex: str = r"(flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}"
    skip_ghidra: bool = True
    timeout: int = 120
    verify: bool = Field(True, alias="do_verify")
    redact: bool = True
    enable_memory: bool = False
    enable_llm_planner: bool = False


class SolveResponse(BaseModel):
    status: str
    sample_sha256: str
    solved: bool = False
    flag: str | None = None
    method: str = ""
    candidates_count: int = 0
    summary: str = ""
    result_path: str = ""
    run_id: str = ""
    report_path: str = ""
    trace_path: str = ""


class AskRequest(BaseModel):
    sample_sha256: str
    question: str


class AskResponse(BaseModel):
    question: str
    answer: str


class MemorySearchRequest(BaseModel):
    query: str
    limit: int = Field(default=10, ge=1, le=50)


class MemorySearchResponse(BaseModel):
    query: str
    results: list[dict] = []
    count: int = 0
