# Auto-Reverse

**LLM-native reverse engineering runtime.**

Auto-Reverse gives LLMs reverse-engineering tools, compact evidence, memory playbooks, sandbox validation, and reproducible traces. It turns model reasoning into verified, reproducible, and learnable reverse workflows.

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-49%20passed-green)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.0-blue)]()

---

## Architecture: 8-Layer Evidence-Driven Design

```
                          solve_challenge(sample)
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                 ▼
           ① Intake/Triage   ② Evidence Graph   ③ Tool Bus
           ────────────────   ─────────────────  ──────────
           file/strings/pe/   functions/strings/  Ghidra/r2/angr/
           r2/hash/imports    imports/xrefs/cfg   strace/ltrace/gdb
                  │                │                │
                  └────────┬───────┴─────────┬──────┘
                           ▼                 ▼
                    ④ Strategy Planner  ⑤ Solver Layer
                    ──────────────────   ──────────────
                    Deterministic/LLM    static_flag/encoding/
                    + Memory plays       z3/z3_extract/angr/
                                         dynamic_trace/brute
                           │                 │
                           └────────┬────────┘
                                    ▼
                              ⑥ Validator
                              ───────────
                              Docker sandbox
                              + OutputOracle
                                    │
                                    ▼
                              ⑦ Report/Trace
                              ─────────────
                              solve_trace.jsonl
                              learning_report.md
                              reproduce.py
                                    │
                                    ▼
                              ⑧ Memory/Learning
                              ─────────────────
                              Playbook + SelfLesson
                              hybrid retrieval
```

## Quick Start

```bash
# Install
pip install -e .
pip install -e ".[ctf]"   # z3 + angr for constraint/symbolic solving

# One-command CTF solve
python -m re_agent solve ./challenge

# With memory-guided planning
python -m re_agent solve ./challenge --enable-memory --enable-llm-planner

# Custom flag regex
python -m re_agent solve ./challenge --flag-regex 'flag\{[^}]+\}'
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `solve` | One-shot CTF challenge solve with full pipeline |
| `analyze` | Static analysis: strings, imports, functions, YARA |
| `dynamic` | Docker sandbox dynamic analysis with strace/ltrace |
| `agent` | OpenAI Brain + local CTF tools (interactive) |
| `agent-tools` | Run individual CTF tools without OpenAI |
| `memory ingest` | Import community articles as Playbooks |
| `memory search` | Search memory for relevant tactics |
| `memory stats` | Memory store statistics |
| `memory reflect` | Generate SelfLesson from solve trace |
| `memory add-playbook` | Import Markdown experience as Playbook |
| `llm-solve` | LLM Brain-driven experimental solve (DeepSeek/GPT) |
| `serve` | Start FastAPI web API |

### API Server

```bash
python -m re_agent serve --port 8000
# Docs at http://localhost:8000/docs
```

#### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/analyze` | Static analysis of a binary |
| POST | `/upload-and-analyze` | Upload + analyze |
| POST | `/solve` | One-shot CTF solve |
| GET | `/report/{sha256}` | Get analysis report |
| POST | `/ask` | Q&A about analyzed sample |
| GET | `/functions/{sha256}` | List analyzed functions |

## Solvers (8)

All solvers produce candidates + evidence; only the Validator declares success.

| Solver | Trigger Signal | Method |
|--------|---------------|--------|
| `static_flag` | flag-like strings | Regex match in strings |
| `encoding` | base64/hex/xor/rot patterns | Beam search multi-layer decode |
| `dynamic_trace` | strcmp/memcmp imports | ltrace/Frida hook comparison APIs |
| `z3_constraints` | constraints.json present | Z3 BitVec constraint solving |
| `z3_extractor` | byte-wise comparison in code | Auto-extract + LLM draft constraints |
| `angr_path` | success/failure strings | Symbolic execution find/avoid |
| `brute_force` | small search space hints | Single-byte XOR + charset brute |
| `patcher` | anti_debug protections | Byte-level anti-debug patch |

## Project Structure

```
re_agent/
├── core/                       # Foundation: evidence, tool spec, policy
│   ├── evidence.py             EvidenceGraph + FunctionNode/StringNode/ImportNode
│   ├── toolspec.py             ToolSpec/ToolCall/ToolObservation/ToolRisk
│   ├── policy.py               ExecutionPolicy/check_policy
│   ├── runlog.py               SolveTrace (JSONL trace + Markdown report)
│   └── errors.py               Unified exception hierarchy
│
├── ctf/                        # CTF solve pipeline
│   ├── models.py               Candidate/SolverRun/SolveResult/EvidenceRef
│   ├── solve_config.py         SolveConfig (unified tuning parameters)
│   ├── profiler.py             Challenge profile builder (12 signal types)
│   ├── strategy.py             DeterministicPlanner + LLMPlanner + PlanMerger
│   ├── pipeline.py             Main solve loop: plan → execute → verify → reflect
│   ├── validator.py            Docker sandbox + OutputOracle (multi-signal)
│   ├── constraints_loop.py     LLM propose→validate→repair constraint loop
│   ├── learning.py             Educational Markdown report generator
│   ├── agent.py                SolverPlanner (LLM solver ordering)
│   ├── brain.py                OpenAI Brain function-calling loop
│   └── solvers/
│       ├── base.py             SolverContext (carries EvidenceGraph + memory_hits)
│       ├── static_flag.py      Direct string flag extraction
│       ├── encoding.py         Beam search decoder (base32/85/url/rot/xor)
│       ├── z3_constraints.py   Z3 constraint DSL solver
│       ├── z3_extractor.py     Auto constraint extraction from decompiled code
│       ├── angr_path.py        Symbolic execution (stdin/argv + libc hooks)
│       ├── dynamic_trace.py    ltrace + Frida probe-based comparison hooking
│       ├── brute_force.py      Small search space brute force
│       └── patcher.py          Byte-level anti-debug patch
│
├── memory/                     # Experience-driven solving
│   ├── schema.py               Playbook / SelfLesson structured models
│   ├── store.py                SQLite CRUD (playbooks + self_lessons tables)
│   ├── retriever.py            Hybrid retrieval (tag exact match + BM25)
│   └── ingest.py               Article → LLM distill → Playbook pipeline
│
├── api/                        # API server + MCP adapter
│   ├── server.py               FastAPI endpoints
│   ├── schemas.py              Pydantic request/response models
│   └── mcp.py                  MCP adapter (5 tools: analyze/solve/report/memory/list)
│
├── tools/                      # Analysis tools + multi-backend
│   ├── base.py                 Base tool class
│   ├── backend.py              ReverseBackend Protocol (Quick/Ghidra/R2)
│   ├── r2_tool.py              R2 headless (functions/strings/imports JSON)
│   ├── gdb_tool.py             GDB hook (strcmp/memcmp parameter capture)
│   ├── ghidra_tool.py          Ghidra headless decompilation
│   ├── pefile_tool.py          PE file analysis
│   ├── strings_tool.py         String extraction
│   ├── readelf_tool.py         ELF header analysis
│   ├── objdump_tool.py         Object dump
│   ├── yara_tool.py            YARA rule matching
│   ├── file_tool.py            File type detection
│   ├── strace_tool.py          System call tracing
│   ├── ltrace_tool.py          Library call tracing
│   └── frida_tool.py           Frida instrumentation
│
├── schema.py                   Core data types (AnalysisResult/ToolResult/Artifact)
├── pipeline.py                 Static analysis pipeline
├── analyzer.py                 Function analysis + LLM summarization
├── database.py                 SQLite analysis session storage
├── sandbox.py                  Docker sandbox (single-file mount, no shell)
├── llm.py                      LLM adapters (MiMo + OpenAI)
├── reporter.py                 Analysis report generator
├── qa.py                       Interactive Q&A system
└── cli.py                      CLI entry (9 commands)

tests/
├── challenges/                 Benchmark suite (5 toy challenges)
│   ├── static_flag/
│   ├── base64_flag/
│   ├── xor_single_byte/
│   ├── argv_strcmp/
│   └── stdin_memcmp/
├── test_solvers.py             Solver regression tests
├── test_new_modules.py         Constraints/learning/patcher/strategy tests
├── test_ctf_benchmark.py       Automated benchmark runner
├── test_function_ranking.py    Function analysis tests
├── test_artifacts.py           Artifact path tests
└── test_imports.py             Module import verification
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MIMO_API_KEY` | Xiaomi MiMo API key (for LLM functions) |
| `OPENAI_API_KEY` | OpenAI API key (for LLM functions) |
| `DEEPSEEK_API_KEY` | DeepSeek API key (for LLM Brain) |
| `DEEPSEEK_BASE_URL` | DeepSeek API base URL |
| `GHIDRA_HOME` | Ghidra installation path |

## LLM Brain Runtime

Auto-Reverse provides an LLM-native reverse engineering runtime that gives models structured tools, evidence, and memory — without burning tokens on raw artifacts.

```bash
# LLM Brain experimental solve (DeepSeek)
python -m re_agent llm-solve ./challenge --brain deepseek --max-steps 5

# With dynamic tools enabled
python -m re_agent llm-solve ./challenge --brain deepseek --allow-dynamic

# Import your refined reverse experience
python -m re_agent memory add-playbook ./my_tactics.md --db memory.db
```

### Brain Architecture

```
LLM (DeepSeek/GPT/Claude)
  ↓ returns BrainAction JSON
BrainContextBuilder         ← token-budgeted evidence assembly
  ↓ Profile(300t) + Memory(800t) + Bundles(1500t) + Observations(700t)
PolicyGate                  ← risk-based tool gating
  ↓
Tool Runtime                ← existing solvers + sandbox validator
  ↓ produces RuntimeObservation
Validator Gate              ← only validator declares "solved"
```

### Three-Mode Benchmark

```bash
# Compare: LLM-only vs Auto-Reverse (no brain) vs Auto-Reverse + Brain
re-agent benchmark tests/challenges --modes llm-only,auto-no-brain,auto-brain --brain deepseek
```

| Mode | Description | Tokens |
|------|-------------|--------|
| `llm-only` | LLM receives evidence brief, outputs candidate directly | ~20K-40K |
| `auto-no-brain` | Existing solver pipeline (zero LLM tokens) | 0 |
| `auto-brain` | LLM plans + tools execute + validator verifies | ~10K-15K |

## Design Principles

1. **Deterministic-first**: Tools produce deterministic evidence; LLM only assists planning and summarization.
2. **Evidence traceable**: Every solver decision references evidence IDs (strings/imports/xrefs/decompiles).
3. **Validator gate**: Only the sandbox validator declares `solved`; solvers only produce candidates + confidence.
4. **Security default-deny**: Network disabled, host fs read-only, no shell user-input concatenation, single-file container mounts.
5. **Reproducible runs**: Each solve produces `runs/<run_id>/` with `manifest.json`, `solve_trace.jsonl`, `report.md`, `candidates.json`, `reproduce.py`, and artifacts.

## License

MIT
