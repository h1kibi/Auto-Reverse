"""
CLI 入口 - 命令行界面

用法:
    python -m re_agent analyze <sample_path>           # 静态分析
    python -m re_agent dynamic <sample_path>           # 动态分析（需确认）
    python -m re_agent ask <sha256> "问题"              # 问答
    python -m re_agent serve                            # 启动 API
    python -m re_agent functions <sha256>               # 列出函数
"""

import argparse
import json
import logging
import sys
from pathlib import Path

from .pipeline import run_analysis
from .reporter import ReportGenerator
from .database import Database
from .analyzer import FunctionAnalyzer
from .qa import QASystem
from .llm import LLMFactory
from .artifacts import compute_sha256, sample_artifact_dir


def setup_logging(verbose: bool = False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def get_llm_client():
    """获取 LLM 客户端"""
    import os
    api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    if os.getenv("MIMO_API_KEY"):
        return LLMFactory.create("mimo", api_key=api_key)
    else:
        return LLMFactory.create("openai", api_key=api_key)


def cmd_analyze(args):
    """执行静态分析命令"""
    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"Error: Sample file not found: {sample_path}")
        return 1

    if not sample_path.is_file():
        print(f"Error: Not a file: {sample_path}")
        return 1

    # 计算 SHA256 并确定输出目录
    sha256 = compute_sha256(sample_path)
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = sample_artifact_dir("artifacts/results", sha256)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Reverse-Agent v0.3.0 - 静态分析 + 函数分析")
    print(f"{'='*60}")
    print(f"样本: {sample_path}")
    print(f"SHA256: {sha256}")
    print(f"输出: {output_dir}")
    print(f"{'='*60}")

    # Stage 1: 静态分析
    print("\n[Stage 1] 静态分析...")
    try:
        result = run_analysis(
            sample_path=str(sample_path),
            output_dir=str(output_dir),
            ghidra_home=args.ghidra_home,
            yara_rules_dir=args.yara_rules,
            skip_ghidra=args.skip_ghidra,
        )
    except Exception as e:
        print(f"\nError during analysis: {e}")
        logging.exception("Analysis failed")
        return 1

    # 生成报告
    print("\n生成报告...")
    reporter = ReportGenerator(str(output_dir))
    report = reporter.generate(result)

    # Stage 2: 函数分析
    if not args.skip_function_analysis:
        print("\n[Stage 2] 函数分析...")
        db = Database(str(output_dir / "database.db"))
        llm = get_llm_client()

        if llm:
            print("  使用 LLM 生成函数摘要...")
        else:
            print("  未配置 LLM API，使用启发式摘要...")

        analyzer = FunctionAnalyzer(db, llm)
        functions = analyzer.analyze_sample(result)
        db.close()

        print(f"  分析了 {len(functions)} 个函数")

    # 打印摘要
    print(f"\n{'='*60}")
    print("静态分析完成!")
    print(f"{'='*60}")
    print(f"样本 SHA256: {result.sample.sha256}")
    print(f"\n报告: {output_dir / 'report.md'}")
    print(f"数据库: {output_dir / 'database.db'}")
    print(f"{'='*60}")

    # 提示下一步
    print(f"\n下一步：")
    print(f"  动态分析: python -m re_agent dynamic {sample_path} --confirm")
    print(f"  查看函数: python -m re_agent functions {result.sample.sha256[:16]}...")
    print(f"  问答: python -m re_agent ask {result.sample.sha256[:16]}... \"哪个函数处理网络？\"")

    return 0


def cmd_dynamic(args):
    """执行动态分析命令"""
    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"Error: Sample file not found: {sample_path}")
        return 1

    # 计算 SHA256
    sha256 = compute_sha256(sample_path)

    # 确定输出目录
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = sample_artifact_dir("artifacts/results", sha256) / "dynamic"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Reverse-Agent v0.3.0 - 动态分析")
    print(f"{'='*60}")
    print(f"样本: {sample_path}")
    print(f"SHA256: {sha256}")
    print(f"输出: {output_dir}")
    print(f"{'='*60}")

    # 安全警告
    if not args.confirm:
        print("\n" + "!"*60)
        print("警告：动态分析将在沙箱中执行样本！")
        print("!"*60)
        print("\n安全措施：")
        print("  - 执行环境: Docker container")
        print("  - 网络: disabled")
        print("  - rootfs: read-only")
        print("  - capabilities: drop ALL")
        print(f"  - 资源限制: memory=512m, cpus=1, pids=128, timeout={args.timeout}s")
        print("\n请确认后添加 --confirm 参数重新运行")
        return 0

    print("\n[Stage 3] 动态分析...")
    print("  安全模式: Docker 沙箱执行")

    from .dynamic_pipeline import run_dynamic_analysis

    result = run_dynamic_analysis(
        sample_path=str(sample_path),
        sample_sha256=sha256,
        output_dir=str(output_dir),
        confirmed=True,
        enable_strace=not args.no_strace,
        enable_ltrace=not args.no_ltrace,
        enable_frida=not args.no_frida,
        timeout=args.timeout,
    )

    # 打印结果
    print(f"\n{'='*60}")
    print("动态分析完成!")
    print(f"{'='*60}")
    print(f"\n摘要:")
    print(result.summary)
    print(f"\n结果目录: {output_dir}")

    return 0


def cmd_functions(args):
    """列出函数"""
    db = Database(args.db)

    if args.tag:
        functions = db.get_functions_by_tag(args.sha256, args.tag)
        print(f"标签 '{args.tag}' 的函数 ({len(functions)} 个):")
    else:
        functions = db.get_functions_by_sample(args.sha256)
        print(f"所有函数 ({len(functions)} 个):")

    print()
    for i, func in enumerate(functions[:20], 1):
        tags = ", ".join(func.behavior_tags) if func.behavior_tags else "无"
        print(f"{i:3}. {func.name:<30} [{tags}]")
        if func.summary:
            print(f"     {func.summary[:80]}...")

    if len(functions) > 20:
        print(f"\n... 还有 {len(functions) - 20} 个函数")

    db.close()
    return 0


def cmd_ask(args):
    """问答"""
    db = Database(args.db)
    llm = get_llm_client()

    if not llm:
        print("Error: 未配置 LLM API")
        print("请设置 MIMO_API_KEY 或 OPENAI_API_KEY 环境变量")
        db.close()
        return 1

    qa = QASystem(db, llm)
    answer = qa.ask(args.sha256, args.question)

    print(f"\n问题: {args.question}")
    print(f"\n{'='*60}")
    print(answer)
    print(f"{'='*60}")

    db.close()
    return 0


def cmd_serve(args):
    """启动 API 服务"""
    from .api import start_api
    print(f"启动 Reverse-Agent API 服务...")
    print(f"地址: http://{args.host}:{args.port}")
    print(f"文档: http://{args.host}:{args.port}/docs")
    start_api(host=args.host, port=args.port)
    return 0


def cmd_solve(args):
    """CTF 求解命令"""
    from .artifacts import compute_sha256, sample_artifact_dir
    from .ctf.pipeline import solve_challenge
    from .ctf.solve_config import SolveConfig

    sample = Path(args.sample)
    if not sample.exists():
        print(f"Error: Sample not found: {sample}")
        return 1

    sha256 = compute_sha256(sample)
    output_dir = Path(args.output) if args.output else sample_artifact_dir("artifacts/results", sha256)

    skip_ghidra = args.skip_ghidra
    if args.deep:
        skip_ghidra = False
    if args.quick:
        skip_ghidra = True

    print(f"{'='*60}")
    print(f"Reverse-Agent CTF Solver")
    print(f"{'='*60}")
    print(f"样本: {sample}")
    print(f"SHA256: {sha256}")
    print(f"输出: {output_dir}")
    print(f"Flag Regex: {args.flag_regex}")
    print(f"Mode: {'Deep' if not skip_ghidra else 'Quick'}")
    print(f"{'='*60}")

    result = solve_challenge(
        sample_path=str(sample),
        output_dir=str(output_dir),
        flag_regex=args.flag_regex,
        skip_ghidra=skip_ghidra,
        timeout=args.timeout,
        validate=not args.no_validate,
        enable_memory=args.enable_memory,
        enable_llm_planner=args.enable_llm_planner,
        config=SolveConfig(
            flag_regex=args.flag_regex,
            skip_ghidra=skip_ghidra,
            max_total_seconds=args.timeout,
            verify=not args.no_validate,
            enable_memory=args.enable_memory,
            enable_llm_planner=args.enable_llm_planner,
            enable_dynamic=args.enable_dynamic,
            redact_candidates_in_logs=args.redact_candidates,
            memory_db_path=args.memory_db,
            allowed_input_channels=args.allowed_input_channels.split(","),
        ),
    )

    print(f"\n{'='*60}")
    print(f"Solve Status: {result.status}")
    print(f"SHA256: {result.sha256}")
    print(f"Method: {result.method or '-'}")

    if result.best_flag:
        print(f"FLAG: {result.best_flag}")
    else:
        print("FLAG: <not found>")

    if result.candidates:
        print(f"\nCandidates ({len(result.candidates)}):")
        for i, c in enumerate(result.candidates[:5], 1):
            verified = "[VERIFIED]" if c.verified else ""
            print(f"  {i}. {c.value} (confidence: {c.confidence:.0%}) {verified}")

    print(f"\nResult: {output_dir / 'solve_result.json'}")
    print(f"{'='*60}")

    return 0 if result.status == "solved" else 2


def _load_json_object(raw: str, source: str) -> dict:
    """解析 JSON object"""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {source}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"{source} must be a JSON object")

    return data


def _load_agent_tool_extra_args(args) -> dict:
    """加载 --args-file 和 --args，并按优先级 merge"""
    payload = {}

    if getattr(args, "args_file", None):
        path = Path(args.args_file).resolve()
        if not path.exists():
            raise ValueError(f"--args-file not found: {path}")
        payload.update(
            _load_json_object(path.read_text(encoding="utf-8"), f"--args-file {path}")
        )

    if getattr(args, "args_json", None):
        payload.update(_load_json_object(args.args_json, "--args"))

    return payload


SAMPLE_PATH_TOOLS = {
    "profile_sample",
    "validate_candidate",
    "decode_strings",
    "run_angr_stdout",
    "run_z3",
    "run_python_snippet_sandbox",
}


def _build_legacy_agent_tool_payload(args, sample: Path, registry) -> dict:
    """兼容 PR-4/PR-6 的旧参数写法"""
    if args.tool == "profile_sample":
        return {"sample_path": str(sample), "skip_ghidra": args.skip_ghidra}

    if args.tool == "validate_candidate":
        if not args.candidate:
            raise ValueError(
                "validate_candidate requires --candidate or --args '{\"candidate\":\"...\"}'"
            )
        return {"sample_path": str(sample), "candidate": args.candidate, "timeout": args.timeout}

    if args.tool == "decompile_function":
        return {"function": args.function, "max_lines": args.max_lines}

    if args.tool == "decode_strings":
        return {"sample_path": str(sample), "flag_regex": args.flag_regex, "timeout": args.timeout}

    if args.tool == "rank_functions":
        return {"max_functions": args.max_functions}

    if args.tool in registry.names():
        return {}

    raise ValueError(f"unknown tool: {args.tool}. Available: {', '.join(registry.names())}")


def _finalize_agent_tool_payload(tool_name: str, payload: dict, sample: Path) -> dict:
    """补齐通用字段"""
    if tool_name in SAMPLE_PATH_TOOLS:
        payload.setdefault("sample_path", str(sample))
    return payload


def cmd_agent_tools(args):
    """运行本地 CTF Agent 工具"""
    from .ctf.tools import ArtifactStore, ToolExecutor, build_default_ctf_registry

    sample = Path(args.sample).resolve()
    if not sample.exists():
        print(f"Error: Sample not found: {sample}")
        return 1

    output_dir = Path(args.output or "artifacts/agent_test").resolve()
    store = ArtifactStore(output_dir)
    registry = build_default_ctf_registry(store)
    executor = ToolExecutor(registry, store)

    try:
        base_payload = _build_legacy_agent_tool_payload(args, sample, registry)
        extra_payload = _load_agent_tool_extra_args(args)

        payload = {**base_payload, **extra_payload}
        payload = _finalize_agent_tool_payload(args.tool, payload, sample)

    except Exception as e:
        print(f"Error: {e}")
        return 1

    if getattr(args, "show_payload", False):
        print("Final tool payload:")
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        print()

    result = executor.execute(args.tool, payload)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nArtifacts: {output_dir}")

    return 0 if result.get("ok") else 2


def cmd_agent(args):
    """运行 OpenAI Brain + 本地 CTF 工具"""
    import json
    import os
    from .ctf.brain import OpenAIBrain
    from .ctf.tools import ArtifactStore

    # 检查 API Key
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY is not set")
        print("Please set it: export OPENAI_API_KEY='...'")
        return 1

    sample = Path(args.sample).resolve()
    if not sample.exists():
        print(f"Error: Sample not found: {sample}")
        return 1

    output_dir = Path(args.output or f"artifacts/agent_{sample.stem}").resolve()
    store = ArtifactStore(output_dir)

    print(f"{'='*60}")
    print(f"Auto-Reverse Agent")
    print(f"{'='*60}")
    print(f"Sample: {sample}")
    print(f"Goal: {args.goal}")
    print(f"Model: {args.model}")
    print(f"Max steps: {args.max_steps}")
    print(f"Output: {output_dir}")
    print(f"{'='*60}")

    try:
        brain = OpenAIBrain(
            store=store,
            model=args.model,
            max_steps=args.max_steps,
        )
    except Exception as e:
        print(f"Error initializing OpenAI Brain: {e}")
        return 1

    print("\nRunning agent...\n")

    try:
        result = brain.run(
            sample_path=str(sample),
            goal=args.goal,
        )
    except Exception as e:
        print(f"Error running OpenAI Brain: {e}")
        return 1

    print(result.get("final_answer") or "")
    print()
    print(json.dumps(
        {
            "status": result.get("status"),
            "solved": result.get("solved"),
            "flag": result.get("flag"),
            "artifacts": result.get("artifacts"),
            "output_dir": str(output_dir),
        },
        ensure_ascii=False,
        indent=2,
    ))

    return 0 if result.get("solved") else 2


def cmd_memory(args):
    """记忆管理命令"""
    import json
    import uuid
    from pathlib import Path

    action = getattr(args, "memory_action", None)
    if not action:
        print("Usage: re-agent memory {ingest|search|stats|reflect}")
        return 1

    db_path = getattr(args, "db", "memory.db")

    if action == "ingest":
        return _cmd_memory_ingest(args, db_path)
    elif action == "search":
        return _cmd_memory_search(args, db_path)
    elif action == "stats":
        return _cmd_memory_stats(db_path)
    elif action == "reflect":
        return _cmd_memory_reflect(args, db_path)
    elif action == "list":
        return _cmd_memory_list(args, db_path)
    elif action == "show":
        return _cmd_memory_show(args, db_path)
    elif action == "add-playbook":
        return _cmd_memory_add_playbook(args, db_path)
    else:
        print(f"Unknown memory action: {action}")
        return 1


def _cmd_memory_ingest(args, db_path):
    from pathlib import Path
    from .memory.store import MemoryStore
    from .memory.ingest import ingest_and_distill

    path = Path(args.path)
    if not path.exists():
        print(f"File not found: {path}")
        return 1

    try:
        store = MemoryStore(db_path)
        use_llm = getattr(args, "use_llm", False)

        pb = ingest_and_distill(
            path=path, store=store,
            source_url=getattr(args, "source_url", ""),
            source_name=getattr(args, "source_name", "manual"),
            use_llm=use_llm,
        )

        if pb:
            print(f"Ingested playbook: {pb.title} (id={pb.id}, tags={pb.pattern_tags})")
            if use_llm:
                print(f"  Signals: {pb.signals[:5]}")
                print(f"  Steps: {len(pb.tactic_steps)}")
        else:
            print("Failed to ingest playbook.")
            return 1

        store.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_search(args, db_path):
    from .memory.store import MemoryStore
    from .memory.retriever import MemoryRetriever

    try:
        store = MemoryStore(db_path)
        retriever = MemoryRetriever(store)
        results = retriever.search(args.query, limit=args.limit)

        print(f"\nMemory search results for '{args.query}':")
        print(f"{'='*60}")
        for i, r in enumerate(results, 1):
            print(f"{i}. [{r['type']}] {r['title']}")
            if r.get("tags"):
                print(f"   Tags: {', '.join(r['tags'][:5])}")
            if r.get("tactic_steps"):
                for step in r["tactic_steps"][:3]:
                    print(f"   - {step[:80]}")
            print()
        if not results:
            print("  (no results)")
        store.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_stats(db_path):
    from .memory.store import MemoryStore

    try:
        store = MemoryStore(db_path)
        stats = store.stats()
        print(f"\nMemory Store Stats:")
        print(f"  Playbooks: {stats['playbooks']}")
        print(f"  Self-lessons: {stats['self_lessons']}")
        print(f"  Solved lessons: {stats['solved_lessons']}")
        store.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_reflect(args, db_path):
    from .memory.schema import SelfLesson
    from .memory.store import MemoryStore

    try:
        store = MemoryStore(db_path)
        lesson = SelfLesson(
            id=f"lesson_{uuid.uuid4().hex[:12]}",
            challenge_sha256=args.sha256,
            solved=False if not args.solver else True,
            verified=False if not args.solver else True,
            winning_solver=args.solver or None,
            key_signals=["manual_reflection"],
            generalized_pattern=f"Manual reflection for {args.sha256[:16]}",
            confidence=0.3,
        )
        store.add_self_lesson(lesson)
        store.close()
        print(f"Added self-lesson for {args.sha256[:16]}...")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_list(args, db_path):
    from .memory.store import MemoryStore
    try:
        store = MemoryStore(db_path)
        if getattr(args, "tag", None):
            pbs = store.search_playbooks_by_tag([args.tag], limit=args.limit)
        else:
            pbs = store.list_playbooks(limit=args.limit)
        print(f"\nPlaybooks ({len(pbs)}):")
        for pb in pbs:
            print(f"  {pb.id} | {pb.title} | tags={pb.pattern_tags[:5]}")
        store.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_show(args, db_path):
    from .memory.store import MemoryStore
    try:
        store = MemoryStore(db_path)
        pb = store.get_playbook(args.id)
        if not pb:
            print(f"Not found: {args.id}")
            return 1
        print(f"\nTitle: {pb.title}")
        print(f"Source: {pb.source_name} {pb.source_url}")
        print(f"Tags: {pb.pattern_tags}")
        print(f"Signals: {pb.signals}")
        print(f"Steps:")
        for s in pb.tactic_steps[:10]:
            print(f"  - {s}")
        print(f"Pitfalls: {pb.pitfalls}")
        store.close()
    except Exception as e:
        print(f"Error: {e}")
        return 1
    return 0


def _cmd_memory_add_playbook(args, db_path):
    from pathlib import Path
    from .memory.store import MemoryStore
    from .memory.playbook_import import parse_playbook_markdown
    path = Path(args.path)
    if not path.exists():
        print(f"File not found: {path}"); return 1
    try:
        store = MemoryStore(db_path)
        pb = parse_playbook_markdown(path)
        store.add_playbook(pb)
        store.close()
        print(f"Added playbook: {pb.title} (id={pb.id})")
        print(f"  Tags: {pb.pattern_tags}")
        print(f"  Signals: {pb.signals[:5]}")
        print(f"  Steps: {len(pb.tactic_steps)}")
    except Exception as e:
        print(f"Error: {e}"); return 1
    return 0


def cmd_llm_solve(args):
    """LLM Brain 驱动实验性求解"""
    import json
    from pathlib import Path
    from .artifacts import compute_sha256, sample_artifact_dir
    from .ctf.pipeline import run_analysis
    from .ctf.profiler import build_profile
    from .core.evidence import EvidenceGraph
    from .ctf.context_bundle import build_evidence_brief
    from .ctf.llm_runtime import LLMReverseRuntime
    from .brain.context_builder import BrainContextBuilder
    from .brain.policy import RuntimePolicy

    sample = Path(args.sample).resolve()
    if not sample.exists():
        print(f"Error: Sample not found: {sample}"); return 1

    sha256 = compute_sha256(sample)
    output_dir = Path(args.output) if args.output else sample_artifact_dir("artifacts/results", sha256)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Auto-Reverse LLM Brain Solve")
    print(f"{'='*60}")
    print(f"Sample: {sample}")
    print(f"Brain: {args.brain}")
    print(f"Max steps: {args.max_steps}")
    print(f"Output: {output_dir}")
    print(f"{'='*60}")

    # Pre-pass (no LLM tokens)
    analysis = run_analysis(sample_path=str(sample), output_dir=str(output_dir), skip_ghidra=True)
    profile = build_profile(analysis)
    evidence = EvidenceGraph.from_analysis(analysis)
    evidence_brief = build_evidence_brief(profile)

    # Packer detection - add to profile dict for Brain context
    try:
        from .ctf.packer_detect import detect_packer
        packer = detect_packer(sample)
        profile_dict["packer"] = packer.model_dump()
        if packer.is_packed:
            print(f"  Packer detected: {packer.packer} (confidence={packer.confidence:.2f})")
    except Exception:
        pass

    # Convert profile to serializable dict
    profile_dict = {
        "file_type": getattr(profile, "file_type", ""),
        "architecture": getattr(profile, "architecture", ""),
        "tags": getattr(profile, "tags", []),
        "input_channels": getattr(profile, "input_channels", []),
        "comparison_hints": getattr(profile, "comparison_hints", []),
        "encoding_hints": getattr(profile, "encoding_hints", []),
        "crypto_hints": getattr(profile, "crypto_hints", []),
        "protections": getattr(profile, "protections", []),
        "solver_hints": getattr(profile, "solver_hints", []),
        "success_strings": getattr(profile, "success_strings", []),
        "failure_strings": getattr(profile, "failure_strings", []),
        "sha256": getattr(profile, "sha256", ""),
    }

    # Memory
    memory_hits = []
    try:
        from .memory.store import MemoryStore
        from .memory.retriever import MemoryRetriever
        store = MemoryStore("memory.db")
        retriever = MemoryRetriever(store)
        memory_hits = retriever.retrieve_for_profile(profile_dict, top_k=3)
        store.close()
    except Exception:
        pass

    # Brain
    try:
        if args.brain == "deepseek":
            from .brain.deepseek import DeepSeekBrain
            brain = DeepSeekBrain(model=args.model or "deepseek-chat")
        elif args.brain == "mimo":
            from .brain.deepseek import MiMoBrain
            brain = MiMoBrain(model=args.model or "mimo-v2.5-pro")
        else:
            from .brain.deepseek import OpenAIBrain
            brain = OpenAIBrain(model=args.model or "gpt-4o")
    except Exception as e:
        print(f"Error initializing brain: {e}")
        print("Set DEEPSEEK_API_KEY or OPENAI_API_KEY")
        return 1

    # Runtime
    policy = RuntimePolicy(allow_dynamic=args.allow_dynamic, max_steps=args.max_steps)
    builder = BrainContextBuilder(token_budget=4096)
    runtime = LLMReverseRuntime(brain=brain, tool_executor=None,
                                 context_builder=builder, max_steps=args.max_steps,
                                 policy=policy)

    state = {
        "run_id": output_dir.name, "sample_path": str(sample),
        "sample_sha256": sha256, "output_dir": str(output_dir),
        "profile": profile_dict, "evidence_brief": evidence_brief.model_dump(),
        "memory_hits": memory_hits, "context_bundles": [],
        "observations": [], "budget_seconds": 300,
        "failed_action_keys": [], "packer_profile": profile_dict.get("packer", {}),
    }

    print("\nRunning LLM Brain loop...\n")
    result_state = runtime.run(state)

    # Write outputs
    trace_path = output_dir / "llm_trace.jsonl"
    with trace_path.open("w", encoding="utf-8") as f:
        for entry in result_state.get("llm_trace", []):
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    (output_dir / "final_state.json").write_text(
        json.dumps(result_state, ensure_ascii=False, indent=2), encoding="utf-8")

    total_est_tokens = sum(
        e.get("context", {}).get("estimated_tokens", 0)
        for e in result_state.get("llm_trace", [])
    )
    (output_dir / "brain_metrics.json").write_text(json.dumps({
        "brain": args.brain,
        "model": args.model or "default",
        "steps": len(result_state.get("llm_trace", [])),
        "observations": len(result_state.get("observations", [])),
        "estimated_context_tokens": total_est_tokens,
        "solved": result_state.get("solved", False),
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    solved = result_state.get("solved", False)
    winning = result_state.get("winning_candidate", {})
    print(f"\n{'='*60}")
    print(f"LLM Solve: {'SOLVED' if solved else 'NOT SOLVED'}")
    print(f"{'='*60}")
    if winning:
        print(f"Candidate: {winning.get('value', '?')[:80]}")
    print(f"Steps: {len(result_state.get('llm_trace', []))}")
    print(f"Observations: {len(result_state.get('observations', []))}")
    print(f"Trace: {trace_path}")
    print(f"{'='*60}")

    return 0 if solved else 2


def cmd_benchmark(args):
    """三模式 benchmark runner"""
    from pathlib import Path
    from .ctf.benchmark import run_benchmark, print_benchmark_report
    modes = args.modes.split(",") if args.modes else ["auto-no-brain"]
    result = run_benchmark(modes=modes, brain_name=args.brain)
    print_benchmark_report(result)
    return 0


def cmd_snapshot(args):
    """Export deterministic Evidence Snapshot (kernagent-style)."""
    import json
    from pathlib import Path
    from .ctf.pipeline import run_analysis
    from .ctf.profiler import build_profile
    from .core.evidence import EvidenceGraph

    sample = Path(args.sample).resolve()
    if not sample.exists():
        print(f"Error: Sample not found: {sample}"); return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"Building snapshot for: {sample}")
    analysis = run_analysis(sample_path=str(sample), output_dir=str(out), skip_ghidra=True)
    evidence = EvidenceGraph.from_analysis(analysis)

    snap = evidence.to_snapshot()
    sid = evidence.snapshot_id()

    (out / "meta.json").write_text(json.dumps({
        "schema_version": "evidence-snapshot-v1",
        "sample_sha256": analysis.sample.sha256,
        "snapshot_id": sid,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    (out / "functions.jsonl").write_text("\n".join(
        json.dumps(f, ensure_ascii=False) for f in snap.get("functions", [])
    ), encoding="utf-8")

    (out / "strings.jsonl").write_text("\n".join(
        json.dumps(s, ensure_ascii=False) for s in snap.get("strings", [])
    ), encoding="utf-8")

    (out / "imports_exports.json").write_text(json.dumps(
        snap.get("imports", []), ensure_ascii=False, indent=2
    ), encoding="utf-8")

    (out / "snapshot_id.txt").write_text(sid)
    (out / "evidence_index.json").write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Snapshot: {out}")
    print(f"Snapshot ID: {sid}")
    print(f"Functions: {len(snap.get('functions',[]))}")
    print(f"Strings: {len(snap.get('strings',[]))}")
    print(f"Imports: {len(snap.get('imports',[]))}")
    return 0


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="Reverse-Agent: 自动化逆向分析 Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细日志",
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # ========== analyze 命令 ==========
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="静态分析",
    )
    analyze_parser.add_argument(
        "sample",
        help="样本文件路径",
    )
    analyze_parser.add_argument(
        "-o", "--output",
        help="输出目录 (默认: artifacts/results/<sha_prefix>/<sha256>)",
    )
    analyze_parser.add_argument(
        "--ghidra-home",
        help="Ghidra 安装路径",
    )
    analyze_parser.add_argument(
        "--yara-rules",
        help="YARA 规则目录",
    )
    analyze_parser.add_argument(
        "--skip-ghidra",
        action="store_true",
        help="跳过 Ghidra 分析",
    )
    analyze_parser.add_argument(
        "--skip-function-analysis",
        action="store_true",
        help="跳过函数分析",
    )

    # ========== dynamic 命令 ==========
    dynamic_parser = subparsers.add_parser(
        "dynamic",
        help="动态分析（需确认）",
    )
    dynamic_parser.add_argument(
        "sample",
        help="样本文件路径",
    )
    dynamic_parser.add_argument(
        "-o", "--output",
        help="输出目录 (默认: artifacts/results/<sha_prefix>/<sha256>/dynamic)",
    )
    dynamic_parser.add_argument(
        "--confirm",
        action="store_true",
        help="确认执行动态分析",
    )
    dynamic_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="执行超时（秒）",
    )
    dynamic_parser.add_argument(
        "--no-strace",
        action="store_true",
        help="禁用 strace",
    )
    dynamic_parser.add_argument(
        "--no-ltrace",
        action="store_true",
        help="禁用 ltrace",
    )
    dynamic_parser.add_argument(
        "--no-frida",
        action="store_true",
        help="禁用 Frida",
    )

    # ========== functions 命令 ==========
    functions_parser = subparsers.add_parser(
        "functions",
        help="列出函数",
    )
    functions_parser.add_argument(
        "sha256",
        help="样本 SHA256 (或前缀)",
    )
    functions_parser.add_argument(
        "--tag",
        help="按标签过滤",
    )
    functions_parser.add_argument(
        "--db",
        default="artifacts/database.db",
        help="数据库路径",
    )

    # ========== ask 命令 ==========
    ask_parser = subparsers.add_parser(
        "ask",
        help="问答",
    )
    ask_parser.add_argument(
        "sha256",
        help="样本 SHA256",
    )
    ask_parser.add_argument(
        "question",
        help="问题",
    )
    ask_parser.add_argument(
        "--db",
        default="artifacts/database.db",
        help="数据库路径",
    )

    # ========== solve 命令 ==========
    solve_parser = subparsers.add_parser(
        "solve",
        help="一键 CTF Reverse 解题",
    )
    solve_parser.add_argument(
        "sample",
        help="挑战文件路径",
    )
    solve_parser.add_argument(
        "-o", "--output",
        help="输出目录",
    )
    solve_parser.add_argument(
        "--flag-regex",
        default=r"(flag|ctf|picoCTF|hgame|nssctf|h1kibi)\{[^}\r\n]{1,160}\}",
        help="Flag 正则表达式",
    )
    solve_parser.add_argument(
        "--skip-ghidra",
        dest="skip_ghidra",
        action="store_true",
        help="跳过 Ghidra 分析",
    )
    solve_parser.add_argument(
        "--ghidra",
        dest="skip_ghidra",
        action="store_false",
        help="启用 Ghidra 分析",
    )
    solve_parser.set_defaults(skip_ghidra=True)
    solve_parser.add_argument(
        "--quick",
        action="store_true",
        help="快速模式 (skip Ghidra)",
    )
    solve_parser.add_argument(
        "--deep",
        action="store_true",
        help="深度模式 (启用 Ghidra)",
    )
    solve_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="超时时间（秒）",
    )
    solve_parser.add_argument(
        "--no-validate",
        action="store_true",
        help="跳过验证",
    )
    solve_parser.add_argument(
        "--enable-memory",
        action="store_true",
        help="启用记忆检索",
    )
    solve_parser.add_argument(
        "--enable-llm-planner",
        action="store_true",
        help="启用 LLM 规划器",
    )
    solve_parser.add_argument(
        "--redact",
        dest="redact_candidates",
        action="store_true",
        help="Redact candidates in output",
    )
    solve_parser.add_argument(
        "--memory-db",
        default="memory.db",
        help="Memory database path",
    )
    solve_parser.add_argument(
        "--enable-dynamic",
        action="store_true",
        help="启用动态追踪 solver",
    )
    solve_parser.add_argument(
        "--allowed-input-channels",
        default="argv,stdin",
        help="允许的验证输入通道 (逗号分隔)",
    )

    # ========== serve 命令 ==========
    serve_parser = subparsers.add_parser(
        "serve",
        help="启动 API 服务",
    )
    serve_parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="监听地址",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="监听端口",
    )

    # ========== agent-tools 命令 ==========
    agent_tools_parser = subparsers.add_parser(
        "agent-tools",
        help="运行本地 CTF Agent 工具，不调用 OpenAI",
    )
    agent_tools_parser.add_argument(
        "sample",
        help="挑战文件路径",
    )
    agent_tools_parser.add_argument(
        "--tool",
        required=True,
        help="工具名 (profile_sample, validate_candidate, decompile_function)",
    )
    agent_tools_parser.add_argument(
        "-o", "--output",
        help="输出目录",
    )
    agent_tools_parser.add_argument(
        "--skip-ghidra",
        action="store_true",
        default=True,
        help="跳过 Ghidra 分析",
    )
    agent_tools_parser.add_argument(
        "--candidate",
        help="validate_candidate 的候选输入",
    )
    agent_tools_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="验证超时（秒）",
    )
    agent_tools_parser.add_argument(
        "--function",
        default="main",
        help="decompile_function 的函数名",
    )
    agent_tools_parser.add_argument(
        "--max-lines",
        type=int,
        default=80,
        help="decompile_function 最大行数",
    )
    agent_tools_parser.add_argument(
        "--flag-regex",
        default=r"(?:flag|ctf)\{[^}\r\n]{1,160}\}",
        help="decode_strings 的 flag 正则表达式",
    )
    agent_tools_parser.add_argument(
        "--max-functions",
        type=int,
        default=10,
        help="rank_functions 最大函数数量",
    )
    agent_tools_parser.add_argument(
        "--args",
        dest="args_json",
        help="JSON object passed to the selected tool. Overrides legacy CLI flags.",
    )
    agent_tools_parser.add_argument(
        "--args-file",
        help="Path to a JSON file containing tool arguments. Overridden by --args.",
    )
    agent_tools_parser.add_argument(
        "--show-payload",
        action="store_true",
        help="Print final tool payload before execution.",
    )

    # ========== agent 命令 ==========
    agent_parser = subparsers.add_parser(
        "agent",
        help="运行 OpenAI Brain + 本地 CTF 工具",
    )
    agent_parser.add_argument(
        "sample",
        help="挑战文件路径",
    )
    agent_parser.add_argument(
        "--goal",
        default="solve this CTF reverse challenge",
        help="Agent 目标",
    )
    agent_parser.add_argument(
        "-o", "--output",
        help="输出目录",
    )
    agent_parser.add_argument(
        "--model",
        default="gpt-4o",
        help="OpenAI 模型名",
    )
    agent_parser.add_argument(
        "--max-steps",
        type=int,
        default=8,
        help="最大工具调用轮数",
    )

    # ========== llm-solve 命令 ==========
    llm_parser = subparsers.add_parser(
        "llm-solve",
        help="LLM Brain 驱动实验性求解（不破坏现有 solve）",
    )
    llm_parser.add_argument("sample", help="挑战文件路径")
    llm_parser.add_argument("--brain", default="deepseek", help="Brain 后端 (deepseek/openai)")
    llm_parser.add_argument("--model", default=None, help="模型名")
    llm_parser.add_argument("--verify", action="store_true", default=True)
    llm_parser.add_argument("--max-steps", type=int, default=5)
    llm_parser.add_argument("--allow-dynamic", action="store_true", help="允许动态执行工具")
    llm_parser.add_argument("-o", "--output", help="输出目录")
    llm_parser.add_argument("--flag-regex", default=r"flag\{[^}]+\}")
    llm_parser.add_argument("--memory-db", default="memory.db", help="Memory 数据库路径")
    llm_parser.add_argument("--token-budget", type=int, default=4096, help="每次 LLM 调用的 token 预算")
    llm_parser.add_argument("--max-actions-per-step", type=int, default=2)
    llm_parser.add_argument("--redact", action="store_true")


    # ========== benchmark 命令 ==========
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="三模式 benchmark (llm-only / auto-no-brain / auto-brain)",
    )
    benchmark_parser.add_argument("root", help="Challenges 目录路径")
    benchmark_parser.add_argument("--modes", default="auto-no-brain")
    benchmark_parser.add_argument("--brain", default="deepseek")
    benchmark_parser.add_argument("--model", default=None)
    benchmark_parser.add_argument("--max-cases", type=int)


    # ========== snapshot 命令 ==========
    snapshot_parser = subparsers.add_parser("snapshot", help="导出确定性 Evidence Snapshot")
    snapshot_parser.add_argument("sample", help="样本文件路径")
    snapshot_parser.add_argument("--out", default="snapshot/", help="输出目录")


    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    setup_logging(args.verbose)

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "dynamic":
        return cmd_dynamic(args)
    elif args.command == "solve":
        return cmd_solve(args)
    elif args.command == "agent-tools":
        return cmd_agent_tools(args)
    elif args.command == "agent":
        return cmd_agent(args)
    elif args.command == "functions":
        return cmd_functions(args)
    elif args.command == "ask":
        return cmd_ask(args)
    elif args.command == "serve":
        return cmd_serve(args)
    elif args.command == "memory":
        return cmd_memory(args)
    elif args.command == "llm-solve":
        return cmd_llm_solve(args)
    elif args.command == "benchmark":
        return cmd_benchmark(args)
    elif args.command == "snapshot":
        return cmd_snapshot(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
