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

    sample = Path(args.sample)
    if not sample.exists():
        print(f"Error: Sample not found: {sample}")
        return 1

    sha256 = compute_sha256(sample)
    output_dir = Path(args.output) if args.output else sample_artifact_dir("artifacts/results", sha256)

    print(f"{'='*60}")
    print(f"Reverse-Agent CTF Solver")
    print(f"{'='*60}")
    print(f"样本: {sample}")
    print(f"SHA256: {sha256}")
    print(f"输出: {output_dir}")
    print(f"Flag Regex: {args.flag_regex}")
    print(f"{'='*60}")

    result = solve_challenge(
        sample_path=str(sample),
        output_dir=str(output_dir),
        flag_regex=args.flag_regex,
        skip_ghidra=args.skip_ghidra,
        timeout=args.timeout,
        validate=not args.no_validate,
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


def cmd_agent_tools(args):
    """运行本地 CTF Agent 工具"""
    import json
    from .ctf.tools import ArtifactStore, ToolExecutor, build_default_ctf_registry

    sample = Path(args.sample).resolve()
    if not sample.exists():
        print(f"Error: Sample not found: {sample}")
        return 1

    output_dir = Path(args.output or "artifacts/agent_test").resolve()
    store = ArtifactStore(output_dir)
    registry = build_default_ctf_registry(store)
    executor = ToolExecutor(registry, store)

    if args.tool == "profile_sample":
        payload = {
            "sample_path": str(sample),
            "skip_ghidra": args.skip_ghidra,
        }
    elif args.tool == "validate_candidate":
        if not args.candidate:
            print("Error: --candidate is required for validate_candidate")
            return 1
        payload = {
            "sample_path": str(sample),
            "candidate": args.candidate,
            "timeout": args.timeout,
        }
    elif args.tool == "decompile_function":
        payload = {
            "function": args.function,
            "max_lines": args.max_lines,
        }
    else:
        print(f"Error: unknown tool: {args.tool}")
        print(f"Available tools: {', '.join(registry.names())}")
        return 1

    result = executor.execute(args.tool, payload)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nArtifacts: {output_dir}")

    return 0 if result.get("ok") else 2


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
        action="store_true",
        default=True,
        help="跳过 Ghidra 分析",
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
    elif args.command == "functions":
        return cmd_functions(args)
    elif args.command == "ask":
        return cmd_ask(args)
    elif args.command == "serve":
        return cmd_serve(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
