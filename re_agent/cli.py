"""
CLI 入口 - 命令行界面

用法:
    python -m re_agent analyze <sample_path>           # 静态分析
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
    """执行分析命令"""
    sample_path = Path(args.sample)
    if not sample_path.exists():
        print(f"Error: Sample file not found: {sample_path}")
        return 1

    if not sample_path.is_file():
        print(f"Error: Not a file: {sample_path}")
        return 1

    # 创建输出目录
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"{'='*60}")
    print(f"Reverse-Agent v0.2.0 - 静态分析 + 函数分析")
    print(f"{'='*60}")
    print(f"样本: {sample_path}")
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
            print("  (设置 MIMO_API_KEY 或 OPENAI_API_KEY 环境变量启用 LLM)")

        analyzer = FunctionAnalyzer(db, llm)
        functions = analyzer.analyze_sample(result)
        db.close()

        print(f"  分析了 {len(functions)} 个函数")

    # 打印摘要
    print(f"\n{'='*60}")
    print("分析完成!")
    print(f"{'='*60}")
    print(f"样本 SHA256: {result.sample.sha256}")
    print(f"执行工具数: {len(result.tool_results)}")
    print(f"Artifact 数: {sum(len(tr.artifacts) for tr in result.tool_results)}")
    print(f"\n报告: {output_dir / 'report.md'}")
    print(f"数据库: {output_dir / 'database.db'}")
    print(f"Artifact: {output_dir}/")
    print(f"{'='*60}")

    # 打印工具执行摘要
    print("\n工具执行摘要:")
    for tr in result.tool_results:
        status_icon = {
            "success": "[OK]",
            "failed": "[FAIL]",
            "partial": "[PARTIAL]",
            "skipped": "[SKIP]",
        }.get(tr.status.value, "[?]")
        print(f"  {status_icon} {tr.tool}: {tr.status.value} ({tr.runtime_ms}ms)")

    # 提示问答命令
    if not args.skip_function_analysis:
        print(f"\n{'='*60}")
        print("下一步：")
        print(f"  查看函数: python -m re_agent functions {result.sample.sha256[:16]}...")
        print(f"  问答: python -m re_agent ask {result.sample.sha256[:16]}... \"哪个函数处理网络？\"")
        print(f"{'='*60}")

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

    # analyze 命令
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="分析二进制文件",
    )
    analyze_parser.add_argument(
        "sample",
        help="样本文件路径",
    )
    analyze_parser.add_argument(
        "-o", "--output",
        default="artifacts",
        help="输出目录 (默认: artifacts)",
    )
    analyze_parser.add_argument(
        "--ghidra-home",
        help="Ghidra 安装路径 (或设置 GHIDRA_HOME 环境变量)",
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

    # functions 命令
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

    # ask 命令
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

    # serve 命令
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    setup_logging(args.verbose)

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "functions":
        return cmd_functions(args)
    elif args.command == "ask":
        return cmd_ask(args)
    elif args.command == "serve":
        return cmd_serve(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
