"""
CLI 入口 - 命令行界面

用法:
    python -m re_agent analyze <sample_path>
    python -m re_agent analyze <sample_path> --output artifacts/ --skip-ghidra
"""

import argparse
import logging
import sys
from pathlib import Path

from .pipeline import run_analysis
from .reporter import ReportGenerator


def setup_logging(verbose: bool = False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


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
    print(f"Reverse-Agent v0.1.0 - 静态 Triage")
    print(f"{'='*60}")
    print(f"样本: {sample_path}")
    print(f"输出: {output_dir}")
    print(f"{'='*60}")

    # 执行分析
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

    # 打印摘要
    print(f"\n{'='*60}")
    print("分析完成!")
    print(f"{'='*60}")
    print(f"样本 SHA256: {result.sample.sha256}")
    print(f"执行工具数: {len(result.tool_results)}")
    print(f"Artifact 数: {sum(len(tr.artifacts) for tr in result.tool_results)}")
    print(f"\n报告: {output_dir / 'report.md'}")
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

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    setup_logging(args.verbose)

    if args.command == "analyze":
        return cmd_analyze(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
