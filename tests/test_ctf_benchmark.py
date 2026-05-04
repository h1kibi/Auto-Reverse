"""
Benchmark runner for CTF solver regression testing.

Runs the pipeline against challenge binaries and verifies expected results.
"""

import json
import subprocess
import sys
from pathlib import Path

CHALLENGES_DIR = Path(__file__).parent / "challenges"
BUILD_DIR = CHALLENGES_DIR / "build"


def compile_challenges():
    """Compile all challenge C sources"""
    BUILD_DIR.mkdir(exist_ok=True)
    results = {}

    for challenge_dir in sorted(CHALLENGES_DIR.iterdir()):
        if not challenge_dir.is_dir() or challenge_dir.name == "build":
            continue

        chal_c = challenge_dir / "chal.c"
        if not chal_c.exists():
            continue

        output = BUILD_DIR / challenge_dir.name
        if sys.platform == "win32":
            output = output.with_suffix(".exe")

        try:
            subprocess.run(
                ["gcc", "-o", str(output), str(chal_c)],
                check=True,
                capture_output=True,
                text=True,
            )
            results[challenge_dir.name] = {"compiled": True, "path": str(output)}
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            results[challenge_dir.name] = {"compiled": False, "error": str(e)}

    return results


def run_benchmark(solver_only: str | None = None):
    """Run all benchmarks and check expected results"""
    from re_agent.ctf.pipeline import solve_challenge

    results = {}

    for challenge_dir in sorted(CHALLENGES_DIR.iterdir()):
        if not challenge_dir.is_dir() or challenge_dir.name == "build":
            continue

        expected_file = challenge_dir / "expected.json"
        if not expected_file.exists():
            continue

        expected = json.loads(expected_file.read_text())

        binary = BUILD_DIR / challenge_dir.name
        if sys.platform == "win32":
            binary = binary.with_suffix(".exe")
        if not binary.exists():
            results[challenge_dir.name] = {
                "status": "skipped",
                "reason": "binary not compiled",
            }
            continue

        if solver_only and solver_only not in expected.get("allowed_solvers", []):
            results[challenge_dir.name] = {
                "status": "skipped",
                "reason": f"solver {solver_only} not applicable",
            }
            continue

        try:
            result = solve_challenge(
                sample_path=str(binary),
                output_dir=str(BUILD_DIR / f"output_{challenge_dir.name}"),
                flag_regex=expected.get("flag_regex", r"flag\{[^}]+\}"),
                skip_ghidra=True,
                timeout=expected.get("max_seconds", 60),
                validate=expected.get("must_verify", False),
            )

            solved = result.best_flag == expected.get("expected_flag")
            results[challenge_dir.name] = {
                "status": "pass" if solved else "fail",
                "expected": expected.get("expected_flag"),
                "got": result.best_flag,
                "method": result.method,
                "solver_runs": len(result.solver_runs),
            }

        except Exception as e:
            results[challenge_dir.name] = {
                "status": "error",
                "error": str(e),
            }

    return results


def print_benchmark_report(results: dict):
    """Print a summary report"""
    total = len(results)
    passed = sum(1 for r in results.values() if r.get("status") == "pass")
    failed = sum(1 for r in results.values() if r.get("status") == "fail")
    skipped = sum(1 for r in results.values() if r.get("status") == "skipped")
    errors = sum(1 for r in results.values() if r.get("status") == "error")

    print(f"\n{'='*60}")
    print(f"CTF Solver Benchmark Report")
    print(f"{'='*60}")
    print(f"Total: {total} | Pass: {passed} | Fail: {failed} | Skip: {skipped} | Error: {errors}")
    print()

    for name, result in sorted(results.items()):
        status = result.get("status", "?")
        icon = {"pass": "[PASS]", "fail": "[FAIL]", "skipped": "[SKIP]", "error": "[ERR!]"}.get(status, "[?]")
        if status == "pass":
            print(f"  {icon} {name}: got '{result.get('got', '?')}' via {result.get('method', '?')}")
        elif status == "fail":
            print(f"  {icon} {name}: expected '{result.get('expected', '?')}' got '{result.get('got', '?')}'")
        else:
            print(f"  {icon} {name}: {result.get('reason', result.get('error', '?'))}")


if __name__ == "__main__":
    print("Compiling challenges...")
    compile_results = compile_challenges()
    for name, info in compile_results.items():
        status = "OK" if info["compiled"] else f"FAIL: {info['error']}"
        print(f"  {name}: {status}")

    print("\nRunning benchmarks...")
    results = run_benchmark()
    print_benchmark_report(results)

    passed = sum(1 for r in results.values() if r.get("status") == "pass")
    if passed < len(results):
        sys.exit(1)
