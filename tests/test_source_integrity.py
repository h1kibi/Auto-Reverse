"""
Source integrity tests - prevent minified/Missing files in repo.
"""

import py_compile
from pathlib import Path

RUNTIME_FILES = [
    "re_agent/brain/actions.py",
    "re_agent/brain/context.py",
    "re_agent/brain/base.py",
    "re_agent/brain/deepseek.py",
    "re_agent/brain/context_builder.py",
    "re_agent/brain/policy.py",
    "re_agent/brain/prompts.py",
    "re_agent/core/observation.py",
    "re_agent/ctf/context_bundle.py",
    "re_agent/ctf/llm_runtime.py",
    "re_agent/ctf/benchmark.py",
    "re_agent/memory/playbook_import.py",
    "re_agent/cli.py",
]


def test_runtime_files_compile():
    for file in RUNTIME_FILES:
        py_compile.compile(file, doraise=True)


def test_runtime_files_are_not_minified():
    for file in RUNTIME_FILES:
        text = Path(file).read_text(encoding="utf-8")
        line_count = len(text.splitlines())
        assert line_count >= 10, f"{file} looks minified ({line_count} lines)"


def test_no_docstring_import_same_line():
    for file in RUNTIME_FILES:
        text = Path(file).read_text(encoding="utf-8")
        assert '""" from __future__' not in text
        assert '""" import ' not in text


def test_version_file_exists():
    from re_agent.version import __version__
    assert __version__ == "0.6.0"


def test_pyproject_version_match():
    import tomllib
    from re_agent.version import __version__
    data = tomllib.loads(open("pyproject.toml", encoding="utf-8").read())
    assert data["project"]["version"] == __version__
