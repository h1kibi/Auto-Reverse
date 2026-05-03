"""测试 Ghidra 脚本生成"""


def test_ghidra_script_no_typo(tmp_path):
    """验证脚本中没有 depiledFunction typo"""
    from re_agent.tools.ghidra_tool import GhidraTool

    tool = GhidraTool(output_dir=str(tmp_path), ghidra_home="/fake")
    script = tool._generate_analysis_script()

    # 应该使用正确的 API
    assert "getDecompiledFunction()" in script
    # 不应该有 typo
    assert "depiledFunction" not in script


def test_ghidra_script_has_output_dir(tmp_path):
    """验证脚本包含输出目录"""
    from re_agent.tools.ghidra_tool import GhidraTool

    tool = GhidraTool(output_dir=str(tmp_path), ghidra_home="/fake")
    script = tool._generate_analysis_script()

    assert "OUTPUT_DIR" in script
    assert "functions.json" in script
    assert "callgraph.json" in script
    assert "decompiled" in script


def test_ghidra_output_dir_structure(tmp_path):
    """验证输出目录结构"""
    from re_agent.tools.ghidra_tool import GhidraTool

    tool = GhidraTool(output_dir=str(tmp_path), ghidra_home="/fake")

    # 检查 ghidra 子目录
    assert tool.ghidra_out == tmp_path / "ghidra"
