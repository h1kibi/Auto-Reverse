"""测试函数打分 reasons"""


def test_rank_functions_adds_reasons():
    """验证排序结果包含 score_reasons"""
    from re_agent.analyzer import FunctionAnalyzer, BEHAVIOR_TAGS

    # 模拟函数列表
    functions = [
        {"name": "connect_to_server", "address": "0x401000", "is_library": False},
        {"name": "memcpy", "address": "0x402000", "is_library": True},
        {"name": "aes_encrypt_data", "address": "0x403000", "is_library": False},
    ]

    # 创建分析器（不需要 db 和 llm）
    class FakeDb:
        def add_function_summary(self, s):
            pass

    analyzer = FunctionAnalyzer(db=FakeDb(), llm=None)

    # 创建模拟的 AnalysisResult
    from re_agent.schema import AnalysisResult, SampleInfo
    fake_result = AnalysisResult(
        sample=SampleInfo(
            path="test.bin",
            sha256="a" * 64,
            md5="b" * 32,
            sha1="c" * 40,
        )
    )

    ranked = analyzer._rank_functions(functions, fake_result)

    # 验证每个函数都有 score 和 score_reasons
    for func in ranked:
        assert "score" in func
        assert "score_reasons" in func
        assert isinstance(func["score_reasons"], list)

    # 验证库函数被降权
    memcpy_func = next(f for f in ranked if f["name"] == "memcpy")
    assert any("library" in r.lower() for r in memcpy_func["score_reasons"])

    # 验证 crypto 函数被识别
    aes_func = next(f for f in ranked if f["name"] == "aes_encrypt_data")
    assert any("crypto" in r.lower() for r in aes_func["score_reasons"])

    # 验证排序：aes_encrypt_data 应该排在 memcpy 前面
    names = [f["name"] for f in ranked]
    assert names.index("aes_encrypt_data") < names.index("memcpy")


def test_behavior_tags_coverage():
    """验证行为标签覆盖主要类别"""
    from re_agent.analyzer import BEHAVIOR_TAGS

    expected_tags = ["network", "crypto", "file", "process"]
    for tag in expected_tags:
        assert tag in BEHAVIOR_TAGS
        assert len(BEHAVIOR_TAGS[tag]) > 0
