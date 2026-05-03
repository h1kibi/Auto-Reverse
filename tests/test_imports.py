"""测试核心模块导入"""


def test_import_schema():
    import re_agent.schema
    assert hasattr(re_agent.schema, "compute_hashes")
    assert hasattr(re_agent.schema, "AnalysisResult")


def test_import_pipeline():
    import re_agent.pipeline
    assert hasattr(re_agent.pipeline, "run_analysis")


def test_import_database():
    import re_agent.database
    assert hasattr(re_agent.database, "Database")


def test_import_analyzer():
    import re_agent.analyzer
    assert hasattr(re_agent.analyzer, "FunctionAnalyzer")


def test_import_reporter():
    import re_agent.reporter
    assert hasattr(re_agent.reporter, "ReportGenerator")


def test_import_qa():
    import re_agent.qa
    assert hasattr(re_agent.qa, "QASystem")


def test_import_llm():
    import re_agent.llm
    assert hasattr(re_agent.llm, "LLMFactory")


def test_import_sandbox():
    import re_agent.sandbox
    assert hasattr(re_agent.sandbox, "DockerSandbox")


def test_import_dynamic_pipeline():
    import re_agent.dynamic_pipeline
    assert hasattr(re_agent.dynamic_pipeline, "DynamicAnalysisPipeline")
