"""
Web API - FastAPI 接口

API:
- POST /analyze - 分析样本
- GET /report/{id} - 获取报告
- POST /ask - 问答
- GET /functions/{sha256} - 获取函数列表
"""

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional
import tempfile
import shutil
from pathlib import Path

from .pipeline import run_analysis
from .reporter import ReportGenerator
from .database import Database
from .analyzer import FunctionAnalyzer
from .qa import QASystem
from .llm import LLMFactory

app = FastAPI(
    title="Reverse-Agent API",
    description="自动化逆向分析 Agent API",
    version="0.2.0",
)

# 全局实例
db = Database("reverse_agent.db")
llm_client = None


def get_llm():
    """获取 LLM 客户端"""
    global llm_client
    if llm_client is None:
        import os
        api_key = os.getenv("MIMO_API_KEY") or os.getenv("OPENAI_API_KEY")
        if api_key:
            if os.getenv("MIMO_API_KEY"):
                llm_client = LLMFactory.create("mimo", api_key=api_key)
            else:
                llm_client = LLMFactory.create("openai", api_key=api_key)
    return llm_client


# ========== 请求/响应模型 ==========

class AnalyzeRequest(BaseModel):
    sample_path: str
    output_dir: str = "artifacts"
    skip_ghidra: bool = False


class AskRequest(BaseModel):
    sample_sha256: str
    question: str


class FunctionInfo(BaseModel):
    name: str
    address: str
    summary: str
    behavior_tags: list[str]
    confidence: float


class AnalyzeResponse(BaseModel):
    status: str
    sample_sha256: str
    report_path: str
    function_count: int
    message: str


class AskResponse(BaseModel):
    question: str
    answer: str


# ========== API 端点 ==========

@app.get("/")
async def root():
    """API 根路径"""
    return {
        "name": "Reverse-Agent API",
        "version": "0.2.0",
        "endpoints": [
            "POST /analyze - 分析样本",
            "GET /report/{sha256} - 获取报告",
            "POST /ask - 问答",
            "GET /functions/{sha256} - 获取函数列表",
        ],
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_sample(request: AnalyzeRequest):
    """分析样本"""
    sample_path = Path(request.sample_path)
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail=f"Sample not found: {request.sample_path}")

    try:
        # 执行分析
        result = run_analysis(
            sample_path=str(sample_path),
            output_dir=request.output_dir,
            skip_ghidra=request.skip_ghidra,
        )

        # 生成报告
        reporter = ReportGenerator(request.output_dir)
        report = reporter.generate(result)

        # 函数分析
        llm = get_llm()
        analyzer = FunctionAnalyzer(db, llm)
        functions = analyzer.analyze_sample(result)

        # 保存会话
        from .database import AnalysisSession
        session = AnalysisSession(
            sample_sha256=result.sample.sha256,
            sample_path=str(sample_path),
            file_type=result.sample.file_type or "unknown",
            status="completed",
            result_json=result.to_json(),
        )
        db.create_session(session)

        return AnalyzeResponse(
            status="success",
            sample_sha256=result.sample.sha256,
            report_path=str(Path(request.output_dir) / "report.md"),
            function_count=len(functions),
            message=f"Analysis complete. {len(functions)} functions analyzed.",
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload-and-analyze")
async def upload_and_analyze(
    file: UploadFile = File(...),
    skip_ghidra: bool = False,
):
    """上传样本并分析"""
    # 保存上传的文件
    temp_dir = Path(tempfile.mkdtemp())
    sample_path = temp_dir / file.filename

    with open(sample_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        output_dir = str(temp_dir / "artifacts")
        result = run_analysis(
            sample_path=str(sample_path),
            output_dir=output_dir,
            skip_ghidra=skip_ghidra,
        )

        reporter = ReportGenerator(output_dir)
        report = reporter.generate(result)

        llm = get_llm()
        analyzer = FunctionAnalyzer(db, llm)
        functions = analyzer.analyze_sample(result)

        return {
            "status": "success",
            "sample_sha256": result.sample.sha256,
            "report_path": str(Path(output_dir) / "report.md"),
            "function_count": len(functions),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # 清理临时文件
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/report/{sha256}")
async def get_report(sha256: str):
    """获取分析报告"""
    sessions = db.get_sessions_by_sha256(sha256)
    if not sessions:
        raise HTTPException(status_code=404, detail="Analysis not found")

    # 查找报告文件
    report_path = Path("artifacts") / "report.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(report_path, media_type="text/markdown")


@app.get("/functions/{sha256}")
async def get_functions(sha256: str, tag: str = None):
    """获取函数列表"""
    if tag:
        functions = db.get_functions_by_tag(sha256, tag)
    else:
        functions = db.get_functions_by_sample(sha256)

    return {
        "sample_sha256": sha256,
        "function_count": len(functions),
        "functions": [
            {
                "name": f.name,
                "address": f.address,
                "summary": f.summary,
                "behavior_tags": f.behavior_tags,
                "confidence": f.confidence,
            }
            for f in functions
        ],
    }


@app.get("/function/{sha256}/{name}")
async def get_function_detail(sha256: str, name: str):
    """获取函数详情"""
    func = db.get_function_by_name(sha256, name)
    if not func:
        raise HTTPException(status_code=404, detail="Function not found")

    return func.to_dict()


@app.post("/ask", response_model=AskResponse)
async def ask_question(request: AskRequest):
    """问答"""
    llm = get_llm()
    qa = QASystem(db, llm)

    answer = qa.ask(request.sample_sha256, request.question)

    return AskResponse(
        question=request.question,
        answer=answer,
    )


@app.get("/stats/{sha256}")
async def get_stats(sha256: str):
    """获取统计信息"""
    func_count = db.get_function_count(sha256)

    # 按标签统计
    tag_stats = {}
    functions = db.get_functions_by_sample(sha256)
    for func in functions:
        for tag in func.behavior_tags:
            tag_stats[tag] = tag_stats.get(tag, 0) + 1

    return {
        "sample_sha256": sha256,
        "function_count": func_count,
        "tag_stats": tag_stats,
    }


# ========== 启动命令 ==========

def start_api(host: str = "0.0.0.0", port: int = 8000):
    """启动 API 服务"""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()
