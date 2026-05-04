"""
Web API - FastAPI 接口

API:
- POST /analyze - 分析样本
- POST /upload-and-analyze - 上传并分析
- GET /report/{sha256} - 获取报告
- POST /ask - 问答
- GET /functions/{sha256} - 获取函数列表
"""

import re
import uuid
import tempfile
import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ..pipeline import run_analysis
from ..reporter import ReportGenerator
from ..database import Database
from ..analyzer import FunctionAnalyzer
from ..qa import QASystem
from ..llm import LLMFactory
from ..artifacts import compute_sha256, sample_artifact_dir, sample_upload_path, safe_filename
from .schemas import (
    AnalyzeRequest, SolveRequest, AnalyzeResponse, SolveResponse,
    AskRequest, AskResponse, MemorySearchRequest, MemorySearchResponse,
)

app = FastAPI(
    title="Reverse-Agent API",
    description="自动化逆向分析 Agent API",
    version="0.3.0",
)

# 全局实例
db = Database("reverse_agent.db")
llm_client = None

# 路径配置
UPLOAD_ROOT = Path("artifacts/uploads")
RESULT_ROOT = Path("artifacts/results")


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


# ========== 请求/响应模型已移至 api/schemas.py ==========


# ========== API 端点 ==========

@app.get("/")
async def root():
    """API 根路径"""
    return {
        "name": "Reverse-Agent API",
        "version": "0.3.0",
        "endpoints": [
            "POST /analyze - 分析样本",
            "POST /upload-and-analyze - 上传并分析",
            "POST /solve - CTF 求解",
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
        # 计算 SHA256 并确定输出目录
        sha256 = compute_sha256(sample_path)
        output_dir = sample_artifact_dir(RESULT_ROOT, sha256)

        # 执行分析
        result = run_analysis(
            sample_path=str(sample_path),
            output_dir=str(output_dir),
            skip_ghidra=request.skip_ghidra,
        )

        # 生成报告
        reporter = ReportGenerator(str(output_dir))
        reporter.generate(result)

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
            report_path=str(output_dir / "report.md"),
            report_url=f"/report/{result.sample.sha256}",
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
    # 创建临时目录保存上传文件
    tmp_dir = Path(tempfile.mkdtemp(prefix="reverse_upload_"))
    tmp_sample = tmp_dir / safe_filename(file.filename or "sample.bin")

    try:
        # 保存上传文件
        with tmp_sample.open("wb") as f:
            shutil.copyfileobj(file.file, f)

        # 计算 SHA256
        sha256 = compute_sha256(tmp_sample)

        # 移动到持久目录
        final_sample = sample_upload_path(UPLOAD_ROOT, sha256, file.filename or "sample.bin")
        final_sample.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp_sample), str(final_sample))

        # 确定输出目录
        output_dir = sample_artifact_dir(RESULT_ROOT, sha256)

        # 执行分析
        result = run_analysis(
            sample_path=str(final_sample),
            output_dir=str(output_dir),
            skip_ghidra=skip_ghidra,
        )

        # 生成报告
        reporter = ReportGenerator(str(output_dir))
        reporter.generate(result)

        # 函数分析
        llm = get_llm()
        analyzer = FunctionAnalyzer(db, llm)
        functions = analyzer.analyze_sample(result)

        return {
            "status": "success",
            "sample_sha256": result.sample.sha256,
            "report_path": str(output_dir / "report.md"),
            "report_url": f"/report/{result.sample.sha256}",
            "function_count": len(functions),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # 清理临时目录
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/report/{sha256}")
async def get_report(sha256: str):
    """获取分析报告"""
    # 验证 SHA256 格式
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise HTTPException(status_code=400, detail="Invalid sha256 format")

    # 查找报告文件
    report_path = sample_artifact_dir(RESULT_ROOT, sha256) / "report.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(report_path, media_type="text/markdown")


@app.post("/solve", response_model=SolveResponse)
async def solve_sample(request: SolveRequest):
    """CTF 求解"""
    from .ctf.pipeline import solve_challenge

    sample = Path(request.sample_path)
    if not sample.exists():
        raise HTTPException(status_code=404, detail="Sample not found")

    try:
        sha256 = compute_sha256(sample)
        output_dir = sample_artifact_dir(RESULT_ROOT, sha256)

        result = solve_challenge(
            sample_path=str(sample),
            output_dir=str(output_dir),
            flag_regex=request.flag_regex,
            skip_ghidra=request.skip_ghidra,
            timeout=request.timeout,
            validate=request.do_verify,
        )

        return SolveResponse(
            status=result.status,
            sample_sha256=result.sha256,
            flag=result.best_flag,
            method=result.method,
            result_path=str(output_dir / "solve_result.json"),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
