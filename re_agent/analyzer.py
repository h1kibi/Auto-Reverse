"""
函数分析模块 - 关键函数识别与摘要生成

核心功能：
- 自动找关键函数（按字符串引用、API 调用、图中心性排序）
- 给每个函数生成自然语言摘要
- 维护 function summary database
"""

import json
import logging
from pathlib import Path
from typing import Optional

from .schema import AnalysisResult, ArtifactType
from .database import Database, FunctionSummary
from .llm import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)

# 关键行为标签
BEHAVIOR_TAGS = {
    "network": ["socket", "connect", "send", "recv", "http", "url", "curl", "wget", "inet"],
    "crypto": ["encrypt", "decrypt", "aes", "rsa", "hash", "md5", "sha", "cipher", "key"],
    "file": ["open", "read", "write", "create", "delete", "file", "path", "directory"],
    "process": ["create", "kill", "exec", "spawn", "thread", "process", "pid"],
    "registry": ["reg", "registry", "hkey", "setvalue", "getvalue"],
    "persistence": ["autorun", "startup", "service", "scheduled", "cron", "boot"],
    "anti_debug": ["debug", "isdebuggerpresent", "ntqueryinformationprocess", "checkremotedebugger"],
    "obfuscation": ["encode", "decode", "pack", "unpack", "decrypt", "deobfuscate"],
    "c2": ["command", "control", "beacon", "callback", "exfil"],
    "exploit": ["overflow", "shellcode", "payload", "rop", "ropchain", "heap", "spray"],
}


class FunctionAnalyzer:
    """函数分析器"""

    def __init__(
        self,
        db: Database,
        llm: BaseLLMClient = None,
    ):
        self.db = db
        self.llm = llm

    def analyze_sample(self, result: AnalysisResult) -> list[FunctionSummary]:
        """分析样本的所有函数"""
        sample_sha256 = result.sample.sha256

        # 1. 从 Ghidra 结果提取函数列表
        functions = self._extract_functions(result)

        if not functions:
            logger.warning("No functions found in analysis result")
            return []

        # 2. 识别关键函数
        key_functions = self._rank_functions(functions, result)

        # 3. 为每个函数生成摘要
        summaries = []
        for func in key_functions:
            summary = self._generate_summary(func, result)
            if summary:
                self.db.add_function_summary(summary)
                summaries.append(summary)

        logger.info(f"Generated {len(summaries)} function summaries")
        return summaries

    def _extract_functions(self, result: AnalysisResult) -> list[dict]:
        """从分析结果提取函数列表"""
        functions = []

        # 从 Ghidra 结果提取
        for tool_result in result.tool_results:
            if tool_result.tool == "ghidra":
                for artifact in tool_result.artifacts:
                    if artifact.type == ArtifactType.FUNCTIONS:
                        try:
                            content = Path(artifact.path).read_text(encoding="utf-8")
                            func_list = json.loads(content)
                            functions.extend(func_list)
                        except Exception as e:
                            logger.error(f"Failed to read functions: {e}")

            # 从 pefile 结果提取导出函数
            elif tool_result.tool == "pefile":
                for artifact in tool_result.artifacts:
                    if artifact.type == ArtifactType.FUNCTIONS:
                        try:
                            content = Path(artifact.path).read_text(encoding="utf-8")
                            for line in content.split("\n"):
                                if line.strip() and "(" in line:
                                    name = line.split("(")[0].strip()
                                    functions.append({
                                        "name": name,
                                        "address": "export",
                                        "is_library": False,
                                    })
                        except Exception as e:
                            logger.error(f"Failed to read exports: {e}")

        return functions

    def _rank_functions(self, functions: list[dict], result: AnalysisResult) -> list[dict]:
        """对函数进行排序，识别关键函数"""
        # 计算每个函数的重要性分数
        scored_functions = []

        # 获取字符串列表（用于检测引用）
        strings = self._extract_strings(result)

        # 获取导入函数列表
        imports = self._extract_imports(result)

        for func in functions:
            score = 0
            name = func.get("name", "")
            address = func.get("address", "")

            # 1. 字符串引用（函数名或地址出现在字符串中）
            for s in strings:
                if name in s or address in s:
                    score += 1

            # 2. 是否是导入函数（库函数通常不太重要）
            if func.get("is_library", False):
                score -= 5

            # 3. 函数名启发式
            name_lower = name.lower()
            for tag, keywords in BEHAVIOR_TAGS.items():
                for keyword in keywords:
                    if keyword in name_lower:
                        score += 3
                        break

            # 4. 地址启发式（入口点附近通常更重要）
            if address and address != "export":
                try:
                    addr_int = int(address, 16)
                    # 入口点附近的函数更重要
                    if addr_int < 0x10000:
                        score += 2
                except:
                    pass

            scored_functions.append({
                **func,
                "score": score,
            })

        # 按分数排序
        scored_functions.sort(key=lambda x: x["score"], reverse=True)

        # 返回前 N 个函数
        return scored_functions[:100]

    def _generate_summary(
        self,
        func: dict,
        result: AnalysisResult,
    ) -> Optional[FunctionSummary]:
        """为函数生成摘要"""
        name = func.get("name", "unknown")
        address = func.get("address", "")

        # 获取反编译代码
        decompiled_code = self._get_decompiled_code(name, address, result)

        # 识别行为标签
        behavior_tags = self._identify_tags(name, decompiled_code)

        # 如果有 LLM，使用 LLM 生成摘要
        if self.llm and decompiled_code:
            summary_text, confidence = self._llm_summarize(name, decompiled_code, behavior_tags)
        else:
            # 否则使用启发式摘要
            summary_text = self._heuristic_summary(name, behavior_tags)
            confidence = 0.5

        return FunctionSummary(
            sample_sha256=result.sample.sha256,
            name=name,
            address=address,
            decompiled_code=decompiled_code[:5000] if decompiled_code else "",  # 限制长度
            summary=summary_text,
            behavior_tags=behavior_tags,
            confidence=confidence,
        )

    def _get_decompiled_code(
        self,
        name: str,
        address: str,
        result: AnalysisResult,
    ) -> str:
        """获取函数的反编译代码"""
        for tool_result in result.tool_results:
            if tool_result.tool == "ghidra":
                for artifact in tool_result.artifacts:
                    if artifact.type == ArtifactType.DECOMPILED_FUNCTION:
                        if artifact.name == name or artifact.address == address:
                            try:
                                return Path(artifact.path).read_text(encoding="utf-8")
                            except:
                                pass
        return ""

    def _identify_tags(self, name: str, code: str) -> list[str]:
        """识别函数行为标签"""
        tags = []
        combined = (name + " " + code).lower()

        for tag, keywords in BEHAVIOR_TAGS.items():
            for keyword in keywords:
                if keyword in combined:
                    tags.append(tag)
                    break

        return list(set(tags))

    def _llm_summarize(
        self,
        name: str,
        code: str,
        tags: list[str],
    ) -> tuple[str, float]:
        """使用 LLM 生成摘要"""
        prompt = f"""分析以下函数，生成简短的功能摘要。

函数名: {name}
行为标签: {', '.join(tags) if tags else '无'}

反编译代码:
```
{code[:3000]}
```

请用中文回答，包含：
1. 函数的主要功能
2. 关键行为（网络、文件、加密等）
3. 置信度（0-1）

回答格式：
功能: [一句话描述]
行为: [关键行为列表]
置信度: [0-1的数值]"""

        try:
            messages = [ChatMessage(role="user", content=prompt)]
            response = self.llm.chat(messages, temperature=0.3, max_tokens=500)

            # 解析响应
            content = response.content
            summary = content

            # 提取置信度
            confidence = 0.7
            if "置信度:" in content:
                try:
                    conf_str = content.split("置信度:")[-1].strip().split()[0]
                    confidence = float(conf_str)
                except:
                    confidence = 0.7

            return summary, confidence

        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            return self._heuristic_summary(name, tags), 0.5

    def _heuristic_summary(self, name: str, tags: list[str]) -> str:
        """启发式摘要"""
        if not tags:
            return f"函数 {name}，功能未知"

        tag_desc = {
            "network": "网络通信",
            "crypto": "加密/解密",
            "file": "文件操作",
            "process": "进程管理",
            "registry": "注册表操作",
            "persistence": "持久化",
            "anti_debug": "反调试",
            "obfuscation": "混淆/编码",
            "c2": "C2通信",
            "exploit": "漏洞利用",
        }

        behaviors = [tag_desc.get(t, t) for t in tags]
        return f"函数 {name}，涉及：{', '.join(behaviors)}"

    def _extract_strings(self, result: AnalysisResult) -> list[str]:
        """提取字符串列表"""
        strings = []
        for tool_result in result.tool_results:
            if tool_result.tool == "strings":
                for artifact in tool_result.artifacts:
                    if artifact.type == ArtifactType.STRINGS:
                        try:
                            content = Path(artifact.path).read_text(encoding="utf-8")
                            strings.extend(content.split("\n")[:1000])  # 限制数量
                        except:
                            pass
        return strings

    def _extract_imports(self, result: AnalysisResult) -> list[str]:
        """提取导入函数列表"""
        imports = []
        for tool_result in result.tool_results:
            if tool_result.tool in ["pefile", "readelf"]:
                for artifact in tool_result.artifacts:
                    if artifact.type == ArtifactType.IMPORTS:
                        try:
                            content = Path(artifact.path).read_text(encoding="utf-8")
                            for line in content.split("\n"):
                                line = line.strip()
                                if line and not line.startswith("[") and not line.startswith("-"):
                                    imports.append(line)
                        except:
                            pass
        return imports
