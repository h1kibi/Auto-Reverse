"""
交互式问答模块 - 支持自然语言查询函数

支持问题：
- "这个样本哪里处理网络？"
- "哪个函数像解密？"
- "main 函数的控制流是什么？"
"""

import logging
from typing import Optional

from .database import Database, FunctionSummary
from .llm import BaseLLMClient, ChatMessage

logger = logging.getLogger(__name__)


class QASystem:
    """问答系统"""

    def __init__(self, db: Database, llm: BaseLLMClient = None):
        self.db = db
        self.llm = llm

    def ask(self, sample_sha256: str, question: str) -> str:
        """回答用户问题"""
        # 1. 解析问题意图
        intent = self._parse_intent(question)

        # 2. 根据意图查询数据库
        if intent["type"] == "search_by_tag":
            return self._search_by_tag(sample_sha256, intent["tag"])
        elif intent["type"] == "search_by_keyword":
            return self._search_by_keyword(sample_sha256, intent["keyword"])
        elif intent["type"] == "get_function_info":
            return self._get_function_info(sample_sha256, intent["function_name"])
        elif intent["type"] == "general_question":
            return self._general_question(sample_sha256, question)
        else:
            return self._general_question(sample_sha256, question)

    def _parse_intent(self, question: str) -> dict:
        """解析问题意图"""
        question_lower = question.lower()

        # 网络相关
        if any(kw in question_lower for kw in ["网络", "network", "socket", "http", "连接", "通信"]):
            return {"type": "search_by_tag", "tag": "network"}

        # 加密相关
        if any(kw in question_lower for kw in ["加密", "decrypt", "encrypt", "解密", "cipher", "crypto"]):
            return {"type": "search_by_tag", "tag": "crypto"}

        # 文件相关
        if any(kw in question_lower for kw in ["文件", "file", "读写", "read", "write"]):
            return {"type": "search_by_tag", "tag": "file"}

        # 进程相关
        if any(kw in question_lower for kw in ["进程", "process", "线程", "thread"]):
            return {"type": "search_by_tag", "tag": "process"}

        # 注册表相关
        if any(kw in question_lower for kw in ["注册表", "registry"]):
            return {"type": "search_by_tag", "tag": "registry"}

        # 持久化相关
        if any(kw in question_lower for kw in ["持久", "persistence", "启动", "autorun"]):
            return {"type": "search_by_tag", "tag": "persistence"}

        # 反调试相关
        if any(kw in question_lower for kw in ["反调试", "anti-debug", "debug"]):
            return {"type": "search_by_tag", "tag": "anti_debug"}

        # C2 相关
        if any(kw in question_lower for kw in ["c2", "command", "control", "beacon"]):
            return {"type": "search_by_tag", "tag": "c2"}

        # 查询特定函数
        if "函数" in question_lower or "function" in question_lower:
            # 尝试提取函数名
            for word in question.split():
                if word.startswith("sub_") or word.startswith("0x"):
                    return {"type": "get_function_info", "function_name": word}

        # 通用搜索
        keywords = ["查找", "搜索", "find", "search", "哪个", "which", "哪里", "where"]
        for kw in keywords:
            if kw in question_lower:
                # 提取关键词
                remaining = question_lower.replace(kw, "").strip()
                if remaining:
                    return {"type": "search_by_keyword", "keyword": remaining}

        # 默认：通用问题
        return {"type": "general_question"}

    def _search_by_tag(self, sample_sha256: str, tag: str) -> str:
        """根据标签搜索函数"""
        functions = self.db.get_functions_by_tag(sample_sha256, tag)

        if not functions:
            return f"未找到与 '{tag}' 相关的函数。"

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

        desc = tag_desc.get(tag, tag)
        lines = [f"找到 {len(functions)} 个与 '{desc}' 相关的函数：\n"]

        for i, func in enumerate(functions[:10], 1):
            lines.append(f"{i}. **{func.name}** (地址: {func.address})")
            if func.summary:
                lines.append(f"   摘要: {func.summary}")
            lines.append(f"   置信度: {func.confidence:.0%}")
            lines.append("")

        if len(functions) > 10:
            lines.append(f"... 还有 {len(functions) - 10} 个函数")

        return "\n".join(lines)

    def _search_by_keyword(self, sample_sha256: str, keyword: str) -> str:
        """根据关键词搜索函数"""
        functions = self.db.search_functions(sample_sha256, keyword)

        if not functions:
            return f"未找到包含 '{keyword}' 的函数。"

        lines = [f"找到 {len(functions)} 个包含 '{keyword}' 的函数：\n"]

        for i, func in enumerate(functions[:10], 1):
            lines.append(f"{i}. **{func.name}** (地址: {func.address})")
            if func.summary:
                lines.append(f"   摘要: {func.summary}")
            lines.append("")

        return "\n".join(lines)

    def _get_function_info(self, sample_sha256: str, function_name: str) -> str:
        """获取函数详细信息"""
        # 尝试按名称查找
        func = self.db.get_function_by_name(sample_sha256, function_name)

        # 尝试按地址查找
        if not func:
            func = self.db.get_function_by_address(sample_sha256, function_name)

        if not func:
            return f"未找到函数 '{function_name}'。"

        lines = [f"## 函数信息: {func.name}\n"]
        lines.append(f"- **地址**: {func.address}")
        lines.append(f"- **置信度**: {func.confidence:.0%}")

        if func.behavior_tags:
            lines.append(f"- **行为标签**: {', '.join(func.behavior_tags)}")

        if func.summary:
            lines.append(f"\n### 摘要\n{func.summary}")

        if func.decompiled_code:
            # 截取前 2000 字符
            code_preview = func.decompiled_code[:2000]
            if len(func.decompiled_code) > 2000:
                code_preview += "\n... (代码已截断)"
            lines.append(f"\n### 反编译代码\n```\n{code_preview}\n```")

        return "\n".join(lines)

    def _general_question(self, sample_sha256: str, question: str) -> str:
        """通用问题（使用 LLM）"""
        if not self.llm:
            return "抱歉，通用问答功能需要配置 LLM API。请设置 MIMO_API_KEY 或 OPENAI_API_KEY 环境变量。"

        # 获取函数统计
        func_count = self.db.get_function_count(sample_sha256)
        functions = self.db.get_functions_by_sample(sample_sha256)

        # 构建上下文
        context_parts = [f"样本 SHA256: {sample_sha256}"]
        context_parts.append(f"函数总数: {func_count}")

        # 添加关键函数信息
        context_parts.append("\n关键函数列表:")
        for func in functions[:30]:  # 限制数量
            tags_str = ", ".join(func.behavior_tags) if func.behavior_tags else "无"
            context_parts.append(f"- {func.name} [{tags_str}]: {func.summary}")

        context = "\n".join(context_parts)

        prompt = f"""你是一个逆向分析专家。根据以下样本信息回答用户问题。

{context}

用户问题: {question}

请用中文回答，基于提供的函数信息进行分析。如果信息不足，请说明。"""

        try:
            messages = [ChatMessage(role="user", content=prompt)]
            response = self.llm.chat(messages, temperature=0.3, max_tokens=1000)
            return response.content
        except Exception as e:
            logger.error(f"LLM question failed: {e}")
            return f"问答失败: {str(e)}"
