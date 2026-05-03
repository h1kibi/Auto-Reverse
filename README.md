# Reverse-Agent

自动化逆向分析 Agent - 支持静态分析 + 函数级 Agent 分析 + 受控动态分析

## 功能

### 阶段1：静态 Triage
- 样本指纹（MD5/SHA1/SHA256）
- 文件类型识别（PE/ELF）
- 字符串提取与分析
- ELF/PE 结构分析
- YARA 规则匹配
- Ghidra 反编译（可选）

### 阶段2：函数级 Agent 分析
- 自动识别关键函数（按字符串引用、API 调用、行为标签排序）
- LLM 生成函数摘要（支持 MiMo / OpenAI API）
- SQLite 存储函数摘要
- 交互式问答（"哪个函数处理网络？"、"哪个函数像解密？"）

### 阶段3：受控动态分析
- 沙箱执行（资源限制、文件隔离）
- strace 系统调用跟踪
- ltrace 库函数跟踪
- Frida 动态 Instrumentation（网络、加密、文件、进程 hook）
- 安全规则：必须人工确认、默认无网络、超时限制

## 安装

```bash
pip install -r requirements.txt

# 可选：安装 Frida（用于动态分析）
pip install frida-tools
```

## 使用方法

### 静态分析

```bash
# 分析样本
python -m re_agent analyze samples/notepad.exe --skip-ghidra

# 指定输出目录
python -m re_agent analyze samples/malware.bin -o output/
```

### 动态分析

```bash
# 查看安全警告
python -m re_agent dynamic samples/notepad.exe

# 确认执行动态分析
python -m re_agent dynamic samples/notepad.exe --confirm

# 自定义选项
python -m re_agent dynamic samples/notepad.exe --confirm --timeout 30 --no-frida
```

### 函数分析

```bash
# 列出函数
python -m re_agent functions <sha256> --db artifacts/database.db

# 按标签过滤
python -m re_agent functions <sha256> --tag network
```

### 问答

```bash
# 询问函数功能
python -m re_agent ask <sha256> "哪个函数处理网络？" --db artifacts/database.db

# 查询特定函数
python -m re_agent ask <sha256> "sub_401000 函数的功能是什么？"
```

### 启动 API 服务

```bash
python -m re_agent serve --port 8000
# 访问 http://localhost:8000/docs
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/analyze` | 静态分析 |
| POST | `/upload-and-analyze` | 上传并分析 |
| GET | `/report/{sha256}` | 获取报告 |
| GET | `/functions/{sha256}` | 获取函数列表 |
| POST | `/ask` | 问答 |

## 环境变量

| 变量 | 说明 |
|------|------|
| `MIMO_API_KEY` | 小米 MiMo API Key |
| `OPENAI_API_KEY` | OpenAI API Key |
| `GHIDRA_HOME` | Ghidra 安装路径 |

## 安全说明

动态分析功能遵循以下安全原则：

1. **必须人工确认**：添加 `--confirm` 参数才能执行
2. **沙箱隔离**：临时目录、资源限制
3. **默认无网络**：防止数据泄露
4. **超时限制**：防止无限执行
5. **文件只读**：防止样本修改

## 项目结构

```
Reverse-Agent/
├── README.md
├── requirements.txt
├── re_agent/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py              # CLI 入口
│   ├── schema.py           # Artifact Schema
│   ├── pipeline.py         # 静态分析 Pipeline
│   ├── dynamic_pipeline.py # 动态分析 Pipeline
│   ├── reporter.py         # 报告生成器
│   ├── database.py         # SQLite 数据库
│   ├── analyzer.py         # 函数分析器
│   ├── qa.py               # 问答系统
│   ├── api.py              # Web API
│   ├── llm.py              # LLM 适配器
│   ├── sandbox.py          # 沙箱执行
│   └── tools/
│       ├── base.py
│       ├── file_tool.py
│       ├── strings_tool.py
│       ├── readelf_tool.py
│       ├── objdump_tool.py
│       ├── yara_tool.py
│       ├── ghidra_tool.py
│       ├── pefile_tool.py
│       ├── dynamic_base.py
│       ├── strace_tool.py
│       ├── ltrace_tool.py
│       └── frida_tool.py
├── samples/
└── artifacts/
```

## License

MIT
