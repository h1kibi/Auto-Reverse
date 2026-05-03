# Reverse-Agent

自动化逆向分析 Agent - 支持静态分析 + 函数级 Agent 分析 + 受控动态分析 + **CTF 求解**

## 功能

### 静态分析
- 样本指纹（MD5/SHA1/SHA256）
- 文件类型识别（PE/ELF）
- 字符串提取与分析
- Ghidra 反编译（可选）

### 函数级 Agent 分析
- 自动识别关键函数（按字符串引用、API 调用、行为标签排序）
- LLM 生成函数摘要（支持 MiMo / OpenAI API）
- 交互式问答

### 受控动态分析
- Docker 沙箱执行（资源限制、文件隔离）
- strace/ltrace 跟踪
- 安全规则：必须人工确认、默认无网络、超时限制

### CTF 求解（新）
- StaticFlagSolver：从 strings 中提取 flag（明文/base64/hex）
- Z3ConstraintSolver：约束求解
- AngrPathSolver：符号执行找 success 分支
- FlagValidator：验证候选 flag（argv/stdin 模式）

## 安装

```bash
# 基础安装
pip install -e .

# CTF 求解功能（含 z3、angr）
pip install -e ".[ctf]"

# 开发依赖
pip install -e ".[dev]"
```

## 快速开始

### CTF 求解

```bash
# 一键求解
python -m re_agent solve ./challenge --skip-ghidra

# 自定义 flag 格式
python -m re_agent solve ./challenge --flag-regex 'h1kibi\{[^}]+\}'

# API 求解
curl -X POST http://localhost:8000/solve \
  -H 'Content-Type: application/json' \
  -d '{"sample_path":"./challenge"}'
```

### 静态分析

```bash
python -m re_agent analyze samples/notepad.exe --skip-ghidra
```

### 动态分析

```bash
python -m re_agent dynamic samples/notepad.exe --confirm
```

### 启动 API

```bash
python -m re_agent serve --port 8000
# 访问 http://localhost:8000/docs
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/analyze` | 静态分析 |
| POST | `/upload-and-analyze` | 上传并分析 |
| POST | `/solve` | CTF 求解 |
| GET | `/report/{sha256}` | 获取报告 |
| POST | `/ask` | 问答 |
| GET | `/functions/{sha256}` | 获取函数列表 |

## 项目结构

```
Reverse-Agent/
├── re_agent/
│   ├── cli.py              # CLI 入口
│   ├── api.py              # Web API
│   ├── pipeline.py         # 静态分析 Pipeline
│   ├── sandbox.py          # Docker 沙箱
│   ├── ctf/
│   │   ├── models.py       # 数据模型
│   │   ├── profiler.py     # 挑战画像
│   │   ├── validator.py    # Flag 验证器
│   │   ├── pipeline.py     # 求解 Pipeline
│   │   ├── agent.py        # LLM Planner
│   │   └── solvers/
│   │       ├── static_flag.py
│   │       ├── z3_constraints.py
│   │       └── angr_path.py
│   └── tools/
├── tests/
├── docker/sandbox/
└── pyproject.toml
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `MIMO_API_KEY` | 小米 MiMo API Key |
| `OPENAI_API_KEY` | OpenAI API Key |
| `GHIDRA_HOME` | Ghidra 安装路径 |

## License

MIT
