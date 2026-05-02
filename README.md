# Reverse-Agent

自动化逆向分析 Agent - 阶段1: 静态 Triage

## 概述

Reverse-Agent 是一个基于 Agent 的逆向分析系统，能够自动完成：

- 样本指纹（MD5/SHA1/SHA256）
- 文件类型识别
- 字符串提取与分析
- ELF/PE 结构分析
- YARA 规则匹配
- Ghidra 反编译（可选）

并生成**证据驱动**的分析报告，所有结论都引用具体的 artifact 证据。

## 核心原则

- **确定性优先**：工具负责确定性分析，Agent 负责推理和摘要
- **证据驱动**：报告必须引用 artifact，带置信度
- **人工把关**：动态分析需要人工批准
- **本地优先**：技术栈轻量化，快速验证核心价值

## 安装

### 系统要求

- Python 3.10+
- Linux 或 Windows (WSL)
- 可选：Ghidra 10+（用于反编译）
- 可选：YARA（用于规则匹配）

### 安装步骤

```bash
# 克隆项目
cd C:\Projects\Agent-projects\Reverse-Agent

# 安装依赖（大部分是标准库）
pip install -r requirements.txt
```

### 工具安装（Linux/WSL）

```bash
# 基础工具（通常已安装）
sudo apt install binutils file

# YARA（可选）
sudo apt install yara

# Ghidra（可选）
# 下载 https://ghidra-sre.org/ 并解压到 /opt/ghidra
# 或设置 GHIDRA_HOME 环境变量
```

## 使用方法

### 基本用法

```bash
# 分析样本
python -m re_agent analyze samples/malware.bin

# 指定输出目录
python -m re_agent analyze samples/malware.bin -o output/

# 跳过 Ghidra（如果未安装）
python -m re_agent analyze samples/malware.bin --skip-ghidra

# 启用详细日志
python -m re_agent analyze samples/malware.bin -v
```

### 输出结构

```
artifacts/
├── analysis_result.json    # 完整分析结果（JSON）
├── report.md               # Markdown 格式报告
├── file_info_file_info.txt # file 命令输出
├── strings_strings.txt     # 提取的字符串
├── sections_sections.txt   # ELF 段信息
├── functions_symbols.txt   # 符号表
├── disassembly_disassembly.txt # 反汇编代码
├── functions.json          # Ghidra 函数列表（如果启用）
├── callgraph.json          # Ghidra 调用图（如果启用）
└── decompiled_*.txt        # 反编译代码（如果启用）
```

### 报告示例

```markdown
## 基本信息

| 属性 | 值 |
|------|-----|
| 文件大小 | 1,234,567 bytes |
| SHA256 | abc123... |

## 文件类型

- **结论**: ELF 64-bit LSB executable, x86-64
- **置信度**: 高
- **证据**: `file` 命令输出

## 字符串分析

- **总字符串数**: 1,234
- **关键字符串**:
  - [URL] http://example.com/api/upload
  - [Credential] password123
```

## 项目结构

```
Reverse-Agent/
├── README.md
├── requirements.txt
├── re_agent/
│   ├── __init__.py
│   ├── __main__.py      # python -m 入口
│   ├── cli.py           # CLI 界面
│   ├── schema.py        # Artifact Schema
│   ├── pipeline.py      # 分析 Pipeline
│   ├── reporter.py      # 报告生成器
│   └── tools/
│       ├── __init__.py
│       ├── base.py      # 工具基类
│       ├── file_tool.py
│       ├── strings_tool.py
│       ├── readelf_tool.py
│       ├── objdump_tool.py
│       ├── yara_tool.py
│       └── ghidra_tool.py
├── samples/             # 样本目录
├── artifacts/           # 输出目录
└── tests/
```

## 后续计划

### 阶段2：函数级 Agent 分析（2-3 周）

- 自动找关键函数（按字符串引用、API 调用、图中心性排序）
- 给每个函数生成自然语言摘要
- 支持交互式问答

### 阶段3：受控动态分析（2-3 周）

- QEMU / sandbox 执行样本
- strace / ltrace 跟踪
- Frida hook 常见 API
- 执行前人工确认

## License

MIT
