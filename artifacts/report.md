# 逆向分析报告

**生成时间**: 2026-05-03T01:02:53.100956
**样本 SHA256**: `ca29e8d8eca84f6f1b39e0bad771752cebf86d7754c20b69c77ab641a9ac2767`

## 基本信息

| 属性 | 值 |
|------|-----|
| 文件路径 | `C:\Projects\Agent-projects\Reverse-Agent\samples\notepad.exe` |
| 文件大小 | 360,448 bytes |
| MD5 | `ff3e29fdfafa0e9030e2fcd71489d41d` |
| SHA1 | `d11d30ad4f2780ffee3626901bc50ccf5b20fc2d` |
| SHA256 | `ca29e8d8eca84f6f1b39e0bad771752cebf86d7754c20b69c77ab641a9ac2767` |

## 文件类型

- **结论**: file command failed: Command not found: file
- **置信度**: 高
- **证据**: `file` 命令输出

## 字符串分析

- **总字符串数**: 0
- **置信度**: 高
- **证据**: `strings` 命令输出


## YARA 匹配

- **状态**: 跳过（YARA not installed or not in PATH）

## 工具执行日志

| 工具 | 状态 | 耗时 | Artifacts |
|------|------|------|-----------|
| file | ✗ failed | 4ms | 0 |
| strings | ✗ failed | 1ms | 0 |
| readelf | ⚠ partial | 5ms | 0 |
| objdump | ⚠ partial | 9ms | 0 |
| yara | ○ skipped | 1ms | 0 |

---

## 待确认事项

- [ ] 动态分析（需人工批准）
- [ ] 网络行为验证
- [ ] 加密算法确认
- [ ] 漏洞验证

---

*报告由 Reverse-Agent 自动生成*
*证据文件位于 `artifacts/` 目录*