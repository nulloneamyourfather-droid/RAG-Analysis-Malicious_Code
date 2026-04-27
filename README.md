# RAG-Analysis-Malicious_Code
本项目面向恶意代码静态分析任务，构建融合 ATT&amp;CK 知识、API 行为链知识和 IDA-MCP 提取样本语义信息的多源知识库，并基于 RAG 机制实现对恶意代码的智能辅助分析。系统能够从样本中提取函数语义、关键 API 调用链和行为特征，结合外部安全知识完成相关内容检索、结果重排和分析生成，最终输出恶意行为解释、ATT&amp;CK 技术映射以及分析报告片段，从而提升恶意代码静态分析的效率、准确性和可解释性。
# Malware Static Analysis Graduation Project

核心内容是：

- [attck_knowledge/README.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/README.md)
- [attck_knowledge/docs/design/TECHNICAL_ROUTE_SYSTEM_DESIGN.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/docs/design/TECHNICAL_ROUTE_SYSTEM_DESIGN.md)
- [attck_knowledge/docs/thesis/CHAPTER6_EXPERIMENT_RESULTS_DRAFT.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/docs/thesis/CHAPTER6_EXPERIMENT_RESULTS_DRAFT.md)

## Keep

- `attck_knowledge/`
  - 核心代码、测试、正式数据结构、样例输出和论文文档归档都在这里
- `samples/`
  - 保留 `sample_ida_semantic.json` 和归档后的地址文件
- `legacy/`
  - 顶层旧数据的归档位置；如果迁移被文件锁中断，可能仍会和根目录 `data/` 并存
- `IDA-MCP/`
  - 作为第三方源码副本保留，但其 `.git` 和 `.vs` 不应进入你的新仓库
- `targets.txt`
  - 当前默认的有效目标函数地址列表，已统一为 `1.bin`

## Ignore

- 顶层 `data/`
  - 早期重复产物，当前主链路不再使用；如已迁移则看 `legacy/top_level_data/`
- `virus/`
  - 本地样本与 IDA 数据库，不适合直接上传
- `__pycache__/`、`.pyc`
- `attck_knowledge/data/index/faiss/`
  - 本地可重建索引
- `attck_knowledge/data/index/metadata/latest_*`
  - 运行期最新结果，可重建

## Recommended Git Entry Points

- 项目主说明：
  - [attck_knowledge/README.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/README.md)
- 一键样本分析：
  - [run_sample_pipeline.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_sample_pipeline.py)
- 实验脚本：
  - [experiment_runner.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/experiment_runner.py)
- 论文材料：
  - [attck_knowledge/docs/thesis](/d:/Graduation%20project/Midterm/asm/attck_knowledge/docs/thesis)
- 清理脚本：
  - [attck_knowledge/tools/cleanup_locked_legacy.ps1](/d:/Graduation%20project/Midterm/asm/attck_knowledge/tools/cleanup_locked_legacy.ps1)
