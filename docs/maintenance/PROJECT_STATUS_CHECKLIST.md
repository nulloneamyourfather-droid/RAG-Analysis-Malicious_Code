# 项目当前状态检查报告

本文档用于对当前 `attck_knowledge` 模块进行阶段性留档，便于毕业设计答辩前自查。内容按三部分组织：

- 已完成
- 已验证
- 待手工清理


## 一、已完成

### 1. 主链路功能

当前项目已经完成如下主链路：

```text
IDA / IDA-MCP
  -> 导出当前样本或当前函数的静态语义事实
  -> 构建 IDA_SEMANTIC raw / rag 数据
  -> 联合 ATT&CK / API_CHAIN / IDA_SEMANTIC 执行多源检索
  -> 执行后检索重排与 evidence 组织
  -> 进行函数级分析
  -> 进行样本级聚合与能力链分析
  -> 输出技术版 / 论文版报告
```

当前已落地的核心脚本包括：

- [export_ida_semantic_from_mcp.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/builders/export_ida_semantic_from_mcp.py)
- [build_ida_semantic_kb.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/builders/build_ida_semantic_kb.py)
- [run_function_rag_demo.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_function_rag_demo.py)
- [analyze_function_evidence.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/analyze_function_evidence.py)
- [aggregate_sample_analysis.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/aggregate_sample_analysis.py)
- [capability_chain.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/capability_chain.py)
- [reporting_v2.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/reporting_v2.py)
- [run_sample_pipeline.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_sample_pipeline.py)
- [run_sample_pipeline_impl.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_sample_pipeline_impl.py)


### 2. 知识源与数据分层

当前项目已实现三类核心知识源：

- `ATT&CK`
- `API_CHAIN`
- `IDA_SEMANTIC`

当前数据分层已经明确：

- `data/raw/`：原始结构化事实
- `data/rag/`：面向检索的统一文档
- `data/index/`：向量索引、分析结果、实验产物
- `data/legacy_snapshots/`：历史遗留快照

Schema 文件位于：

- [schemas/rag_doc.schema.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/schemas/rag_doc.schema.json)
- [schemas/attack_record.schema.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/schemas/attack_record.schema.json)
- [schemas/api_behavior.schema.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/schemas/api_behavior.schema.json)
- [schemas/ida_function.schema.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/schemas/ida_function.schema.json)


### 3. RAG 实现

当前 RAG 不是概念层描述，而是已经具备真实索引文件与检索后端：

- 语义后端：`SentenceTransformer + FAISS`
- 轻量后端：`TF-IDF`

当前索引文件位于：

- [rag_docs.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/rag_docs.json)
- [rag_index_metadata.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/rag_index_metadata.json)
- [semantic_embeddings.npy](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/semantic_embeddings.npy)
- [semantic_faiss.index](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/semantic_faiss.index)
- [tfidf_matrix.npz](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/tfidf_matrix.npz)
- [tfidf_vectorizer.joblib](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/faiss/tfidf_vectorizer.joblib)


### 4. 查询构造、重排与生成载荷

当前项目已经完成：

- 查询构造模块：[query_constructor.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/query_constructor.py)
- 重排模块：[reranker.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/reranker.py)
- 生成载荷模块：[generator.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/generator.py)

需要明确的是：

- 当前已完成 evidence 组织与模板化输出
- 当前尚未完成完全独立的自动化 LLM 生成闭环
- 当前可以结合 Cline 中的大语言模型能力继续做增强解释


### 5. 样本级聚合与能力链

当前项目已经支持：

- 函数级可疑 / runtime-like 判断
- 样本级 ATT&CK 聚合
- 行为标签聚合
- 能力链生成
- 阶段命名
- 链路摘要
- 链路证据解释

当前相关产物包括：

- [latest_function_evidence.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_function_evidence.json)
- [latest_function_analysis.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_function_analysis.json)
- [latest_sample_analysis.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_sample_analysis.json)
- [latest_capability_chains.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_capability_chains.json)


### 6. 报告与论文辅助材料

当前项目已经支持：

- 技术版报告：[latest_sample_report.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_sample_report.md)
- 论文版报告：[latest_sample_report_paper.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_sample_report_paper.md)
- 第6章草稿：[CHAPTER6_EXPERIMENT_RESULTS_DRAFT.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/CHAPTER6_EXPERIMENT_RESULTS_DRAFT.md)
- 第7章草稿：[CHAPTER7_CONCLUSION_AND_FUTURE_WORK.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/CHAPTER7_CONCLUSION_AND_FUTURE_WORK.md)
- 第1章至第5章修改建议：[THESIS_CHAPTER1_TO_5_REVISION_GUIDE.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/THESIS_CHAPTER1_TO_5_REVISION_GUIDE.md)


### 7. 实验脚本

当前已完成论文实验脚本：

- [experiment_runner.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/experiment_runner.py)

支持实验类型：

- 有无 RAG 对比
- 不同知识源组合对比
- 不同分片策略对比

实验输出位于：

- [rag_vs_no_rag.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/experiments/rag_vs_no_rag.json)
- [source_combinations.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/experiments/source_combinations.json)
- [chunking_strategies.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/experiments/chunking_strategies.json)
- [experiment_summary.md](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/experiments/experiment_summary.md)


## 二、已验证

### 1. 编码与语法

已完成的验证包括：

- `builder` 文件头 BOM 已去掉
- `attck_knowledge` 目录下 Python 文件语法已通过检查
- `README.md` 中文已恢复正常且不再是问号损坏


### 2. 导入与入口兼容性

当前已验证：

- 关键脚本既能直接运行，也能按 `attck_knowledge.xxx` 形式导入
- 主入口命令帮助正常输出
- 实验脚本命令帮助正常输出

已实际验证的主入口包括：

- [run_sample_pipeline.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_sample_pipeline.py)
- [run_sample_pipeline_impl.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_sample_pipeline_impl.py)
- [run_function_rag_demo.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/run_function_rag_demo.py)
- [experiment_runner.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/experiment_runner.py)


### 3. 实验函数选择逻辑

当前已验证：

- `experiment_runner.select_functions()` 不再简单截取前 `N` 个函数
- 会优先按 `selection_score` 或重新计算的高价值评分排序
- 这与论文中“高价值函数”表述一致


### 4. 最小回归测试

当前已新增并验证通过的测试文件：

- [test_entrypoints.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/tests/test_entrypoints.py)
- [test_experiment_runner.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/tests/test_experiment_runner.py)
- [test_result_shapes.py](/d:/Graduation%20project/Midterm/asm/attck_knowledge/tests/test_result_shapes.py)

当前已覆盖的检查点包括：

- 主入口模块可导入
- 实验脚本可导入
- 主入口和实验脚本 `--help` 正常输出
- 高价值函数排序逻辑符合预期
- `latest_sample_analysis.json` 关键字段结构稳定
- `rag_vs_no_rag.json` 关键字段结构稳定

最近一次测试结果：

```text
Ran 9 tests ... OK
```


## 三、待手工清理

### 1. `schemas/` 目录中的历史数据文件

当前 `schemas/` 下仍残留以下历史数据产物：

- `attack_knowledge_raw.json`
- `attack_knowledge_for_rag.jsonl`
- `api_chain_knowledge_raw.json`
- `api_chain_knowledge_for_rag.jsonl`
- `ida_semantic_knowledge_raw.json`
- `ida_semantic_knowledge_for_rag.jsonl`

这些文件不是当前主链路的正式输出位置，已经被 `data/legacy_snapshots/` 所替代。

当前未能自动删除的原因是：

- 这些文件处于占用状态
- PowerShell 删除时返回 `Access is denied`


### 2. 建议的手工清理命令

在确认这些文件没有被编辑器、终端或其他进程占用后，可以手工执行：

```powershell
Remove-Item attck_knowledge\schemas\attack_knowledge_raw.json
Remove-Item attck_knowledge\schemas\attack_knowledge_for_rag.jsonl
Remove-Item attck_knowledge\schemas\api_chain_knowledge_raw.json
Remove-Item attck_knowledge\schemas\api_chain_knowledge_for_rag.jsonl
Remove-Item attck_knowledge\schemas\ida_semantic_knowledge_raw.json
Remove-Item attck_knowledge\schemas\ida_semantic_knowledge_for_rag.jsonl
```

执行完成后，`schemas/` 应仅保留：

- `rag_doc.schema.json`
- `attack_record.schema.json`
- `api_behavior.schema.json`
- `ida_function.schema.json`


### 3. 仍需在答辩中口头说明的边界

虽然当前项目已经形成完整原型，但答辩时仍建议明确说明以下边界：

- 当前系统是“恶意代码静态分析辅助原型系统”，不是生产级自动判定平台
- 当前生成层主要是 evidence 组织与模板化输出，不是完全自动化 LLM 闭环
- 当前实验规模仍较小，主要用于验证技术路线可行性
- 当前分析质量仍依赖高价值函数是否被正确导出


## 四、答辩前最终自查建议

答辩前建议按如下顺序快速自查：

1. 确认 `README.md`、第 6 章、第 7 章文档可以正常打开且中文无乱码  
2. 确认 `python -m unittest discover attck_knowledge/tests` 仍然通过  
3. 确认 `run_sample_pipeline.py --help` 和 `experiment_runner.py --help` 正常  
4. 确认 `data/index/faiss/` 下索引文件存在  
5. 确认 `data/index/metadata/` 下样本级产物存在  
6. 如条件允许，清理 `schemas/` 下历史数据文件  
7. 在论文中统一系统定位与当前实现边界表述


## 五、当前结论

截至当前阶段，`attck_knowledge` 模块已经具备以下答辩可用特征：

- 主链路完整
- 目录职责基本清晰
- 关键脚本与实验脚本可运行
- 论文实验章节有对应脚本与结果支撑
- 论文第 6、7 章已有可直接修改使用的正文草稿
- 已有最小回归测试保护关键入口与结果结构

因此，当前项目已经达到“毕业设计原型系统可演示、可复现、可留档”的状态。剩余工作主要集中在文档统一、历史文件清理与论文最终润色，而不再是主链路功能缺失。
