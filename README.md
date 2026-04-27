#环境默认配置好了IDA-MCP

# Malware Static Analysis Graduation Project

核心内容是：

- [attck_knowledge/README.md](/attck_knowledge/README.md)
- [attck_knowledge/docs/design/TECHNICAL_ROUTE_SYSTEM_DESIGN.md](/attck_knowledge/docs/design/TECHNICAL_ROUTE_SYSTEM_DESIGN.md)

## Keep

- `attck_knowledge/`
  - 核心代码、测试、正式数据结构、样例输出


## Ignore

- `__pycache__/`、`.pyc`
- `attck_knowledge/data/index/faiss/`
  - 本地可重建索引
- `attck_knowledge/data/index/metadata/latest_*`
  - 运行期最新结果，可重建

## Recommended Git Entry Points

- 项目主说明：
  - [attck_knowledge/README.md](/attck_knowledge/README.md)
- 一键样本分析：
  - [run_sample_pipeline.py](/attck_knowledge/run_sample_pipeline.py)
- 实验脚本：
  - [experiment_runner.py](/attck_knowledge/experiment_runner.py)
- 清理脚本：
  - [attck_knowledge/tools/cleanup_locked_legacy.ps1](/attck_knowledge/tools/cleanup_locked_legacy.ps1)



# attck_knowledge

`attck_knowledge` 负责知识构建、检索增强分析、样本级聚合与报告输出的核心模块。它围绕 `IDA-MCP + ATT&CK + API_CHAIN + IDA_SEMANTIC + RAG` 这条链路工作，目标是把 IDA 当前正在分析的样本转换为结构化证据、能力链和样本级分析报告。

## 1. 当前实现范围

当前工程已经落地的主流程如下：

```text
IDA / IDA-MCP
  -> 导出当前样本或当前函数的静态语义事实
  -> 构建 IDA_SEMANTIC raw / rag 数据
  -> 联合 ATT&CK / API_CHAIN / IDA_SEMANTIC 进行多源检索
  -> 检索后重排与证据融合
  -> 生成函数级 evidence / analysis
  -> 进行样本级聚合与能力链分析
  -> 输出 Markdown / JSON 报告
```

当前知识源包括：
- `ATT&CK`
- `API_CHAIN`
- `IDA_SEMANTIC`

当前支持的 RAG 后端包括：
- `semantic`：`SentenceTransformer + FAISS`
- `tfidf`：`TF-IDF` 轻量检索后端

## 2. 目录结构

```text
attck_knowledge/
├─ builders/
│  ├─ build_attack_kb.py
│  ├─ build_api_chain_kb.py
│  ├─ build_ida_semantic_kb.py
│  └─ export_ida_semantic_from_mcp.py
├─ data/
│  ├─ raw/
│  ├─ rag/
│  ├─ legacy_snapshots/
│  └─ index/
│     ├─ faiss/
│     └─ metadata/
├─ docs/
│  ├─ design/
│  ├─ thesis/
│  └─ maintenance/
├─ schemas/
├─ tests/
├─ tools/
├─ aggregate_sample_analysis.py
├─ analyze_function_evidence.py
├─ build_rag_index.py
├─ capability_chain.py
├─ experiment_runner.py
├─ generator.py
├─ query_constructor.py
├─ rag_index.py
├─ reporting_v2.py
├─ reranker.py
├─ run_function_rag_demo.py
├─ run_sample_pipeline.py
├─ run_sample_pipeline_impl.py
├─ select_high_value_functions.py
└─ README.md
```

## 3. 模块说明

### 3.1 知识构建
- [build_attack_kb.py](/attck_knowledge/builders/build_attack_kb.py)：构建 ATT&CK 原始知识与 RAG 文档。
- [build_api_chain_kb.py](/attck_knowledge/builders/build_api_chain_kb.py)：构建 API 行为模板知识。
- [build_ida_semantic_kb.py](/attck_knowledge/builders/build_ida_semantic_kb.py)：把导出的函数事实整理为 `raw` 和 `rag` 两层数据。

### 3.2 IDA / MCP 导出
- [export_ida_semantic_from_mcp.py](/attck_knowledge/builders/export_ida_semantic_from_mcp.py)：从 IDA-MCP 导出当前样本的函数语义、API、字符串、调用关系等信息。
- [select_high_value_functions.py](/attck_knowledge/select_high_value_functions.py)：对当前样本函数进行质量评分，优先筛掉 thunk/runtime 噪声，并生成高价值函数列表。

### 3.3 查询构造、重排与生成
- [query_constructor.py](/attck_knowledge/query_constructor.py)：把函数语义、API、字符串等信息整理为检索查询包。
- [rag_index.py](/attck_knowledge/rag_index.py)：封装 RAG 文档加载、向量索引构建与检索接口。
- [reranker.py](/attck_knowledge/reranker.py)：对多源召回结果做规则化重排与 ATT&CK 候选融合。
- [generator.py](/attck_knowledge/generator.py)：把 evidence 组织成可供解释或继续交给 LLM 的生成载荷。

### 3.4 函数级与样本级分析
- [run_function_rag_demo.py](/attck_knowledge/run_function_rag_demo.py)：执行函数级检索、重排、evidence 生成。
- [analyze_function_evidence.py](/attck_knowledge/analyze_function_evidence.py)：根据函数级 evidence 给出是否可疑、是否像 runtime/helper 的判断。
- [aggregate_sample_analysis.py](/attck_knowledge/aggregate_sample_analysis.py)：把多个函数的 evidence 和分析结果聚合成样本级结论。
- [capability_chain.py](/attck_knowledge/capability_chain.py)：生成能力链、阶段命名、摘要和证据解释。
- [reporting_v2.py](/attck_knowledge/reporting_v2.py)：输出技术版报告和论文版报告。

### 3.5 主入口
- [run_sample_pipeline.py](/attck_knowledge/run_sample_pipeline.py)：项目主入口，当前是一个极简壳文件。
- [run_sample_pipeline_impl.py](/attck_knowledge/run_sample_pipeline_impl.py)：真实的一键分析实现。

### 3.6 实验脚本
- [experiment_runner.py](/attck_knowledge/experiment_runner.py)：用于支撑论文实验章节，包括：
  - 有无 RAG 对比
  - 不同知识源组合对比
  - 不同分片策略对比

### 3.7 文档与维护脚本
- [docs/README.md](/attck_knowledge/docs/README.md)：文档目录总说明。
- [docs/design](/attck_knowledge/docs/design)：技术路线和数据重构设计文档。
- [docs/maintenance](/attck_knowledge/docs/maintenance)：项目状态检查、工作区审计和维护记录。
重复 Markdown、`__pycache__`、嵌套 `.git/.vs` 等遗留物。

## 4. 数据分层

### 4.1 raw 层
`raw` 层保存原始结构化事实，主要给程序和调试使用。

例如：
- ATT&CK 技术原始字段
- API 行为模板原始定义
- IDA 导出的函数语义事实

### 4.2 rag 层
`rag` 层把原始事实改写成适合检索的文档。

典型字段包括：
- `doc_id`
- `source`
- `title`
- `summary`
- `content`
- `keywords`

### 4.3 index 层
`index` 层保存已经构建好的检索索引和分析结果。

当前主要包括：
- 向量索引和检索元数据：`data/index/faiss/`
- 函数级、样本级、实验输出：`data/index/metadata/`

### 4.4 legacy_snapshots 层
`data/legacy_snapshots/` 用于存放历史阶段遗留下来的旧版知识产物快照，仅用于兼容旧路径或手工排查。

当前规范是：
- `schemas/` 只放 schema 文件
- `data/raw/`、`data/rag/` 放当前正式产物
- `data/legacy_snapshots/` 放旧版快照

如果你仍在 `schemas/` 下看到 `*_raw.json` 或 `*_for_rag.jsonl`，那是历史遗留文件，不是当前主链路的正式输出位置。

如果这些历史文件当前没有被编辑器、终端或脚本占用，可以手工清理：

```powershell
Remove-Item attck_knowledge\schemas\attack_knowledge_raw.json
Remove-Item attck_knowledge\schemas\attack_knowledge_for_rag.jsonl
Remove-Item attck_knowledge\schemas\api_chain_knowledge_raw.json
Remove-Item attck_knowledge\schemas\api_chain_knowledge_for_rag.jsonl
Remove-Item attck_knowledge\schemas\ida_semantic_knowledge_raw.json
Remove-Item attck_knowledge\schemas\ida_semantic_knowledge_for_rag.jsonl
```

清理后建议保留：
- `schemas/*.schema.json`
- `data/raw/*`
- `data/rag/*`
- `data/legacy_snapshots/*`

## 5. 向量索引位置

当前真实存在的索引文件位于 [data/index/faiss](/attck_knowledge/data/index/faiss)：

- [rag_docs.json](/attck_knowledge/data/index/faiss/rag_docs.json)
- [rag_index_metadata.json](/attck_knowledge/data/index/faiss/rag_index_metadata.json)
- [semantic_embeddings.npy](/attck_knowledge/data/index/faiss/semantic_embeddings.npy)
- [semantic_faiss.index](/attck_knowledge/data/index/faiss/semantic_faiss.index)
- [tfidf_matrix.npz](/attck_knowledge/data/index/faiss/tfidf_matrix.npz)
- [tfidf_vectorizer.joblib](/attck_knowledge/data/index/faiss/tfidf_vectorizer.joblib)

也就是说，当前项目已经有实际落盘的本地 RAG 索引，不再只是 JSONL 文档。

## 6. 主要输出文件

函数级和样本级分析产物位于 [data/index/metadata](/attck_knowledge/data/index/metadata)：

- [latest_function_evidence.json](/attck_knowledge/data/index/metadata/latest_function_evidence.json)
- [latest_function_analysis.json](/attck_knowledge/data/index/metadata/latest_function_analysis.json)
- [latest_sample_analysis.json](/attck_knowledge/data/index/metadata/latest_sample_analysis.json)
- [latest_capability_chains.json](/attck_knowledge/data/index/metadata/latest_capability_chains.json)
- [latest_sample_report.md](/attck_knowledge/data/index/metadata/latest_sample_report.md)
- [latest_sample_report_paper.md](/attck_knowledge/data/index/metadata/latest_sample_report_paper.md)

实验输出位于 [data/index/metadata/experiments](/attck_knowledge/data/index/metadata/experiments)：

- [rag_vs_no_rag.json](/attck_knowledge/data/index/metadata/experiments/rag_vs_no_rag.json)
- [source_combinations.json](/attck_knowledge/data/index/metadata/experiments/source_combinations.json)
- [chunking_strategies.json](/attck_knowledge/data/index/metadata/experiments/chunking_strategies.json)
- [experiment_summary.md](/attck_knowledge/data/index/metadata/experiments/experiment_summary.md)

## 7. 使用方式

### 7.1 构建知识库与索引
先构建基础知识和索引：

```powershell
python attck_knowledge\builders\build_attack_kb.py
python attck_knowledge\builders\build_api_chain_kb.py
python attck_knowledge\build_rag_index.py --backend semantic --allow-model-download
```

如果只想使用轻量后端：

```powershell
python attck_knowledge\build_rag_index.py --backend tfidf
```

### 7.2 直接分析 IDA 当前正在分析的样本
这是当前最推荐的在线用法：

```powershell
python attck_knowledge\run_sample_pipeline.py --mcp-url http://127.0.0.1:13337/mcp --backend semantic
```

含义是：
- 从当前 IDA-MCP 会话中识别正在分析的样本
- 自动筛选高价值函数
- 导出函数语义信息
- 执行 RAG 检索、重排、聚合与报告输出

也可以显式写成：

```powershell
python attck_knowledge\run_sample_pipeline.py --mcp-url http://127.0.0.1:13337/mcp --analyze-current-sample --backend semantic
```

### 7.3 只分析当前函数
如果只想围绕 IDA 当前光标所在函数做分析：

```powershell
python attck_knowledge\run_sample_pipeline.py --mcp-url http://127.0.0.1:13337/mcp --analyze-current-function --backend semantic
```

### 7.4 使用显式地址或文件列表
如果你已经手工挑好了函数地址：

```powershell
python attck_knowledge\run_sample_pipeline.py --mcp-url http://127.0.0.1:13337/mcp --function-addresses-file .\targets.txt --backend semantic
```

历史地址文件已经归档到 [samples/targets](/d:/Graduation%20project/Midterm/asm/samples/targets)。当前默认入口仍然是根目录 [targets.txt](/d:/Graduation%20project/Midterm/asm/targets.txt)，它已经统一为 `1.bin` 的有效地址集合。

### 7.5 离线复用已有 sample JSON
如果暂时不连 MCP，可以复用已有导出结果：

```powershell
python attck_knowledge\run_sample_pipeline.py --skip-export --sample-json samples\ida_exports\sample_ida_semantic.json --backend semantic
```

## 8. MCP 样本名一致性校验

为了避免把旧样本结果误当成当前 IDA 样本，主入口已经加入样本名校验。

当前行为是：
- 在线导出时，会检查当前 MCP 样本名和旧 `sample_json` 中记录的样本名是否一致。
- `--skip-export` 时，也会检查当前 MCP 样本和已有 JSON 是否冲突。
- 默认不一致就报错，防止继续复用错误样本。
- 只有显式传入 `--force-overwrite-sample-json` 时，才允许覆盖旧结果。

示例：

```powershell
python attck_knowledge\run_sample_pipeline.py --mcp-url http://127.0.0.1:13337/mcp --backend semantic --force-overwrite-sample-json
```

## 9. 高价值函数筛选

为了减少 thunk、wrapper、runtime/helper 函数带来的噪声，当前项目在导出前增加了高价值函数筛选。

你也可以单独执行：

```powershell
python attck_knowledge\select_high_value_functions.py --mcp-url http://127.0.0.1:13337/mcp --limit 20
```

这会基于当前 IDA 样本生成新的 `targets.txt`，便于后续批量分析。

如果你希望保留历史记录，建议手工再复制一份到 [samples/targets](/d:/Graduation%20project/Midterm/asm/samples/targets)。

## 10. 实验脚本

### 10.1 有无 RAG 对比

```powershell
python attck_knowledge\experiment_runner.py --experiments rag_vs_no_rag --sample-json samples\ida_exports\sample_ida_semantic.json --backend semantic
```

### 10.2 不同知识源组合对比

```powershell
python attck_knowledge\experiment_runner.py --experiments source_combinations --sample-json samples\ida_exports\sample_ida_semantic.json --backend semantic
```

### 10.3 不同分片策略对比

```powershell
python attck_knowledge\experiment_runner.py --experiments chunking_strategies --sample-json samples\ida_exports\sample_ida_semantic.json --backend semantic
```

### 10.4 一次跑完三类实验

```powershell
python attck_knowledge\experiment_runner.py --sample-json samples\ida_exports\sample_ida_semantic.json --backend semantic --function-limit 20
```

## 11. 在 Cline 里的推荐问法

当 pipeline 跑完后，可以直接在 Cline 里继续读取产物并追问，例如：

- 读取 `latest_sample_report.md`，帮我解释这个样本
- 哪个函数最可疑
- 把样本级结果改写成论文里的实验结果描述
- 根据 ATT&CK 候选生成正式分析报告
- 解释这个能力链为什么成立

## 12. 当前边界

当前项目已经实现：
- 多源知识构建
- `semantic + FAISS` 与 `TF-IDF` 两种 RAG 后端
- 查询构造、召回、重排、evidence 组织
- 函数级分析
- 样本级聚合
- 能力链生成与阶段命名
- 技术版 / 论文版双报告输出
- 论文实验脚本

当前仍然需要注意：
- 生成层目前主要是结构化模板生成，Cline 侧可以继续接 LLM 做更强解释。
- 分析质量依赖于当前样本中高价值函数是否被正确导出。
- 若样本主要由 runtime/helper/thunk 构成，能力链和 ATT&CK 映射结果会偏弱。
- 这套系统适合毕业设计原型与实验平台，不应直接当作生产级恶意代码分析系统使用。
