# attck_knowledge 检查结果、统一数据结构与改造方案

## 1. 当前目录检查结果

当前目录结构如下：

```text
attck_knowledge/
├─ build_attack_kb.py
├─ build_api_chain_kb.py
├─ build_ida_semantic_kb.py
└─ data/
   ├─ attack/
   │  ├─ attack_knowledge_raw.json
   │  └─ attack_knowledge_for_rag.jsonl
   ├─ api_chain/
   │  ├─ api_chain_knowledge_raw.json
   │  └─ api_chain_knowledge_for_rag.jsonl
   └─ ida_semantic/
      ├─ ida_semantic_knowledge_raw.json
      └─ ida_semantic_knowledge_for_rag.jsonl
```

### 1.1 当前优点

当前方案已经具备多源知识库的基本雏形：

- `attack`：ATT&CK 技术知识
- `api_chain`：恶意行为模板知识
- `ida_semantic`：函数级语义知识

并且已经初步采用了 `raw + jsonl for rag` 的双层产出模式，方向正确。


### 1.2 当前主要问题

#### 问题一：中文编码乱码

经检查，以下位置存在明显乱码：

- [`build_attack_kb.py`](/d:/毕业设计/期中/源代码/attck_knowledge/build_attack_kb.py)
- [`build_api_chain_kb.py`](/d:/毕业设计/期中/源代码/attck_knowledge/build_api_chain_kb.py)
- [`build_ida_semantic_kb.py`](/d:/毕业设计/期中/源代码/attck_knowledge/build_ida_semantic_kb.py)
- [`data/api_chain/api_chain_knowledge_raw.json`](/d:/毕业设计/期中/源代码/attck_knowledge/data/api_chain/api_chain_knowledge_raw.json)
- [`data/api_chain/api_chain_knowledge_for_rag.jsonl`](/d:/毕业设计/期中/源代码/attck_knowledge/data/api_chain/api_chain_knowledge_for_rag.jsonl)
- [`data/ida_semantic/ida_semantic_knowledge_raw.json`](/d:/毕业设计/期中/源代码/attck_knowledge/data/ida_semantic/ida_semantic_knowledge_raw.json)
- [`data/ida_semantic/ida_semantic_knowledge_for_rag.jsonl`](/d:/毕业设计/期中/源代码/attck_knowledge/data/ida_semantic/ida_semantic_knowledge_for_rag.jsonl)

影响：

- 直接降低 embedding 质量
- 检索关键词污染
- 最终生成报告可读性差
- 不利于论文展示与实验复现


#### 问题二：三类数据的字段风格不统一

当前 3 类知识的字段各自独立，虽然都能用，但后续检索、过滤、重排、评估会变复杂。


#### 问题三：`ida_semantic` 仍偏样例数据

`ida_semantic` 的构建脚本当前仍然以示例 JSON 为主，尚未完全形成“从 IDA-MCP 自动导出真实样本函数语义”的流水线。


#### 问题四：行为模板表达能力还不够

当前 `api_chain` 已有 `attack_mapping`，但缺少更适合规则化推理与可解释召回的结构字段，例如：

- 必选 API
- 可选 API
- 负向信号
- 行为证据模板
- 置信度策略


## 2. 推荐的统一数据分层

建议将知识数据统一分为三层：

### 2.1 原始层 `raw`

保留原始结构化信息，面向清洗、分析、调试。

特点：

- 字段完整
- 不做 embedding 文本拼接
- 保留尽可能多的上下文


### 2.2 检索层 `rag_docs`

面向向量检索与混合检索的标准文档格式。

特点：

- 全部知识源统一 schema
- 每条记录可直接进入向量库
- 保留足够元数据用于过滤


### 2.3 分析层 `evidence`

面向在线推理阶段的证据对象。

特点：

- 从当前样本函数和检索结果临时拼装
- 不一定落盘
- 用于生成函数级 ATT&CK 归因与解释


## 3. 统一的 RAG 文档 Schema

建议三类知识统一使用如下 schema：

```json
{
  "doc_id": "string",
  "source": "ATTACK | API_CHAIN | IDA_SEMANTIC | REPORT_MEMORY",
  "doc_type": "string",
  "title": "string",
  "summary": "string",
  "content": "string",
  "tags": ["string"],
  "keywords": ["string"],
  "platforms": ["Windows"],
  "attack_ids": ["T1055"],
  "metadata": {
    "language": "zh-CN",
    "sample_name": "optional",
    "sample_hash": "optional",
    "function_name": "optional",
    "function_addr": "optional",
    "behavior_id": "optional",
    "category": "optional",
    "api_sequence": ["optional"],
    "tactics": ["optional"],
    "url": "optional"
  }
}
```

说明：

- `summary` 用于简短语义表示，适合 embedding
- `content` 用于保留可读描述，适合送入 LLM
- `keywords` 用于 BM25/关键词过滤
- `attack_ids` 用于 ATT&CK 关联与统计
- `platforms` 用于过滤 Windows/Linux 等场景


## 4. 三类知识源推荐数据结构

### 4.1 ATT&CK 知识推荐结构

#### Raw 层

```json
{
  "stix_id": "...",
  "attack_id": "T1055",
  "name": "Process Injection",
  "type": "technique",
  "description": "...",
  "tactics": ["Defense Evasion", "Privilege Escalation"],
  "tactic_ids": ["TA0005", "TA0004"],
  "platforms": ["Windows"],
  "data_sources": ["Process", "Memory"],
  "detection": "...",
  "mitigations": [
    {
      "mitigation_id": "M1040",
      "mitigation_name": "...",
      "mitigation_desc": "..."
    }
  ],
  "url": "https://attack.mitre.org/techniques/T1055"
}
```

#### RAG 层


```json
{
  "doc_id": "attack::T1055",
  "source": "ATTACK",
  "doc_type": "attack-technique",
  "title": "T1055 Process Injection",
  "summary": "Windows 平台上的进程注入技术，可用于代码执行与逃避检测。",
  "content": "...",
  "tags": ["Process Injection", "Defense Evasion", "Privilege Escalation"],
  "keywords": ["OpenProcess", "WriteProcessMemory", "CreateRemoteThread"],
  "platforms": ["Windows"],
  "attack_ids": ["T1055"],
  "metadata": {
    "tactics": ["Defense Evasion", "Privilege Escalation"],
    "url": "https://attack.mitre.org/techniques/T1055"
  }
}
```


### 4.2 API 行为链知识推荐结构

#### Raw 层

```json
{
  "behavior_id": "behavior::process_injection::001",
  "behavior_name": "进程注入",
  "category": "进程控制",
  "platform": "Windows",
  "required_apis": ["OpenProcess", "WriteProcessMemory"],
  "optional_apis": ["VirtualAllocEx", "CreateRemoteThread", "NtCreateThreadEx"],
  "negative_signals": [],
  "api_sequence_examples": [
    ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
  ],
  "semantic_description": "向远程进程写入数据并触发执行的行为。",
  "malicious_purpose": "代码注入、权限逃逸、隐蔽执行载荷。",
  "evidence_template": "函数调用 OpenProcess/WriteProcessMemory 等远程进程内存写入相关 API。",
  "attack_mapping": [
    {
      "attack_id": "T1055",
      "attack_name": "Process Injection"
    }
  ],
  "variant_note": "部分样本使用 APC 或 NtCreateThreadEx 变体。"
}
```

#### RAG 层

```json
{
  "doc_id": "api_chain::behavior::process_injection::001",
  "source": "API_CHAIN",
  "doc_type": "api-behavior-chain",
  "title": "进程注入",
  "summary": "涉及远程进程打开、内存分配、写入和线程执行的典型恶意行为模板。",
  "content": "...",
  "tags": ["进程注入", "Windows", "进程控制"],
  "keywords": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
  "platforms": ["Windows"],
  "attack_ids": ["T1055"],
  "metadata": {
    "behavior_id": "behavior::process_injection::001",
    "category": "进程控制",
    "required_apis": ["OpenProcess", "WriteProcessMemory"],
    "optional_apis": ["VirtualAllocEx", "CreateRemoteThread", "NtCreateThreadEx"]
  }
}
```


### 4.3 IDA 函数语义知识推荐结构

#### Raw 层

```json
{
  "sample_name": "xxx.exe",
  "sample_hash": "sha256...",
  "function_name": "sub_401000",
  "function_addr": "0x401000",
  "segment": ".text",
  "pseudo_code": "...",
  "disasm_summary": "...",
  "api_calls": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
  "strings": ["explorer.exe", "kernel32.dll"],
  "imports": ["OpenProcess", "WriteProcessMemory"],
  "callers": ["sub_402000"],
  "callees": [],
  "behavior_tags": ["进程注入"],
  "summary": "该函数执行远程进程内存写入并创建远程线程。",
  "mapped_attack_ids": ["T1055"]
}
```

#### RAG 层

```json
{
  "doc_id": "ida_semantic::sha256...::0x401000::sub_401000",
  "source": "IDA_SEMANTIC",
  "doc_type": "function-semantic",
  "title": "xxx.exe::sub_401000@0x401000",
  "summary": "函数实现远程进程内存写入与线程启动，疑似进程注入。",
  "content": "...",
  "tags": ["进程注入", "Windows", "函数语义"],
  "keywords": ["OpenProcess", "WriteProcessMemory", "CreateRemoteThread", "explorer.exe"],
  "platforms": ["Windows"],
  "attack_ids": ["T1055"],
  "metadata": {
    "sample_name": "xxx.exe",
    "sample_hash": "sha256...",
    "function_name": "sub_401000",
    "function_addr": "0x401000",
    "api_calls": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
    "behavior_tags": ["进程注入"]
  }
}
```


## 5. 目录重构建议

建议将当前目录整理为：

```text
attck_knowledge/
├─ builders/
│  ├─ build_attack_kb.py
│  ├─ build_api_chain_kb.py
│  ├─ build_ida_semantic_kb.py
│  └─ export_ida_semantic_from_mcp.py
├─ schemas/
│  ├─ rag_doc.schema.json
│  ├─ attack_record.schema.json
│  ├─ api_behavior.schema.json
│  └─ ida_function.schema.json
├─ data/
│  ├─ raw/
│  │  ├─ attack/
│  │  ├─ api_chain/
│  │  └─ ida_semantic/
│  ├─ rag/
│  │  ├─ attack/
│  │  ├─ api_chain/
│  │  └─ ida_semantic/
│  └─ index/
│     ├─ faiss/
│     └─ metadata/
├─ docs/
│  ├─ TECHNICAL_ROUTE_SYSTEM_DESIGN.md
│  └─ DATA_REFACTOR_PLAN.md
└─ README.md
```


## 6. 具体改造方案

### 第一阶段：先修数据质量

1. 统一所有脚本文件编码为 `UTF-8`
2. 修复 `api_chain` 和 `ida_semantic` 中的中文乱码
3. 重建以下产物：
   - `api_chain_knowledge_raw.json`
   - `api_chain_knowledge_for_rag.jsonl`
   - `ida_semantic_knowledge_raw.json`
   - `ida_semantic_knowledge_for_rag.jsonl`

这是最高优先级，否则后面的 embedding 和检索实验会严重失真。


### 第二阶段：统一 schema

目标：

- 让三类知识都输出统一 `rag_doc`
- 强化 `summary / keywords / attack_ids / platforms`
- 便于后续接入 FAISS、Chroma、Milvus 或 Elasticsearch

落地方式：

1. 保留原始 raw 数据
2. 新增统一的 `build_rag_doc()` 输出规范
3. 为每个 builder 增加字段校验


### 第三阶段：打通 IDA-MCP 自动导出

新增 `export_ida_semantic_from_mcp.py`，职责如下：

1. 通过 IDA-MCP 枚举函数
2. 获取函数伪代码
3. 提取 API 调用、字符串、调用关系、导入信息
4. 生成统一的 `sample_ida_semantic.json`
5. 再由 `build_ida_semantic_kb.py` 转成 raw 与 rag 文档

建议最低导出字段：

- `sample_name`
- `sample_hash`
- `function_name`
- `function_addr`
- `pseudo_code`
- `api_calls`
- `strings`
- `callers`
- `callees`
- `summary`


### 第四阶段：增强 API 行为链知识

在当前模板基础上新增：

- `required_apis`
- `optional_apis`
- `negative_signals`
- `api_sequence_examples`
- `evidence_template`
- `risk_level`

这样既方便检索，也方便规则辅助评分。


### 第五阶段：加入历史分析记忆

新增第四类知识源 `report_memory`：

- 历史样本分析报告
- 家族总结
- 人工修订的函数注释
- 恶意能力总结

统一进入相同的 `rag_doc` schema，后续可直接用于混合检索。


## 7. 推荐的在线分析证据对象

在线推理阶段可使用如下证据对象，不要求长期落盘：

```json
{
  "sample_hash": "sha256...",
  "function_addr": "0x401000",
  "current_facts": {
    "api_calls": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
    "strings": ["explorer.exe"],
    "summary": "..."
  },
  "retrieved_attack_docs": ["attack::T1055"],
  "retrieved_api_chain_docs": ["api_chain::behavior::process_injection::001"],
  "retrieved_similar_functions": ["ida_semantic::..."],
  "candidate_attack_ids": ["T1055"],
  "evidence_lines": [
    "调用 OpenProcess 和 WriteProcessMemory",
    "存在 CreateRemoteThread 远程执行模式",
    "与进程注入行为模板高度相似"
  ]
}
```

该对象适合直接交给 LLM 生成可解释结论。


## 8. 推荐的实施顺序

建议按以下顺序推进：

1. 修复编码乱码
2. 统一三类知识的 schema
3. 重建全部 json/jsonl
4. 实现 IDA-MCP 自动导出函数语义
5. 接入向量库与元数据检索
6. 做函数级行为识别与 ATT&CK 映射 demo
7. 做样本级聚合与报告生成


## 9. 结论

当前 `attck_knowledge` 已经具备较好的起点，但要支撑毕业设计中的“研究及实践”，还需要完成三项关键工作：

1. 修复数据质量问题，尤其是中文乱码。
2. 将多源知识统一到可检索、可过滤、可评估的标准 schema。
3. 将 `IDA-MCP` 真实接入知识构建流水线，而不是停留在示例级数据。

完成上述改造后，这套知识库即可作为 `IDA-MCP + RAG + ATT&CK` 恶意代码静态分析系统的可靠基础数据层。
