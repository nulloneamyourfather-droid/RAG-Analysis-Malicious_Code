# 实验结果：样本 `1.bin` 的静态分析

## 1. 实验对象
本节选取样本 `1.bin` 作为分析对象，其 SHA-256 为 `d99aee68d77549e2e533f9f074635a62c673e4efb3fb7ba002a8dd91ad138aa8`。
基于 IDA-MCP 共导出 `20` 个函数事实，并在此基础上执行知识召回、函数级分析和样本级聚合。

## 2. 分析流程
实验流程包括四个阶段：
1. 通过 IDA-MCP 导出函数伪代码、API 调用、字符串和调用关系。
2. 将导出结果转换为 `IDA_SEMANTIC` 文档，并与 `ATT&CK`、`API_CHAIN` 一起纳入 RAG 索引。
3. 对每个函数执行语义召回与规则过滤，生成函数级证据和 ATT&CK 候选。
4. 在样本级对可疑函数、行为标签、ATT&CK 候选和函数级能力链进行聚合。

## 3. 样本级总体结果
1.bin contains 20 function(s) with malicious signals out of 20. Top ATT&CK candidate is T1001.

1.bin shows suspicious behavior concentrated in 20 function(s); the current sample-level hypothesis is most related to T1001, T1001.001, T1001.002.

## 4. ATT&CK 映射结果
样本级 ATT&CK 候选如下所示。该结果来自函数级证据聚合，而非单一函数的直接命中。

| ATT&CK ID | 综合分数 | 关联函数 |
| --- | ---: | --- |
| `T1001` | 71.293639 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1001.001` | 69.701954 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1001.002` | 68.83543 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1055` | 12.59939 | sub_245859C, sub_24594D4 |

## 5. 函数级能力链分析
为避免仅依赖单函数信号，系统进一步对函数调用关系、共享能力标签和 ATT&CK 候选进行聚合，形成函数级能力链。

### 持久化链
- 链路 ID：`chain::004`
- 行为阶段：`持久化链`
- 置信度：`high`
- 覆盖函数数：`6`
- 关联 ATT&CK：`T1001, T1001.001, T1001.002`
- 主要能力：`registry_modification, execution_loader`
- 函数集合：`sub_24582C4, sub_24579BC, sub_24596E8, sub_2459780, sub_2457AB8, sub_24595C8`
- 链路摘要：该链当前被归纳为“持久化链”，对应的行为阶段为“持久化链”，当前置信度为 high。它主要围绕 注册表修改、执行与装载 展开，关联函数包括 sub_24582C4, sub_24579BC, sub_24596E8, sub_2459780，当前 ATT&CK 候选为 T1001、T1001.001、T1001.002。
- 链路证据：
  - 多个函数共享能力标签：注册表修改、执行与装载。
  - 链内函数聚合出相同或相近的 ATT&CK 候选：T1001、T1001.001、T1001.002。
  - 链内函数出现了可相互印证的 API 调用：RegOpenKeyExW, RegCreateKeyW, RegSetValueExA, RegCloseKey, LoadLibraryA, GetProcAddress。
  - 这些函数在调用关系或命名模式上可形成聚合：sub_24582C4 -> sub_24579BC -> sub_24596E8 -> sub_2459780。
  - 链内存在较高信号函数：sub_24582C4, sub_24579BC, sub_24596E8, sub_2459780。

### 进程注入链
- 链路 ID：`chain::006`
- 行为阶段：`进程注入链`
- 置信度：`high`
- 覆盖函数数：`2`
- 关联 ATT&CK：`T1055, T1001, T1001.001, T1001.002`
- 主要能力：`process_injection`
- 函数集合：`sub_245859C, sub_24594D4`
- 链路摘要：该链当前被归纳为“进程注入链”，对应的行为阶段为“进程注入链”，当前置信度为 high。它主要围绕 进程注入 展开，关联函数包括 sub_245859C, sub_24594D4，当前 ATT&CK 候选为 T1055、T1001、T1001.001。
- 链路证据：
  - 多个函数共享能力标签：进程注入。
  - 链内函数聚合出相同或相近的 ATT&CK 候选：T1055、T1001、T1001.001、T1001.002。
  - 链内函数出现了可相互印证的 API 调用：CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, OpenProcess, K32GetModuleFileNameExA, CloseHandle。
  - 这些函数在调用关系或命名模式上可形成聚合：sub_245859C -> sub_24594D4。
  - 链内存在较高信号函数：sub_245859C, sub_24594D4。

### ATT&CK T1001 相关链
- 链路 ID：`chain::001`
- 行为阶段：`通用行为链`
- 置信度：`high`
- 覆盖函数数：`1`
- 关联 ATT&CK：`T1001, T1001.001, T1001.002`
- 主要能力：`none`
- 函数集合：`sub_2454D7C`
- 链路摘要：该链当前被归纳为“ATT&CK T1001 相关链”，对应的行为阶段为“通用行为链”，当前置信度为 high。它主要围绕 通用行为 展开，关联函数包括 sub_2454D7C，当前 ATT&CK 候选为 T1001、T1001.001、T1001.002。
- 链路证据：
  - 链内函数聚合出相同或相近的 ATT&CK 候选：T1001、T1001.001、T1001.002。
  - 链内函数出现了可相互印证的 API 调用：VariantInit, WideCharToMultiByte, VariantClear。
  - 链内存在较高信号函数：sub_2454D7C。

### ATT&CK T1001 相关链
- 链路 ID：`chain::002`
- 行为阶段：`通用行为链`
- 置信度：`high`
- 覆盖函数数：`1`
- 关联 ATT&CK：`T1001, T1001.001, T1001.002`
- 主要能力：`none`
- 函数集合：`sub_2455800`
- 链路摘要：该链当前被归纳为“ATT&CK T1001 相关链”，对应的行为阶段为“通用行为链”，当前置信度为 high。它主要围绕 通用行为 展开，关联函数包括 sub_2455800，当前 ATT&CK 候选为 T1001、T1001.001、T1001.002。
- 链路证据：
  - 链内函数聚合出相同或相近的 ATT&CK 候选：T1001、T1001.001、T1001.002。
  - 链内函数出现了可相互印证的 API 调用：VariantInit, VariantClear, WideCharToMultiByte。
  - 链内存在较高信号函数：sub_2455800。

### ATT&CK T1001 相关链
- 链路 ID：`chain::003`
- 行为阶段：`通用行为链`
- 置信度：`high`
- 覆盖函数数：`1`
- 关联 ATT&CK：`T1001, T1001.001, T1001.002`
- 主要能力：`none`
- 函数集合：`sub_2457260`
- 链路摘要：该链当前被归纳为“ATT&CK T1001 相关链”，对应的行为阶段为“通用行为链”，当前置信度为 high。它主要围绕 通用行为 展开，关联函数包括 sub_2457260，当前 ATT&CK 候选为 T1001、T1001.001、T1001.002。
- 链路证据：
  - 链内函数聚合出相同或相近的 ATT&CK 候选：T1001、T1001.001、T1001.002。
  - 链内函数出现了可相互印证的 API 调用：VariantInit, WideCharToMultiByte, VariantClear。
  - 链内存在较高信号函数：sub_2457260。

## 6. 函数类别统计
- 可疑函数数量：`20`
- Runtime/Helper 函数数量：`0`
- 行为标签数量：`1`

## 7. 结果讨论
实验结果表明，样本中已经出现具备可疑行为信号的函数，说明基于 RAG 的多源知识召回能够为恶意能力判断提供有效支持。
从工程角度看，函数级能力链有助于把分散的 API、字符串和调用关系拼接成更高层的行为片段，而不是停留在单函数匹配。

## 8. 局限性
- 当前结果基于静态反编译事实、语义召回和规则过滤，仍需要人工复核。
- ATT&CK 映射结果用于辅助归因，不应直接替代最终人工分析结论。
- 当前能力链构建仍以规则聚合为主，尚未达到完整程序语义恢复的粒度。

## 9. 小结
本实验表明，将 IDA-MCP 导出的静态事实与 ATT&CK、API 行为模板及本地 RAG 检索机制结合，可以形成从函数级证据到样本级结论的闭环分析流程。
该流程能够输出 ATT&CK 候选、函数级能力链以及结构化分析报告，具备毕业设计实验展示和案例分析的可用性。
