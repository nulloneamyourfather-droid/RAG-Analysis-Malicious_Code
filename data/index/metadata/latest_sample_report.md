# 恶意样本静态分析报告：1.bin

## 1. 样本概况
- 样本名称：`1.bin`
- 样本哈希：`d99aee68d77549e2e533f9f074635a62c673e4efb3fb7ba002a8dd91ad138aa8`
- 已分析函数数量：`20`
- 可疑函数数量：`20`
- Runtime/Helper 函数数量：`0`
- 未明确分类函数数量：`0`

## 2. 分析摘要
1.bin contains 20 function(s) with malicious signals out of 20. Top ATT&CK candidate is T1001.

## 3. 总体结论
1.bin shows suspicious behavior concentrated in 20 function(s); the current sample-level hypothesis is most related to T1001, T1001.001, T1001.002.

## 4. ATT&CK 技术映射
| ATT&CK ID | 综合分数 | 关联函数 |
| --- | ---: | --- |
| `T1001` | 71.293639 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1001.001` | 69.701954 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1001.002` | 68.83543 | sub_2454D7C, sub_2455800, sub_2457260, sub_24579BC, sub_2457AB8, sub_2457F64, sub_24582C4, sub_245859C, sub_24587A8, sub_2458D64, sub_24594D4, sub_24595C8, sub_24596E8, sub_2459780, nishishabi, __crtLCMapStringA, sub_2460AD0, __raise_securityfailure, capture_current_context, __security_init_cookie |
| `T1055` | 12.59939 | sub_245859C, sub_24594D4 |

## 5. 行为标签聚合
| 行为标签 | 命中次数 | 关联函数 |
| --- | ---: | --- |
| `Registry Persistence` | 3 | sub_24582C4, sub_24596E8, sub_2459780 |

## 6. 函数级能力链
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

## 7. 关键函数分析
### 7.1 可疑函数
- `sub_2454D7C` @ `0x2454d7c`：sub_2454D7C shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2455800` @ `0x2455800`：sub_2455800 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2457260` @ `0x2457260`：sub_2457260 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24579BC` @ `0x24579bc`：sub_24579BC shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2457AB8` @ `0x2457ab8`：sub_2457AB8 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2457F64` @ `0x2457f64`：sub_2457F64 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24582C4` @ `0x24582c4`：sub_24582C4 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_245859C` @ `0x245859c`：sub_245859C shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24587A8` @ `0x24587a8`：sub_24587A8 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2458D64` @ `0x2458d64`：sub_2458D64 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24594D4` @ `0x24594d4`：sub_24594D4 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24595C8` @ `0x24595c8`：sub_24595C8 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_24596E8` @ `0x24596e8`：sub_24596E8 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2459780` @ `0x2459780`：sub_2459780 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `nishishabi` @ `0x245d864`：nishishabi shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `__crtLCMapStringA` @ `0x24607bc`：__crtLCMapStringA shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `sub_2460AD0` @ `0x2460ad0`：sub_2460AD0 shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `__raise_securityfailure` @ `0x2461a7c`：__raise_securityfailure shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `capture_current_context` @ `0x2461c34`：capture_current_context shows behavior worth mapping to ATT&CK and deeper malware analysis.
- `__security_init_cookie` @ `0x2461d18`：__security_init_cookie shows behavior worth mapping to ATT&CK and deeper malware analysis.

### 7.2 Runtime/Helper 函数
未识别到明显的 runtime/helper 函数。

### 7.3 函数级结果总览
| 函数 | 地址 | 置信度 | Runtime-like | Malicious Signal | 结论 |
| --- | --- | --- | --- | --- | --- |
| `sub_2454D7C` | `0x2454d7c` | high | False | True | sub_2454D7C shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2455800` | `0x2455800` | high | False | True | sub_2455800 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2457260` | `0x2457260` | high | False | True | sub_2457260 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24579BC` | `0x24579bc` | high | False | True | sub_24579BC shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2457AB8` | `0x2457ab8` | high | False | True | sub_2457AB8 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2457F64` | `0x2457f64` | high | False | True | sub_2457F64 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24582C4` | `0x24582c4` | high | False | True | sub_24582C4 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_245859C` | `0x245859c` | high | False | True | sub_245859C shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24587A8` | `0x24587a8` | high | False | True | sub_24587A8 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2458D64` | `0x2458d64` | high | False | True | sub_2458D64 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24594D4` | `0x24594d4` | high | False | True | sub_24594D4 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24595C8` | `0x24595c8` | high | False | True | sub_24595C8 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_24596E8` | `0x24596e8` | high | False | True | sub_24596E8 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2459780` | `0x2459780` | high | False | True | sub_2459780 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `nishishabi` | `0x245d864` | high | False | True | nishishabi shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `__crtLCMapStringA` | `0x24607bc` | high | False | True | __crtLCMapStringA shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `sub_2460AD0` | `0x2460ad0` | high | False | True | sub_2460AD0 shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `__raise_securityfailure` | `0x2461a7c` | high | False | True | __raise_securityfailure shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `capture_current_context` | `0x2461c34` | high | False | True | capture_current_context shows behavior worth mapping to ATT&CK and deeper malware analysis. |
| `__security_init_cookie` | `0x2461d18` | high | False | True | __security_init_cookie shows behavior worth mapping to ATT&CK and deeper malware analysis. |

## 8. 分析限制
- 当前结果来自静态反编译事实、RAG 召回和规则分析，仍需结合人工复核。
- ATT&CK 候选属于分析假设，不应在未验证的情况下直接作为最终标签。

## 9. 后续建议
- Prioritize manual review of the suspicious functions and their callers/callees in IDA.
- Verify the top ATT&CK hypotheses against actual API sequences and strings before writing final labels.
- Extend the export to neighboring functions so the sample-level capability chain is complete.
