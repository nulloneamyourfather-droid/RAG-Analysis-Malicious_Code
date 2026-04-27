# 论文题目、摘要、关键词与结论页替换建议

本文档用于根据当前项目真实实现状态，对论文题目、中文摘要、英文摘要、关键词以及结论页进行统一收口。目标是：

- 让论文表述与当前代码实现一致
- 避免把未完全实现的部分写成“已完成”
- 保留论文应有的学术表达和完整性


## 一、题目建议

当前论文题目若仍为：

> 基于RAG对的恶意代码静态分析研究及实践

建议直接替换为：

> 基于RAG的恶意代码静态分析研究与实践

如果你想让方法属性更强，也可以用：

> 基于RAG的恶意代码静态分析方法研究与实践

更推荐第一种，表达更自然，也更适合本科毕业设计题目。


## 二、中文摘要建议替换版

建议替换为以下版本：

> 随着网络安全威胁持续加剧，恶意代码的种类与复杂度不断上升，传统恶意代码静态分析方法在知识获取、分析效率和结果组织方面面临较大挑战。尤其是在面对具备混淆、加壳以及复杂行为链的恶意样本时，单纯依赖人工经验或传统规则库的方法，往往存在分析成本高、知识利用不足和结果解释性较弱等问题。近年来，大语言模型在代码理解与文本生成方面展现出较强能力，但其在恶意代码分析场景中仍存在领域知识不足、证据不可追溯以及结果稳定性不足等局限。针对上述问题，本文提出一种基于检索增强生成（Retrieval-Augmented Generation，RAG）的恶意代码静态分析方法，并完成了原型系统设计与实现。  
>  
> 本文以恶意代码静态分析任务为核心，构建了融合 ATT&CK 知识、API 行为链知识和 IDA-MCP 提取样本语义信息的多源知识库。首先，对恶意代码分析相关知识进行整理和结构化表示，形成适用于检索增强场景的知识条目；其次，结合恶意代码静态分析特点，设计面向函数语义、行为链和安全知识条目的文档组织与分片方式，并通过向量化表示与索引构建实现知识入库；然后，在分析阶段，围绕当前函数的摘要信息、API 调用和语义特征构造查询，通过多源知识召回和相关性重排，获取与当前样本最相关的上下文证据；最后，将检索结果与样本静态事实进行融合，生成函数级 evidence、ATT&CK 技术映射候选、样本级能力链以及结构化分析结果。  
>  
> 本文实现了一个面向恶意代码静态分析的 RAG 原型系统，并基于典型样本开展实验验证。实验结果表明，相较于不使用检索增强的分析方式，本文方法在当前实验条件下能够提升函数级恶意行为识别能力、增强分析结果的可解释性，并提高样本级证据组织与 ATT&CK 映射能力。本文研究为 RAG 技术在恶意代码静态分析领域的应用提供了一种可行思路，也为智能化恶意代码分析辅助系统的构建提供了参考。


## 三、中文关键词建议

建议替换为：

> 关键词：恶意代码静态分析；检索增强生成；ATT&CK；API行为链；IDA-MCP；样本级聚合

说明：

- 保留 `ATT&CK`、`API行为链`、`IDA-MCP`
- 去掉“**大语言模型**”作为强核心关键词更稳妥，因为当前系统生成层还不是完全独立闭环
- 加入“**样本级聚合**”，更贴近你当前项目实现特色


## 四、英文摘要建议替换版

建议替换为以下版本：

> With the continuous intensification of cybersecurity threats, the variety and complexity of malware are constantly increasing. Traditional malware static analysis methods face significant challenges in knowledge acquisition, analysis efficiency, and result organization. Especially when dealing with malicious samples featuring obfuscation, packing, and complex behavior chains, methods that rely solely on manual experience or traditional rule bases often suffer from high analysis cost, insufficient knowledge utilization, and limited interpretability. In recent years, large language models have shown strong capabilities in code understanding and text generation. However, in the context of malware analysis, they still suffer from insufficient domain knowledge, weak evidence traceability, and unstable outputs. To address these issues, this paper proposes a malware static analysis method based on Retrieval-Augmented Generation (RAG), and designs and implements a prototype system.  
>  
> Focusing on malware static analysis tasks, this study constructs a multi-source knowledge base integrating ATT&CK knowledge, API behavior chain knowledge, and sample semantic information extracted by IDA-MCP. First, malware analysis-related knowledge is organized and structurally represented to form knowledge entries suitable for retrieval-augmented scenarios. Second, according to the characteristics of malware static analysis, document organization and chunking strategies are designed for function semantics, behavior chains, and security knowledge entries, and knowledge storage is achieved through vector representation and index construction. Then, during the analysis stage, queries are constructed based on function summaries, API calls, and semantic features. Through multi-source knowledge retrieval and relevance reranking, the most relevant contextual evidence for the current sample is obtained. Finally, the retrieved results are fused with current static facts to generate function-level evidence, ATT&CK technique hypotheses, sample-level capability chains, and structured analysis results.  
>  
> This paper implements a RAG-based prototype system for malware static analysis and conducts experimental verification on representative samples. The results show that, compared with analysis without retrieval augmentation, the proposed method can improve function-level malicious behavior identification, enhance interpretability, and strengthen sample-level evidence organization and ATT&CK mapping under the current experimental setting. This study provides a feasible approach for applying RAG to malware static analysis and offers a reference for building intelligent malware analysis assistance systems.


## 五、英文关键词建议

建议替换为：

> Key words: malware static analysis; retrieval-augmented generation; ATT&CK; API behavior chain; IDA-MCP; sample-level aggregation


## 六、结论页建议替换版

如果你论文最后的“结论”部分还没有完全按当前实现收口，建议使用以下版本作为基础：

> 本文围绕恶意代码静态分析场景中“函数级语义难以稳定提取、外部知识难以有效利用、分析结果缺乏结构化组织”这一问题，设计并实现了一套基于 IDA-MCP 与 RAG 的增强分析原型系统。本文工作以 IDA 当前样本为分析对象，以函数级静态事实为输入基础，联合 ATT&CK、API 行为链和函数语义知识，完成了查询构造、多源知识召回、结果重排、evidence 组织、样本级聚合与报告输出。  
>  
> 在系统实现方面，本文完成了恶意代码静态分析相关多源知识库构建，并采用 `raw / rag / index` 的方式组织原始事实、检索文档与索引结果；实现了基于 `SentenceTransformer + FAISS` 和 `TF-IDF` 的两类 RAG 后端；实现了函数级 evidence 生成、样本级 ATT&CK 候选聚合、能力链分析以及技术版和论文版报告输出；同时，围绕有无 RAG、知识源组合以及分片策略设计并实现了实验脚本，为实验复现和论文写作提供了支撑。  
>  
> 实验结果表明，相较于不使用检索增强的分析方式，本文方法在当前实验条件下能够提升函数级恶意行为识别能力、增强分析结果的可解释性，并在样本级 ATT&CK 技术映射和证据组织方面表现出较好的工程可行性。这说明，面向恶意代码静态分析任务，将函数级静态事实与多源安全知识通过 RAG 方式结合，是一条具有应用价值的技术路线。  
>  
> 需要指出的是，本文实现的系统仍属于毕业设计原型系统，而非生产级恶意代码自动判定平台。当前工作在实验规模、自动化生成闭环、精排模型能力和动态证据融合等方面仍有进一步提升空间。后续工作可在更大规模样本集、多模态证据融合、更强重排模型和大语言模型生成闭环等方向继续扩展。  
>  
> 总体而言，本文提出的基于 RAG 的恶意代码静态分析方法已经形成较完整的原型实现，并在函数级分析、样本级聚合和实验验证层面取得了阶段性结果，可为恶意代码智能辅助分析系统的进一步研究提供参考。


## 七、使用建议

建议你按以下顺序把这份替换文本落实到 Word：

1. 先改题目  
2. 再替换中文摘要和关键词  
3. 再替换英文摘要和英文关键词  
4. 最后统一修改结论页  
5. 修改完成后更新目录和摘要页页码


## 八、当前口径统一句

如果答辩时需要用一句话概括整篇论文，建议统一为：

> 本文设计并实现了一套基于 IDA-MCP、ATT&CK、API 行为链、函数语义知识与 RAG 的恶意代码静态分析辅助原型系统，重点提升函数级恶意行为识别、ATT&CK 技术映射和样本级证据组织能力。
