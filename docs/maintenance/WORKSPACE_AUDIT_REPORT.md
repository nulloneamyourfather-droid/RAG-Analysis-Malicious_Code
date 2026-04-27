# 工作区审计报告

本文档用于对当前整个工作区进行审计，不只关注 `attck_knowledge`，还包括 `samples/`、顶层 `data/`、`IDA-MCP/`、目标地址文件以及样本文件，目的是在答辩前定位可能造成混淆或被追问的“脏点”。


## 一、当前总体状态

当前工作区顶层结构如下：

- `attck_knowledge/`
- `data/`
- `IDA-MCP/`
- `samples/`
- `virus/`
- `targets.txt`
- `targets_1bin.txt`

其中，真正和当前毕业设计主链路直接相关的是：

- [attck_knowledge](/d:/Graduation%20project/Midterm/asm/attck_knowledge)
- [samples/ida_exports/sample_ida_semantic.json](/d:/Graduation%20project/Midterm/asm/samples/ida_exports/sample_ida_semantic.json)
- [targets_1bin.txt](/d:/Graduation%20project/Midterm/asm/targets_1bin.txt)


## 二、已确认正常的部分

### 1. 当前样本身份已统一

当前几个关键结果文件中的样本身份已经一致，均为 `1.bin`：

- [sample_ida_semantic.json](/d:/Graduation%20project/Midterm/asm/samples/ida_exports/sample_ida_semantic.json)
- [latest_sample_analysis.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/latest_sample_analysis.json)
- [rag_vs_no_rag.json](/d:/Graduation%20project/Midterm/asm/attck_knowledge/data/index/metadata/experiments/rag_vs_no_rag.json)

这说明之前 `test1.exe` / `1.bin` 混用的问题，在当前主链路产物里已经基本消失。


### 2. `samples/` 目录状态正常

当前 `samples/` 下的关键输出是：

- [sample_ida_semantic.json](/d:/Graduation%20project/Midterm/asm/samples/ida_exports/sample_ida_semantic.json)

该文件目前体积正常，且已经是当前样本 `1.bin` 的导出结果，可继续作为离线复用输入。


### 3. `IDA-MCP/` 仓库本身没有明显脏点

当前 [IDA-MCP](/d:/Graduation%20project/Midterm/asm/IDA-MCP) 目录看起来是完整仓库，包含：

- `.git/`
- `src/`
- `tests/`
- `pyproject.toml`
- `README.md`

它本身作为参考源码和本地 MCP 仓库保留是合理的。  
需要注意的是，你当前实际在 Cline 中使用的 IDA-MCP 仍然是 `site-packages` 版本，而不是这个工作区里的仓库版本。因此答辩时如果要讲运行环境，建议明确说明：

> 工作区中保留了 IDA-MCP 源码仓库用于参考与比对；实际分析时，Cline 连接的是本地已安装并运行的 IDA-MCP 服务。


## 三、发现的主要脏点

### 1. 顶层 `data/` 仍保留旧版知识产物

当前顶层 [data](/d:/Graduation%20project/Midterm/asm/data) 目录下仍有：

- [data/api_chain/api_chain_knowledge_raw.json](/d:/Graduation%20project/Midterm/asm/data/api_chain/api_chain_knowledge_raw.json)
- [data/api_chain/api_chain_knowledge_for_rag.jsonl](/d:/Graduation%20project/Midterm/asm/data/api_chain/api_chain_knowledge_for_rag.jsonl)
- [data/ida_semantic/ida_semantic_knowledge_raw.json](/d:/Graduation%20project/Midterm/asm/data/ida_semantic/ida_semantic_knowledge_raw.json)
- [data/ida_semantic/ida_semantic_knowledge_for_rag.jsonl](/d:/Graduation%20project/Midterm/asm/data/ida_semantic/ida_semantic_knowledge_for_rag.jsonl)

这批数据属于早期目录结构遗留，与当前主链路已经不一致。当前正式链路应以：

- `attck_knowledge/data/raw/`
- `attck_knowledge/data/rag/`
- `attck_knowledge/data/index/`

为准。

答辩风险：

- 老师如果看到顶层 `data/` 和 `attck_knowledge/data/` 两套路径，容易追问到底哪一套才是正式输出
- 你自己演示时也容易误开旧文件

建议：

- 论文和 README 中只引用 `attck_knowledge/data/...`
- 顶层 `data/` 暂时保留，但明确视为历史遗留


### 2. 根目录 `targets.txt` 仍是旧样本地址

当前 [targets.txt](/d:/Graduation%20project/Midterm/asm/targets.txt) 内容仍然是：

- `0x14001a005`
- `0x14001a00a`
- `0x14001a00f`
- ...

这明显是旧样本 `test1.exe` 时期留下的地址，不适合继续作为默认目标文件。

而当前真正和 `1.bin` 对应的目标文件是：

- [targets_1bin.txt](/d:/Graduation%20project/Midterm/asm/targets_1bin.txt)

答辩风险：

- 如果你演示时误用了 `targets.txt`，又会重新触发“地址不存在”或样本混用问题

建议：

- 演示时优先使用 `--analyze-current-sample`
- 如果必须用地址文件，只用 `targets_1bin.txt`
- `targets.txt` 最好改名为 `targets_legacy_test1.txt`，或者至少在答辩前不要打开它


### 3. `virus/` 目录中的样本命名与当前论文样本命名不统一

当前 [virus](/d:/Graduation%20project/Midterm/asm/virus) 下有：

- [test1.exe](/d:/Graduation%20project/Midterm/asm/virus/test1.exe)
- [test1.exe.i64](/d:/Graduation%20project/Midterm/asm/virus/test1.exe.i64)

但你当前分析链和实验结果中使用的是 `1.bin`。

答辩风险：

- 老师可能会问“`1.bin` 和 `test1.exe` 是不是同一个样本”
- 如果你讲不清，会显得实验对象管理不规范

建议：

- 在答辩时统一说清楚：
  - `test1.exe` 是早期测试样本
  - 当前实验结果与论文最终展示以 `1.bin` 为准
- 不要在同一次演示中来回切换这两个名字


### 4. 论文原文中的目录页码明显未更新

从 [张翀宇论文.docx](/d:/Graduation%20project/Midterm/%E5%BC%A0%E7%BF%94%E5%AE%87%E8%AE%BA%E6%96%87.docx) 当前内容看，目录中大量页码仍为 `11`、`12`。这不是项目代码问题，但属于非常典型的答辩前格式脏点。

建议：

- 在 Word 中全选目录，更新整个目录
- 再检查第 6 章、第 7 章是否正确进入目录和页码


## 四、建议的答辩使用口径

为了避免工作区中的历史遗留路径干扰答辩，建议你答辩时统一采用以下口径：

1. 正式项目代码位于 [attck_knowledge](/d:/Graduation%20project/Midterm/asm/attck_knowledge)  
2. 正式样本导出结果位于 [sample_ida_semantic.json](/d:/Graduation%20project/Midterm/asm/samples/ida_exports/sample_ida_semantic.json)  
3. 正式实验结果位于 `attck_knowledge/data/index/metadata/experiments/`  
4. 当前展示样本以 `1.bin` 为准  
5. 顶层 `data/`、旧 `targets.txt`、`test1.exe` 属于早期阶段遗留，不作为最终实验结果依据


## 五、建议的手工处理顺序

答辩前建议按以下顺序处理：

1. 不再使用根目录的 [targets.txt](/d:/Graduation%20project/Midterm/asm/targets.txt)  
2. 若需要地址文件，统一只保留 [targets_1bin.txt](/d:/Graduation%20project/Midterm/asm/targets_1bin.txt)  
3. 论文中只引用 `attck_knowledge/data/...` 路径对应的结果  
4. 在讲样本时，明确 `1.bin` 是当前最终实验样本  
5. 更新 Word 目录页码


## 六、当前结论

从整个工作区来看，当前真正会影响答辩的脏点已经不多，核心不是代码不可用，而是“历史遗留路径和旧样本命名可能造成混淆”。  

一句话总结当前工作区状态：

> 主链路已经收拢到 `attck_knowledge + samples/ida_exports + attck_knowledge/data/index` 这一组路径；剩余问题主要是顶层旧数据目录、旧目标地址文件和旧样本命名仍然存在，需要在答辩口径和手工整理上避免混用。
