from typing import Any, Dict, List


def _format_attack_id_rows(attack_ids: List[Dict[str, Any]]) -> List[str]:
    rows = ["| ATT&CK ID | 综合分数 | 关联函数 |", "| --- | ---: | --- |"]
    for item in attack_ids[:10]:
        rows.append(
            f"| `{item['attack_id']}` | {item.get('score', 0)} | {', '.join(item.get('functions', []))} |"
        )
    return rows


def _format_behavior_tag_rows(behavior_tags: List[Dict[str, Any]]) -> List[str]:
    rows = ["| 行为标签 | 命中次数 | 关联函数 |", "| --- | ---: | --- |"]
    for item in behavior_tags[:10]:
        rows.append(
            f"| `{item['behavior_tag']}` | {item.get('count', 0)} | {', '.join(item.get('functions', []))} |"
        )
    return rows


def _format_chain_block(chain: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    function_names = ", ".join(item["function_name"] for item in chain.get("functions", [])[:8])
    lines.append(f"### {chain.get('display_name', chain.get('title', chain.get('chain_id', 'chain')))}")
    lines.append(f"- 链路 ID：`{chain.get('chain_id', '')}`")
    lines.append(f"- 行为阶段：`{chain.get('stage_name', '通用行为链')}`")
    lines.append(f"- 置信度：`{chain.get('confidence', '')}`")
    lines.append(f"- 覆盖函数数：`{chain.get('function_count', 0)}`")
    lines.append(f"- 关联 ATT&CK：`{', '.join(chain.get('attack_ids', [])[:5]) or 'none'}`")
    lines.append(f"- 主要能力：`{', '.join(chain.get('capabilities', [])[:6]) or 'none'}`")
    lines.append(f"- 函数集合：`{function_names or 'none'}`")
    if chain.get("summary"):
        lines.append(f"- 链路摘要：{chain['summary']}")
    evidence_lines = chain.get("evidence_explanation", [])
    if evidence_lines:
        lines.append("- 链路证据：")
        for line in evidence_lines[:6]:
            lines.append(f"  - {line}")
    return lines


def build_markdown_report(sample_analysis: Dict[str, Any]) -> str:
    sample_name = sample_analysis["sample_name"]
    sample_hash = sample_analysis.get("sample_hash", "")
    function_count = sample_analysis.get("function_count", 0)
    suspicious_functions = sample_analysis.get("suspicious_functions", [])
    runtime_functions = sample_analysis.get("runtime_like_functions", [])
    unknown_functions = sample_analysis.get("unknown_functions", [])
    attack_ids = sample_analysis.get("aggregated_attack_ids", [])
    behavior_tags = sample_analysis.get("aggregated_behavior_tags", [])
    capability_chains = sample_analysis.get("capability_chains", [])
    function_results = sample_analysis.get("function_results", [])

    lines: List[str] = []
    lines.append(f"# 恶意样本静态分析报告：{sample_name}")
    lines.append("")
    lines.append("## 1. 样本概况")
    lines.append(f"- 样本名称：`{sample_name}`")
    lines.append(f"- 样本哈希：`{sample_hash}`")
    lines.append(f"- 已分析函数数量：`{function_count}`")
    lines.append(f"- 可疑函数数量：`{len(suspicious_functions)}`")
    lines.append(f"- Runtime/Helper 函数数量：`{len(runtime_functions)}`")
    lines.append(f"- 未明确分类函数数量：`{len(unknown_functions)}`")
    lines.append("")

    lines.append("## 2. 分析摘要")
    lines.append(sample_analysis.get("summary", ""))
    lines.append("")

    lines.append("## 3. 总体结论")
    lines.append(sample_analysis.get("conclusion", ""))
    lines.append("")

    lines.append("## 4. ATT&CK 技术映射")
    if attack_ids:
        lines.extend(_format_attack_id_rows(attack_ids))
    else:
        lines.append("当前样本尚未形成稳定、可信的 ATT&CK 技术映射。")
    lines.append("")

    lines.append("## 5. 行为标签聚合")
    if behavior_tags:
        lines.extend(_format_behavior_tag_rows(behavior_tags))
    else:
        lines.append("当前样本尚未聚合出稳定的行为标签。")
    lines.append("")

    lines.append("## 6. 函数级能力链")
    if capability_chains:
        for chain in capability_chains[:5]:
            lines.extend(_format_chain_block(chain))
            lines.append("")
    else:
        lines.append("当前样本尚未形成稳定的函数级能力链。")
        lines.append("")

    lines.append("## 7. 关键函数分析")
    lines.append("### 7.1 可疑函数")
    if suspicious_functions:
        for item in suspicious_functions:
            lines.append(f"- `{item['function_name']}` @ `{item['function_addr']}`：{item['conclusion']}")
    else:
        lines.append("当前分析集中尚未识别出高可信的可疑函数。")
    lines.append("")

    lines.append("### 7.2 Runtime/Helper 函数")
    if runtime_functions:
        for item in runtime_functions[:15]:
            lines.append(f"- `{item['function_name']}` @ `{item['function_addr']}`：{item['conclusion']}")
    else:
        lines.append("未识别到明显的 runtime/helper 函数。")
    lines.append("")

    lines.append("### 7.3 函数级结果总览")
    if function_results:
        lines.append("| 函数 | 地址 | 置信度 | Runtime-like | Malicious Signal | 结论 |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for item in function_results[:30]:
            classification = item.get("classification", {})
            lines.append(
                f"| `{item['function_name']}` | `{item['function_addr']}` | {classification.get('confidence', '')} | "
                f"{classification.get('runtime_like', False)} | {classification.get('malicious_signal', False)} | "
                f"{item.get('conclusion', '')} |"
            )
    else:
        lines.append("无函数级结果可展示。")
    lines.append("")

    lines.append("## 8. 分析限制")
    lines.append("- 当前结果来自静态反编译事实、RAG 召回和规则分析，仍需结合人工复核。")
    lines.append("- ATT&CK 候选属于分析假设，不应在未验证的情况下直接作为最终标签。")
    if not suspicious_functions and runtime_functions:
        lines.append("- 当前导出的函数偏向 runtime/helper 逻辑，说明样本核心业务函数仍未充分覆盖。")
    lines.append("")

    lines.append("## 9. 后续建议")
    for step in sample_analysis.get("next_steps", []):
        lines.append(f"- {step}")
    lines.append("")
    return "\n".join(lines)


def build_paper_markdown_report(sample_analysis: Dict[str, Any]) -> str:
    sample_name = sample_analysis["sample_name"]
    sample_hash = sample_analysis.get("sample_hash", "")
    function_count = sample_analysis.get("function_count", 0)
    suspicious_functions = sample_analysis.get("suspicious_functions", [])
    runtime_functions = sample_analysis.get("runtime_like_functions", [])
    attack_ids = sample_analysis.get("aggregated_attack_ids", [])
    behavior_tags = sample_analysis.get("aggregated_behavior_tags", [])
    capability_chains = sample_analysis.get("capability_chains", [])

    lines: List[str] = []
    lines.append(f"# 实验结果：样本 `{sample_name}` 的静态分析")
    lines.append("")
    lines.append("## 1. 实验对象")
    lines.append(f"本节选取样本 `{sample_name}` 作为分析对象，其 SHA-256 为 `{sample_hash}`。")
    lines.append(f"基于 IDA-MCP 共导出 `{function_count}` 个函数事实，并在此基础上执行知识召回、函数级分析和样本级聚合。")
    lines.append("")

    lines.append("## 2. 分析流程")
    lines.append("实验流程包括四个阶段：")
    lines.append("1. 通过 IDA-MCP 导出函数伪代码、API 调用、字符串和调用关系。")
    lines.append("2. 将导出结果转换为 `IDA_SEMANTIC` 文档，并与 `ATT&CK`、`API_CHAIN` 一起纳入 RAG 索引。")
    lines.append("3. 对每个函数执行语义召回与规则过滤，生成函数级证据和 ATT&CK 候选。")
    lines.append("4. 在样本级对可疑函数、行为标签、ATT&CK 候选和函数级能力链进行聚合。")
    lines.append("")

    lines.append("## 3. 样本级总体结果")
    lines.append(sample_analysis.get("summary", ""))
    lines.append("")
    lines.append(sample_analysis.get("conclusion", ""))
    lines.append("")

    lines.append("## 4. ATT&CK 映射结果")
    if attack_ids:
        lines.append("样本级 ATT&CK 候选如下所示。该结果来自函数级证据聚合，而非单一函数的直接命中。")
        lines.append("")
        lines.extend(_format_attack_id_rows(attack_ids))
    else:
        lines.append("在当前函数覆盖范围下，尚未形成稳定的 ATT&CK 技术映射结果。")
    lines.append("")

    lines.append("## 5. 函数级能力链分析")
    if capability_chains:
        lines.append("为避免仅依赖单函数信号，系统进一步对函数调用关系、共享能力标签和 ATT&CK 候选进行聚合，形成函数级能力链。")
        lines.append("")
        for chain in capability_chains[:5]:
            lines.extend(_format_chain_block(chain))
            lines.append("")
    else:
        lines.append("当前样本尚未形成稳定的函数级能力链，说明函数覆盖范围或行为信号仍然不足。")
        lines.append("")

    lines.append("## 6. 函数类别统计")
    lines.append(f"- 可疑函数数量：`{len(suspicious_functions)}`")
    lines.append(f"- Runtime/Helper 函数数量：`{len(runtime_functions)}`")
    lines.append(f"- 行为标签数量：`{len(behavior_tags)}`")
    lines.append("")

    lines.append("## 7. 结果讨论")
    if suspicious_functions:
        lines.append("实验结果表明，样本中已经出现具备可疑行为信号的函数，说明基于 RAG 的多源知识召回能够为恶意能力判断提供有效支持。")
    elif runtime_functions and not suspicious_functions:
        lines.append("当前导出的函数更多表现为运行时辅助逻辑，尚不能直接支撑恶意行为定性。这说明函数选择阶段对最终结果影响较大。")
    else:
        lines.append("当前结果更适合作为中间分析状态，后续仍需扩大导出函数范围并增强行为信号。")
    lines.append("从工程角度看，函数级能力链有助于把分散的 API、字符串和调用关系拼接成更高层的行为片段，而不是停留在单函数匹配。")
    lines.append("")

    lines.append("## 8. 局限性")
    lines.append("- 当前结果基于静态反编译事实、语义召回和规则过滤，仍需要人工复核。")
    lines.append("- ATT&CK 映射结果用于辅助归因，不应直接替代最终人工分析结论。")
    lines.append("- 当前能力链构建仍以规则聚合为主，尚未达到完整程序语义恢复的粒度。")
    lines.append("")

    lines.append("## 9. 小结")
    lines.append("本实验表明，将 IDA-MCP 导出的静态事实与 ATT&CK、API 行为模板及本地 RAG 检索机制结合，可以形成从函数级证据到样本级结论的闭环分析流程。")
    lines.append("该流程能够输出 ATT&CK 候选、函数级能力链以及结构化分析报告，具备毕业设计实验展示和案例分析的可用性。")
    lines.append("")
    return "\n".join(lines)
