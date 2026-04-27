from typing import Any, Dict, List


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        item = str(item or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def build_user_question(function_record: Dict[str, Any]) -> str:
    function_name = str(function_record.get("function_name", "unknown_function"))
    api_calls = unique_strs(function_record.get("api_calls", []))
    if api_calls:
        return (
            f"函数 {function_name} 调用了 {', '.join(api_calls[:6])} 等 API。"
            f"请结合 ATT&CK、API 行为链和相似函数语义，分析它可能对应的恶意行为、行为阶段与 ATT&CK 技术。"
        )
    return (
        f"请分析函数 {function_name} 的伪代码、字符串和调用关系，"
        f"判断其可能的恶意行为、行为阶段以及 ATT&CK 技术映射。"
    )


def build_function_summary_query(function_record: Dict[str, Any]) -> str:
    summary = str(function_record.get("summary", "")).strip()
    pseudocode = str(function_record.get("pseudo_code", "")).strip()
    if summary:
        return summary
    if pseudocode:
        compact = " ".join(pseudocode.split())
        return compact[:400]
    return "该函数缺少显式摘要，需要结合 API、字符串和调用链进行语义推断。"


def build_api_call_chain_description(function_record: Dict[str, Any]) -> str:
    api_calls = unique_strs(function_record.get("api_calls", []))
    callers = unique_strs(function_record.get("callers", []))
    callees = unique_strs(function_record.get("callees", []))

    parts: List[str] = []
    if api_calls:
        parts.append(f"核心 API: {', '.join(api_calls[:8])}")
    if callers:
        parts.append(f"Caller 数量={len(callers)}，示例: {', '.join(callers[:4])}")
    if callees:
        parts.append(f"Callee 数量={len(callees)}，示例: {', '.join(callees[:4])}")
    return "；".join(parts) if parts else "未提取到明确的 API 调用链描述。"


def build_query_package(function_record: Dict[str, Any]) -> Dict[str, Any]:
    api_calls = unique_strs(function_record.get("api_calls", []))
    strings = unique_strs(function_record.get("strings", []))
    behavior_tags = unique_strs(function_record.get("behavior_tags", []))

    user_question = build_user_question(function_record)
    function_summary = build_function_summary_query(function_record)
    api_call_chain = build_api_call_chain_description(function_record)

    combined_parts = [
        user_question,
        f"函数摘要: {function_summary}",
        f"API调用链描述: {api_call_chain}",
    ]
    if api_calls:
        combined_parts.append(f"API集合: {', '.join(api_calls[:10])}")
    if strings:
        combined_parts.append(f"字符串集合: {', '.join(strings[:10])}")
    if behavior_tags:
        combined_parts.append(f"行为标签: {', '.join(behavior_tags)}")

    return {
        "user_question": user_question,
        "function_summary_query": function_summary,
        "api_call_chain_query": api_call_chain,
        "combined_query_text": "\n".join(combined_parts),
    }
