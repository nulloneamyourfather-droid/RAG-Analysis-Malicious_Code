from typing import Any, Dict, List


def build_prompt_payload(
    query_package: Dict[str, Any],
    attack_docs: List[Dict[str, Any]],
    api_chain_docs: List[Dict[str, Any]],
    similar_funcs: List[Dict[str, Any]],
    candidate_attack_ids: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "system_role": "你是恶意代码静态分析助手，需要基于证据输出可追溯结论。",
        "analysis_task": "基于函数摘要、API调用链、多源知识召回结果，对当前函数进行恶意行为解释与ATT&CK映射。",
        "user_question": query_package.get("user_question", ""),
        "function_summary_query": query_package.get("function_summary_query", ""),
        "api_call_chain_query": query_package.get("api_call_chain_query", ""),
        "top_attack_docs": attack_docs[:3],
        "top_api_chain_docs": api_chain_docs[:3],
        "top_similar_functions": similar_funcs[:3],
        "candidate_attack_ids": candidate_attack_ids[:5],
        "instructions": [
            "只基于检索证据和当前函数事实输出结论。",
            "优先说明行为目的、关键证据和ATT&CK候选。",
            "如果证据不足，明确指出证据不足，不要强行定性。",
        ],
    }


def generate_structured_explanation(
    query_package: Dict[str, Any],
    attack_docs: List[Dict[str, Any]],
    api_chain_docs: List[Dict[str, Any]],
    similar_funcs: List[Dict[str, Any]],
    candidate_attack_ids: List[Dict[str, Any]],
) -> Dict[str, Any]:
    explanation_lines: List[str] = []
    if api_chain_docs:
        top = api_chain_docs[0]
        explanation_lines.append(
            f"API行为链最相关证据为“{top.get('title', '')}”，其重排分数为 {top.get('rerank_score', top.get('score', 0))}。"
        )
    if attack_docs:
        top = attack_docs[0]
        explanation_lines.append(
            f"ATT&CK知识最相关条目为“{top.get('title', '')}”，其重排分数为 {top.get('rerank_score', top.get('score', 0))}。"
        )
    if similar_funcs:
        top = similar_funcs[0]
        explanation_lines.append(
            f"样本语义侧最相近函数为“{top.get('title', '')}”，可作为局部行为参考。"
        )

    if candidate_attack_ids:
        attack_text = "、".join(item["attack_id"] for item in candidate_attack_ids[:3])
        final_judgement = f"当前函数可优先关注的 ATT&CK 候选为 {attack_text}。"
    else:
        final_judgement = "当前函数尚未形成稳定的 ATT&CK 候选，证据仍不足。"

    return {
        "prompt_payload": build_prompt_payload(
            query_package,
            attack_docs,
            api_chain_docs,
            similar_funcs,
            candidate_attack_ids,
        ),
        "analysis_mode": "template_generation",
        "behavior_explanation": explanation_lines,
        "attack_mapping_statement": final_judgement,
        "report_fragment": "\n".join(explanation_lines + [final_judgement]),
    }
