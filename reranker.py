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


def rerank_docs(
    docs: List[Dict[str, Any]],
    query: Dict[str, Any],
    source: str,
) -> List[Dict[str, Any]]:
    api_calls = set(unique_strs(query.get("api_calls", [])))
    strings = set(unique_strs(query.get("strings", [])))
    behavior_tags = set(unique_strs(query.get("behavior_tags", [])))

    reranked: List[Dict[str, Any]] = []
    for doc in docs:
        metadata = doc.get("metadata", {})
        score = float(doc.get("score", doc.get("hybrid_score", 0)))
        reasons: List[str] = []

        overlap_terms = set(unique_strs(doc.get("overlap_terms", [])))
        if overlap_terms:
            score += min(len(overlap_terms), 6) * 0.05
            reasons.append(f"关键词重叠={len(overlap_terms)}")

        if source == "API_CHAIN":
            required = set(unique_strs(metadata.get("required_apis", [])))
            optional = set(unique_strs(metadata.get("optional_apis", [])))
            required_hits = len(api_calls & required)
            optional_hits = len(api_calls & optional)
            if required_hits:
                score += required_hits * 0.8
                reasons.append(f"命中必需API={required_hits}")
            if optional_hits:
                score += optional_hits * 0.25
                reasons.append(f"命中可选API={optional_hits}")

        if source == "ATTACK":
            attack_ids = set(unique_strs(doc.get("attack_ids", [])))
            if attack_ids and behavior_tags:
                score += 0.2
                reasons.append("具备行为标签支撑")
            if api_calls and overlap_terms:
                score += 0.15
                reasons.append("API与技术描述相关")

        if source == "IDA_SEMANTIC":
            doc_api_calls = set(unique_strs(metadata.get("api_calls", [])))
            doc_tags = set(unique_strs(metadata.get("behavior_tags", [])))
            api_overlap = len(api_calls & doc_api_calls)
            tag_overlap = len(behavior_tags & doc_tags)
            string_overlap = len(strings & set(unique_strs(metadata.get("strings", []))))
            if api_overlap:
                score += api_overlap * 0.3
                reasons.append(f"相似函数API重合={api_overlap}")
            if tag_overlap:
                score += tag_overlap * 0.4
                reasons.append(f"相似函数标签重合={tag_overlap}")
            if string_overlap:
                score += min(string_overlap, 3) * 0.1
                reasons.append(f"相似函数字符串重合={string_overlap}")

        reranked.append(
            {
                **doc,
                "rerank_score": round(score, 6),
                "rerank_reasons": reasons,
            }
        )

    reranked.sort(
        key=lambda item: (
            -float(item.get("rerank_score", 0)),
            -float(item.get("score", item.get("hybrid_score", 0))),
            item.get("doc_id", ""),
        )
    )
    return reranked


def fuse_attack_candidates(
    attack_docs: List[Dict[str, Any]],
    api_chain_docs: List[Dict[str, Any]],
    similar_funcs: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    fused: Dict[str, Dict[str, Any]] = {}

    def add_docs(source: str, docs: List[Dict[str, Any]], weight: float) -> None:
        for doc in docs:
            score = float(doc.get("rerank_score", doc.get("score", doc.get("hybrid_score", 0))))
            for attack_id in doc.get("attack_ids", []):
                entry = fused.setdefault(
                    attack_id,
                    {"attack_id": attack_id, "score": 0.0, "sources": [], "evidence_titles": []},
                )
                entry["score"] += score * weight
                entry["sources"].append(source)
                entry["evidence_titles"].append(doc.get("title", ""))

    add_docs("ATTACK", attack_docs, 1.0)
    add_docs("API_CHAIN", api_chain_docs, 1.5)
    add_docs("IDA_SEMANTIC", similar_funcs, 0.8)

    ranked = list(fused.values())
    for item in ranked:
        item["score"] = round(float(item["score"]), 6)
        item["sources"] = unique_strs(item["sources"])
        item["evidence_titles"] = unique_strs(item["evidence_titles"])
    ranked.sort(key=lambda item: (-item["score"], item["attack_id"]))
    return ranked
