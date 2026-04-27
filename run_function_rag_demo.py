import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from .generator import generate_structured_explanation
    from .query_constructor import build_query_package
    from .rag_index import ensure_index, hybrid_search
    from .reranker import fuse_attack_candidates, rerank_docs
except ImportError:
    from generator import generate_structured_explanation
    from query_constructor import build_query_package
    from rag_index import ensure_index, hybrid_search
    from reranker import fuse_attack_candidates, rerank_docs


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SAMPLE_JSON = PROJECT_ROOT.parent / "samples" / "ida_exports" / "sample_ida_semantic.json"
ATTACK_RAG_PATH = PROJECT_ROOT / "data" / "rag" / "attack" / "attack_knowledge_for_rag.jsonl"
API_CHAIN_RAG_PATH = PROJECT_ROOT / "data" / "rag" / "api_chain" / "api_chain_knowledge_for_rag.jsonl"
IDA_RAG_PATH = PROJECT_ROOT / "data" / "rag" / "ida_semantic" / "ida_semantic_knowledge_for_rag.jsonl"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_function_evidence.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


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


def normalize_tokens(text: str) -> List[str]:
    token = []
    out: List[str] = []
    for ch in text.lower():
        if ch.isalnum() or ch in {"_", "@", "?"}:
            token.append(ch)
        else:
            if token:
                out.append("".join(token))
                token = []
    if token:
        out.append("".join(token))
    return out


def build_function_query(function_record: Dict[str, Any]) -> Dict[str, Any]:
    api_calls = unique_strs(function_record.get("api_calls", []))
    strings = unique_strs(function_record.get("strings", []))
    behavior_tags = unique_strs(function_record.get("behavior_tags", []))
    summary = str(function_record.get("summary", "")).strip()
    pseudocode = str(function_record.get("pseudo_code", "")).strip()
    keywords = unique_strs(
        api_calls
        + strings
        + behavior_tags
        + normalize_tokens(summary)
        + normalize_tokens(pseudocode[:1200])
    )
    return {
        "sample_hash": function_record.get("sample_hash", ""),
        "function_name": function_record.get("function_name", ""),
        "function_addr": function_record.get("function_addr", ""),
        "api_calls": api_calls,
        "strings": strings,
        "behavior_tags": behavior_tags,
        "summary": summary,
        "pseudocode": pseudocode,
        "keywords": keywords,
    }


def overlap_score(query_terms: List[str], doc_terms: List[str]) -> Tuple[int, List[str]]:
    query_set = set(unique_strs(query_terms))
    doc_set = set(unique_strs(doc_terms))
    overlap = sorted(query_set & doc_set)
    return len(overlap), overlap


def score_attack_docs(query: Dict[str, Any], docs: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
    ranked: List[Dict[str, Any]] = []
    query_terms = query["api_calls"] + query["behavior_tags"] + query["keywords"]
    for doc in docs:
        doc_terms = doc.get("keywords", []) + doc.get("tags", []) + doc.get("attack_ids", [])
        score, overlap = overlap_score(query_terms, doc_terms)
        if score <= 0:
            continue
        ranked.append(
            {
                "doc_id": doc["doc_id"],
                "title": doc["title"],
                "attack_ids": doc.get("attack_ids", []),
                "score": score,
                "overlap_terms": overlap,
                "summary": doc.get("summary", ""),
            }
        )
    ranked.sort(key=lambda item: (-item["score"], item["doc_id"]))
    return ranked[:top_k]


def score_api_chain_docs(query: Dict[str, Any], docs: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
    ranked: List[Dict[str, Any]] = []
    query_apis = set(query["api_calls"])
    query_terms = query["api_calls"] + query["behavior_tags"] + query["keywords"]
    for doc in docs:
        metadata = doc.get("metadata", {})
        required = unique_strs(metadata.get("required_apis", []))
        optional = unique_strs(metadata.get("optional_apis", []))
        doc_terms = required + optional + doc.get("keywords", []) + doc.get("tags", [])
        overlap_total, overlap_terms = overlap_score(query_terms, doc_terms)
        required_hits = len(query_apis & set(required))
        optional_hits = len(query_apis & set(optional))
        score = required_hits * 5 + optional_hits * 2 + overlap_total
        if score <= 0:
            continue
        ranked.append(
            {
                "doc_id": doc["doc_id"],
                "title": doc["title"],
                "attack_ids": doc.get("attack_ids", []),
                "score": score,
                "required_hits": required_hits,
                "optional_hits": optional_hits,
                "overlap_terms": overlap_terms,
                "summary": doc.get("summary", ""),
                "evidence_template": extract_line(doc.get("content", ""), "Evidence Template:"),
            }
        )
    ranked.sort(key=lambda item: (-item["score"], -item["required_hits"], item["doc_id"]))
    return ranked[:top_k]


def score_ida_docs(query: Dict[str, Any], docs: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
    ranked: List[Dict[str, Any]] = []
    query_terms = query["api_calls"] + query["strings"] + query["behavior_tags"] + query["keywords"]
    current_addr = query["function_addr"]
    for doc in docs:
        metadata = doc.get("metadata", {})
        if metadata.get("function_addr") == current_addr:
            continue
        doc_terms = doc.get("keywords", []) + metadata.get("api_calls", []) + metadata.get("behavior_tags", [])
        score, overlap = overlap_score(query_terms, doc_terms)
        if score <= 0:
            continue
        ranked.append(
            {
                "doc_id": doc["doc_id"],
                "title": doc["title"],
                "attack_ids": doc.get("attack_ids", []),
                "score": score,
                "overlap_terms": overlap,
                "summary": doc.get("summary", ""),
            }
        )
    ranked.sort(key=lambda item: (-item["score"], item["doc_id"]))
    return ranked[:top_k]


def extract_line(content: str, prefix: str) -> str:
    for line in str(content).splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :].strip()
    return ""


def doc_score(doc: Dict[str, Any]) -> float:
    return float(doc.get("hybrid_score", doc.get("score", 0)))


def normalize_retrieved_docs(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for doc in docs:
        metadata = doc.get("metadata", {})
        normalized.append(
            {
                **doc,
                "score": round(doc_score(doc), 6),
                "required_hits": len(set(unique_strs(metadata.get("required_apis", []))) & set(doc.get("overlap_terms", []))),
                "optional_hits": len(set(unique_strs(metadata.get("optional_apis", []))) & set(doc.get("overlap_terms", []))),
                "evidence_template": metadata.get("evidence_template", "") or doc.get("evidence_template", ""),
            }
        )
    return normalized


def build_candidate_attack_ids(
    attack_docs: List[Dict[str, Any]], api_chain_docs: List[Dict[str, Any]], similar_funcs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    scores: Dict[str, Dict[str, Any]] = {}

    def add(source: str, docs: List[Dict[str, Any]], weight: int) -> None:
        for doc in docs:
            for attack_id in doc.get("attack_ids", []):
                entry = scores.setdefault(attack_id, {"attack_id": attack_id, "score": 0, "sources": []})
                entry["score"] += doc_score(doc) * weight
                entry["sources"].append({"source": source, "doc_id": doc["doc_id"], "title": doc["title"]})

    add("ATTACK", attack_docs, 1)
    add("API_CHAIN", api_chain_docs, 2)
    add("IDA_SEMANTIC", similar_funcs, 1)

    ranked = list(scores.values())
    for item in ranked:
        item["score"] = round(float(item["score"]), 6)
    ranked.sort(key=lambda item: (-item["score"], item["attack_id"]))
    return ranked


def build_evidence_lines(
    query: Dict[str, Any], attack_docs: List[Dict[str, Any]], api_chain_docs: List[Dict[str, Any]], similar_funcs: List[Dict[str, Any]]
) -> List[str]:
    lines: List[str] = []
    if query["api_calls"]:
        lines.append(f"Observed API calls: {', '.join(query['api_calls'][:8])}")
    if query["strings"]:
        lines.append(f"Observed strings: {', '.join(query['strings'][:5])}")
    if api_chain_docs:
        top = api_chain_docs[0]
        lines.append(
            f"API behavior match: {top['title']} (score={top['score']}, overlap={', '.join(top['overlap_terms'][:6])})"
        )
        if top.get("evidence_template"):
            lines.append(f"Behavior evidence template: {top['evidence_template']}")
    if attack_docs:
        top = attack_docs[0]
        lines.append(
            f"ATT&CK candidate: {top['title']} (score={top['score']}, overlap={', '.join(top['overlap_terms'][:6])})"
        )
    if similar_funcs:
        top = similar_funcs[0]
        lines.append(
            f"Similar function match: {top['title']} (score={top['score']}, overlap={', '.join(top['overlap_terms'][:6])})"
        )
    return lines


def select_function(sample: Dict[str, Any], function_addr: str, function_name: str) -> Dict[str, Any]:
    functions = sample.get("functions", [])
    if function_addr:
        for func in functions:
            if str(func.get("function_addr", "")).lower() == function_addr.lower():
                return func
        raise ValueError(f"Function address not found: {function_addr}")
    if function_name:
        for func in functions:
            if str(func.get("function_name", "")) == function_name:
                return func
        raise ValueError(f"Function name not found: {function_name}")
    if not functions:
        raise ValueError("No functions available in sample JSON")
    return functions[0]


def build_demo_result_with_sources(
    sample_json: Path,
    function_addr: str,
    function_name: str,
    top_k: int,
    backend: str = "auto",
    enabled_sources: List[str] | None = None,
) -> Dict[str, Any]:
    sample = load_json(sample_json)
    selected_function = select_function(sample, function_addr, function_name)
    selected_function = {
        **selected_function,
        "sample_hash": sample.get("sample_hash", ""),
    }
    query = build_function_query(selected_function)
    query_package = build_query_package(selected_function)
    enabled = set(enabled_sources or ["ATTACK", "API_CHAIN", "IDA_SEMANTIC"])
    current_doc_id = (
        f"ida_semantic::{query['sample_hash']}::{query['function_addr']}::{query['function_name']}"
        if query["sample_hash"] and query["function_addr"] and query["function_name"]
        else None
    )

    ensure_index(backend=backend)
    attack_docs_initial = (
        normalize_retrieved_docs(hybrid_search(query, top_k=top_k, source_filter="ATTACK", backend=backend))
        if "ATTACK" in enabled
        else []
    )
    api_chain_docs_initial = (
        normalize_retrieved_docs(hybrid_search(query, top_k=top_k, source_filter="API_CHAIN", backend=backend))
        if "API_CHAIN" in enabled
        else []
    )
    similar_funcs_initial = (
        normalize_retrieved_docs(
            hybrid_search(query, top_k=top_k, source_filter="IDA_SEMANTIC", exclude_doc_id=current_doc_id, backend=backend)
        )
        if "IDA_SEMANTIC" in enabled
        else []
    )
    attack_docs = rerank_docs(attack_docs_initial, query, "ATTACK")
    api_chain_docs = rerank_docs(api_chain_docs_initial, query, "API_CHAIN")
    similar_funcs = rerank_docs(similar_funcs_initial, query, "IDA_SEMANTIC")
    candidate_attack_ids = fuse_attack_candidates(attack_docs, api_chain_docs, similar_funcs)
    evidence_lines = build_evidence_lines(query, attack_docs, api_chain_docs, similar_funcs)
    generation = generate_structured_explanation(
        query_package,
        attack_docs,
        api_chain_docs,
        similar_funcs,
        candidate_attack_ids,
    )

    return {
        "sample_name": sample.get("sample_name", ""),
        "sample_hash": sample.get("sample_hash", ""),
        "function_name": query["function_name"],
        "function_addr": query["function_addr"],
        "query_package": query_package,
        "current_facts": {
            "api_calls": query["api_calls"],
            "strings": query["strings"],
            "behavior_tags": query["behavior_tags"],
            "summary": query["summary"],
        },
        "retrieval_pipeline": {
            "backend": backend,
            "stages": ["query_construction", "multi_source_retrieval", "rule_rerank", "template_generation"],
        },
        "retrieved_attack_docs": attack_docs,
        "retrieved_api_chain_docs": api_chain_docs,
        "retrieved_similar_functions": similar_funcs,
        "candidate_attack_ids": candidate_attack_ids,
        "evidence_lines": evidence_lines,
        "generation": generation,
    }


def build_demo_result(sample_json: Path, function_addr: str, function_name: str, top_k: int, backend: str = "auto") -> Dict[str, Any]:
    return build_demo_result_with_sources(
        sample_json=sample_json,
        function_addr=function_addr,
        function_name=function_name,
        top_k=top_k,
        backend=backend,
        enabled_sources=["ATTACK", "API_CHAIN", "IDA_SEMANTIC"],
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a lightweight RAG demo for one exported IDA function.")
    parser.add_argument("--sample-json", default=str(DEFAULT_SAMPLE_JSON), help="Path to sample_ida_semantic.json")
    parser.add_argument("--function-addr", default="", help="Target function address")
    parser.add_argument("--function-name", default="", help="Target function name")
    parser.add_argument("--top-k", type=int, default=3, help="Top K docs per knowledge source")
    parser.add_argument("--backend", choices=["auto", "tfidf", "semantic"], default="auto", help="RAG backend")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Output evidence JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ensure_index(backend=args.backend)
    result = build_demo_result(Path(args.sample_json), args.function_addr, args.function_name, max(1, args.top_k), args.backend)
    output_path = Path(args.output)
    save_json(output_path, result)

    print("[+] Function-level RAG demo completed.")
    print(f"    Sample        : {result['sample_name']}")
    print(f"    Function      : {result['function_name']} @ {result['function_addr']}")
    print(f"    Attack docs   : {len(result['retrieved_attack_docs'])}")
    print(f"    API chain docs: {len(result['retrieved_api_chain_docs'])}")
    print(f"    Similar funcs : {len(result['retrieved_similar_functions'])}")
    print(f"    Output        : {output_path}")


if __name__ == "__main__":
    main()
