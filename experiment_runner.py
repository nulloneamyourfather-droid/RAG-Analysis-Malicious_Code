import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from sklearn.feature_extraction.text import TfidfVectorizer

try:
    from .analyze_function_evidence import analyze, find_raw_record, load_json as load_json_file
    from .builders.export_ida_semantic_from_mcp import score_function_value
    from .rag_index import load_docs, normalize_tokens
    from .run_function_rag_demo import build_demo_result, build_demo_result_with_sources, build_function_query
except ImportError:
    from analyze_function_evidence import analyze, find_raw_record, load_json as load_json_file
    from builders.export_ida_semantic_from_mcp import score_function_value
    from rag_index import load_docs, normalize_tokens
    from run_function_rag_demo import build_demo_result, build_demo_result_with_sources, build_function_query


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SAMPLE_JSON = PROJECT_ROOT.parent / "samples" / "ida_exports" / "sample_ida_semantic.json"
DEFAULT_RAW_IDA_PATH = PROJECT_ROOT / "data" / "raw" / "ida_semantic" / "ida_semantic_knowledge_raw.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "index" / "metadata" / "experiments"


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rank_function_record(function_record: Dict[str, Any]) -> float:
    existing = function_record.get("selection_score")
    if existing is not None:
        try:
            return float(existing)
        except (TypeError, ValueError):
            pass

    score, _ = score_function_value(
        str(function_record.get("function_name", "")),
        str(function_record.get("pseudo_code", "")),
        [str(item) for item in function_record.get("api_calls", [])],
        [str(item) for item in function_record.get("strings", [])],
        [str(item) for item in function_record.get("callers", [])],
        [str(item) for item in function_record.get("callees", [])],
        [str(item) for item in function_record.get("behavior_tags", [])],
    )
    return float(score)


def select_functions(sample: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    functions = sample.get("functions", [])
    ranked = sorted(
        functions,
        key=lambda item: (
            -rank_function_record(item),
            -len(item.get("behavior_tags", [])),
            -len(item.get("api_calls", [])),
            str(item.get("function_addr", "")),
        ),
    )
    return ranked[: max(1, limit)]


def empty_evidence(sample: Dict[str, Any], function_record: Dict[str, Any]) -> Dict[str, Any]:
    query = build_function_query({**function_record, "sample_hash": sample.get("sample_hash", "")})
    return {
        "sample_name": sample.get("sample_name", ""),
        "sample_hash": sample.get("sample_hash", ""),
        "function_name": query["function_name"],
        "function_addr": query["function_addr"],
        "current_facts": {
            "api_calls": query["api_calls"],
            "strings": query["strings"],
            "behavior_tags": query["behavior_tags"],
            "summary": query["summary"],
        },
        "retrieved_attack_docs": [],
        "retrieved_api_chain_docs": [],
        "retrieved_similar_functions": [],
        "candidate_attack_ids": [],
        "evidence_lines": [],
    }


def summarize_analyses(label: str, analyses: List[Dict[str, Any]], evidences: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious_count = sum(1 for item in analyses if item["classification"]["malicious_signal"])
    runtime_count = sum(1 for item in analyses if item["classification"]["runtime_like"])
    candidate_count = sum(len(ev.get("candidate_attack_ids", [])) for ev in evidences)
    attack_doc_hits = sum(1 for ev in evidences if ev.get("retrieved_attack_docs"))
    api_chain_hits = sum(1 for ev in evidences if ev.get("retrieved_api_chain_docs"))
    similar_func_hits = sum(1 for ev in evidences if ev.get("retrieved_similar_functions"))
    evidence_line_count = sum(len(ev.get("evidence_lines", [])) for ev in evidences)
    function_count = max(len(analyses), 1)

    return {
        "label": label,
        "function_count": len(analyses),
        "suspicious_count": suspicious_count,
        "runtime_like_count": runtime_count,
        "candidate_attack_total": candidate_count,
        "attack_doc_hit_count": attack_doc_hits,
        "api_chain_hit_count": api_chain_hits,
        "similar_func_hit_count": similar_func_hits,
        "avg_candidate_attack_count": round(candidate_count / function_count, 4),
        "avg_evidence_lines": round(evidence_line_count / function_count, 4),
    }


def evaluate_rag_vs_no_rag(sample_json: Path, raw_ida_path: Path, top_k: int, function_limit: int, backend: str) -> Dict[str, Any]:
    sample = load_json_file(sample_json)
    raw_records = load_json_file(raw_ida_path)
    functions = select_functions(sample, function_limit)

    rag_analyses: List[Dict[str, Any]] = []
    rag_evidences: List[Dict[str, Any]] = []
    no_rag_analyses: List[Dict[str, Any]] = []
    no_rag_evidences: List[Dict[str, Any]] = []

    for function_record in functions:
        addr = str(function_record.get("function_addr", ""))
        raw_record = find_raw_record(raw_records, addr)

        rag_evidence = build_demo_result(sample_json, addr, "", top_k=top_k, backend=backend)
        rag_evidences.append(rag_evidence)
        rag_analyses.append(analyze(rag_evidence, raw_record))

        baseline_evidence = empty_evidence(sample, function_record)
        no_rag_evidences.append(baseline_evidence)
        no_rag_analyses.append(analyze(baseline_evidence, raw_record))

    return {
        "experiment": "rag_vs_no_rag",
        "sample_name": sample.get("sample_name", ""),
        "settings": {"top_k": top_k, "function_limit": function_limit, "backend": backend},
        "results": [
            summarize_analyses("with_rag", rag_analyses, rag_evidences),
            summarize_analyses("without_rag", no_rag_analyses, no_rag_evidences),
        ],
    }


def evaluate_source_combinations(sample_json: Path, raw_ida_path: Path, top_k: int, function_limit: int, backend: str) -> Dict[str, Any]:
    sample = load_json_file(sample_json)
    raw_records = load_json_file(raw_ida_path)
    functions = select_functions(sample, function_limit)
    configs = [
        ("attack_only", ["ATTACK"]),
        ("api_chain_only", ["API_CHAIN"]),
        ("ida_semantic_only", ["IDA_SEMANTIC"]),
        ("attack_api_chain", ["ATTACK", "API_CHAIN"]),
        ("all_sources", ["ATTACK", "API_CHAIN", "IDA_SEMANTIC"]),
    ]

    results: List[Dict[str, Any]] = []
    for label, enabled_sources in configs:
        analyses: List[Dict[str, Any]] = []
        evidences: List[Dict[str, Any]] = []
        for function_record in functions:
            addr = str(function_record.get("function_addr", ""))
            raw_record = find_raw_record(raw_records, addr)
            evidence = build_demo_result_with_sources(
                sample_json=sample_json,
                function_addr=addr,
                function_name="",
                top_k=top_k,
                backend=backend,
                enabled_sources=enabled_sources,
            )
            evidences.append(evidence)
            analyses.append(analyze(evidence, raw_record))
        result = summarize_analyses(label, analyses, evidences)
        result["enabled_sources"] = enabled_sources
        results.append(result)

    return {
        "experiment": "source_combinations",
        "sample_name": sample.get("sample_name", ""),
        "settings": {"top_k": top_k, "function_limit": function_limit, "backend": backend},
        "results": results,
    }


def chunk_text(doc: Dict[str, Any], strategy: str) -> str:
    if strategy == "summary_only":
        return "\n".join([str(doc.get("title", "")), str(doc.get("summary", ""))]).strip()
    if strategy == "keyword_focused":
        parts = [
            str(doc.get("title", "")),
            " ".join(doc.get("keywords", [])),
            " ".join(doc.get("tags", [])),
            " ".join(doc.get("attack_ids", [])),
        ]
        return "\n".join(part for part in parts if part).strip()
    parts = [
        str(doc.get("title", "")),
        str(doc.get("summary", "")),
        str(doc.get("content", "")),
        " ".join(doc.get("keywords", [])),
        " ".join(doc.get("tags", [])),
        " ".join(doc.get("attack_ids", [])),
    ]
    return "\n".join(part for part in parts if part).strip()


def query_text_for_chunking(function_record: Dict[str, Any]) -> str:
    query = build_function_query(function_record)
    parts = [
        query.get("summary", ""),
        query.get("pseudocode", "")[:800],
        " ".join(query.get("api_calls", [])),
        " ".join(query.get("strings", [])),
        " ".join(query.get("behavior_tags", [])),
        " ".join(query.get("keywords", [])),
    ]
    return "\n".join(part for part in parts if part).strip()


def evaluate_chunking_strategies(sample_json: Path, function_limit: int) -> Dict[str, Any]:
    sample = load_json_file(sample_json)
    functions = select_functions(sample, function_limit)
    docs = load_docs()
    strategies = ["summary_only", "keyword_focused", "full_content"]

    results: List[Dict[str, Any]] = []
    for strategy in strategies:
        texts = [chunk_text(doc, strategy) for doc in docs]
        vectorizer = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), max_features=10000)
        matrix = vectorizer.fit_transform(texts)

        top_scores: List[float] = []
        attack_hit_count = 0
        nonzero_hit_count = 0
        for function_record in functions:
            record = {**function_record, "sample_hash": sample.get("sample_hash", "")}
            qtext = query_text_for_chunking(record)
            qvec = vectorizer.transform([qtext])
            scores = (matrix @ qvec.T).toarray().ravel()
            best_score = float(scores.max()) if scores.size else 0.0
            top_scores.append(best_score)
            if best_score > 0:
                nonzero_hit_count += 1
                best_idx = int(scores.argmax())
                if docs[best_idx].get("source") == "ATTACK":
                    attack_hit_count += 1

        count = max(len(functions), 1)
        results.append(
            {
                "strategy": strategy,
                "function_count": len(functions),
                "avg_top_score": round(sum(top_scores) / count, 6),
                "nonzero_hit_count": nonzero_hit_count,
                "attack_top_hit_count": attack_hit_count,
            }
        )

    return {
        "experiment": "chunking_strategies",
        "sample_name": sample.get("sample_name", ""),
        "settings": {"function_limit": function_limit},
        "results": results,
    }


def render_markdown_summary(payloads: List[Dict[str, Any]]) -> str:
    lines: List[str] = ["# RAG 实验结果汇总", ""]
    for payload in payloads:
        lines.append(f"## {payload['experiment']}")
        lines.append(f"- 样本：`{payload.get('sample_name', '')}`")
        settings = payload.get("settings", {})
        if settings:
            settings_text = ", ".join(f"{k}={v}" for k, v in settings.items())
            lines.append(f"- 设置：`{settings_text}`")
        lines.append("")
        results = payload.get("results", [])
        if results:
            headers = list(results[0].keys())
            lines.append("| " + " | ".join(headers) + " |")
            lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
            for item in results:
                lines.append("| " + " | ".join(str(item.get(h, "")) for h in headers) + " |")
        lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run experiment scripts for thesis evaluation.")
    parser.add_argument("--sample-json", default=str(DEFAULT_SAMPLE_JSON), help="Path to sample_ida_semantic.json")
    parser.add_argument("--raw-ida", default=str(DEFAULT_RAW_IDA_PATH), help="Path to ida_semantic raw JSON")
    parser.add_argument("--top-k", type=int, default=3, help="Top K docs per source")
    parser.add_argument("--function-limit", type=int, default=20, help="Max number of functions used in experiments")
    parser.add_argument("--backend", choices=["auto", "tfidf", "semantic"], default="semantic", help="RAG backend")
    parser.add_argument(
        "--experiments",
        default="rag_vs_no_rag,source_combinations,chunking_strategies",
        help="Comma-separated experiments to run",
    )
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sample_json = Path(args.sample_json)
    raw_ida = Path(args.raw_ida)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    requested = [item.strip() for item in str(args.experiments).split(",") if item.strip()]
    payloads: List[Dict[str, Any]] = []

    if "rag_vs_no_rag" in requested:
        payload = evaluate_rag_vs_no_rag(sample_json, raw_ida, args.top_k, args.function_limit, args.backend)
        payloads.append(payload)
        save_json(output_dir / "rag_vs_no_rag.json", payload)
    if "source_combinations" in requested:
        payload = evaluate_source_combinations(sample_json, raw_ida, args.top_k, args.function_limit, args.backend)
        payloads.append(payload)
        save_json(output_dir / "source_combinations.json", payload)
    if "chunking_strategies" in requested:
        payload = evaluate_chunking_strategies(sample_json, args.function_limit)
        payloads.append(payload)
        save_json(output_dir / "chunking_strategies.json", payload)

    save_text(output_dir / "experiment_summary.md", render_markdown_summary(payloads))

    print("[+] Experiment runner completed.")
    print(f"    Output dir : {output_dir}")
    print(f"    Experiments: {', '.join(requested)}")


if __name__ == "__main__":
    main()
