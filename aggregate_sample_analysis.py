import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

try:
    from .capability_chain import build_capability_chains, summarize_capability_chains
    from .run_function_rag_demo import build_demo_result
    from .analyze_function_evidence import analyze, find_raw_record, load_json as load_json_file
except ImportError:
    from capability_chain import build_capability_chains, summarize_capability_chains
    from run_function_rag_demo import build_demo_result
    from analyze_function_evidence import analyze, find_raw_record, load_json as load_json_file


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_SAMPLE_JSON = PROJECT_ROOT.parent / "samples" / "ida_exports" / "sample_ida_semantic.json"
DEFAULT_RAW_IDA_PATH = PROJECT_ROOT / "data" / "raw" / "ida_semantic" / "ida_semantic_knowledge_raw.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_sample_analysis.json"


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


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


def filter_attack_candidates_for_function(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    analysis = item["analysis"]
    evidence = item["evidence"]
    raw = item.get("raw_record") or {}

    if analysis["classification"]["runtime_like"]:
        return []
    if not analysis["classification"]["malicious_signal"]:
        return []

    api_calls = unique_strs(raw.get("api_calls", []))
    behavior_tags = unique_strs(raw.get("behavior_tags", []))
    strings = unique_strs(raw.get("strings", []))
    attack_docs = evidence.get("retrieved_attack_docs", [])
    api_chain_docs = evidence.get("retrieved_api_chain_docs", [])

    filtered: List[Dict[str, Any]] = []
    for candidate in analysis.get("candidate_attack_ids", []):
        attack_id = candidate["attack_id"]
        candidate_score = float(candidate.get("score", 0))
        matched_attack_docs = [doc for doc in attack_docs if attack_id in doc.get("attack_ids", [])]
        matched_api_chain_docs = [doc for doc in api_chain_docs if attack_id in doc.get("attack_ids", [])]

        strong_api_chain = [
            doc for doc in matched_api_chain_docs if int(doc.get("required_hits", 0)) > 0 or float(doc.get("score", 0)) >= 0.8
        ]
        strong_attack = [
            doc
            for doc in matched_attack_docs
            if (int(doc.get("keyword_overlap", 0)) >= 2 and float(doc.get("score", 0)) >= 0.2)
            or float(doc.get("score", 0)) >= 0.45
        ]

        support = candidate_score
        if strong_api_chain:
            support += 3.0
        if strong_attack:
            support += 1.5
        if len(api_calls) >= 2:
            support += 1.0
        if behavior_tags:
            support += 1.5
        if len(strings) >= 2:
            support += 0.5

        if strong_api_chain or (strong_attack and (len(api_calls) >= 2 or behavior_tags)):
            filtered.append(
                {
                    **candidate,
                    "score": round(support, 6),
                    "attack_doc_count": len(strong_attack),
                    "api_chain_doc_count": len(strong_api_chain),
                }
            )

    filtered.sort(key=lambda candidate: (-float(candidate.get("score", 0)), candidate["attack_id"]))
    return filtered


def aggregate_attack_ids(function_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    scores: Dict[str, Dict[str, Any]] = {}
    for item in function_analyses:
        analysis = item["analysis"]
        function_name = analysis["function_name"]
        filtered_candidates = filter_attack_candidates_for_function(item)
        for candidate in filtered_candidates:
            attack_id = candidate["attack_id"]
            entry = scores.setdefault(
                attack_id,
                {
                    "attack_id": attack_id,
                    "score": 0.0,
                    "functions": [],
                },
            )
            entry["score"] += float(candidate.get("score", 0))
            entry["functions"].append(function_name)

    ranked = list(scores.values())
    for entry in ranked:
        entry["score"] = round(float(entry["score"]), 6)
        entry["functions"] = unique_strs(entry["functions"])
    ranked.sort(key=lambda item: (-item["score"], item["attack_id"]))
    return ranked


def aggregate_behavior_tags(function_analyses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, Dict[str, Any]] = {}
    for item in function_analyses:
        raw = item.get("raw_record") or {}
        function_name = item["analysis"]["function_name"]
        for tag in raw.get("behavior_tags", []):
            entry = counts.setdefault(tag, {"behavior_tag": tag, "count": 0, "functions": []})
            entry["count"] += 1
            entry["functions"].append(function_name)

    ranked = list(counts.values())
    for entry in ranked:
        entry["functions"] = unique_strs(entry["functions"])
    ranked.sort(key=lambda item: (-item["count"], item["behavior_tag"]))
    return ranked


def classify_functions(function_analyses: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    suspicious: List[Dict[str, Any]] = []
    runtime_like: List[Dict[str, Any]] = []
    unknown: List[Dict[str, Any]] = []

    for item in function_analyses:
        analysis = item["analysis"]
        summary = {
            "function_name": analysis["function_name"],
            "function_addr": analysis["function_addr"],
            "confidence": analysis["classification"]["confidence"],
            "conclusion": analysis["conclusion"],
        }
        if analysis["classification"]["malicious_signal"]:
            suspicious.append(summary)
        elif analysis["classification"]["runtime_like"]:
            runtime_like.append(summary)
        else:
            unknown.append(summary)

    return {
        "suspicious_functions": suspicious,
        "runtime_like_functions": runtime_like,
        "unknown_functions": unknown,
    }


def build_sample_summary(
    sample_name: str,
    function_count: int,
    classes: Dict[str, List[Dict[str, Any]]],
    aggregated_attack_ids: List[Dict[str, Any]],
) -> str:
    suspicious_count = len(classes["suspicious_functions"])
    runtime_count = len(classes["runtime_like_functions"])
    if suspicious_count > 0:
        top_attack = aggregated_attack_ids[0]["attack_id"] if aggregated_attack_ids else "no stable ATT&CK mapping"
        return (
            f"{sample_name} contains {suspicious_count} function(s) with malicious signals out of {function_count}. "
            f"Top ATT&CK candidate is {top_attack}."
        )
    if runtime_count == function_count:
        return (
            f"{sample_name} currently resolves mostly to runtime/helper logic; no strong malicious behavior "
            f"has been aggregated yet."
        )
    return (
        f"{sample_name} has {function_count} analyzed function(s), but the current evidence is insufficient "
        f"for a strong sample-level ATT&CK conclusion."
    )


def build_sample_conclusion(
    sample_name: str,
    classes: Dict[str, List[Dict[str, Any]]],
    aggregated_attack_ids: List[Dict[str, Any]],
) -> str:
    suspicious_count = len(classes["suspicious_functions"])
    if suspicious_count > 0:
        attack_text = ", ".join(item["attack_id"] for item in aggregated_attack_ids[:3]) or "no stable ATT&CK mapping"
        return (
            f"{sample_name} shows suspicious behavior concentrated in {suspicious_count} function(s); "
            f"the current sample-level hypothesis is most related to {attack_text}."
        )
    if classes["runtime_like_functions"] and not classes["unknown_functions"]:
        return (
            f"{sample_name} is currently dominated by runtime/helper functions in the analyzed set, "
            f"so deeper export of business-logic functions is still required."
        )
    return (
        f"{sample_name} has partial function coverage, but the current aggregate does not yet support "
        f"a confident malicious capability statement."
    )


def build_next_steps(classes: Dict[str, List[Dict[str, Any]]], aggregated_attack_ids: List[Dict[str, Any]]) -> List[str]:
    if classes["suspicious_functions"]:
        return [
            "Prioritize manual review of the suspicious functions and their callers/callees in IDA.",
            "Verify the top ATT&CK hypotheses against actual API sequences and strings before writing final labels.",
            "Extend the export to neighboring functions so the sample-level capability chain is complete.",
        ]
    if classes["runtime_like_functions"] and not classes["unknown_functions"]:
        return [
            "Do not keep exporting from the start of the function list; pick higher-level logic functions manually.",
            "Search in IDA for functions with network, file, registry, process, or crypto APIs.",
            "Re-run the pipeline on those functions to build a meaningful sample-level picture.",
        ]
    return [
        "Expand function coverage around the current targets.",
        "Look for stronger strings, imports, and external API usage.",
        "Re-run sample aggregation after adding more meaningful functions.",
    ]


def run_sample_aggregation(sample_json: Path, raw_ida_path: Path, top_k: int) -> Dict[str, Any]:
    sample = load_json_file(sample_json)
    raw_records = load_json_file(raw_ida_path)
    functions = sample.get("functions", [])

    function_analyses: List[Dict[str, Any]] = []
    for function in functions:
        function_addr = str(function.get("function_addr", ""))
        evidence = build_demo_result(sample_json, function_addr, "", top_k)
        raw_record = find_raw_record(raw_records, function_addr)
        analysis = analyze(evidence, raw_record)
        filtered_attack_ids = filter_attack_candidates_for_function(
            {
                "analysis": analysis,
                "evidence": evidence,
                "raw_record": raw_record,
            }
        )
        function_analyses.append(
            {
                "function_addr": function_addr,
                "function_name": function.get("function_name", ""),
                "evidence": evidence,
                "analysis": analysis,
                "raw_record": raw_record,
                "filtered_attack_ids": filtered_attack_ids,
            }
        )

    classes = classify_functions(function_analyses)
    aggregated_attack_ids = aggregate_attack_ids(function_analyses)
    aggregated_behavior_tags = aggregate_behavior_tags(function_analyses)
    capability_chains = build_capability_chains(
        {"function_results": [
            {
                "function_addr": item["analysis"]["function_addr"],
                "function_name": item["analysis"]["function_name"],
                "classification": item["analysis"]["classification"],
                "candidate_attack_ids": item["filtered_attack_ids"],
            }
            for item in function_analyses
        ]},
        raw_records,
    )

    sample_name = str(sample.get("sample_name", "unknown_sample"))
    result = {
        "sample_name": sample_name,
        "sample_hash": sample.get("sample_hash", ""),
        "function_count": len(function_analyses),
        "summary": build_sample_summary(sample_name, len(function_analyses), classes, aggregated_attack_ids),
        "conclusion": build_sample_conclusion(sample_name, classes, aggregated_attack_ids),
        "aggregated_attack_ids": aggregated_attack_ids,
        "aggregated_behavior_tags": aggregated_behavior_tags,
        "capability_chains": capability_chains,
        "capability_chain_summary": summarize_capability_chains(capability_chains),
        "suspicious_functions": classes["suspicious_functions"],
        "runtime_like_functions": classes["runtime_like_functions"],
        "unknown_functions": classes["unknown_functions"],
        "function_results": [
            {
                "function_name": item["analysis"]["function_name"],
                "function_addr": item["analysis"]["function_addr"],
                "classification": item["analysis"]["classification"],
                "conclusion": item["analysis"]["conclusion"],
                "candidate_attack_ids": item["filtered_attack_ids"],
                "evidence_lines": item["analysis"]["evidence_lines"],
            }
            for item in function_analyses
        ],
        "next_steps": build_next_steps(classes, aggregated_attack_ids),
    }
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Aggregate multiple function-level analyses into a sample-level report.")
    parser.add_argument("--sample-json", default=str(DEFAULT_SAMPLE_JSON), help="Path to sample_ida_semantic.json")
    parser.add_argument("--raw-ida", default=str(DEFAULT_RAW_IDA_PATH), help="Path to ida_semantic raw JSON")
    parser.add_argument("--top-k", type=int, default=3, help="Top K docs per knowledge source during function analysis")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Output sample analysis JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = run_sample_aggregation(Path(args.sample_json), Path(args.raw_ida), max(1, args.top_k))
    output_path = Path(args.output)
    save_json(output_path, result)

    print("[+] Sample-level aggregation completed.")
    print(f"    Sample         : {result['sample_name']}")
    print(f"    Function count : {result['function_count']}")
    print(f"    Suspicious     : {len(result['suspicious_functions'])}")
    print(f"    Runtime-like   : {len(result['runtime_like_functions'])}")
    print(f"    Output         : {output_path}")


if __name__ == "__main__":
    main()
