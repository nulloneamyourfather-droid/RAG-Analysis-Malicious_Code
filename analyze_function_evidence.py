import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_EVIDENCE_PATH = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_function_evidence.json"
DEFAULT_RAW_IDA_PATH = PROJECT_ROOT / "data" / "raw" / "ida_semantic" / "ida_semantic_knowledge_raw.json"
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_function_analysis.json"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


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


def find_raw_record(raw_records: List[Dict[str, Any]], function_addr: str) -> Dict[str, Any] | None:
    for record in raw_records:
        if str(record.get("function_addr", "")).lower() == function_addr.lower():
            return record
    return None


def infer_runtime_library(function_name: str, pseudocode: str, callers: List[str], callees: List[str]) -> Dict[str, Any]:
    name = function_name.lower()
    code = pseudocode.lower()
    indicators: List[str] = []
    score = 0

    runtime_prefixes = ("_rtc_", "__scrt_", "__vcrt_", "std::", "j__", "__acrt", "_initterm")
    if name.startswith(runtime_prefixes):
        score += 4
        indicators.append("Function name matches common CRT/runtime prefix")
    if "stackfailure" in code or "varcount" in code or "_rtc_" in code:
        score += 4
        indicators.append("Pseudocode contains runtime stack-check logic")
    if not callers and not callees:
        score += 1
    if any(callee.lower().startswith(runtime_prefixes) for callee in callees):
        score += 2
        indicators.append("Callees include CRT/runtime helpers")

    return {
        "is_runtime_like": score >= 4,
        "score": score,
        "indicators": indicators,
    }


def infer_malicious_signal(
    api_calls: List[str],
    behavior_tags: List[str],
    candidate_attack_ids: List[Dict[str, Any]],
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    score = 0
    indicators: List[str] = []
    attack_docs = evidence.get("retrieved_attack_docs", [])
    api_chain_docs = evidence.get("retrieved_api_chain_docs", [])
    strong_api_chain_docs = [
        doc for doc in api_chain_docs if int(doc.get("required_hits", 0)) > 0 or float(doc.get("score", 0)) >= 0.8
    ]
    strong_attack_docs = [
        doc
        for doc in attack_docs
        if (int(doc.get("keyword_overlap", 0)) >= 2 and float(doc.get("score", 0)) >= 0.2)
        or float(doc.get("score", 0)) >= 0.45
    ]

    if len(api_calls) >= 2:
        score += min(len(api_calls), 4)
        indicators.append(f"Observed API calls: {', '.join(api_calls[:6])}")
    elif len(api_calls) == 1:
        score += 1
        indicators.append(f"Observed single API call: {api_calls[0]}")
    if behavior_tags:
        score += len(behavior_tags) * 2
        indicators.append(f"Behavior tags: {', '.join(behavior_tags)}")
    if strong_api_chain_docs:
        score += 4
        indicators.append(
            f"Strong API-chain matches: {', '.join(doc['title'] for doc in strong_api_chain_docs[:2])}"
        )
    if strong_attack_docs and (api_calls or behavior_tags):
        score += 2
        indicators.append(
            f"Strong ATT&CK evidence: {', '.join(doc['title'] for doc in strong_attack_docs[:2])}"
        )
    if candidate_attack_ids and (strong_api_chain_docs or behavior_tags or len(api_calls) >= 2):
        score += 1
        indicators.append(f"Retrieved ATT&CK candidates: {', '.join(item['attack_id'] for item in candidate_attack_ids[:3])}")

    return {
        "has_malicious_signal": score >= 5,
        "score": score,
        "indicators": indicators,
    }


def build_confidence(runtime_signal: Dict[str, Any], malicious_signal: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    if malicious_signal["has_malicious_signal"] and evidence.get("retrieved_api_chain_docs"):
        return "high"
    if malicious_signal["has_malicious_signal"] or evidence.get("candidate_attack_ids"):
        return "medium"
    if runtime_signal["is_runtime_like"]:
        return "medium"
    return "low"


def build_conclusion(function_name: str, runtime_signal: Dict[str, Any], malicious_signal: Dict[str, Any]) -> str:
    if runtime_signal["is_runtime_like"] and not malicious_signal["has_malicious_signal"]:
        return f"{function_name} is more consistent with compiler/runtime support logic than malware behavior."
    if malicious_signal["has_malicious_signal"]:
        return f"{function_name} shows behavior worth mapping to ATT&CK and deeper malware analysis."
    return f"{function_name} currently lacks enough behavioral evidence for ATT&CK mapping."


def build_next_steps(runtime_signal: Dict[str, Any], malicious_signal: Dict[str, Any]) -> List[str]:
    if runtime_signal["is_runtime_like"] and not malicious_signal["has_malicious_signal"]:
        return [
            "Skip this helper and move to its non-runtime callers.",
            "Search for functions with Windows API calls, strings, or network/file/registry behavior.",
            "Export a function that is closer to the real program logic instead of CRT support code.",
        ]
    if malicious_signal["has_malicious_signal"]:
        return [
            "Inspect the top API behavior chain matches and verify the call sequence in IDA.",
            "Check surrounding callers/callees to determine whether this is one step in a larger malicious workflow.",
            "Use the candidate ATT&CK IDs as hypotheses, not final labels, until manual verification is complete.",
        ]
    return [
        "Pick a function with richer API calls or meaningful strings.",
        "Re-run the export for a non-thunk, non-runtime function.",
        "If needed, inspect callers of this function to locate higher-level behavior.",
    ]


def analyze(evidence: Dict[str, Any], raw_record: Dict[str, Any] | None) -> Dict[str, Any]:
    function_name = str(evidence.get("function_name", "unknown_function"))
    current_facts = evidence.get("current_facts", {})
    api_calls = unique_strs(current_facts.get("api_calls", []))
    behavior_tags = unique_strs(current_facts.get("behavior_tags", []))
    candidate_attack_ids = evidence.get("candidate_attack_ids", [])

    pseudocode = ""
    callers: List[str] = []
    callees: List[str] = []
    if raw_record:
        pseudocode = str(raw_record.get("pseudo_code", ""))
        callers = unique_strs(raw_record.get("callers", []))
        callees = unique_strs(raw_record.get("callees", []))

    runtime_signal = infer_runtime_library(function_name, pseudocode, callers, callees)
    malicious_signal = infer_malicious_signal(api_calls, behavior_tags, candidate_attack_ids, evidence)
    confidence = build_confidence(runtime_signal, malicious_signal, evidence)
    conclusion = build_conclusion(function_name, runtime_signal, malicious_signal)
    next_steps = build_next_steps(runtime_signal, malicious_signal)

    return {
        "sample_name": evidence.get("sample_name", ""),
        "sample_hash": evidence.get("sample_hash", ""),
        "function_name": function_name,
        "function_addr": evidence.get("function_addr", ""),
        "classification": {
            "runtime_like": runtime_signal["is_runtime_like"],
            "malicious_signal": malicious_signal["has_malicious_signal"],
            "confidence": confidence,
        },
        "conclusion": conclusion,
        "runtime_signal": runtime_signal,
        "malicious_signal": malicious_signal,
        "candidate_attack_ids": candidate_attack_ids,
        "evidence_lines": evidence.get("evidence_lines", []),
        "next_steps": next_steps,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate a short function-level analysis from evidence JSON.")
    parser.add_argument("--evidence", default=str(DEFAULT_EVIDENCE_PATH), help="Path to evidence JSON")
    parser.add_argument("--raw-ida", default=str(DEFAULT_RAW_IDA_PATH), help="Path to ida_semantic raw JSON")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Output analysis JSON path")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    evidence = load_json(Path(args.evidence))
    raw_records = load_json(Path(args.raw_ida))
    raw_record = find_raw_record(raw_records, str(evidence.get("function_addr", "")))
    analysis = analyze(evidence, raw_record)
    output_path = Path(args.output)
    save_json(output_path, analysis)

    print("[+] Function-level analysis generated.")
    print(f"    Function   : {analysis['function_name']} @ {analysis['function_addr']}")
    print(f"    Confidence : {analysis['classification']['confidence']}")
    print(f"    Conclusion : {analysis['conclusion']}")
    print(f"    Output     : {output_path}")


if __name__ == "__main__":
    main()
