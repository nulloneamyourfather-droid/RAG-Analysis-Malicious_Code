import json
from pathlib import Path
from typing import Any, Dict, List, Set


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_PATH = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_capability_chains.json"


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def unique_strs(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        item = str(item or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


CAPABILITY_LABELS = {
    "network_communication": "网络通信",
    "file_operations": "文件操作",
    "registry_modification": "注册表修改",
    "process_injection": "进程注入",
    "execution_loader": "执行与装载",
    "input_capture": "输入捕获",
    "crypto_processing": "加解密处理",
    "system_discovery": "系统发现",
    "download_execute": "下载执行",
}

STAGE_PATTERNS = [
    {
        "stage_name": "下载执行链",
        "match_caps": {"download_execute", "network_communication", "execution_loader"},
        "min_hits": 2,
    },
    {
        "stage_name": "持久化链",
        "match_caps": {"registry_modification", "file_operations", "execution_loader"},
        "min_hits": 2,
    },
    {
        "stage_name": "环境发现链",
        "match_caps": {"system_discovery", "network_communication"},
        "min_hits": 1,
    },
    {
        "stage_name": "进程注入链",
        "match_caps": {"process_injection", "execution_loader"},
        "min_hits": 1,
    },
    {
        "stage_name": "输入窃取链",
        "match_caps": {"input_capture", "file_operations", "network_communication"},
        "min_hits": 1,
    },
    {
        "stage_name": "加密处理链",
        "match_caps": {"crypto_processing", "file_operations"},
        "min_hits": 1,
    },
    {
        "stage_name": "文件操作链",
        "match_caps": {"file_operations"},
        "min_hits": 1,
    },
    {
        "stage_name": "网络通信链",
        "match_caps": {"network_communication"},
        "min_hits": 1,
    },
]


def infer_capabilities(raw_record: Dict[str, Any]) -> List[str]:
    api_calls = [str(x).lower() for x in raw_record.get("api_calls", [])]
    strings = [str(x).lower() for x in raw_record.get("strings", [])]
    tags = [str(x).lower() for x in raw_record.get("behavior_tags", [])]
    text = " ".join(api_calls + strings + tags)
    capabilities: List[str] = []

    if any(x in text for x in ["socket", "connect", "wsasocket", "internetopen", "http"]):
        capabilities.append("network_communication")
    if any(x in text for x in ["createfile", "writefile", "readfile", "findfirstfile", "copyfile"]):
        capabilities.append("file_operations")
    if any(x in text for x in ["regopenkey", "regsetvalue", "currentversion\\run", "registry"]):
        capabilities.append("registry_modification")
    if any(x in text for x in ["openprocess", "virtualalloc", "writeprocessmemory", "createremotethread"]):
        capabilities.append("process_injection")
    if any(x in text for x in ["createprocess", "shellexecute", "winexec", "loadlibrary"]):
        capabilities.append("execution_loader")
    if any(x in text for x in ["getasynckeystate", "setwindowshookex", "keyboard", "keylog"]):
        capabilities.append("input_capture")
    if any(x in text for x in ["crypt", "bcrypt", "cryptencrypt", "cryptdecrypt"]):
        capabilities.append("crypto_processing")
    if any(x in text for x in ["getcomputername", "getusername", "getversion", "systeminfo"]):
        capabilities.append("system_discovery")
    if any(x in text for x in ["download", "url", "httpsendrequest", "urldownloadtofile"]):
        capabilities.append("download_execute")

    return unique_strs(capabilities)


def raw_record_signal(raw_record: Dict[str, Any]) -> int:
    return (
        len(raw_record.get("api_calls", [])) * 2
        + len(raw_record.get("behavior_tags", [])) * 3
        + min(len(raw_record.get("strings", [])), 5)
    )


def related(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    a_addr = a["function_addr"].lower()
    b_addr = b["function_addr"].lower()
    a_callers = {str(x).lower() for x in a.get("callers", [])}
    a_callees = {str(x).lower() for x in a.get("callees", [])}
    b_callers = {str(x).lower() for x in b.get("callers", [])}
    b_callees = {str(x).lower() for x in b.get("callees", [])}
    a_caps = set(a.get("capabilities", []))
    b_caps = set(b.get("capabilities", []))

    if b_addr in a_callers or b_addr in a_callees or a_addr in b_callers or a_addr in b_callees:
        return True
    if set(a.get("function_name_tokens", [])) & set(b.get("function_name_tokens", [])):
        return True
    if a_caps & b_caps:
        return True
    return False


def tokenize_name(name: str) -> List[str]:
    out: List[str] = []
    token = []
    for ch in name.lower():
        if ch.isalnum() or ch == "_":
            token.append(ch)
        else:
            if token:
                out.append("".join(token))
                token = []
    if token:
        out.append("".join(token))
    return [x for x in out if x not in {"sub", "j", "std"}]


def build_function_nodes(sample_analysis: Dict[str, Any], raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result_by_addr = {
        str(item.get("function_addr", "")).lower(): item
        for item in sample_analysis.get("function_results", [])
    }
    raw_by_addr = {
        str(item.get("function_addr", "")).lower(): item
        for item in raw_records
    }

    nodes: List[Dict[str, Any]] = []
    for addr, raw_record in raw_by_addr.items():
        result = result_by_addr.get(addr)
        if not result:
            continue
        classification = result.get("classification", {})
        if classification.get("runtime_like"):
            continue

        capabilities = infer_capabilities(raw_record)
        signal = raw_record_signal(raw_record)
        if signal <= 0 and not classification.get("malicious_signal"):
            continue

        nodes.append(
            {
                "function_addr": raw_record.get("function_addr", ""),
                "function_name": raw_record.get("function_name", ""),
                "callers": raw_record.get("callers", []),
                "callees": raw_record.get("callees", []),
                "api_calls": raw_record.get("api_calls", []),
                "strings": raw_record.get("strings", []),
                "behavior_tags": raw_record.get("behavior_tags", []),
                "capabilities": capabilities,
                "signal": signal,
                "candidate_attack_ids": result.get("candidate_attack_ids", []),
                "malicious_signal": bool(classification.get("malicious_signal")),
                "function_name_tokens": tokenize_name(str(raw_record.get("function_name", ""))),
            }
        )
    return nodes


def connected_components(nodes: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    if not nodes:
        return []
    neighbors: Dict[int, Set[int]] = {i: set() for i in range(len(nodes))}
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            if related(nodes[i], nodes[j]):
                neighbors[i].add(j)
                neighbors[j].add(i)

    seen: Set[int] = set()
    groups: List[List[Dict[str, Any]]] = []
    for i in range(len(nodes)):
        if i in seen:
            continue
        stack = [i]
        seen.add(i)
        group_idx: List[int] = []
        while stack:
            cur = stack.pop()
            group_idx.append(cur)
            for nxt in neighbors[cur]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        groups.append([nodes[idx] for idx in group_idx])
    return groups


def build_chain(group: List[Dict[str, Any]], chain_id: int) -> Dict[str, Any]:
    functions = sorted(group, key=lambda item: (-int(item.get("signal", 0)), item["function_addr"]))
    capabilities = unique_strs([cap for item in functions for cap in item.get("capabilities", [])])
    attack_ids = unique_strs(
        [attack["attack_id"] for item in functions for attack in item.get("candidate_attack_ids", [])]
    )
    title = " / ".join(capabilities[:3]) if capabilities else "generic_behavior_cluster"
    malicious_count = sum(1 for item in functions if item.get("malicious_signal"))
    avg_signal = sum(int(item.get("signal", 0)) for item in functions) / max(len(functions), 1)

    if malicious_count >= 2 or avg_signal >= 5:
        confidence = "high"
    elif malicious_count >= 1 or avg_signal >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    stage_name = infer_stage_name(capabilities, attack_ids, functions)
    display_name = build_chain_display_name(stage_name, capabilities, attack_ids, functions)
    summary = build_chain_summary(display_name, stage_name, confidence, capabilities, attack_ids, functions)
    evidence_explanation = build_chain_evidence(functions, capabilities, attack_ids)

    return {
        "chain_id": f"chain::{chain_id:03d}",
        "title": title,
        "stage_name": stage_name,
        "display_name": display_name,
        "confidence": confidence,
        "malicious_function_count": malicious_count,
        "capabilities": capabilities,
        "attack_ids": attack_ids,
        "function_count": len(functions),
        "summary": summary,
        "evidence_explanation": evidence_explanation,
        "functions": [
            {
                "function_name": item["function_name"],
                "function_addr": item["function_addr"],
                "signal": item["signal"],
                "capabilities": item["capabilities"],
                "api_calls": item.get("api_calls", [])[:8],
            }
            for item in functions
        ],
    }


def build_capability_chains(sample_analysis: Dict[str, Any], raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    nodes = build_function_nodes(sample_analysis, raw_records)
    groups = connected_components(nodes)
    chains = []
    for idx, group in enumerate(groups):
        if not group:
            continue
        chain = build_chain(group, idx + 1)
        if chain["function_count"] <= 1 and not chain["capabilities"] and chain["malicious_function_count"] == 0:
            continue
        chains.append(chain)
    chains.sort(key=lambda item: (-item["function_count"], item["chain_id"]))
    return chains


def summarize_capability_chains(chains: List[Dict[str, Any]]) -> List[str]:
    lines: List[str] = []
    for chain in chains[:5]:
        lines.append(
            f"{chain.get('display_name', chain['title'])} (confidence={chain['confidence']}, functions={chain['function_count']}, attack_ids={', '.join(chain['attack_ids'][:3]) or 'none'})"
        )
    return lines


def readable_capability_names(capabilities: List[str]) -> List[str]:
    return [CAPABILITY_LABELS.get(item, item) for item in capabilities]


def infer_stage_name(capabilities: List[str], attack_ids: List[str], functions: List[Dict[str, Any]]) -> str:
    cap_set = set(capabilities)
    for pattern in STAGE_PATTERNS:
        hits = len(cap_set & set(pattern["match_caps"]))
        if hits >= int(pattern["min_hits"]):
            return str(pattern["stage_name"])

    attack_text = " ".join(attack_ids).upper()
    if "T1055" in attack_text:
        return "进程注入链"
    if "T1082" in attack_text:
        return "环境发现链"
    if "T1105" in attack_text:
        return "下载执行链"
    if "T1112" in attack_text:
        return "持久化链"

    if functions:
        names = " ".join(str(item.get("function_name", "")).lower() for item in functions)
        if any(token in names for token in ["reg", "autorun", "startup"]):
            return "持久化链"
        if any(token in names for token in ["download", "http", "url", "recv"]):
            return "下载执行链"
        if any(token in names for token in ["inject", "remote", "thread"]):
            return "进程注入链"
        if any(token in names for token in ["system", "computer", "version", "user"]):
            return "环境发现链"

    return "通用行为链"


def build_chain_display_name(
    stage_name: str, capabilities: List[str], attack_ids: List[str], functions: List[Dict[str, Any]]
) -> str:
    if stage_name and stage_name != "通用行为链":
        return stage_name
    readable = readable_capability_names(capabilities)
    if readable:
        return " -> ".join(readable[:2]) if len(readable) >= 2 else f"{readable[0]}链"
    if attack_ids:
        return f"ATT&CK {attack_ids[0]} 相关链"
    if functions:
        return f"{functions[0]['function_name']} 邻域链"
    return "通用能力链"


def build_chain_summary(
    display_name: str,
    stage_name: str,
    confidence: str,
    capabilities: List[str],
    attack_ids: List[str],
    functions: List[Dict[str, Any]],
) -> str:
    function_names = ", ".join(item["function_name"] for item in functions[:4])
    capability_text = "、".join(readable_capability_names(capabilities[:3])) or "通用行为"
    attack_text = "、".join(attack_ids[:3]) if attack_ids else "无稳定 ATT&CK 映射"
    return (
        f"该链当前被归纳为“{display_name}”，对应的行为阶段为“{stage_name}”，当前置信度为 {confidence}。"
        f"它主要围绕 {capability_text} 展开，关联函数包括 {function_names or '无'}，"
        f"当前 ATT&CK 候选为 {attack_text}。"
    )


def build_chain_evidence(functions: List[Dict[str, Any]], capabilities: List[str], attack_ids: List[str]) -> List[str]:
    evidence: List[str] = []
    if capabilities:
        evidence.append(f"多个函数共享能力标签：{'、'.join(readable_capability_names(capabilities[:4]))}。")
    if attack_ids:
        evidence.append(f"链内函数聚合出相同或相近的 ATT&CK 候选：{'、'.join(attack_ids[:4])}。")

    api_examples = unique_strs([api for item in functions for api in item.get("api_calls", [])])[:6]
    if api_examples:
        evidence.append(f"链内函数出现了可相互印证的 API 调用：{', '.join(api_examples)}。")

    if len(functions) >= 2:
        names = " -> ".join(item["function_name"] for item in functions[:4])
        evidence.append(f"这些函数在调用关系或命名模式上可形成聚合：{names}。")

    strong_funcs = [item for item in functions if int(item.get("signal", 0)) >= 3]
    if strong_funcs:
        evidence.append(
            f"链内存在较高信号函数：{', '.join(item['function_name'] for item in strong_funcs[:4])}。"
        )

    return evidence
