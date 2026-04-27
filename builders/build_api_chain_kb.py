import json
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "api_chain"
RAG_OUTPUT_DIR = PROJECT_ROOT / "data" / "rag" / "api_chain"

RAW_OUTPUT = RAW_OUTPUT_DIR / "api_chain_knowledge_raw.json"
RAG_OUTPUT = RAG_OUTPUT_DIR / "api_chain_knowledge_for_rag.jsonl"

API_DESC = {
    "CreateFile": "Create or open a file, device, or named pipe.",
    "ReadFile": "Read bytes from a file or device.",
    "WriteFile": "Write bytes into a file or device.",
    "FindFirstFile": "Start enumerating files in a directory.",
    "FindNextFile": "Continue enumerating files in a directory.",
    "OpenProcess": "Open a target process and obtain a handle.",
    "CreateProcess": "Create a new process.",
    "VirtualAllocEx": "Allocate memory inside another process.",
    "WriteProcessMemory": "Write bytes into another process.",
    "CreateRemoteThread": "Start execution in another process by creating a remote thread.",
    "RegOpenKeyEx": "Open a registry key.",
    "RegCreateKeyEx": "Create or open a registry key.",
    "RegSetValueEx": "Write a registry value.",
    "InternetOpen": "Initialize a WinINet session.",
    "InternetConnect": "Connect to a remote server via WinINet.",
    "HttpOpenRequest": "Prepare an HTTP request handle.",
    "HttpSendRequest": "Send an HTTP request.",
    "URLDownloadToFile": "Download a remote resource to a local file.",
    "socket": "Create a socket endpoint.",
    "connect": "Connect a socket to a remote host.",
    "send": "Send data over a socket.",
    "recv": "Receive data from a socket.",
    "GetComputerName": "Get the system hostname.",
    "GetUserName": "Get the current user name.",
    "GetVersionEx": "Get operating system version information.",
    "GetAdaptersInfo": "Get network adapter information.",
    "GetLogicalDrives": "Get available drive letters.",
    "SetWindowsHookEx": "Install a Windows hook procedure.",
    "GetAsyncKeyState": "Check keyboard state for a key.",
    "GetForegroundWindow": "Get the current foreground window.",
    "GetWindowText": "Read the window title text.",
    "CreateService": "Create a Windows service entry.",
    "StartService": "Start a Windows service.",
}

API_CHAIN_TEMPLATES: List[Dict[str, Any]] = [
    {
        "behavior_id": "behavior::process_injection::001",
        "behavior_name": "Process Injection",
        "category": "Process Control",
        "platform": "Windows",
        "required_apis": ["OpenProcess", "WriteProcessMemory"],
        "optional_apis": ["VirtualAllocEx", "CreateRemoteThread"],
        "negative_signals": [],
        "api_sequence_examples": [
            ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        ],
        "semantic_description": (
            "The function opens a remote process, writes content into remote memory, "
            "and triggers execution in that process."
        ),
        "malicious_purpose": (
            "Often used for stealthy code execution, payload staging, privilege escalation, "
            "or evasion."
        ),
        "evidence_template": (
            "Evidence typically includes remote process access plus memory write and remote "
            "execution APIs."
        ),
        "attack_mapping": [{"attack_id": "T1055", "attack_name": "Process Injection"}],
        "variant_note": "Variants may replace CreateRemoteThread with APC or NtCreateThreadEx.",
        "risk_level": "high",
    },
    {
        "behavior_id": "behavior::registry_persistence::001",
        "behavior_name": "Registry Persistence",
        "category": "Persistence",
        "platform": "Windows",
        "required_apis": ["RegOpenKeyEx", "RegSetValueEx"],
        "optional_apis": ["RegCreateKeyEx"],
        "negative_signals": [],
        "api_sequence_examples": [["RegOpenKeyEx", "RegSetValueEx"]],
        "semantic_description": (
            "The function edits autorun-related registry keys so a payload can execute "
            "automatically on boot or user logon."
        ),
        "malicious_purpose": "Used to maintain persistence after system restart.",
        "evidence_template": (
            "Evidence includes access to Run/RunOnce or similar startup-related registry paths."
        ),
        "attack_mapping": [
            {"attack_id": "T1547", "attack_name": "Boot or Logon Autostart Execution"}
        ],
        "variant_note": "Common targets include HKCU/HKLM Run and RunOnce paths.",
        "risk_level": "high",
    },
    {
        "behavior_id": "behavior::download_execute::001",
        "behavior_name": "Download and Execute",
        "category": "Network Communication",
        "platform": "Windows",
        "required_apis": ["CreateProcess"],
        "optional_apis": [
            "InternetOpen",
            "InternetConnect",
            "HttpOpenRequest",
            "HttpSendRequest",
            "URLDownloadToFile",
        ],
        "negative_signals": [],
        "api_sequence_examples": [
            [
                "InternetOpen",
                "InternetConnect",
                "HttpOpenRequest",
                "HttpSendRequest",
                "URLDownloadToFile",
                "CreateProcess",
            ]
        ],
        "semantic_description": (
            "The function establishes a network connection, downloads a payload, and launches it."
        ),
        "malicious_purpose": "Used by droppers and staged malware payload delivery chains.",
        "evidence_template": (
            "Look for a network download primitive followed by process creation on the downloaded file."
        ),
        "attack_mapping": [{"attack_id": "T1105", "attack_name": "Ingress Tool Transfer"}],
        "variant_note": "Some samples use WinHTTP or raw sockets instead of WinINet.",
        "risk_level": "high",
    },
    {
        "behavior_id": "behavior::c2_communication::001",
        "behavior_name": "Command and Control Communication",
        "category": "Network Communication",
        "platform": "Windows",
        "required_apis": ["socket", "connect"],
        "optional_apis": ["send", "recv"],
        "negative_signals": [],
        "api_sequence_examples": [["socket", "connect", "send", "recv"]],
        "semantic_description": (
            "The function creates a socket, connects to a remote endpoint, and exchanges data."
        ),
        "malicious_purpose": "Used for remote command execution, tasking, and data exfiltration.",
        "evidence_template": (
            "Evidence includes persistent socket communication with bidirectional data exchange."
        ),
        "attack_mapping": [
            {"attack_id": "T1071", "attack_name": "Application Layer Protocol"}
        ],
        "variant_note": "Protocol details may require strings, packet formats, or decryption analysis.",
        "risk_level": "medium",
    },
    {
        "behavior_id": "behavior::keylogging::001",
        "behavior_name": "Input Capture",
        "category": "Credential Access",
        "platform": "Windows",
        "required_apis": [],
        "optional_apis": [
            "SetWindowsHookEx",
            "GetAsyncKeyState",
            "GetForegroundWindow",
            "GetWindowText",
        ],
        "negative_signals": [],
        "api_sequence_examples": [
            ["SetWindowsHookEx", "GetForegroundWindow", "GetWindowText"],
            ["GetAsyncKeyState", "GetForegroundWindow", "GetWindowText"],
        ],
        "semantic_description": (
            "The function monitors keyboard activity and may capture the active window context."
        ),
        "malicious_purpose": "Used to steal credentials and monitor user input.",
        "evidence_template": (
            "Evidence often includes keyboard APIs combined with active window title collection."
        ),
        "attack_mapping": [{"attack_id": "T1056", "attack_name": "Input Capture"}],
        "variant_note": "Polling-based keyloggers may not install hooks.",
        "risk_level": "high",
    },
    {
        "behavior_id": "behavior::env_discovery::001",
        "behavior_name": "System Information Discovery",
        "category": "Discovery",
        "platform": "Windows",
        "required_apis": [],
        "optional_apis": [
            "GetComputerName",
            "GetUserName",
            "GetVersionEx",
            "GetAdaptersInfo",
            "GetLogicalDrives",
        ],
        "negative_signals": [],
        "api_sequence_examples": [
            ["GetComputerName", "GetUserName", "GetVersionEx", "GetAdaptersInfo"]
        ],
        "semantic_description": (
            "The function collects host, user, OS, network, and storage environment details."
        ),
        "malicious_purpose": "Used to fingerprint the environment and guide follow-up behavior.",
        "evidence_template": "Evidence includes clustered host and network enumeration APIs.",
        "attack_mapping": [
            {"attack_id": "T1082", "attack_name": "System Information Discovery"}
        ],
        "variant_note": "Some malware also collects locale, domain, or process list details.",
        "risk_level": "medium",
    },
    {
        "behavior_id": "behavior::file_encryption::001",
        "behavior_name": "Bulk File Processing for Encryption",
        "category": "Impact",
        "platform": "Windows",
        "required_apis": ["CreateFile", "ReadFile", "WriteFile"],
        "optional_apis": ["FindFirstFile", "FindNextFile"],
        "negative_signals": [],
        "api_sequence_examples": [
            ["FindFirstFile", "FindNextFile", "CreateFile", "ReadFile", "WriteFile"]
        ],
        "semantic_description": (
            "The function enumerates files and performs repeated read and write operations on them."
        ),
        "malicious_purpose": (
            "Common in ransomware pre-encryption workflows and bulk file tampering."
        ),
        "evidence_template": (
            "Evidence requires directory traversal plus large-scale file access and overwrite patterns."
        ),
        "attack_mapping": [
            {"attack_id": "T1486", "attack_name": "Data Encrypted for Impact"}
        ],
        "variant_note": "Confirm real encryption behavior with crypto routines or extension renaming evidence.",
        "risk_level": "high",
    },
    {
        "behavior_id": "behavior::service_persistence::001",
        "behavior_name": "Service-Based Persistence",
        "category": "Persistence",
        "platform": "Windows",
        "required_apis": ["CreateService"],
        "optional_apis": ["StartService"],
        "negative_signals": [],
        "api_sequence_examples": [["CreateService", "StartService"]],
        "semantic_description": (
            "The function registers a Windows service and may start it immediately."
        ),
        "malicious_purpose": "Used for persistence and privileged background execution.",
        "evidence_template": "Evidence includes SCM operations creating or enabling a service.",
        "attack_mapping": [
            {"attack_id": "T1543", "attack_name": "Create or Modify System Process"}
        ],
        "variant_note": "Malware may also pair this with registry edits or dropped service binaries.",
        "risk_level": "high",
    },
]


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def validate_templates(templates: List[Dict[str, Any]]) -> None:
    required_fields = {
        "behavior_id",
        "behavior_name",
        "category",
        "platform",
        "required_apis",
        "optional_apis",
        "negative_signals",
        "api_sequence_examples",
        "semantic_description",
        "malicious_purpose",
        "evidence_template",
        "attack_mapping",
        "variant_note",
        "risk_level",
    }

    seen_behavior_ids: set[str] = set()
    for idx, template in enumerate(templates, start=1):
        missing_fields = sorted(required_fields - set(template))
        if missing_fields:
            raise ValueError(f"Template #{idx} is missing fields: {', '.join(missing_fields)}")

        behavior_id = template["behavior_id"]
        if behavior_id in seen_behavior_ids:
            raise ValueError(f"Duplicate behavior_id: {behavior_id}")
        seen_behavior_ids.add(behavior_id)

        all_apis = (
            list(template["required_apis"])
            + list(template["optional_apis"])
            + [api for seq in template["api_sequence_examples"] for api in seq]
        )
        missing_api_desc = [api for api in all_apis if api not in API_DESC]
        if missing_api_desc:
            raise ValueError(
                f"{behavior_id} references APIs without descriptions: {', '.join(sorted(set(missing_api_desc)))}"
            )


def build_api_chain_record(template: Dict[str, Any]) -> Dict[str, Any]:
    api_sequence_examples = [list(sequence) for sequence in template["api_sequence_examples"]]
    api_names = unique_strs(
        template["required_apis"] + template["optional_apis"] + [api for seq in api_sequence_examples for api in seq]
    )
    api_details = [{"api_name": api_name, "api_desc": API_DESC[api_name]} for api_name in api_names]
    attack_ids = [mapping["attack_id"] for mapping in template["attack_mapping"]]

    return {
        "behavior_id": template["behavior_id"],
        "behavior_name": template["behavior_name"],
        "category": template["category"],
        "platform": template["platform"],
        "required_apis": list(template["required_apis"]),
        "optional_apis": list(template["optional_apis"]),
        "negative_signals": list(template["negative_signals"]),
        "api_sequence_examples": api_sequence_examples,
        "api_details": api_details,
        "semantic_description": template["semantic_description"],
        "malicious_purpose": template["malicious_purpose"],
        "evidence_template": template["evidence_template"],
        "attack_mapping": list(template["attack_mapping"]),
        "variant_note": template["variant_note"],
        "risk_level": template["risk_level"],
        "attack_ids": attack_ids,
        "keywords": unique_strs(api_names + attack_ids + [template["behavior_name"], template["category"]]),
    }


def build_rag_doc(record: Dict[str, Any]) -> Dict[str, Any]:
    api_lines = [
        f"- {item['api_name']}: {item['api_desc']}"
        for item in record["api_details"]
    ]
    required_apis = ", ".join(record["required_apis"]) or "None"
    optional_apis = ", ".join(record["optional_apis"]) or "None"
    attack_text = ", ".join(
        f"{item['attack_id']} {item['attack_name']}" for item in record["attack_mapping"]
    )
    example_text = " | ".join(" -> ".join(sequence) for sequence in record["api_sequence_examples"])
    summary = (
        f"{record['behavior_name']} on {record['platform']}. "
        f"Maps to {attack_text}. Required APIs: {required_apis}."
    )
    content = (
        f"Behavior: {record['behavior_name']}\n"
        f"Category: {record['category']}\n"
        f"Platform: {record['platform']}\n"
        f"Risk Level: {record['risk_level']}\n"
        f"Required APIs: {required_apis}\n"
        f"Optional APIs: {optional_apis}\n"
        f"Example Sequences: {example_text}\n"
        f"Semantic Description: {record['semantic_description']}\n"
        f"Malicious Purpose: {record['malicious_purpose']}\n"
        f"Evidence Template: {record['evidence_template']}\n"
        f"ATT&CK Mapping: {attack_text}\n"
        f"Variant Note: {record['variant_note']}\n"
        f"API Details:\n" + "\n".join(api_lines) + "\n"
    )

    return {
        "doc_id": f"api_chain::{record['behavior_id']}",
        "source": "API_CHAIN",
        "doc_type": "api-behavior-chain",
        "title": record["behavior_name"],
        "summary": summary,
        "content": content,
        "tags": unique_strs([record["category"], record["platform"], record["behavior_name"], record["risk_level"]]),
        "keywords": record["keywords"],
        "platforms": [record["platform"]],
        "attack_ids": record["attack_ids"],
        "metadata": {
            "language": "en",
            "behavior_id": record["behavior_id"],
            "category": record["category"],
            "required_apis": record["required_apis"],
            "optional_apis": record["optional_apis"],
            "negative_signals": record["negative_signals"],
            "risk_level": record["risk_level"],
        },
    }


def main() -> None:
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAG_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    validate_templates(API_CHAIN_TEMPLATES)

    print("[+] Building API chain knowledge records...")
    records = [build_api_chain_record(template) for template in API_CHAIN_TEMPLATES]
    save_json(RAW_OUTPUT, records)

    print("[+] Building RAG-ready API chain documents...")
    rag_docs = [build_rag_doc(record) for record in records]
    save_jsonl(RAG_OUTPUT, rag_docs)

    print("[+] Done.")
    print(f"    Raw records   : {RAW_OUTPUT}")
    print(f"    RAG documents : {RAG_OUTPUT}")
    print(f"    Total records : {len(records)}")


if __name__ == "__main__":
    main()
