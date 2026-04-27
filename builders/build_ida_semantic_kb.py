import json
import re
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
INPUT_DIR = WORKSPACE_ROOT / "samples" / "ida_exports"
RAW_OUTPUT_DIR = PROJECT_ROOT / "data" / "raw" / "ida_semantic"
RAG_OUTPUT_DIR = PROJECT_ROOT / "data" / "rag" / "ida_semantic"

RAW_OUTPUT = RAW_OUTPUT_DIR / "ida_semantic_knowledge_raw.json"
RAG_OUTPUT = RAG_OUTPUT_DIR / "ida_semantic_knowledge_for_rag.jsonl"
SAMPLE_INPUT = INPUT_DIR / "sample_ida_semantic.json"

SAMPLE_DATA = {
    "sample_name": "demo_sample.exe",
    "sample_hash": "demo_sha256_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "platform": "Windows",
    "functions": [
        {
            "function_name": "sub_401000",
            "function_addr": "0x401000",
            "pseudo_code": """
int __stdcall sub_401000()
{
    HANDLE hProcess;
    LPVOID remoteMem;
    hProcess = OpenProcess(0x1F0FFF, 0, pid);
    remoteMem = VirtualAllocEx(hProcess, 0, 4096, 0x3000, 0x40);
    WriteProcessMemory(hProcess, remoteMem, shellcode, shellcode_len, 0);
    CreateRemoteThread(hProcess, 0, 0, remoteMem, 0, 0, 0);
    return 0;
}
""",
            "api_calls": [
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
            "strings": ["explorer.exe", "kernel32.dll"],
            "callers": ["sub_402000"],
            "callees": [],
            "behavior_tags": ["Process Injection", "Remote Thread Creation"],
            "mapped_attack_ids": ["T1055"],
            "summary": "Writes shellcode into another process and starts a remote thread.",
        },
        {
            "function_name": "sub_402000",
            "function_addr": "0x402000",
            "pseudo_code": """
int __stdcall sub_402000()
{
    HKEY hKey;
    RegOpenKeyEx(HKEY_CURRENT_USER,
                 \"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\",
                 0, KEY_SET_VALUE, &hKey);
    RegSetValueEx(hKey, \"Updater\", 0, REG_SZ, \"C:\\\\Users\\\\Public\\\\svchost.exe\", 30);
    return 0;
}
""",
            "api_calls": ["RegOpenKeyEx", "RegSetValueEx"],
            "strings": [
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Updater",
                "C:\\Users\\Public\\svchost.exe",
            ],
            "callers": [],
            "callees": ["sub_401000"],
            "behavior_tags": ["Registry Persistence"],
            "mapped_attack_ids": ["T1547"],
            "summary": "Creates a Run key entry for automatic execution at logon.",
        },
    ],
}


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def ensure_sample_input() -> None:
    if SAMPLE_INPUT.exists():
        return
    SAMPLE_INPUT.parent.mkdir(parents=True, exist_ok=True)
    SAMPLE_INPUT.write_text(json.dumps(SAMPLE_DATA, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] Sample input created: {SAMPLE_INPUT}")


def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def normalize_list(items: Any) -> List[str]:
    if items is None:
        return []
    if isinstance(items, list):
        return [str(item).strip() for item in items if str(item).strip()]
    value = str(items).strip()
    return [value] if value else []


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def shorten_code(code: str, max_len: int = 1200) -> str:
    code = clean_text(code)
    if len(code) <= max_len:
        return code
    truncated = code[:max_len]
    last_newline = truncated.rfind("\n")
    if last_newline > max_len // 2:
        truncated = truncated[:last_newline]
    return truncated.rstrip() + "\n... (truncated)"


def validate_input_data(data: Dict[str, Any], source_path: Path) -> List[Dict[str, Any]]:
    functions = data.get("functions", [])
    if not isinstance(functions, list):
        raise ValueError(f"{source_path} has invalid 'functions'; expected a list")
    for idx, func in enumerate(functions, start=1):
        if not isinstance(func, dict):
            raise ValueError(f"{source_path} function #{idx} is not an object")
    return functions


def build_function_record(
    sample_name: str,
    sample_hash: str,
    platform: str,
    func: Dict[str, Any],
) -> Dict[str, Any]:
    function_name = func.get("function_name", "unknown_func")
    function_addr = func.get("function_addr", "")
    pseudo_code = shorten_code(func.get("pseudo_code", ""))
    api_calls = unique_strs(normalize_list(func.get("api_calls")))
    strings = unique_strs(normalize_list(func.get("strings")))
    callers = unique_strs(normalize_list(func.get("callers", func.get("xrefs_from"))))
    callees = unique_strs(normalize_list(func.get("callees", func.get("xrefs_to"))))
    behavior_tags = unique_strs(normalize_list(func.get("behavior_tags")))
    mapped_attack_ids = unique_strs(normalize_list(func.get("mapped_attack_ids")))
    summary = clean_text(func.get("summary", ""))

    return {
        "sample_name": sample_name,
        "sample_hash": sample_hash,
        "platform": platform,
        "function_name": function_name,
        "function_addr": function_addr,
        "pseudo_code": pseudo_code,
        "api_calls": api_calls,
        "strings": strings,
        "callers": callers,
        "callees": callees,
        "behavior_tags": behavior_tags,
        "mapped_attack_ids": mapped_attack_ids,
        "summary": summary,
        "keywords": unique_strs(api_calls + strings + behavior_tags + mapped_attack_ids + [function_name]),
    }


def build_rag_doc(record: Dict[str, Any]) -> Dict[str, Any]:
    summary = record["summary"] or (
        f"Function {record['function_name']} at {record['function_addr']} in {record['sample_name']}."
    )
    api_text = ", ".join(record["api_calls"]) or "None"
    strings_text = ", ".join(record["strings"]) or "None"
    tags_text = ", ".join(record["behavior_tags"]) or "None"
    callers_text = ", ".join(record["callers"]) or "None"
    callees_text = ", ".join(record["callees"]) or "None"
    attack_text = ", ".join(record["mapped_attack_ids"]) or "None"

    content = (
        f"Sample Name: {record['sample_name']}\n"
        f"Sample Hash: {record['sample_hash']}\n"
        f"Platform: {record['platform']}\n"
        f"Function Name: {record['function_name']}\n"
        f"Function Address: {record['function_addr']}\n"
        f"Summary: {summary}\n"
        f"Behavior Tags: {tags_text}\n"
        f"Mapped ATT&CK IDs: {attack_text}\n"
        f"API Calls: {api_text}\n"
        f"Strings: {strings_text}\n"
        f"Callers: {callers_text}\n"
        f"Callees: {callees_text}\n"
        f"Pseudocode:\n{record['pseudo_code']}\n"
    )

    return {
        "doc_id": (
            f"ida_semantic::{record['sample_hash']}::{record['function_addr']}::{record['function_name']}"
        ),
        "source": "IDA_SEMANTIC",
        "doc_type": "function-semantic",
        "title": f"{record['sample_name']}::{record['function_name']}@{record['function_addr']}",
        "summary": summary,
        "content": content,
        "tags": unique_strs(record["behavior_tags"] + [record["platform"], "Function Semantic"]),
        "keywords": record["keywords"],
        "platforms": [record["platform"]],
        "attack_ids": record["mapped_attack_ids"],
        "metadata": {
            "language": "en",
            "sample_name": record["sample_name"],
            "sample_hash": record["sample_hash"],
            "function_name": record["function_name"],
            "function_addr": record["function_addr"],
            "api_calls": record["api_calls"],
            "behavior_tags": record["behavior_tags"],
        },
    }


def main() -> None:
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAG_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    input_files = list(INPUT_DIR.glob("*.json"))
    if not input_files:
        print(f"[!] No input JSON files found in {INPUT_DIR}")
        print(f"[!] Creating sample input: {SAMPLE_INPUT}")
        ensure_sample_input()
        input_files = [SAMPLE_INPUT]

    all_records: List[Dict[str, Any]] = []
    print("[+] Building IDA semantic knowledge records...")
    for input_file in input_files:
        data = load_json(input_file)
        sample_name = data.get("sample_name", input_file.stem)
        sample_hash = data.get("sample_hash", "unknown_hash")
        platform = data.get("platform", "Windows")
        functions = validate_input_data(data, input_file)

        for func in functions:
            record = build_function_record(sample_name, sample_hash, platform, func)
            all_records.append(record)

    save_json(RAW_OUTPUT, all_records)

    print("[+] Building RAG-ready IDA semantic documents...")
    rag_docs = [build_rag_doc(record) for record in all_records]
    save_jsonl(RAG_OUTPUT, rag_docs)

    print("[+] Done.")
    print(f"    Raw records   : {RAW_OUTPUT}")
    print(f"    RAG documents : {RAG_OUTPUT}")
    print(f"    Total records : {len(all_records)}")


if __name__ == "__main__":
    main()
