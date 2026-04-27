import argparse
import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
OUTPUT_DIR = WORKSPACE_ROOT / "samples" / "ida_exports"
DEFAULT_OUTPUT_FILE = OUTPUT_DIR / "sample_ida_semantic.json"
DEFAULT_MCP_URL = "http://127.0.0.1:13337/mcp"
RUNTIME_PREFIXES = ("_rtc_", "__scrt_", "__vcrt_", "std::", "j__", "__acrt", "_initterm")


def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def unique_strs(items: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def normalize_addr(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text if text.startswith("0x") else f"0x{text.lower()}"


def clean_text(text: Any) -> str:
    return str(text or "").replace("\r\n", "\n").strip()


def parse_csv_items(value: str) -> List[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def load_items_from_file(path_str: str) -> List[str]:
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"List file not found: {path}")
    items: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(line)
    return items


def infer_behavior_tags(api_calls: List[str], strings: List[str], pseudocode: str) -> List[str]:
    haystack = " ".join(api_calls + strings + [pseudocode]).lower()
    tags: List[str] = []
    if "writeprocessmemory" in haystack or "createremotethread" in haystack:
        tags.append("Process Injection")
    if "regsetvalueex" in haystack or "currentversion\\run" in haystack:
        tags.append("Registry Persistence")
    if "urldownloadtofile" in haystack or "httpsendrequest" in haystack:
        tags.append("Download and Execute")
    if "socket" in haystack and "connect" in haystack:
        tags.append("C2 Communication")
    if "getasynckeystate" in haystack or "setwindowshookex" in haystack:
        tags.append("Input Capture")
    if "createfile" in haystack and "writefile" in haystack and "findfirstfile" in haystack:
        tags.append("Bulk File Processing")
    return tags


def build_summary(function_name: str, api_calls: List[str], strings: List[str], pseudocode: str) -> str:
    if api_calls:
        return f"{function_name} uses APIs: {', '.join(api_calls[:6])}."
    if strings:
        return f"{function_name} references strings: {', '.join(strings[:4])}."
    if pseudocode:
        first_line = next((line.strip() for line in pseudocode.splitlines() if line.strip()), "")
        if first_line:
            return f"{function_name} pseudocode begins with: {first_line[:120]}"
    return f"{function_name} exported from IDA-MCP."


def is_trivial_wrapper(function_name: str, pseudocode: str, api_calls: List[str], callees: List[str]) -> bool:
    code = pseudocode.lower()
    non_self_callees = [callee for callee in callees if callee and callee != function_name]
    if "attributes: thunk" in code:
        return True
    code_lines = [line.strip() for line in pseudocode.splitlines() if line.strip()]
    if len(code_lines) <= 6 and not api_calls and len(non_self_callees) <= 1:
        if any("return " in line for line in code_lines):
            return True
    return False


def score_function_value(
    function_name: str,
    pseudocode: str,
    api_calls: List[str],
    strings: List[str],
    callers: List[str],
    callees: List[str],
    behavior_tags: List[str],
) -> tuple[float, List[str]]:
    score = 0.0
    reasons: List[str] = []
    lower_name = function_name.lower()
    code_lines = [line.strip() for line in pseudocode.splitlines() if line.strip()]

    if behavior_tags:
        score += min(len(behavior_tags) * 4.0, 12.0)
        reasons.append(f"behavior_tags={','.join(behavior_tags[:3])}")
    if api_calls:
        score += min(len(api_calls) * 2.5, 10.0)
        reasons.append(f"api_calls={len(api_calls)}")
    if strings:
        score += min(len(strings) * 1.0, 6.0)
        reasons.append(f"strings={len(strings)}")
    if len(callers) >= 2:
        score += min(len(callers), 5)
        reasons.append(f"callers={len(callers)}")
    if len(callees) >= 2:
        score += min(len(callees), 5) * 0.5
        reasons.append(f"callees={len(callees)}")
    if len(code_lines) >= 12:
        score += 2.0
        reasons.append(f"code_lines={len(code_lines)}")
    if len(pseudocode) >= 400:
        score += 2.0
        reasons.append("long_pseudocode")

    if "createfile" in pseudocode.lower() or "writefile" in pseudocode.lower() or "socket" in pseudocode.lower():
        score += 2.0
        reasons.append("behavioral_keywords")

    if "attributes: thunk" in pseudocode.lower():
        score -= 10.0
        reasons.append("thunk_penalty")
    if lower_name.startswith(RUNTIME_PREFIXES):
        score -= 6.0
        reasons.append("runtime_name_penalty")
    if not api_calls and not strings and not behavior_tags:
        score -= 3.0
        reasons.append("low_signal_penalty")
    if len(code_lines) <= 6:
        score -= 2.0
        reasons.append("short_wrapper_penalty")
    if len(callees) <= 1 and not api_calls:
        score -= 1.5
        reasons.append("single_callee_penalty")

    return round(score, 4), reasons


class McpHttpClient:
    def __init__(self, mcp_url: str, timeout: int = 60):
        parsed = urlparse(mcp_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid MCP URL: {mcp_url}")
        self.mcp_url = mcp_url
        self.timeout = timeout
        self.session_id: Optional[str] = None
        self.request_counter = 0
        self.protocol_mode = "modern"

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        request = Request(self.mcp_url, data=body, headers=headers, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                session_id = response.headers.get("Mcp-Session-Id")
                if session_id:
                    self.session_id = session_id
                return json.loads(raw)
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code} while calling MCP: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Failed to connect to MCP server at {self.mcp_url}: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"Unexpected MCP transport error for {self.mcp_url}: {exc}") from exc

    def initialize(self) -> None:
        response = self._post(
            {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "attck-knowledge-exporter", "version": "0.1.0"},
                },
            }
        )
        if "error" in response:
            self.protocol_mode = "legacy"
            return

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        if self.protocol_mode == "legacy":
            raise RuntimeError("Modern MCP tools are unavailable in legacy mode")
        self.request_counter += 1
        response = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.request_counter,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }
        )
        if "error" in response:
            raise RuntimeError(f"MCP tool call failed for {name}: {response['error']}")
        result = response.get("result", {})
        if result.get("isError"):
            raise RuntimeError(f"MCP tool returned error for {name}: {result.get('content')}")
        if "structuredContent" in result:
            structured = result["structuredContent"]
            if isinstance(structured, dict) and "result" in structured and len(structured) == 1:
                return structured["result"]
            return structured
        return result

    def read_resource(self, uri: str) -> Any:
        if self.protocol_mode == "legacy":
            raise RuntimeError("MCP resources are unavailable in legacy mode")
        self.request_counter += 1
        response = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.request_counter,
                "method": "resources/read",
                "params": {"uri": uri},
            }
        )
        if "error" in response:
            raise RuntimeError(f"MCP resource read failed for {uri}: {response['error']}")
        result = response.get("result", {})
        contents = result.get("contents", [])
        if not contents:
            return None
        return json.loads(contents[0].get("text", "null"))

    def legacy_call(self, method: str, *params: Any) -> Any:
        self.request_counter += 1
        response = self._post(
            {
                "jsonrpc": "2.0",
                "id": self.request_counter,
                "method": method,
                "params": list(params),
            }
        )
        if "error" in response:
            raise RuntimeError(f"Legacy JSON-RPC call failed for {method}: {response['error']}")
        return response.get("result")


def extract_import_names(import_rows: List[Dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for row in import_rows:
        for entry in row.get("data", []):
            name = str(entry.get("imported_name") or entry.get("name") or "").strip()
            if name:
                names.add(name)
    return names


def extract_calls_from_pseudocode(pseudocode: str) -> List[str]:
    call_names = re.findall(r"\b([A-Za-z_?@$][A-Za-z0-9_?@$]*)\s*\(", pseudocode)
    ignored = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "__int64",
        "__int32",
        "__int16",
        "__int8",
    }
    return unique_strs([name for name in call_names if name not in ignored and not name.startswith("sub_")])


def extract_strings_from_pseudocode(pseudocode: str) -> List[str]:
    return unique_strs(re.findall(r'"([^"\n]{1,200})"', pseudocode))


def dedupe_exported_functions(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen_keys: set[str] = set()
    for item in items:
        key = f"{item['function_addr']}::{item['function_name']}"
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(item)
    deduped.sort(key=lambda item: (item["function_addr"], item["function_name"]))
    return deduped


def rank_high_value_functions(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            -float(item.get("selection_score", 0)),
            -len(item.get("behavior_tags", [])),
            -len(item.get("api_calls", [])),
            item.get("function_addr", ""),
        ),
    )


def collect_modern_function_rows(
    client: McpHttpClient,
    offset: int,
    limit: int,
    filter_pattern: str,
    current_function_only: bool,
    function_addresses: List[str],
    function_names: List[str],
) -> List[Dict[str, Any]]:
    if function_addresses or function_names:
        rows: List[Dict[str, Any]] = []
        for address in function_addresses:
            rows.append({"addr": address, "name": address})
        for name in function_names:
            rows.append({"addr": name, "name": name})
        return rows
    if current_function_only:
        current_item = (client.read_resource("ida://cursor") or {}).get("function")
        return [current_item] if current_item else []

    rows: List[Dict[str, Any]] = []
    batch_size = min(max(limit, 50), 200)
    scan_budget = max(limit * 20, 200)
    current_offset = offset
    scanned = 0
    while scanned < scan_budget:
        page_list = client.call_tool(
            "list_funcs", {"filter": filter_pattern, "offset": current_offset, "count": batch_size}
        )
        if not isinstance(page_list, list) or not page_list:
            break
        page = page_list[0]
        data = page.get("data", [])
        if not data:
            break
        rows.extend(data)
        current_offset = page.get("next_offset")
        scanned += len(data)
        if current_offset is None:
            break
    return rows


def collect_legacy_function_rows(
    client: McpHttpClient,
    offset: int,
    limit: int,
    current_function_only: bool,
    function_addresses: List[str],
    function_names: List[str],
) -> List[Dict[str, Any]]:
    if function_addresses or function_names:
        rows: List[Dict[str, Any]] = []
        for address in function_addresses:
            function_row = client.legacy_call("get_function_by_address", address)
            if function_row:
                rows.append(function_row)
        for name in function_names:
            function_row = client.legacy_call("get_function_by_name", name)
            if function_row:
                rows.append(function_row)
        return rows
    if current_function_only:
        current_function = client.legacy_call("get_current_function")
        return [current_function] if current_function else []

    rows: List[Dict[str, Any]] = []
    batch_size = min(max(limit, 50), 200)
    scan_budget = max(limit * 20, 200)
    current_offset = offset
    scanned = 0
    while scanned < scan_budget:
        page = client.legacy_call("list_functions", current_offset, batch_size) or {}
        data = page.get("data", [])
        if not data:
            break
        rows.extend(data)
        next_offset = page.get("next_offset")
        scanned += len(data)
        if next_offset is None:
            break
        current_offset = next_offset
    return rows


def export_modern(
    client: McpHttpClient,
    mcp_url: str,
    limit: int,
    offset: int,
    filter_pattern: str,
    include_thunks: bool,
    auto_select_high_value: bool,
    current_function_only: bool,
    function_addresses: List[str],
    function_names: List[str],
) -> Dict[str, Any]:
    client.call_tool("server_warmup", {"wait_auto_analysis": True, "build_caches": True, "init_hexrays": True})

    metadata = client.read_resource("ida://idb/metadata") or {}
    sample_name = str(metadata.get("module") or "unknown_sample")
    sample_hash = str(metadata.get("sha256") or "unknown_hash")

    functions_data = collect_modern_function_rows(
        client, offset, limit, filter_pattern, current_function_only, function_addresses, function_names
    )

    import_rows = client.call_tool("imports_query", {"filter": "*", "offset": 0, "count": 2000})
    import_names = extract_import_names(import_rows if isinstance(import_rows, list) else [])

    exported_functions: List[Dict[str, Any]] = []
    export_errors: List[Dict[str, str]] = []
    for fn in functions_data:
        addr = str(fn.get("addr") or "")
        name = str(fn.get("name") or addr)
        if not addr:
            continue
        try:
            analysis = client.call_tool("analyze_function", {"addr": addr, "include_asm": False})
            pseudocode = clean_text(analysis.get("decompiled"))
            strings = unique_strs([str(item).strip() for item in analysis.get("strings", []) if str(item).strip()])

            callee_rows = client.call_tool("callees", {"addrs": [addr], "limit": 500})
            callee_items = callee_rows[0].get("callees", []) if callee_rows else []
            callees = unique_strs([str(item.get("name") or item.get("addr") or "").strip() for item in callee_items])
            api_calls = unique_strs(
                [
                    str(item.get("name") or "").strip()
                    for item in callee_items
                    if str(item.get("type") or "").lower() == "external"
                    or str(item.get("name") or "").strip() in import_names
                ]
            )

            xref_rows = client.call_tool("xrefs_to", {"addrs": [addr], "limit": 200})
            xref_items = xref_rows[0].get("xrefs", []) if xref_rows else []
            callers = unique_strs(
                [
                    str((item.get("fn") or {}).get("name") or item.get("addr") or "").strip()
                    for item in xref_items
                    if item.get("type") == "code"
                ]
            )

            behavior_tags = infer_behavior_tags(api_calls, strings, pseudocode)
            summary = build_summary(name, api_calls, strings, pseudocode)
            selection_score, selection_reasons = score_function_value(
                name, pseudocode, api_calls, strings, callers, callees, behavior_tags
            )
            if not include_thunks and is_trivial_wrapper(name, pseudocode, api_calls, callees):
                continue

            exported_functions.append(
                {
                    "function_name": name,
                    "function_addr": normalize_addr(addr),
                    "pseudo_code": pseudocode,
                    "api_calls": api_calls,
                    "strings": strings,
                    "imports": [api for api in api_calls if api in import_names],
                    "callers": callers,
                    "callees": callees,
                    "behavior_tags": behavior_tags,
                    "mapped_attack_ids": [],
                    "summary": summary,
                    "selection_score": selection_score,
                    "selection_reasons": selection_reasons,
                }
            )
        except Exception as exc:
            export_errors.append({"function_addr": normalize_addr(addr), "function_name": name, "error": str(exc)})
            continue

    exported_functions = dedupe_exported_functions(exported_functions)
    if not (function_addresses or function_names or current_function_only):
        if auto_select_high_value:
            exported_functions = rank_high_value_functions(exported_functions)[:limit]
        else:
            exported_functions = exported_functions[:limit]
        export_errors = export_errors[: max(limit * 5, 100)]
    return {
        "sample_name": sample_name,
        "sample_hash": sample_hash,
        "platform": "Windows",
        "source": "IDA-MCP",
        "protocol_mode": "modern",
        "mcp_url": mcp_url,
        "selection_mode": "high_value" if auto_select_high_value else "sequential",
        "functions": exported_functions,
        "export_errors": export_errors,
    }


def export_legacy(
    client: McpHttpClient,
    mcp_url: str,
    limit: int,
    offset: int,
    include_thunks: bool,
    auto_select_high_value: bool,
    current_function_only: bool,
    function_addresses: List[str],
    function_names: List[str],
) -> Dict[str, Any]:
    metadata = client.legacy_call("get_metadata") or {}
    sample_name = str(metadata.get("module") or "unknown_sample")
    sample_hash = str(metadata.get("sha256") or "unknown_hash")
    functions_data = collect_legacy_function_rows(
        client, offset, limit, current_function_only, function_addresses, function_names
    )
    imports_page = client.legacy_call("list_imports", 0, 2000) or {}
    import_names = extract_import_names([imports_page])

    exported_functions: List[Dict[str, Any]] = []
    export_errors: List[Dict[str, str]] = []
    for fn in functions_data:
        addr = str(fn.get("address") or "")
        name = str(fn.get("name") or addr)
        if not addr:
            continue
        try:
            pseudocode = clean_text(client.legacy_call("decompile_function", addr))
            xrefs = client.legacy_call("get_xrefs_to", addr) or []

            callers = unique_strs(
                [str((item.get("function") or {}).get("name") or item.get("address") or "").strip() for item in xrefs]
            )
            call_candidates = extract_calls_from_pseudocode(pseudocode)
            api_calls = unique_strs([name for name in call_candidates if name in import_names])
            callees = unique_strs(call_candidates)
            strings = extract_strings_from_pseudocode(pseudocode)
            behavior_tags = infer_behavior_tags(api_calls, strings, pseudocode)
            summary = build_summary(name, api_calls, strings, pseudocode)
            selection_score, selection_reasons = score_function_value(
                name, pseudocode, api_calls, strings, callers, callees, behavior_tags
            )
            if not include_thunks and is_trivial_wrapper(name, pseudocode, api_calls, callees):
                continue

            exported_functions.append(
                {
                    "function_name": name,
                    "function_addr": normalize_addr(addr),
                    "pseudo_code": pseudocode,
                    "api_calls": api_calls,
                    "strings": strings,
                    "imports": [api for api in api_calls if api in import_names],
                    "callers": callers,
                    "callees": callees,
                    "behavior_tags": behavior_tags,
                    "mapped_attack_ids": [],
                    "summary": summary,
                    "selection_score": selection_score,
                    "selection_reasons": selection_reasons,
                }
            )
        except Exception as exc:
            export_errors.append({"function_addr": normalize_addr(addr), "function_name": name, "error": str(exc)})
            continue

    deduped = dedupe_exported_functions(exported_functions)
    if not (function_addresses or function_names or current_function_only):
        if auto_select_high_value:
            deduped = rank_high_value_functions(deduped)[:limit]
        else:
            deduped = deduped[:limit]
        export_errors = export_errors[: max(limit * 5, 100)]

    return {
        "sample_name": sample_name,
        "sample_hash": sample_hash,
        "platform": "Windows",
        "source": "IDA-MCP",
        "protocol_mode": "legacy",
        "mcp_url": mcp_url,
        "selection_mode": "high_value" if auto_select_high_value else "sequential",
        "functions": deduped,
        "export_errors": export_errors,
    }


def export_from_mcp(
    mcp_url: str,
    limit: int,
    offset: int,
    filter_pattern: str,
    include_thunks: bool,
    auto_select_high_value: bool,
    current_function_only: bool,
    function_addresses: List[str],
    function_names: List[str],
    timeout: int = 60,
) -> Dict[str, Any]:
    client = McpHttpClient(mcp_url, timeout=timeout)
    client.initialize()
    if client.protocol_mode == "legacy":
        return export_legacy(
            client,
            mcp_url,
            limit,
            offset,
            include_thunks,
            auto_select_high_value,
            current_function_only,
            function_addresses,
            function_names,
        )
    return export_modern(
        client,
        mcp_url,
        limit,
        offset,
        filter_pattern,
        include_thunks,
        auto_select_high_value,
        current_function_only,
        function_addresses,
        function_names,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export function semantic data from a running IDA-MCP server.")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help=f"MCP endpoint URL (default: {DEFAULT_MCP_URL})")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_FILE), help="Output JSON file path")
    parser.add_argument("--limit", type=int, default=200, help="Maximum number of functions to export")
    parser.add_argument("--offset", type=int, default=0, help="Start offset when enumerating functions")
    parser.add_argument("--filter", default="*", help="Function filter pattern for list_funcs")
    parser.add_argument("--include-thunks", action="store_true", help="Keep trivial thunk/wrapper functions in export")
    parser.add_argument("--auto-select-high-value", action="store_true", help="Rank enumerated functions and keep the highest-value ones")
    parser.add_argument("--current-function-only", action="store_true", help="Export only the function currently selected in IDA")
    parser.add_argument("--function-address", default="", help="Export one function by address")
    parser.add_argument("--function-name", default="", help="Export one function by name")
    parser.add_argument("--function-addresses", default="", help="Comma-separated function addresses to export")
    parser.add_argument("--function-names", default="", help="Comma-separated function names to export")
    parser.add_argument("--function-addresses-file", default="", help="Text file with one function address per line")
    parser.add_argument("--function-names-file", default="", help="Text file with one function name per line")
    parser.add_argument("--timeout", type=int, default=60, help="MCP request timeout in seconds")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    function_addresses = unique_strs(
        parse_csv_items(args.function_addresses)
        + ([args.function_address] if args.function_address else [])
        + (load_items_from_file(args.function_addresses_file) if args.function_addresses_file else [])
    )
    function_names = unique_strs(
        parse_csv_items(args.function_names)
        + ([args.function_name] if args.function_name else [])
        + (load_items_from_file(args.function_names_file) if args.function_names_file else [])
    )

    payload = export_from_mcp(
        args.mcp_url,
        max(1, args.limit),
        max(0, args.offset),
        args.filter,
        args.include_thunks,
        args.auto_select_high_value,
        args.current_function_only,
        function_addresses,
        function_names,
        max(5, args.timeout),
    )
    save_json(output_path, payload)

    print("[+] IDA semantic export generated from MCP.")
    print(f"    MCP endpoint : {args.mcp_url}")
    print(f"    Sample name  : {payload['sample_name']}")
    print(f"    Function count: {len(payload['functions'])}")
    print(f"    Export errors : {len(payload.get('export_errors', []))}")
    print(f"    Output file  : {output_path}")


if __name__ == "__main__":
    main()
