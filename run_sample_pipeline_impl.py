import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

try:
    from .aggregate_sample_analysis import run_sample_aggregation
    from .builders.build_ida_semantic_kb import main as build_ida_semantic_main
    from .builders.export_ida_semantic_from_mcp import McpHttpClient
    from .builders.export_ida_semantic_from_mcp import export_from_mcp, save_json as save_export_json
    from .rag_index import DEFAULT_SEMANTIC_MODEL, build_and_save_index
    from .reporting_v2 import build_markdown_report as render_markdown_report
    from .reporting_v2 import build_paper_markdown_report as render_paper_markdown_report
except ImportError:
    from aggregate_sample_analysis import run_sample_aggregation
    from builders.build_ida_semantic_kb import main as build_ida_semantic_main
    from builders.export_ida_semantic_from_mcp import McpHttpClient
    from builders.export_ida_semantic_from_mcp import export_from_mcp, save_json as save_export_json
    from rag_index import DEFAULT_SEMANTIC_MODEL, build_and_save_index
    from reporting_v2 import build_markdown_report as render_markdown_report
    from reporting_v2 import build_paper_markdown_report as render_paper_markdown_report


PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
DEFAULT_MCP_URL = "http://127.0.0.1:13337/mcp"
DEFAULT_SAMPLE_JSON = WORKSPACE_ROOT / "samples" / "ida_exports" / "sample_ida_semantic.json"
DEFAULT_SAMPLE_ANALYSIS_JSON = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_sample_analysis.json"
DEFAULT_CAPABILITY_CHAINS_JSON = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_capability_chains.json"
DEFAULT_REPORT_MD = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_sample_report.md"
DEFAULT_REPORT_PAPER_MD = PROJECT_ROOT / "data" / "index" / "metadata" / "latest_sample_report_paper.md"


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


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def load_existing_sample_name(sample_json_path: Path) -> str:
    if not sample_json_path.exists():
        return ""
    try:
        payload = json.loads(sample_json_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    return str(payload.get("sample_name", "")).strip()


def peek_current_mcp_sample_name(mcp_url: str, timeout: int) -> str:
    try:
        client = McpHttpClient(mcp_url, timeout=max(5, timeout))
        client.initialize()
        if client.protocol_mode == "legacy":
            metadata = client.legacy_call("get_metadata") or {}
            return str(metadata.get("module") or "").strip()
        metadata = client.call_tool("get_metadata", {}) or {}
        if isinstance(metadata, dict):
            return str(metadata.get("module") or metadata.get("filename") or metadata.get("sample_name") or "").strip()
    except Exception:
        return ""
    return ""


def ensure_mcp_sample_consistency(
    sample_json_path: Path,
    export_payload: Dict[str, Any],
    skip_export: bool,
    force_overwrite: bool,
    existing_sample_name: str,
) -> None:
    current_mcp_sample = str(export_payload.get("sample_name", "")).strip()
    existing_sample = str(existing_sample_name or "").strip()
    if not current_mcp_sample or not existing_sample or current_mcp_sample == existing_sample:
        return
    if force_overwrite:
        return
    if skip_export:
        raise RuntimeError(
            f"--skip-export is reusing sample JSON for '{existing_sample}', but current MCP sample is '{current_mcp_sample}'. "
            f"Remove --skip-export or pass --force-overwrite-sample-json."
        )
    raise RuntimeError(
        f"Existing sample JSON belongs to '{existing_sample}', but current MCP export belongs to '{current_mcp_sample}'. "
        f"Pass --force-overwrite-sample-json to replace the old export."
    )


def should_use_current_sample_default(
    skip_export: bool,
    current_function_only: bool,
    analyze_current_sample: bool,
    function_addresses: List[str],
    function_names: List[str],
    function_addresses_file: str,
    function_names_file: str,
) -> bool:
    if skip_export or current_function_only or analyze_current_sample:
        return False
    if function_addresses or function_names:
        return False
    if function_addresses_file or function_names_file:
        return False
    return True


def resolve_target_mode(
    args: argparse.Namespace,
    function_addresses: List[str],
    function_names: List[str],
) -> tuple[bool, bool]:
    current_function_only = args.current_function_only or args.analyze_current_function
    analyze_current_sample = bool(args.analyze_current_sample)
    if should_use_current_sample_default(
        args.skip_export,
        current_function_only,
        analyze_current_sample,
        function_addresses,
        function_names,
        args.function_addresses_file,
        args.function_names_file,
    ):
        analyze_current_sample = True
    if analyze_current_sample and not current_function_only:
        args.auto_select_high_value = True
    return current_function_only, analyze_current_sample


def target_mode_label(
    current_function_only: bool,
    analyze_current_sample: bool,
    function_addresses: List[str],
    function_names: List[str],
    args: argparse.Namespace,
) -> str:
    if current_function_only:
        return "current-function"
    if analyze_current_sample:
        return "current-sample"
    if function_addresses or function_names or args.function_addresses_file or args.function_names_file:
        return "explicit-targets"
    return "enumeration"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="One-command pipeline for export, build, retrieval, and sample-level aggregation.")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help=f"MCP endpoint URL (default: {DEFAULT_MCP_URL})")
    parser.add_argument("--sample-json", default=str(DEFAULT_SAMPLE_JSON), help="Output path for sample_ida_semantic.json")
    parser.add_argument("--top-k", type=int, default=3, help="Top K docs per knowledge source during aggregation")
    parser.add_argument("--capability-chains-json", default=str(DEFAULT_CAPABILITY_CHAINS_JSON), help="Output capability chain JSON path")
    parser.add_argument("--report-md", default=str(DEFAULT_REPORT_MD), help="Output markdown report path")
    parser.add_argument("--report-paper-md", default=str(DEFAULT_REPORT_PAPER_MD), help="Output paper-style markdown report path")
    parser.add_argument("--timeout", type=int, default=60, help="MCP request timeout in seconds")
    parser.add_argument("--skip-export", action="store_true", help="Skip MCP export and reuse existing sample JSON")
    parser.add_argument("--force-overwrite-sample-json", action="store_true", help="Overwrite an existing sample JSON even if it belongs to a different MCP sample")
    parser.add_argument("--backend", choices=["auto", "tfidf", "semantic"], default="auto", help="RAG backend")
    parser.add_argument("--semantic-model", default=DEFAULT_SEMANTIC_MODEL, help="SentenceTransformer model name")
    parser.add_argument("--allow-model-download", action="store_true", help="Allow downloading semantic model files")
    parser.add_argument("--limit", type=int, default=200, help="Maximum number of functions to export when enumerating")
    parser.add_argument("--offset", type=int, default=0, help="Start offset when enumerating functions")
    parser.add_argument("--filter", default="*", help="Function filter pattern for enumeration")
    parser.add_argument("--include-thunks", action="store_true", help="Keep trivial thunk/wrapper functions in export")
    parser.add_argument("--auto-select-high-value", action="store_true", help="Rank enumerated functions and export the highest-value ones")
    parser.add_argument("--current-function-only", action="store_true", help="Export only the current function in IDA")
    parser.add_argument("--analyze-current-function", action="store_true", help="Alias of --current-function-only, intended for one-click analysis of the function currently selected in IDA")
    parser.add_argument("--analyze-current-sample", action="store_true", help="Analyze the sample currently opened in IDA by exporting a high-value function subset")
    parser.add_argument("--function-address", default="", help="Single function address")
    parser.add_argument("--function-name", default="", help="Single function name")
    parser.add_argument("--function-addresses", default="", help="Comma-separated function addresses")
    parser.add_argument("--function-names", default="", help="Comma-separated function names")
    parser.add_argument("--function-addresses-file", default="", help="Text file with one function address per line")
    parser.add_argument("--function-names-file", default="", help="Text file with one function name per line")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sample_json_path = Path(args.sample_json)
    existing_sample_name = load_existing_sample_name(sample_json_path)

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
    current_function_only, analyze_current_sample = resolve_target_mode(args, function_addresses, function_names)

    if args.skip_export:
        if not sample_json_path.exists():
            raise FileNotFoundError(f"--skip-export was set but sample JSON does not exist: {sample_json_path}")
        current_mcp_sample_name = peek_current_mcp_sample_name(args.mcp_url, args.timeout)
        if current_mcp_sample_name and existing_sample_name and current_mcp_sample_name != existing_sample_name:
            if not args.force_overwrite_sample_json:
                raise RuntimeError(
                    f"--skip-export is reusing sample JSON for '{existing_sample_name}', but current MCP sample is '{current_mcp_sample_name}'. "
                    f"Remove --skip-export or pass --force-overwrite-sample-json."
                )
        export_payload = json.loads(sample_json_path.read_text(encoding="utf-8"))
    else:
        export_payload = export_from_mcp(
            args.mcp_url,
            max(1, args.limit),
            max(0, args.offset),
            args.filter,
            args.include_thunks,
            args.auto_select_high_value,
            current_function_only,
            function_addresses,
            function_names,
            max(5, args.timeout),
        )
        ensure_mcp_sample_consistency(
            sample_json_path,
            export_payload,
            skip_export=False,
            force_overwrite=args.force_overwrite_sample_json,
            existing_sample_name=existing_sample_name,
        )
        sample_json_path.parent.mkdir(parents=True, exist_ok=True)
        save_export_json(sample_json_path, export_payload)

    build_ida_semantic_main()
    rag_index_metadata = build_and_save_index(
        backend=args.backend,
        semantic_model=args.semantic_model,
        allow_model_download=args.allow_model_download,
    )

    raw_ida_path = PROJECT_ROOT / "data" / "raw" / "ida_semantic" / "ida_semantic_knowledge_raw.json"
    sample_analysis = run_sample_aggregation(sample_json_path, raw_ida_path, max(1, args.top_k))
    save_json(DEFAULT_SAMPLE_ANALYSIS_JSON, sample_analysis)
    save_json(Path(args.capability_chains_json), sample_analysis.get("capability_chains", []))

    save_text(Path(args.report_md), render_markdown_report(sample_analysis))
    save_text(Path(args.report_paper_md), render_paper_markdown_report(sample_analysis))

    print("[+] Sample pipeline completed.")
    print(f"    Sample JSON   : {sample_json_path}")
    print(f"    Existing JSON : {existing_sample_name or 'none'}")
    print(f"    Sample name   : {export_payload.get('sample_name', 'unknown_sample')}")
    print(f"    Export mode   : {'reuse-existing' if args.skip_export else 'mcp-export'}")
    print(f"    Target mode   : {target_mode_label(current_function_only, analyze_current_sample, function_addresses, function_names, args)}")
    print(f"    Function count: {len(export_payload.get('functions', []))}")
    print(f"    Export errors : {len(export_payload.get('export_errors', []))}")
    print(f"    RAG backend   : {rag_index_metadata.get('backend', 'unknown')}")
    print(f"    RAG docs      : {rag_index_metadata.get('doc_count', 0)}")
    print(f"    RAG features  : {rag_index_metadata.get('feature_count', 0)}")
    print(f"    Capability    : {args.capability_chains_json}")
    print(f"    Sample report : {args.report_md}")
    print(f"    Paper report  : {args.report_paper_md}")
    print(f"    Summary       : {sample_analysis.get('summary', '')}")
