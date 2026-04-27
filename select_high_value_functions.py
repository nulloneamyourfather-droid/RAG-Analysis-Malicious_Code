import argparse
from pathlib import Path
from typing import List

try:
    from .builders.export_ida_semantic_from_mcp import export_from_mcp
except ImportError:
    from builders.export_ida_semantic_from_mcp import export_from_mcp


PROJECT_ROOT = Path(__file__).resolve().parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
DEFAULT_MCP_URL = "http://127.0.0.1:13337/mcp"
DEFAULT_OUTPUT = WORKSPACE_ROOT / "targets.txt"


def save_targets(path: Path, functions: List[dict]) -> None:
    lines = [str(item.get("function_addr", "")).strip() for item in functions if str(item.get("function_addr", "")).strip()]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Select higher-value IDA functions and write addresses to targets.txt.")
    parser.add_argument("--mcp-url", default=DEFAULT_MCP_URL, help=f"MCP endpoint URL (default: {DEFAULT_MCP_URL})")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output targets file path")
    parser.add_argument("--limit", type=int, default=20, help="How many target addresses to keep")
    parser.add_argument("--offset", type=int, default=0, help="Start offset when enumerating functions")
    parser.add_argument("--filter", default="*", help="Function filter pattern")
    parser.add_argument("--include-thunks", action="store_true", help="Keep trivial thunk/wrapper functions in candidate pool")
    parser.add_argument("--timeout", type=int, default=60, help="MCP request timeout in seconds")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = export_from_mcp(
        args.mcp_url,
        max(1, args.limit),
        max(0, args.offset),
        args.filter,
        args.include_thunks,
        True,
        False,
        [],
        [],
        max(5, args.timeout),
    )
    functions = payload.get("functions", [])
    output_path = Path(args.output)
    save_targets(output_path, functions)

    print("[+] High-value function targets prepared.")
    print(f"    Sample name   : {payload.get('sample_name', '')}")
    print(f"    Selection mode: {payload.get('selection_mode', 'unknown')}")
    print(f"    Target count  : {len(functions)}")
    print(f"    Targets file  : {output_path}")
    if functions:
        top = functions[0]
        print(f"    Top target    : {top.get('function_name', '')} @ {top.get('function_addr', '')}")
        print(f"    Top score     : {top.get('selection_score', 0)}")


if __name__ == "__main__":
    main()
