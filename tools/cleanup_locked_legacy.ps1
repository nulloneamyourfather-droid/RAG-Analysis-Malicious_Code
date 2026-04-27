$ErrorActionPreference = "Continue"

$root = Split-Path -Parent $PSScriptRoot

$targets = @(
    (Join-Path $root "__pycache__"),
    (Join-Path $root "builders\__pycache__"),
    (Join-Path $root "tests\__pycache__"),
    (Join-Path (Split-Path -Parent $root) "IDA-MCP\.git"),
    (Join-Path (Split-Path -Parent $root) "IDA-MCP\.vs"),
    (Join-Path (Split-Path -Parent $root) "targets_1bin.txt"),
    (Join-Path (Split-Path -Parent $root) "fix_thesis_docx.py"),
    (Join-Path $root "ACKNOWLEDGEMENTS.md"),
    (Join-Path $root "CHAPTER6_EXPERIMENT_RESULTS_DRAFT.md"),
    (Join-Path $root "CHAPTER7_CONCLUSION_AND_FUTURE_WORK.md"),
    (Join-Path $root "DATA_REFACTOR_PLAN.md"),
    (Join-Path $root "DEFENSE_OUTLINE.md"),
    (Join-Path $root "PROJECT_STATUS_CHECKLIST.md"),
    (Join-Path $root "TECHNICAL_ROUTE_SYSTEM_DESIGN.md"),
    (Join-Path $root "THESIS_CHAPTER1_TO_5_DIRECT_REWRITE.md"),
    (Join-Path $root "THESIS_CHAPTER1_TO_5_REVISION_GUIDE.md"),
    (Join-Path $root "THESIS_FRONTMATTER_REWRITE.md"),
    (Join-Path $root "WORKSPACE_AUDIT_REPORT.md")
)

foreach ($path in $targets) {
    if (Test-Path -LiteralPath $path) {
        Write-Host "Removing $path"
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

Write-Host "Cleanup attempt finished."
