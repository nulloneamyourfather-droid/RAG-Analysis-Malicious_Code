try:
    from .reporting_v2 import build_markdown_report, build_paper_markdown_report
except ImportError:
    from reporting_v2 import build_markdown_report, build_paper_markdown_report

__all__ = ['build_markdown_report', 'build_paper_markdown_report']
