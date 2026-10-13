"""Stable, bounded JSON/Markdown reports. Never embed untrusted workflow body."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json

from .audit import Finding, SEVERITY_ORDER


def make_report(findings: list[Finding], scanned: list[dict[str, str]]) -> dict:
    ordered = sorted(findings, key=lambda f: (f.repo, -SEVERITY_ORDER[f.severity], f.path, f.job, f.rule, f.evidence))
    return {
        "schema_version": "0.1", "generated_at": datetime.now(timezone.utc).isoformat(),
        "analysis_type": "static-only", "runtime_usage_observed": False,
        "repositories": sorted(set(s["repo"] for s in scanned)),
        "scanned_files": len(scanned),
        "counts": {level: sum(f.severity == level for f in findings) for level in ("high", "medium", "low", "info")},
        "findings": [f.to_dict() for f in ordered],
    }


def markdown_report(report: dict) -> str:
    lines = ["# Least Privilege Bot — v0.1 audit", "",
             f"- Analysis: **static-only** (no runtime API usage evidence)",
             f"- Workflow files inspected: **{report['scanned_files']}**",
             f"- Findings: **{len(report['findings'])}** "
             f"(high {report['counts']['high']}, medium {report['counts']['medium']}, low {report['counts']['low']})",
             "- Permission recommendations require human review; this report does not establish minimum needed scopes.", ""]
    if not report["findings"]:
        lines += ["No rule violations detected. This does not prove that the workflow is secure.", ""]
    else:
        lines += ["| Severity | Repo | File / Job | Rule | Evidence |", "|---|---|---|---|---|"]
        for f in report["findings"]:
            clean = lambda v: str(v).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("`", "'")[:240]
            lines.append(f"| {clean(f['severity'])} | {clean(f['repo'])} | {clean(f['path'])} / {clean(f['job'])} | {clean(f['rule'])} | {clean(f['evidence'])} |")
        lines += ["", "## Suggested review actions", ""]
        for f in report["findings"]:
            lines.append(f"- **{f['id']}** ({f['rule']}): {f['recommendation']}")
        lines.append("")
    return "\n".join(lines)


def write_report(report: dict, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (directory / "report.md").write_text(markdown_report(report), encoding="utf-8")
