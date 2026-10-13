"""CLI entry point for local or GitHub remote scanning and opt-in Issue publishing."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from .audit import SEVERITY_ORDER, analyze_workflow, local_workflows
from .github import GitHubClient, GitHubError
from .report import make_report, markdown_report, write_report

ISSUE_TITLE = "[least-privilege-bot] GitHub Actions permissions audit"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lpbot", description="Audit declared GitHub Actions token permissions")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Audit GitHub Actions YAML files without executing them")
    target = scan.add_mutually_exclusive_group()
    target.add_argument("--repo", action="append", help="owner/name; can be repeated (default: local --path .)")
    target.add_argument("--path", type=Path, default=Path("."), help="local repository root")
    scan.add_argument("--output-dir", type=Path, default=Path("reports"))
    scan.add_argument("--fail-on", choices=["none", "high", "medium", "low"], default="none")
    publish = sub.add_parser("publish-issue", help="Publish high-severity audit results to the SAME repository")
    publish.add_argument("--repo", required=True, help="owner/name that was audited")
    publish.add_argument("--report", type=Path, default=Path("reports/report.json"))
    publish.add_argument("--min-severity", choices=["high", "medium", "low"], default="high")
    return parser


def _scan(args: argparse.Namespace) -> int:
    findings, scanned = [], []
    if args.repo:
        client = GitHubClient()
        sources = [(repo, client.workflows(repo)) for repo in sorted(set(args.repo))]
    else:
        repo = os.getenv("GITHUB_REPOSITORY", "local")
        sources = [(repo, local_workflows(args.path.resolve()))]
    for repo, workflow_files in sources:
        for path, content in workflow_files:
            scanned.append({"repo": repo, "path": path})
            findings.extend(analyze_workflow(repo, path, content))
    report = make_report(findings, scanned)
    write_report(report, args.output_dir)
    print(f"Audited {report['scanned_files']} workflow(s); findings: "
          f"high={report['counts']['high']}, medium={report['counts']['medium']}, low={report['counts']['low']}")
    print(f"Reports: {args.output_dir / 'report.md'} and {args.output_dir / 'report.json'}")
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 2
    return 0


def _publish(args: argparse.Namespace) -> int:
    if not (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")):
        raise ValueError("An explicit GitHub token is required to publish an issue")
    data = json.loads(args.report.read_text(encoding="utf-8"))
    if (data.get("schema_version") != "0.1" or data.get("analysis_type") != "static-only"
            or data.get("repositories") != [args.repo] or not isinstance(data.get("findings"), list)):
        raise ValueError("Report is invalid or targets a different repository; refusing cross-repo disclosure")
    relevant = [f for f in data["findings"] if isinstance(f, dict)
                and f.get("repo") == args.repo and f.get("severity") in SEVERITY_ORDER
                and SEVERITY_ORDER[f["severity"]] >= SEVERITY_ORDER[args.min_severity]]
    if not relevant:
        print("No matching findings; no issue created or updated")
        return 0
    body = markdown_report({**data, "findings": relevant})
    if len(body) > 60000:
        raise ValueError("Issue body too long; publish refused")
    url = GitHubClient().sync_issue(args.repo, ISSUE_TITLE, body)
    print("Synced audit issue: " + url)
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return _scan(args) if args.command == "scan" else _publish(args)
    except (ValueError, OSError, GitHubError, json.JSONDecodeError) as exc:
        print(f"lpbot error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
