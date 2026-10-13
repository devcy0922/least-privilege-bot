"""Conservative static auditing of GitHub Actions GITHUB_TOKEN permissions.

Does not execute steps, interpolate expressions or infer necessary runtime scopes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
import re
from typing import Any

import yaml

MAX_WORKFLOW_BYTES = 512 * 1024


class WorkflowLoader(yaml.SafeLoader):
    """Read GitHub's YAML 'on' key correctly; PyYAML defaults to YAML 1.1 booleans."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [item for item in resolvers if item[0] != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class Finding:
    repo: str
    path: str
    job: str
    rule: str
    severity: str
    evidence: str
    recommendation: str
    confidence: str = "static"

    def to_dict(self) -> dict[str, str]:
        result = asdict(self)
        stable = "\0".join((self.repo, self.path, self.job, self.rule, self.evidence))
        result["id"] = sha256(stable.encode()).hexdigest()[:16]
        return result


def _finding(repo: str, path: str, job: str, rule: str, severity: str,
             evidence: str, recommendation: str) -> Finding:
    return Finding(repo, path, job, rule, severity, evidence, recommendation)


def _parse_permissions(value: Any) -> tuple[str, list[tuple[str, str]]]:
    """Return (kind, granted scopes). No explicit declaration is represented separately."""
    if value is None:
        return "invalid", []
    if isinstance(value, str):
        if value in ("write-all", "read-all"):
            return value, []
        return "invalid", []
    if isinstance(value, dict):
        result = []
        for scope, grant in value.items():
            if not isinstance(scope, str) or grant not in ("none", "read", "write"):
                return "invalid", []
            result.append((scope, str(grant)))
        return "scoped", sorted(result)
    return "invalid", []


def analyze_workflow(repo: str, path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    if len(content.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        return [_finding(repo, path, "-", "FILE_TOO_LARGE", "high",
                         f"YAML file exceeds {MAX_WORKFLOW_BYTES} bytes",
                         "Review this file manually; audit was not performed.")]
    try:
        workflow = yaml.load(content, Loader=WorkflowLoader)
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or "invalid YAML"
        return [_finding(repo, path, "-", "PARSE_ERROR", "high", str(problem)[:160],
                         "Repair YAML; the auditor cannot assess this workflow.")]
    if not isinstance(workflow, dict):
        return [_finding(repo, path, "-", "INVALID_WORKFLOW", "high",
                         "Workflow root is not a YAML mapping",
                         "Correct the workflow structure.")]
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        return [_finding(repo, path, "-", "INVALID_WORKFLOW", "high",
                         "Workflow has no valid jobs mapping",
                         "Correct the workflow structure.")]
    event_spec = workflow.get("on", {})
    if isinstance(event_spec, str):
        triggers = {event_spec}
    elif isinstance(event_spec, list):
        triggers = {item for item in event_spec if isinstance(item, str)}
    elif isinstance(event_spec, dict):
        triggers = {name for name in event_spec if isinstance(name, str)}
    else:
        triggers = set()

    for job_id, job in sorted(jobs.items(), key=lambda item: str(item[0])):
        job_name = str(job_id)
        if not isinstance(job, dict):
            findings.append(_finding(repo, path, job_name, "INVALID_JOB", "high",
                                     "Job definition is not a mapping",
                                     "Correct the job structure."))
            continue
        if "permissions" in job:
            value = job["permissions"]
            source = "job"
        elif "permissions" in workflow:
            value = workflow["permissions"]
            source = "workflow (inherited)"
        else:
            findings.append(_finding(repo, path, job_name, "IMPLICIT_DEFAULT", "medium",
                                     "No explicit job or workflow permissions declaration",
                                     "Declare job-level permissions after reviewing every step's API needs; actual default depends on repository/org settings."))
            continue
        kind, grants = _parse_permissions(value)
        if kind == "invalid":
            findings.append(_finding(repo, path, job_name, "INVALID_PERMISSIONS", "high",
                                     f"Unrecognized permissions declaration at {source}",
                                     "Fix permissions syntax; no effective scope inference is possible."))
        elif kind == "write-all":
            findings.append(_finding(repo, path, job_name, "WRITE_ALL", "high",
                                     f"{source}: write-all",
                                     "Review all steps and replace write-all with required explicit scopes; never shrink without verification."))
        elif kind == "read-all":
            findings.append(_finding(repo, path, job_name, "READ_ALL", "low",
                                     f"{source}: read-all",
                                     "Consider declaring only the scopes actually required by this job."))
        else:
            for scope, grant in grants:
                if grant == "write":
                    findings.append(_finding(repo, path, job_name, "WRITE_SCOPE", "medium",
                                             f"{source}: {scope}: write",
                                             "Check whether this scope needs write access; its necessity cannot be determined statically."))
        if "pull_request_target" in triggers and (kind == "write-all" or any(grant == "write" for _, grant in grants)):
            findings.append(_finding(repo, path, job_name, "PR_TARGET_WRITE", "high",
                                     f"pull_request_target with {source} write permissions",
                                     "Review checkout of untrusted PR code, secrets exposure, and event-specific privileges."))
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.job, f.rule, f.evidence))


def local_workflows(root: Path) -> list[tuple[str, str]]:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        raise ValueError(f"No .github/workflows directory in {root}")
    paths = sorted(p for p in workflows.iterdir() if p.is_file() and p.suffix.lower() in (".yml", ".yaml"))
    if not paths:
        raise ValueError(f"No YAML workflows found in {workflows}")
    results = []
    for path in paths:
        if path.stat().st_size > MAX_WORKFLOW_BYTES:
            results.append((path.relative_to(root).as_posix(), " " * (MAX_WORKFLOW_BYTES + 1)))
        else:
            results.append((path.relative_to(root).as_posix(), path.read_text(encoding="utf-8")))
    return results
