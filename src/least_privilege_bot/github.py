"""Read-only GitHub workflow collector plus opt-in same-repository Issue publishing."""
from __future__ import annotations

import base64
import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from .audit import MAX_WORKFLOW_BYTES


class GitHubError(RuntimeError):
    pass


class GitHubClient:
    def __init__(self, token: str | None = None):
        self.token = token if token is not None else (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"))

    def request(self, method: str, path: str, data: dict | None = None) -> Any:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("GitHub API path must begin with exactly one /")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "least-privilege-bot/0.1",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = None if data is None else json.dumps(data).encode("utf-8")
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = Request("https://api.github.com" + path, data=body, headers=headers, method=method)
        try:
            with urlopen(req, timeout=20) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise GitHubError("GitHub API response exceeds safety limit")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            # Never include response body: it might contain sensitive information.
            raise GitHubError(f"GitHub API {method} returned HTTP {exc.code}") from None
        except (URLError, TimeoutError) as exc:
            raise GitHubError(f"GitHub API {method} connection failed: {type(exc).__name__}") from None

    @staticmethod
    def _repo_path(repo: str) -> str:
        pieces = repo.split("/")
        if len(pieces) != 2 or not all(pieces) or any(not part.replace("-", "").replace("_", "").replace(".", "").isalnum() for part in pieces):
            raise ValueError("Repository must be in owner/name form")
        return f"/repos/{quote(pieces[0], safe='')}/{quote(pieces[1], safe='')}"

    def workflows(self, repo: str) -> list[tuple[str, str]]:
        base = self._repo_path(repo)
        metadata = self.request("GET", base)
        branch = metadata.get("default_branch")
        if not isinstance(branch, str) or not branch:
            raise GitHubError("Repository has no default branch")
        tree = self.request("GET", base + "/git/trees/" + quote(branch, safe="") + "?recursive=1")
        if tree.get("truncated"):
            raise GitHubError("Git tree was truncated; cannot perform a complete audit")
        entries = tree.get("tree")
        if not isinstance(entries, list):
            raise GitHubError("Git tree response is missing its entries")
        paths = sorted(entry["path"] for entry in entries
                       if isinstance(entry, dict) and entry.get("type") == "blob"
                       and isinstance(entry.get("path"), str)
                       and entry["path"].startswith(".github/workflows/")
                       and entry["path"].count("/") == 2
                       and entry["path"].lower().endswith((".yml", ".yaml")))
        if not paths:
            raise GitHubError(f"No workflow files in {repo}")
        if len(paths) > 250:
            raise GitHubError("Too many workflows (>250); audit aborted")
        results = []
        for path in paths:
            data = self.request("GET", base + "/contents/" + quote(path, safe="/") + "?" + urlencode({"ref": branch}))
            size = data.get("size", 0)
            if not isinstance(size, int) or size > MAX_WORKFLOW_BYTES:
                raise GitHubError(f"Workflow exceeds size limit: {path}")
            if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
                raise GitHubError(f"Cannot decode workflow: {path}")
            try:
                decoded = base64.b64decode(data["content"], validate=False)
                if len(decoded) > MAX_WORKFLOW_BYTES:
                    raise GitHubError(f"Workflow exceeds size limit: {path}")
                results.append((path, decoded.decode("utf-8")))
            except (ValueError, UnicodeError) as exc:
                raise GitHubError(f"Cannot decode workflow: {path}: {type(exc).__name__}") from None
        return results

    def sync_issue(self, repo: str, title: str, body: str) -> str:
        base = self._repo_path(repo)
        for page in range(1, 11):
            issues = self.request("GET", base + f"/issues?state=open&per_page=100&page={page}")
            if not isinstance(issues, list):
                raise GitHubError("Issue list has unexpected format")
            for issue in issues:
                if "pull_request" not in issue and issue.get("title") == title:
                    if issue.get("body", "") != body:
                        updated = self.request("PATCH", base + "/issues/" + str(issue["number"]), {"body": body})
                        return str(updated.get("html_url", ""))
                    return str(issue.get("html_url", ""))
            if len(issues) < 100:
                break
        else:
            raise GitHubError("More than 1000 open issues: refusing duplicate-prone publish")
        created = self.request("POST", base + "/issues", {"title": title, "body": body})
        return str(created.get("html_url", ""))
