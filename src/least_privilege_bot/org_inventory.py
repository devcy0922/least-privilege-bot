"""Organization-level approved fine-grained PAT metadata collector.

Requires a GitHub App installation/user token with Personal access tokens: read.
Not an inventory of Classic PATs or all credentials used by an organization.
"""
from __future__ import annotations

import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen

from .enterprise import ExportError


class OrganizationInventory:
    def __init__(self, token: str, requester=None):
        if not token:
            raise ValueError("LPBOT_ORG_APP_TOKEN is required (GitHub App, org Personal access tokens: read)")
        self.token = token
        self.requester = requester or urlopen

    def fetch(self, org: str) -> list[dict[str, str]]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", org):
            raise ValueError("Invalid organization slug")
        rows = []
        for page in range(1, 101):
            path = f"/orgs/{quote(org)}/personal-access-tokens?{urlencode({'per_page': 100, 'page': page})}"
            req = Request("https://api.github.com" + path, headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
                "User-Agent": "least-privilege-bot/0.1.1"})
            try:
                with self.requester(req, timeout=25) as r:
                    blob = r.read(1024 * 1024 + 1)
            except HTTPError as exc:
                raise ExportError(f"Organization PAT API returned HTTP {exc.code}") from None
            except (URLError, TimeoutError):
                raise ExportError("Organization PAT API connection failed") from None
            if len(blob) > 1024 * 1024:
                raise ExportError("Organization PAT list page too large")
            try:
                data = json.loads(blob)
            except (ValueError, UnicodeDecodeError):
                raise ExportError("Invalid organization PAT response") from None
            if not isinstance(data, list):
                raise ExportError("Organization PAT response was not a list")
            for item in data:
                if not isinstance(item, dict):
                    raise ExportError("Malformed organization PAT entry")
                perms = item.get("permissions") or {}
                pairs = []
                for section, entries in perms.items():
                    if isinstance(entries, dict):
                        pairs.extend(f"{section}.{key}:{value}" for key, value in entries.items())
                owner = item.get("owner") or {}
                rows.append({
                    "credential_type": "fine_grained_pat", "credential_id": str(item.get("token_id") or item.get("id") or ""),
                    "display_name": str(item.get("token_name") or "(unnamed)"),
                    "owner": str(owner.get("login", "unknown")) if isinstance(owner, dict) else "unknown",
                    "owner_id": str(owner.get("id", "")) if isinstance(owner, dict) else "",
                    "credential_state": "expired" if item.get("token_expired") is True else "active",
                    "last_used_at": str(item.get("token_last_used_at") or ""),
                    "created_at": str(item.get("access_granted_at") or ""),
                    "expires_at": str(item.get("token_expires_at") or ""),
                    "expiry_status": "unknown",  # No explicit 'never' semantics in this API.
                    "repository_selection": str(item.get("repository_selection") or "unknown"),
                    "scopes": "", "permissions": "; ".join(pairs), "organization": org})
                if len(rows) > 10_000:
                    raise ExportError("Organization PAT inventory exceeded limit; partial audit refused")
            if len(data) < 100:
                return rows
        raise ExportError("Organization PAT inventory pagination limit; partial audit refused")
