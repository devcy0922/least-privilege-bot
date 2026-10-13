"""GitHub Enterprise Cloud async credential inventory export client.

Authorization is only ever sent to api.github.com. Signed CSV redirect requests
omit authorization, use HTTPS, and are size limited.
"""
from __future__ import annotations

import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .inventory import MAX_CSV_BYTES


class ExportError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class EnterpriseExport:
    def __init__(self, token: str, *, opener=None, sleeper=time.sleep):
        if not token:
            raise ValueError("An enterprise-authorized token is required")
        self.token = token
        self.opener = opener or build_opener(NoRedirect)
        self.sleeper = sleeper

    @staticmethod
    def _validate_slug(slug: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", slug):
            raise ValueError("Invalid enterprise or organization slug")
        return slug

    def _api(self, method: str, endpoint: str, payload: dict | None = None):
        url = "https://api.github.com" + endpoint
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                   "User-Agent": "least-privilege-bot/0.1.1", "X-GitHub-Api-Version": "2026-03-10"}
        data = json.dumps(payload).encode() if payload is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=25) as r:
                raw = r.read(64 * 1024 + 1)
                if len(raw) > 64 * 1024:
                    raise ExportError("Export status response exceeds limit")
                return r.status, json.loads(raw) if raw else {}, None
        except HTTPError as e:
            if e.code == 302:
                return 302, {}, e.headers.get("Location")
            raise ExportError(f"Enterprise export API returned HTTP {e.code}") from None
        except (URLError, TimeoutError):
            raise ExportError("Enterprise export API connection failed") from None

    def _download(self, location: str) -> bytes:
        parsed = urlsplit(location or "")
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or
                parsed.port not in (None, 443) or parsed.fragment):
            raise ExportError("Unsafe CSV download redirect")
        # Never forward an enterprise token to the short-lived download URL.
        req = Request(location, headers={"User-Agent": "least-privilege-bot/0.1.1"})
        try:
            with self.opener.open(req, timeout=45) as r:
                blob = r.read(MAX_CSV_BYTES + 1)
                if len(blob) > MAX_CSV_BYTES:
                    raise ExportError("Exported CSV exceeds safety limit")
                return blob
        except HTTPError as e:
            raise ExportError(f"CSV download HTTP {e.code}") from None
        except (URLError, TimeoutError):
            raise ExportError("CSV download connection failed") from None

    def export(self, enterprise: str, *, organization: str | None = None,
               polls: int = 12, interval: int = 5) -> bytes:
        self._validate_slug(enterprise)
        if organization:
            self._validate_slug(organization)
        if polls < 1 or interval < 0:
            raise ValueError("Invalid poll parameters")
        endpoint = f"/enterprises/{quote(enterprise)}/credentials/exports"
        payload = {"organization": organization} if organization else {}
        code, body, _ = self._api("POST", endpoint, payload)
        export_id = body.get("export_id") if isinstance(body, dict) else None
        if code != 202 or not isinstance(export_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{8,160}", export_id):
            raise ExportError("Unexpected enterprise export creation response")
        for i in range(polls):
            code, state, location = self._api("GET", endpoint + "/" + quote(export_id))
            if code == 302 and location:
                return self._download(location)
            if code != 200 or not isinstance(state, dict) or state.get("status") not in (
                "queued", "pending", "processing", "in_progress", "running"):
                raise ExportError("Unexpected or failed enterprise export status")
            if i < polls - 1:
                self.sleeper(interval)
        raise ExportError("Enterprise export did not finish within the poll budget; retry later without increasing export rate")
