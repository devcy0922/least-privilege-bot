"""Enterprise credential inventory normalization, conservative rules and safe reports.

Input is the GitHub Enterprise Cloud asynchronous credentials export CSV (one
row per credential/authorizing organization). Never store raw CSV or credentials.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from hashlib import sha256
from html import escape
from io import StringIO
import json
from pathlib import Path
import re

MAX_CSV_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100_000
SEVERITIES = ("high", "medium", "low")
WIDE_SCOPES = {"repo", "admin:org", "admin:enterprise", "delete_repo", "workflow", "write:packages", "admin:repo_hook"}
WRITE_WORDS = ("write", "admin")


def _date(value: str | None) -> datetime | None:
    if not value or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _parts(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(";") if v.strip()]


def _clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _identity(row: dict[str, str], ordinal: int) -> str:
    kind = row.get("credential_type", "unknown").lower()
    unique = (row.get("credential_id") or row.get("fingerprint") or "").strip()
    if not unique:
        unique = "|".join(row.get(k, "") for k in ("owner_id", "owner", "owner_type", "application", "display_name"))
    if not unique.strip("|"):
        unique = f"unknown-row:{ordinal}"
    return sha256((kind + "|" + unique).encode()).hexdigest()[:16]


def _truth(value: str) -> bool | None:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return None


def _safe_cell(value: object) -> str:
    # Escape Markdown/HTML, newlines and mentions; do not trust spreadsheet fields.
    return escape(_clean(value), quote=True).replace("|", "\\|").replace("\r", " ").replace("\n", " ").replace("@", "&#64;")[:200]


def parse_inventory(content: bytes, *, max_rows: int = MAX_ROWS) -> list[dict[str, str]]:
    if len(content) > MAX_CSV_BYTES:
        raise ValueError("Inventory CSV is too large")
    try:
        data = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("Expected a UTF-8 credential inventory CSV") from None
    reader = csv.DictReader(StringIO(data, newline=""), strict=True)
    fields = set(reader.fieldnames or [])
    required = {"credential_type", "owner", "last_used_at"}
    if not required <= fields:
        raise ValueError("Not an enterprise credential inventory CSV (missing: " + ", ".join(sorted(required - fields)) + ")")
    rows = []
    try:
        for row in reader:
            if len(rows) >= max_rows:
                raise ValueError("Inventory exceeds maximum row count; partial audit refused")
            if None in row:
                raise ValueError("Malformed CSV: unexpected extra columns")
            if not any(_clean(x) for x in row.values()):
                continue
            rows.append({k: _clean(v) for k, v in row.items()})
    except csv.Error:
        raise ValueError("Malformed credential inventory CSV") from None
    return rows


def analyze_inventory(rows: list[dict[str, str]], *, as_of: datetime | None = None,
                      stale_days: int = 90, organization: str | None = None,
                      source: str = "enterprise-export") -> dict:
    if stale_days <= 0:
        raise ValueError("stale-days must be positive")
    now = as_of or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("as-of must have timezone")
    now = now.astimezone(timezone.utc)
    unique: dict[str, dict] = {}
    for ordinal, row in enumerate(rows):
        org = row.get("organization", "")
        if organization and org.lower() != organization.lower():
            continue
        uid = _identity(row, ordinal)
        scopes = _parts(row.get("scopes"))
        perms = _parts(row.get("permissions"))
        if uid not in unique:
            unique[uid] = {
                "id": uid,
                "type": row.get("credential_type") or "unknown",
                "owner": row.get("owner") or "unknown",
                "name": row.get("display_name") or "(unnamed)",
                "state": row.get("credential_state") or "unknown",
                "access_state": row.get("authorization_state") or "unknown",
                "last_used_at": row.get("last_used_at") or None,
                "created_at": row.get("created_at") or None,
                "expires_at": row.get("expires_at") or None,
                "expiry_status": row.get("expiry_status") or "unknown",
                "repository_selection": row.get("repository_selection") or "unknown",
                "scopes": scopes,
                "permissions": perms,
                "organizations": [],
            }
        ent = unique[uid]
        if org and org not in ent["organizations"]:
            ent["organizations"].append(org)
        # A credential's metadata should be consistent across organization rows.
        if (ent["owner"] != (row.get("owner") or "unknown") or
                ent["type"] != (row.get("credential_type") or "unknown")):
            raise ValueError("Conflicting credential inventory rows")

    entries = sorted(unique.values(), key=lambda x: (x["owner"].casefold(), x["type"], x["id"]))
    findings: list[dict] = []

    def flag(ent: dict, rule: str, severity: str, detail: str, recommendation: str):
        findings.append({"id": ent["id"] + ":" + rule, "credential_id": ent["id"],
                         "rule": rule, "severity": severity, "evidence": detail,
                         "recommendation": recommendation, "confidence": "candidate-review"})

    for ent in entries:
        if ent["state"].lower() not in ("active", "unknown", ""):
            continue
        last = _date(ent["last_used_at"])
        created = _date(ent["created_at"])
        if last:
            elapsed = (now - last).days
            ent["days_since_use"] = max(0, elapsed)
            if elapsed >= stale_days:
                flag(ent, "STALE_CREDENTIAL", "high" if elapsed >= stale_days * 2 else "medium",
                     f"Last recorded use {elapsed} days ago (threshold {stale_days} days)",
                     "Confirm ownership and rare-use workflows before revocation")
        else:
            ent["days_since_use"] = None
            if created and (now - created).days >= stale_days:
                flag(ent, "USAGE_UNKNOWN", "low", "No last-use timestamp is available",
                     "Investigate audit coverage; do not assume this credential is unused")
        if ent["expiry_status"].lower() == "never" or (ent["expiry_status"] == "unknown" and
                ent["expires_at"] is None and ent["type"] == "classic_pat"):
            # Blank classic PAT expiry with 'unknown' means we cannot prove never expires.
            if ent["expiry_status"].lower() == "never":
                flag(ent, "NO_EXPIRATION", "medium", "Credential explicitly marked never-expiring",
                     "Set an appropriate expiration and rotation plan")
        if ent["repository_selection"].lower() == "all":
            flag(ent, "ALL_REPOSITORIES", "medium", "Credential scope covers all repositories",
                 "Confirm necessity and restrict to selected repositories where supported")
        dangerous = sorted(set(s for s in ent["scopes"] if s.lower() in WIDE_SCOPES))
        if dangerous:
            flag(ent, "BROAD_CLASSIC_SCOPE", "high" if {"repo", "admin:org", "admin:enterprise"} & set(dangerous) else "medium",
                 "Broad OAuth scopes: " + ", ".join(dangerous),
                 "Review replacement with a finer-grained token; no automatic downgrade")
        elevated = sorted(set(p for p in ent["permissions"] if ":" in p and
                              p.rsplit(":", 1)[1].strip().lower() in WRITE_WORDS))
        if elevated:
            flag(ent, "WRITE_PERMISSION", "medium", "Declared write permissions: " + ", ".join(elevated),
                 "Compare against supported API usage; write permission is not automatically excessive")
        ent["finding_count"] = len([f for f in findings if f["credential_id"] == ent["id"]])
        ent["max_severity"] = next((sev for sev in SEVERITIES if any(
            f["credential_id"] == ent["id"] and f["severity"] == sev for f in findings)), "none")

    counts = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    owners: dict[str, dict] = {}
    for ent in entries:
        own = owners.setdefault(ent["owner"], {"credentials": 0, "flagged": 0, "high": 0})
        own["credentials"] += 1
        own["flagged"] += int(ent["finding_count"] > 0)
        own["high"] += int(ent["max_severity"] == "high")
    return {"schema_version": "0.1.1", "analysis_type": "credential-inventory-metadata",
            "source": source, "organization": organization, "as_of": now.isoformat(),
            "stale_days": stale_days, "credential_count": len(entries),
            "counts": counts, "coverage": {"credentials_with_last_use": sum(
                bool(e["last_used_at"]) for e in entries), "api_calls_observed": False,
                "not_a_minimum_permission_proof": True}, "owners": owners,
            "credentials": entries, "findings": findings}


def inventory_markdown(report: dict) -> str:
    c = report["counts"]
    rows = ["# Credential Inventory Audit", "",
            f"- As of: {_safe_cell(report['as_of'])}",
            f"- Source: {_safe_cell(report['source'])}",
            f"- Organization filter: {_safe_cell(report['organization'] or '(all)')}",
            f"- Unique credentials: **{report['credential_count']}**", 
            f"- Findings: high **{c['high']}**, medium **{c['medium']}**, low **{c['low']}**", "",
            "> **Coverage:** Last-used timestamps are metadata, not full API activity history. Missing timestamps do not prove non-use. Broad permissions are review candidates, not verified excess. No token values/hashes/fingerprints are exported.", "",
            "## Owners", "", "| Owner | Credentials | Flagged | High-risk credentials |", "| --- | ---: | ---: | ---: |"]
    for owner, stats in sorted(report["owners"].items()):
        rows.append(f"| {_safe_cell(owner)} | {stats['credentials']} | {stats['flagged']} | {stats['high']} |")
    rows.extend(["", "## Credentials", "", "| Owner | Type | Name | Alias | Last used | Expiry | Access | Findings |", "| --- | --- | --- | --- | --- | --- | --- | ---: |"])
    for ent in report["credentials"]:
        rows.append("| " + " | ".join(_safe_cell(x) for x in (
            ent["owner"], ent["type"], ent["name"], ent["id"],
            ent["last_used_at"] or "unknown", ent["expiry_status"],
            ent["repository_selection"], ent["finding_count"])) + " |")
    rows.extend(["", "## Review candidates", ""])
    by_id = {ent["id"]: ent for ent in report["credentials"]}
    for f in sorted(report["findings"], key=lambda x: (SEVERITIES.index(x["severity"]), x["id"])):
        ent = by_id[f["credential_id"]]
        rows.extend([f"### {_safe_cell(f['severity'].upper())} — {_safe_cell(f['rule'])}", "",
                     f"- Credential: {_safe_cell(ent['owner'])} / {_safe_cell(ent['name'])} (`{ent['id']}`)",
                     f"- Evidence: {_safe_cell(f['evidence'])}",
                     f"- Recommendation: {_safe_cell(f['recommendation'])}", ""])
    if not report["findings"]:
        rows.append("No findings under the configured heuristic checks. This is **not** a guarantee of least privilege.")
    return "\n".join(rows) + "\n"


def write_inventory_report(report: dict, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "inventory.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (folder / "inventory.md").write_text(inventory_markdown(report), encoding="utf-8")
