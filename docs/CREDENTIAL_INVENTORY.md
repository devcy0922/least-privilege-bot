# Credential Inventory Collector — v0.1.1

## Scope and security model

- Reports: owner, credential type/name, non-reversible display alias, last-used metadata, declared scopes/permissions and heuristic flags.
- Secret values and signed URLs are never stored in the report. No raw CSV file is persisted in API mode; temporary in-memory data is discarded when the process exits. Organization inventory metadata is confidential even after identifiers are omitted.
- The report is an **advisory audit**, not a proven least-privilege calculation or log of every API request. No credential revocation, scope modification, notification, PR/Issue publication, or database in v0.1.1.
- Prefer dedicated read-only credentials. `GITHUB_TOKEN` inside an Actions job does **not** have enterprise credentials permission by default.
- Do not pass secrets as command arguments, put reports in public Actions summaries/artifacts, or commit downloaded exports. For a scheduled run, execute in a private repo with access restricted to auditors and secrets scoped to that environment.

## Enterprise coverage

The [GitHub Enterprise Cloud credential inventory REST documentation](https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/token-inventory) specifies the asynchronous export:

1. `POST /enterprises/{enterprise}/credentials/exports` with optional `organization` filter.
2. Poll `GET /enterprises/{enterprise}/credentials/exports/{export_id}` (GitHub rate limits and export quotas apply).
3. On HTTP `302`, fetch its short-lived HTTPS download target *without forwarding the bearer token*.
4. Parse UTF-8 CSV, up to 32 MiB / 100,000 rows. Fail rather than silently truncating.

CSV fields include `credential_type`, `credential_id`, `owner`, `display_name`, `last_used_at`, `scopes`, `permissions`, `expiry_status`, and `organization`. A credential can appear multiple times when multiple organizations authorize it. Aliases deduplicate across authorizing organizations when stable metadata IDs exist. Where GitHub provides no stable ID, a metadata-derived fallback can collide; this remains a known limitation and requires review.

The older enterprise inventory list/detail API operations were retired on 2026-10-02. Do not reintroduce them. The export API requires an enterprise owner (or equivalent delegated permission). Classic PAT needs `read:enterprise`; a GitHub App needs enterprise `Enterprise credentials: read`.

## Organization-only coverage

The [GitHub Organization PAT API](https://docs.github.com/en/rest/orgs/personal-access-tokens#list-fine-grained-personal-access-tokens-with-access-to-organization-resources) only covers **approved Fine-grained PATs**. The API requires a GitHub App token with `Personal access tokens: read` org permission. It does not prove that a user owns no other tokens and does not supply classic PATs or all GitHub App OAuth credentials. Report source `org-approved-fine-grained-pats-only` identifies the gap.

## Interpretation and detection rules

| Rule | Meaning | Safety caveat |
| --- | --- | --- |
| `STALE_CREDENTIAL` | `last_used_at` is 90+ days old | Rare-use emergency tokens may still be needed |
| `USAGE_UNKNOWN` | Old credential with no last-use timestamp | **Never** label as unused |
| `NO_EXPIRATION` | `expiry_status=never` explicitly | Blank expiration is **not** enough |
| `ALL_REPOSITORIES` | `repository_selection=all` | Broad scope may be intentional |
| `BROAD_CLASSIC_SCOPE` | Scope contains e.g. `repo`, `admin:org` | Scope granularity may require a credential migration |
| `WRITE_PERMISSION` | Declared `*:write` permission | No actual API usage coverage or proof of excess |

All findings request human review. Severity prioritizes investigation, not an automatic policy or truth value. APIs cannot reliably distinguish MCP client, local CLI and Runner when all share a token, and v0.1.1 makes **no** such attribution.

## Local validation

```bash
python -m pip install -r requirements.txt -e . --no-deps
python -m unittest discover -s tests -v
lpbot inventory --csv /private/export.csv --output-dir /private/audit
```
