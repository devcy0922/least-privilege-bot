# Least Privilege Bot

**Evidence-aware audits for GitHub Actions permissions and enterprise credential inventory, without a dashboard.**

[![CI](https://github.com/devcy0922/least-privilege-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/devcy0922/least-privilege-bot/actions/workflows/ci.yml)

> **v0.1.1** adds read-only credential inventory analysis. It does **not** observe full API usage, prove minimum permissions, revoke credentials, change token scopes, or create pull requests. No credential metadata is published automatically.

## Why

Default/inherited token privileges and `write-all` are easy to overlook in CI. Least Privilege Bot reads workflows **without executing any step**, reports risky token declarations, and produces versionable JSON and Markdown findings. It never asks for the raw secret values of a PAT or GitHub App token.

## v0.1 features

- Audits every `.yml` / `.yaml` file directly inside `.github/workflows/`.
- Honors **job-level permissions overriding workflow-level permissions** (not merging them).
- Detects `write-all` (high), explicit `write` scopes (medium; human review), implicit inherited defaults (medium), `read-all` (low), `pull_request_target` + write permissions (high), and malformed workflow/permissions declarations.
- Scans a local checkout or remote repositories via GitHub's read-only REST APIs.
- Generates `reports/report.json` with stable finding IDs and a `reports/report.md` summary.
- Runs CI tests on pushes/PRs, and a **weekly scheduled self-audit** (Monday 10:17 KST).
- The optional publishing command **creates or updates only one Issue in the audited repository**, and only when findings meet the selected severity. It does not write PRs or source files.

## Quick start

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -e . --no-deps
python -m unittest discover -s tests -v

# Audit this local checkout; no GitHub token required.
lpbot scan --path . --output-dir reports
cat reports/report.md

# Fail the command if any high finding exists (exit 2).
lpbot scan --path . --fail-on high
```

### Audit a remote repository

```bash
# Public repositories work without credentials but are subject to lower API rate limits.
lpbot scan --repo devcy0922/least-privilege-bot --output-dir reports

# For private repositories, use a narrowly scoped token with repository Contents: read.
GITHUB_TOKEN=... lpbot scan --repo OWNER/REPO --output-dir reports

# Several repositories (the report remains local; it is NOT published cross-repository).
lpbot scan --repo OWNER/REPO_A --repo OWNER/REPO_B
```

**Do not commit tokens or unreviewed private-repository findings into a public repository.** The token is read from the environment and is never included in normal reports. Access for the remote collector is read-only. GitHub App credentials and API Insights are **not** part of v0.1.

### Publish a high-severity Issue (optional)

```bash
# Must match the sole repository represented in the report.
GITHUB_TOKEN=... lpbot publish-issue \
  --repo OWNER/REPO \
  --report reports/report.json \
  --min-severity high
```

The publish token requires repository **Issues: write**. With no findings at or above the threshold, no Issue is created. The command updates an existing open Issue with the same fixed title rather than opening a new one each run. No auto-merge or auto-fix exists in v0.1.

## v0.1.1: credential inventory (read-only)

No UI, database or raw token storage. Admins receive a per-owner inventory, stale-credential review candidates, never-expiring credentials where *explicitly* recorded, overly broad classic OAuth scopes, all-repository coverage, and declared write permissions. Output is JSON and Markdown (`inventory.json`, `inventory.md`). These are **review candidates**, never proof of unused rights.

Three data sources have different coverage:

| Mode | Inputs | Coverage | Required access |
| --- | --- | --- | --- |
| Enterprise API | `--enterprise ENTERPRISE` | Enterprise credential export: Classic/Fine-grained PATs, OAuth/GitHub App user tokens, SSH keys, installations, and more | Enterprise owner / View enterprise credentials + `read:enterprise` Classic PAT, or Enterprise credentials: read GitHub App |
| Organization API | `--org ORG` | **Approved Fine-grained PATs only** with access to org resources; not Classic PATs or all org credentials | GitHub App installation/user token with Organization **Personal access tokens: read** |
| Offline | `--csv export.csv` | Whatever Enterprise CSV rows were supplied | No network access |

### Enterprise: fully automatic CSV export + audit

GitHub Enterprise Cloud provides asynchronous export APIs. **Older enterprise inventory list/detail endpoints closed on 2026-10-02.** We call `POST /enterprises/{enterprise}/credentials/exports`, poll `GET /enterprises/{enterprise}/credentials/exports/{export_id}`, fetch the short-lived CSV and analyze it **in memory**. No manual download and no CSV saved by `lpbot`. API export quotas apply; use a **weekly** schedule instead of retrying on every failure.

```bash
export LPBOT_ENTERPRISE_TOKEN='...' # enterprise owner with read:enterprise, or authorized GitHub App token
lpbot inventory --enterprise YOUR_ENTERPRISE --output-dir /secure/reports
lpbot inventory --enterprise YOUR_ENTERPRISE --organization YOUR_ORG --stale-days 90
```

### Organization: approved Fine-grained PATs only

```bash
export LPBOT_ORG_APP_TOKEN='...' # GitHub App installation/user token, PATs read org permission
lpbot inventory --org YOUR_ORG --output-dir /secure/reports
```

GitHub's `GET /orgs/{org}/personal-access-tokens` endpoint explicitly allows **GitHub App tokens only**. An org-owner PAT alone cannot use that endpoint. You install **one** read-only auditing GitHub App for the organization, **not** one App per repository. Do not describe this as a complete enterprise credential inventory.

### Offline / reproducible analysis

```bash
lpbot inventory --csv /secure/credential-export.csv --output-dir /secure/reports
lpbot inventory --csv /secure/credential-export.csv --as-of 2026-10-14T00:00:00Z
```

The Enterprise export may contain multiple rows per credential (one per authorized organization): the analyzer deduplicates and aggregates. Credential aliases use one-way truncated digests of metadata identifiers rather than displaying token IDs, hashes or SSH fingerprints. Names, owners and usage metadata are still sensitive: **never publish reports from this tool to public repositories, Issues, PRs, or public Actions logs**. Run organization/enterprise auditing in a separately protected **private** repository/environment. Reports contain no raw token strings, original hashes, fingerprints, or short-lived download URLs; input CSV is not persisted in API mode.

**Interpretation constraints:** a missing last-used timestamp is **unknown**, not proof of non-use. A blank expiry timestamp is **unknown** unless `expiry_status=never`. `write` is a declared privilege, not automatically unnecessary. `last_used_at` is metadata; API endpoint usage, MCP tool names, Runner job attribution, actual future requirements, and minimum privilege are **not observed** by v0.1.1. Inventory API coverage depends on GitHub plan and administrative privileges.

[Credential inventory architecture and security details](docs/CREDENTIAL_INVENTORY.md)

## Rule semantics

| Rule | Severity | What is proven | What is **not** proven |
|---|---|---|---|
| `WRITE_ALL` | high | Job receives an explicit broad write declaration | Every write permission is unnecessary |
| `WRITE_SCOPE` | medium | Scope is explicitly granted write | Scope can be safely downgraded |
| `IMPLICIT_DEFAULT` | medium | No job/workflow declaration controls that job | Actual org/repo default token privilege |
| `READ_ALL` | low | Job has a broad read-all declaration | Its exact minimum set of read scopes |
| `PR_TARGET_WRITE` | high | `pull_request_target` coexists with write declaration | Untrusted PR code definitely executes |
| `PARSE_ERROR`, `INVALID_*`, `FILE_TOO_LARGE` | high | Auditor could not safely assess this file/job | No vulnerabilities exist elsewhere |

GitHub Actions semantics: defining any individual permission sets all **unspecified** permissions to `none`; a job-level `permissions` key overrides the workflow-level key. Reusable workflows, composite actions, organization defaults, fork event rules, external PATs, secrets, and actual API usage need separate analysis. Absence of findings is **not** a security guarantee.

## Output and automation

The GitHub Actions workflows in this repo are self-contained:

- `.github/workflows/ci.yml`: installation, unit tests, local audit.
- `.github/workflows/scheduled-scan.yml`: weekly local audit, job summary, downloadable 30-day artifacts, and a second **issues:write** job for a high-severity Issue.

The scheduled scan inspects **this repository only**. Other repositories must be enrolled explicitly via the CLI. No dashboard, hosted database, or automatic PR creation is required.

## Roadmap

- **v0.1 (this release):** deterministic static scanner, reports, scheduled self-audit, optional idempotent Issue publishing.
- **v0.1.1:** optional Enterprise API/org API credential metadata inventory with owner risk summaries and no UI or automatic publication.
- **v0.2:** trace coverage and supported usage correlation, then carefully evaluated Draft PR proposals (only when verifiable).
- **v0.3:** optional Enterprise Cloud API Insights for supported PAT and GitHub App actors, with coverage gaps explicitly recorded.
- **v0.4:** optional runner/proxy evidence for `GITHUB_TOKEN` API calls; never equate “not observed” with “not required.”

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY.md), and [agent/contributor instructions](AGENTS.md).

## Contributing and licensing

Issues and PRs are welcome. A source redistribution license has not yet been selected; do not assume an OSS license grant until a `LICENSE` file is added.
