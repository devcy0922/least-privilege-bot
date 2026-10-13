# Least Privilege Bot

**Audit GitHub Actions `GITHUB_TOKEN` declarations on a schedule — with evidence, not guesses.**

[![CI](https://github.com/devcy0922/least-privilege-bot/actions/workflows/ci.yml/badge.svg)](https://github.com/devcy0922/least-privilege-bot/actions/workflows/ci.yml)

> **v0.1 — static permissions auditor.** This release does **not** observe actual token usage, prove minimum required permissions, change token scopes, or create pull requests. Those are distinct follow-up milestones.

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
- **v0.2:** GitHub App enrollment, conservative draft PR proposals where evidence suffices, rules for generated fixes, richer test fixtures.
- **v0.3:** optional Enterprise Cloud API Insights for supported PAT and GitHub App actors, with coverage gaps explicitly recorded.
- **v0.4:** optional runner/proxy evidence for `GITHUB_TOKEN` API calls; never equate “not observed” with “not required.”

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY.md), and [agent/contributor instructions](AGENTS.md).

## Contributing and licensing

Issues and PRs are welcome. A source redistribution license has not yet been selected; do not assume an OSS license grant until a `LICENSE` file is added.
