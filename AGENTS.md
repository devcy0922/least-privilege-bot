# Engineering instructions — Least Privilege Bot

## Mission

Build an **evidence-aware** least-privilege auditor for GitHub Actions. Be precise: observing a broad permission declaration is not proof that the permission is unnecessary. Default behavior should be read-only. No hidden token collection.

## Development rules

1. Keep modules separable: `audit.py` has pure YAML analysis, `github.py` performs GitHub API I/O, `report.py` serializes findings, and `cli.py` wires entrypoints.
2. Never execute arbitrary repository scripts, workflow steps, or shell commands during analysis. Treat YAML and GitHub API payloads as untrusted.
3. Never send raw PAT, GitHub App private key, `GITHUB_TOKEN`, process environment, or workflow body in reports/issues/logs.
4. Report **observed facts**, confidence and **unknowns**. Do not state that a permission is unused unless sufficient runtime evidence exists, and even then do not infer future safety.
5. Fail closed on truncated GitHub trees, undecodable files, invalid YAML, and insufficient access. Never issue a clean bill of health on partial coverage.
6. Default GitHub API access is read-only; publishing uses a distinct explicit operation. No PR generation, automatic permissions reduction, auto-merge, or credential rotation in v0.1.
7. Keep Issues idempotent; do not create duplicates during a repeated schedule. Never publish a private repo's findings into a different repo without explicit user control (v0.1 forbids it).
8. Use job-over-workflow permission precedence, not a union. GitHub Actions event and organization defaults may require extra context and must remain unknown when unobserved.
9. Make each rule deterministic with stable finding IDs, clear severity, and reproducible tests. Fail tests on regressions in parsing and scope inheritance.
10. All workflow third-party Actions should be pinned to a full commit SHA. Permissions must be minimal per job, and checkout must use `persist-credentials: false` unless there is a documented reason not to.

## Validate before merging

```bash
python -m pip install -r requirements.txt -e . --no-deps
python -m unittest discover -s tests -v
python -m least_privilege_bot scan --path . --output-dir reports
```

Review any newly added rule for false positives, GitHub semantics and README updates. Do not change scan results based on superficial assumptions about script names.

## v0.1 acceptance criteria

- `scan --path` works without secrets; `scan --repo` reads remote Actions YAML on the default branch.
- YAML's `on` is not coerced to `True` by PyYAML.
- Inherited and job override permissions are correctly differentiated.
- Dangerous configurations generate machine-readable/Markdown reports with no secrets.
- Scheduled CI runs with read permissions, and separate publish job has Issues write.
- At or above the chosen severity, one Issue is updated/reused instead of duplicated.
- No UI, database, GitHub App registration, PR creation, or runtime-usage claims.

## v0.1.1 credential inventory constraints

- `inventory` is metadata-only, not a source of definitive API-use or minimum permission evidence.
- Use GitHub Enterprise **asynchronous** inventory export endpoints; old list/detail inventory endpoints closed on 2026-10-02.
- Do not persist raw CSV, secret values, token hashes, SSH fingerprints, authenticated download URLs, or API tokens.
- No credential inventory data belongs in public Actions summaries, issues, PRs, or public artifacts. Run scheduled credential audits from a separately controlled **private** repository.
- Treat blank last-use timestamp and unknown expiry as unknown, not unused/never-expiring. One credential may appear once per authorizing organization: deduplicate safely.
- v0.1.1 only recommends human reviews. Never revoke credentials, edit scopes, notify owners, or publish credential inventory automatically.
