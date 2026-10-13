# Architecture (v0.1)

```text
Local checkout (.github/workflows/*.yml) OR GitHub REST read-only API
                   |
                   v
             WorkflowLoader
         (safe YAML; 'on' fix)
                   |
                   v
                Analyzer
      (effective job permissions)
                   |
                   v
             Findings + IDs
                 /    \
                v      v
          JSON report  Markdown report
                            |
                            v
                    Job summary/artifact
                            |
                     opt-in only
                            v
                same-repository Issue
```

The scheduled workflow isolates the read-only audit job from the `issues: write` publication job. For ordinary local and remote CLI runs no Issue mutation occurs. Audit reports contain metadata (workflow path/job, scopes, verdict, recommendations), never a copy of the workflow or token values.

## Static data model

`repo`, `path`, `job`, `rule`, `severity`, `evidence`, `recommendation`, `confidence`, `id`.

Finding IDs are a deterministic SHA-256 prefix of the scope and evidence. `generated_at` is informative and excluded from stable identities. The Markdown report is designed for human review, not as a verified machine policy.

## Known limitations

- Does not resolve external reusable workflow code or action internals; they may request broader scopes.
- Does not know organization/repository defaults, inherited policy for forks, or actual requests made by a token.
- Does not audit third-party PATs, GitHub Apps, non-GitHub credentials, or exfiltration pathways.
- A scanner returning zero findings does not certify workflow security.
- GitHub REST tree recursion can be truncated: scanning aborts rather than hiding incomplete coverage.
- No automatic remediation. Draft PR generation must be gated by evidence and confirmation in a later release.
