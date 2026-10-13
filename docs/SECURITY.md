# Security model and disclosure

## Trust boundaries

- Repository workflows are **untrusted input**. They are read as text and parsed through `yaml.SafeLoader` with a dedicated YAML-1.2-compatible boolean resolver; no step commands or shell variables are executed by the scanner.
- GitHub's API response is untrusted: fail closed on truncation/decoding errors and apply size limits.
- Do not grant broad tokens to read-only audit jobs. The scheduled Issue publisher is a separate job with `issues: write`, and publishes findings **only back to the same repository**.
- Never attach actual token strings as findings. Store credentials only in environment variables or GitHub Actions secrets, not configuration files.
- Scheduled artifacts and Issues may reveal repository security posture. Before enabling remote audits, review who can read them. In v0.1 there is no cross-repository publishing.

## Not protected by v0.1

No runtime egress firewall, secret-scanning guarantee, or confirmation of genuinely minimum token permissions. A declared `contents: write` may be required by a release workflow. Not observing writes is not proof the permission is unnecessary, especially for seldom-executed workflows.

## Responsible reporting

Avoid posting exploit payloads, real credentials or private security findings to public Issues. Contact the maintainer through a private security report where the GitHub UI supports it.
