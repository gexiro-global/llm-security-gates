# Security Policy

## Supported Versions

llm-security-gates 0.x is experimental. Security fixes are handled on the latest
0.x release line.

## Reporting a Vulnerability

If GitHub private vulnerability reporting is enabled for this repository, use it.
Otherwise, email `security@gexiro.com`.

Please include:

- A concise description of the issue and its impact.
- A minimal reproduction (a crafted report/prompt/sitemap and the exact command).
- The package version and your Python version.

This project is defensive tooling. A finding is most valuable when it shows a gate
**failing open** — a case where a scan/guard should have blocked but did not. Do not
include secrets or third-party data in reports.
