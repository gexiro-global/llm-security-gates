# Security and trust evidence

This page is an evidence index, not a certification. The evidence does not prove the project is vulnerability-free, does not establish a SLSA level, and does not imply OpenSSF affiliation or endorsement. Tool output describes observed posture; it is not proof of compromise or absence of compromise.

- [Security policy](../SECURITY.md), [threat model](../THREAT_MODEL.md) and [authorized-use boundary](../AUTHORIZED_USE.md)
- [Contribution process](../CONTRIBUTING.md), [governance](../GOVERNANCE.md), [maintainers](../MAINTAINERS.md) and [support](../SUPPORT.md)
- CI tests fail-closed verdict contracts without requiring optional ML backends and builds the distribution.
- CodeQL, dependency review, Dependabot and OpenSSF Scorecard are configured in `.github/`.
- Third-party actions are pinned to immutable commit SHAs with version comments.

The official public Scorecard result is 6.3, generated 2026-09-04T13:39:16Z for commit `ce2b610421113ec2c396aeba04f6c7ca279eea84`; see the [official public viewer](https://scorecard.dev/viewer/?uri=github.com/gexiro-global/llm-security-gates). This numeric result is point-in-time posture evidence, not a certification. `.bestpractices.json` contains evidence-backed automation proposals only; it is not an OpenSSF Best Practices or OSPS Baseline claim. A human must review any badge submission.
