# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-08

### Added
- `modelscan-gate` — block unsafe model files before load via ProtectAI ModelScan;
  fail-closed on incomplete/errored reports and non-completion exit codes.
- `llmguard-proxy` — OpenAI-compatible reverse proxy that scans the entire inbound
  message set (LLM Guard) and refuses to run an empty input firewall.
- `llmguard-scan` — CLI for the same scanning core.
- `garak-assurance` — turn a garak run into a per-model resilience score with a
  unique-prefix / freshness / probe-coverage contract and a whole-fleet gate.
- Full offline test suite (no ML backends required) and pinned-action CI.

[Unreleased]: https://github.com/gexiro-global/llm-security-gates/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gexiro-global/llm-security-gates/releases/tag/v0.1.0
