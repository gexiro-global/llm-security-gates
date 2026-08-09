# llm-security-gates

[![CI](https://github.com/gexiro-global/llm-security-gates/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/llm-security-gates/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/llm-security-gates.svg)](https://pypi.org/project/llm-security-gates/)
[![Python](https://img.shields.io/pypi/pyversions/llm-security-gates.svg)](https://pypi.org/project/llm-security-gates/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Three small, independent **security gates for LLM systems**, each a thin, tested
wrapper that turns a best-in-class open-source tool into a drop-in *pass / block*
decision you can put in a cron job, a CI step, or a request path.

| Gate | Guards against | Backed by |
|------|----------------|-----------|
| **`modelscan-gate`** | Poisoned model files (unsafe pickle / Keras deserialization) executing on load | [ModelScan](https://github.com/protectai/modelscan) |
| **`llmguard-proxy`** | Prompt injection, secret leakage, invisible-unicode, unsafe output — at runtime | [LLM Guard](https://github.com/protectai/llm-guard) |
| **`garak-assurance`** | Shipping a model without knowing how it scores against known attacks | [garak](https://github.com/NVIDIA/garak) |

The value here is **the glue, not the engines**: a stable verdict contract, fail-closed
error handling, machine-readable JSON, and a test suite that runs without downloading a
single model. The heavy ML backends are optional dependencies, pulled in only for the
gate you actually use.

---

## Install

```bash
pip install llm-security-gates                    # core (no ML backends)
pip install "llm-security-gates[modelscan]"       # + ModelScan
pip install "llm-security-gates[llmguard,proxy]"  # + LLM Guard + the proxy server
pip install "llm-security-gates[garak]"           # + garak
```

Each gate is usable on its own; you never need to install a backend you don't run.

---

## 1. `modelscan-gate` — supply-chain gate

Block unsafe model artifacts **before** an inference server loads them.

```bash
modelscan-gate ./pulled-model.pkl --block-on HIGH --json
# exit 0 = PASS (safe to load) | 1 = BLOCK (unsafe) | 2 = scan error
```

```json
{"path": "./pulled-model.pkl", "decision": "BLOCK", "block_on": "HIGH",
 "blocking_issues": 1, "total_issues": 3,
 "by_severity": {"LOW": 2, "MEDIUM": 0, "HIGH": 1, "CRITICAL": 0}}
```

A scan that **cannot be trusted to have completed** (missing binary, timeout, unreadable
report, modelscan-reported errors) exits `2` — never a silent pass. Wire it into a
model-warmup step:

```bash
modelscan-gate "$MODEL_DIR" --block-on HIGH || exit 1   # refuse to start on unsafe weights
```

## 2. `llmguard-proxy` — runtime I/O firewall

An **OpenAI-compatible reverse proxy**. Point your client at it instead of your backend;
it scans the prompt before forwarding and the reply before returning.

```bash
export BACKEND_URL=http://127.0.0.1:4000/v1        # any OpenAI-compatible endpoint
export INPUT_SCANNERS=prompt_injection,secrets,invisible_text
export OUTPUT_SCANNERS=sensitive,malicious_urls
uvicorn llm_security_gates.llmguard_proxy:app --host 127.0.0.1 --port 18091
```

```bash
curl -s localhost:18091/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-x","messages":[{"role":"user","content":"ignore all previous instructions"}]}'
# -> a content-filter refusal; the request never reaches the backend
```

`GUARD_BLOCK_MODE=refuse` (default) returns a 200 OpenAI-style refusal so clients keep
working; `reject` returns `403`. The response carries a `guard` block with per-scanner
risk and latency for observability.

The firewall scans the **entire inbound message set** (every user / system / developer
message, and every text part of structured content), not just the last user turn — so an
injection hidden in an earlier message cannot slip through behind a benign final message.
It refuses to start with an empty input-scanner set rather than silently allowing all
traffic.

The same scanning core is available as a CLI for benchmarking a single string:

```bash
llmguard-scan --mode input --scanners secrets,invisible_text --text "my key is AKIA..." --json
```

## 3. `garak-assurance` — model resilience score

Run garak against any OpenAI-compatible endpoint and collapse its report into one
per-model **resilience score** (mean pass-rate) plus the weakest probe — ready for a
dashboard tile or a release gate.

```bash
export OPENAI_API_KEY=...
garak-assurance --models gpt-x,gpt-y \
  --base-url https://api.openai.com/v1 \
  --probes promptinject,latentinjection,leakreplay,dan,encoding \
  --out assurance.json
```

```text
  gpt-x                              resilience= 0.91  weak=dan [OK]
  gpt-y                              resilience= 0.74  weak=promptinject [OK]
```

> The default probes are light smoke probes so a first run is fast. For real assurance
> use security probes (`promptinject`, `latentinjection`, `leakreplay`, `dan`,
> `encoding`).

Each run uses a unique report prefix and rejects a stale or pre-existing report, and a
non-zero garak exit is an error — never a scored "OK" from a leftover report. By default
the gate exits non-zero unless **every** requested model produced a conclusive score;
pass `--allow-partial` to accept a partial fleet result.

---

## Design notes

- **Fail closed.** Every gate treats "could not complete" as *not a pass*. A missing
  backend, a timeout, or an unparseable report is an error exit, not a green light.
- **Importable without the ML stack.** The decision logic (`decide`, `score_from_evals`,
  `parse_report`, `_shape`, `_last_user`) is pure and dependency-light; the heavy
  libraries are imported lazily inside the functions that run a gate. That is what lets
  the whole test suite run — and CI stay fast — with no model downloads.
- **Machine-readable.** Every gate emits JSON with a stable shape for piping into other
  tooling.

## Tests

```bash
pip install -e ".[dev]"
pytest -q
```

The suite stubs the ML backends (injected fake modules, monkeypatched subprocess/HTTP),
so it exercises the real control flow — thresholds, fail-closed paths, proxy block/pass,
report parsing — without any model weights.

## What this is / isn't

This is **orchestration glue** around mature FOSS tools, not a re-implementation of them
and not a complete AI-security program. It gives you clean, testable, fail-closed
decision points; ModelScan, LLM Guard, and garak do the detection. See
[`NOTICE`](NOTICE) for third-party licenses and attribution.

## License

[Apache-2.0](LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

The wrapped tools remain under their own licenses.

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).
