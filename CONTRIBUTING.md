# Contributing

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Run tests

```bash
pytest -q
```

The suite runs **without any ML backend** — the heavy libraries (ModelScan, LLM
Guard, garak) are imported lazily and stubbed in tests. Keep it that way: put new
decision logic in pure functions and inject/monkeypatch the network or subprocess
boundary so tests stay offline and fast.

## Style & principles

- **Fail closed.** Any "could not complete" path must be an error, never a silent
  pass. Every fix should come with a regression test that fails if the fail-open
  behaviour returns.
- Keep the verdict contracts (JSON shapes, exit codes) stable and documented.
- Match the surrounding code; keep functions small and testable.

## Sign-off

Contributions should carry a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

## Scope

This is orchestration glue around mature FOSS security tools. Contributions that add
offensive payloads or turn a gate into an attack tool are out of scope.
