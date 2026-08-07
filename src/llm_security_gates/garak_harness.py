#!/usr/bin/env python3
"""garak assurance harness -> compact per-model resilience score.

Runs NVIDIA ``garak`` against one or more OpenAI-compatible endpoints, parses the
JSONL report's ``eval`` entries, and emits a per-model resilience score suitable
for a dashboard panel or a CI gate. Standard library only (garak itself is
invoked as a subprocess).

The scoring maths (``score_from_evals``) and the report parser (``parse_report``)
are pure and import-safe -- unit-testable without garak installed.

Note: the default probes below are light smoke probes. For real assurance use
security probes such as ``promptinject``, ``latentinjection``, ``leakreplay``,
``dan`` and ``encoding``.
"""
import argparse
import json
import os
import re
import statistics
import subprocess
import sys
from datetime import datetime, timezone

REPORT_DIR = os.environ.get(
    "GARAK_REPORT_DIR",
    os.path.expanduser("~/.local/share/garak/garak_runs"),
)


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def _run_garak(model, base_url, api_key, probes, generations, prefix, timeout):
    env = dict(os.environ)
    env["OPENAI_API_KEY"] = api_key
    env["OPENAI_BASE_URL"] = base_url
    cmd = [
        "garak", "--model_type", "openai", "--model_name", model,
        "--probes", probes, "--generations", str(generations),
        "--report_prefix", prefix,
    ]
    return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)


def parse_report(prefix: str, report_dir: str = REPORT_DIR) -> dict:
    """Return ``{(probe, detector): eval_obj}`` deduped, last-wins (pure I/O).

    Malformed lines are skipped. Raises ``FileNotFoundError`` if the report is
    absent and ``ValueError`` if it contains no eval entries -- either way the
    caller must not treat the model as scored.
    """
    path = os.path.join(report_dir, f"{prefix}.report.jsonl")
    if not os.path.exists(path):
        raise FileNotFoundError(f"report missing: {path}")
    evals = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("entry_type") == "eval":
                evals[(obj.get("probe"), obj.get("detector"))] = obj
    if not evals:
        raise ValueError("no eval entries in report")
    return evals


def score_from_evals(evals: dict) -> dict:
    """Compute resilience score, attack-success-rate and weakest probe (pure).

    resilience_score = mean pass-rate across scorable (total>0) probes.
    Probes with ``total_evaluated == 0`` are listed but excluded from the mean.
    Returns ``resilience_score = None`` when nothing was scorable.
    """
    probes, rates = [], []
    for (probe, detector), e in sorted(evals.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        total = int(e.get("total_evaluated", 0) or 0)
        passed = int(e.get("passed", 0) or 0)
        pr = round(passed / total, 4) if total > 0 else None
        probes.append({"probe": probe, "detector": detector,
                       "passed": passed, "total": total, "pass_rate": pr})
        if pr is not None:
            rates.append((pr, probe))
    if not rates:
        return {"resilience_score": None, "attack_success_rate": None,
                "weakest_probe": None, "probes": probes}
    score = round(statistics.mean(r for r, _ in rates), 4)
    return {
        "resilience_score": score,
        "attack_success_rate": round(1 - score, 4),
        "weakest_probe": min(rates, key=lambda x: x[0])[1],
        "probes": probes,
    }


def score_model(model, base_url, api_key, probes, generations, index, timeout,
                report_dir=REPORT_DIR) -> dict:
    prefix = f"selftest_{_safe(model)}_{index}"
    out = {"model": model, "resilience_score": None, "attack_success_rate": None,
           "weakest_probe": None, "probes": [], "status": "OK"}
    try:
        proc = _run_garak(model, base_url, api_key, probes, generations, prefix, timeout)
        evals = parse_report(prefix, report_dir)  # parse even if rc!=0; report may still exist
        scored = score_from_evals(evals)
        out.update(scored)
        if scored["resilience_score"] is None:
            out["status"] = "ERROR: no scorable probes (all total_evaluated=0)"
        elif proc.returncode != 0:
            out["status"] = "OK (garak rc!=0 but report parsed)"
    except subprocess.TimeoutExpired:
        out["status"] = "ERROR: garak timeout"
    except Exception as exc:  # never let one model crash the fleet run
        out["status"] = f"ERROR: {exc}"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="garak -> Model Assurance score")
    ap.add_argument("--models", required=True, help="comma-separated model names")
    ap.add_argument("--base-url", default="https://api.openai.com/v1")
    ap.add_argument("--api-key-env", default="OPENAI_API_KEY")
    ap.add_argument("--probes", default="lmrc.Anthropomorphisation,lmrc.Bullying")
    ap.add_argument("--generations", type=int, default=1)
    ap.add_argument("--out", default="garak_assurance.json")
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args(argv)

    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        print(f"[garak-harness] ERROR: env {args.api_key_env} not set", file=sys.stderr)
        return 2

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    probes = [p.strip() for p in args.probes.split(",") if p.strip()]
    results = [
        score_model(m, args.base_url, api_key, args.probes, args.generations, i, args.timeout)
        for i, m in enumerate(models)
    ]

    report = {"schema": "model-assurance/v1",
              "generated_at": datetime.now(timezone.utc).isoformat(),
              "base_url": args.base_url, "probes": probes,
              "generations": args.generations, "models": results}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    for r in results:
        s = r["resilience_score"]
        print(f"  {r['model']:34} resilience={s if s is not None else 'n/a':>6} "
              f"weak={r['weakest_probe']} [{r['status']}]")
    print(f"[garak-harness] -> {args.out}")
    return 0 if any(r["resilience_score"] is not None for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
