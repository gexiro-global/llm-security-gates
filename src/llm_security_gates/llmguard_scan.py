#!/usr/bin/env python3
"""LLM Guard scan core.

A thin, configurable wrapper over ProtectAI's ``llm-guard`` that runs a chosen
set of input/output scanners and returns a uniform verdict + per-scanner risk +
latency. Used by ``llmguard_proxy`` and runnable standalone for benchmarking.

Input scanners:  prompt_injection, ban_code, secrets, invisible_text, anonymize
Output scanners: sensitive, malicious_urls, no_refusal, deanonymize

Model-free (fast, no download): secrets, invisible_text.
Model-based (first load pulls HF weights): prompt_injection, ban_code,
malicious_urls, no_refusal.

``llm-guard`` is imported lazily inside the builder functions, so this module
imports cleanly (and the result-shaping logic stays unit-testable) on a machine
where the heavy ML dependency is not installed.
"""
import argparse
import json
import sys
import time

DEFAULT_INPUT_SCANNERS = "secrets,invisible_text"


def parse_scanner_names(csv: str) -> list:
    """Split a comma-separated scanner list, trimming blanks (pure)."""
    return [n.strip() for n in (csv or "").split(",") if n.strip()]


def build_input_scanners(names):
    from llm_guard.input_scanners import (
        PromptInjection, BanCode, Secrets, InvisibleText, Anonymize,
    )
    from llm_guard.vault import Vault
    vault = Vault()
    registry = {
        "prompt_injection": lambda: PromptInjection(threshold=0.85),
        "ban_code": lambda: BanCode(),
        "secrets": lambda: Secrets(),
        "invisible_text": lambda: InvisibleText(),
        "anonymize": lambda: Anonymize(vault),
    }
    _reject_unknown(names, registry)
    return [registry[n]() for n in names], vault


def build_output_scanners(names, vault):
    from llm_guard.output_scanners import (
        Sensitive, MaliciousURLs, NoRefusal, Deanonymize,
    )
    registry = {
        "sensitive": lambda: Sensitive(redact=True),
        "malicious_urls": lambda: MaliciousURLs(),
        "no_refusal": lambda: NoRefusal(),
        "deanonymize": lambda: Deanonymize(vault),
    }
    _reject_unknown(names, registry)
    return [registry[n]() for n in names]


def _reject_unknown(names, registry):
    unknown = [n for n in names if n not in registry]
    if unknown:
        raise ValueError(f"unknown scanner(s): {unknown}; known: {sorted(registry)}")


def _shape(mode, original, sanitized, valid, scores, elapsed_ms):
    """Assemble the uniform verdict dict from raw llm-guard outputs (pure).

    ``blocked`` is true if ANY scanner marked the text invalid. ``valid`` and
    ``scores`` are keyed by scanner name (llm-guard's contract).
    """
    return {
        "mode": mode,
        "blocked": not all(valid.values()) if valid else False,
        "per_scanner": {k: {"valid": bool(valid[k]), "risk": scores.get(k)} for k in valid},
        "sanitized_changed": sanitized != original,
        "elapsed_ms": elapsed_ms,
    }


def scan_input(text, scanners):
    from llm_guard import scan_prompt
    t0 = time.perf_counter()
    sanitized, valid, scores = scan_prompt(scanners, text)
    return _shape("input", text, sanitized, valid, scores,
                  round((time.perf_counter() - t0) * 1000, 1))


def scan_output_text(prompt, output, scanners):
    from llm_guard import scan_output
    t0 = time.perf_counter()
    sanitized, valid, scores = scan_output(scanners, prompt, output)
    return _shape("output", output, sanitized, valid, scores,
                  round((time.perf_counter() - t0) * 1000, 1))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan text with an llm-guard scanner set.")
    ap.add_argument("--mode", choices=["input", "output"], default="input")
    ap.add_argument("--scanners", default=DEFAULT_INPUT_SCANNERS,
                    help="csv of scanner names for the chosen mode")
    ap.add_argument("--text", required=True, help="text to scan (output mode: the model reply)")
    ap.add_argument("--prompt", default="", help="original prompt (output mode only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    names = parse_scanner_names(args.scanners)
    t_load = time.perf_counter()
    if args.mode == "input":
        scanners, _vault = build_input_scanners(names)
    else:
        _in, vault = build_input_scanners([])  # vault only
        scanners = build_output_scanners(names, vault)
    load_ms = round((time.perf_counter() - t_load) * 1000, 1)

    if args.mode == "input":
        res = scan_input(args.text, scanners)
    else:
        res = scan_output_text(args.prompt, args.text, scanners)
    res["scanner_load_ms"] = load_ms
    res["scanners"] = names

    if args.json:
        print(json.dumps(res))
    else:
        flag = "BLOCK" if res["blocked"] else "PASS"
        print(f"[llm-guard] {flag} mode={res['mode']} scan={res['elapsed_ms']}ms load={load_ms}ms")
        for k, v in res["per_scanner"].items():
            mark = "ok" if v["valid"] else "FLAG"
            print(f"    {k:18} {mark:4} risk={v['risk']}")
    return 1 if res["blocked"] else 0


if __name__ == "__main__":
    sys.exit(main())
