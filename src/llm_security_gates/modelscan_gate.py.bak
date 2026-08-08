#!/usr/bin/env python3
"""Model-file supply-chain gate.

Scans a model file/dir (pickle / h5 / keras / SavedModel) with ProtectAI's
``modelscan`` and BLOCKS (exit 1) when unsafe-deserialization issues at or above
a chosen severity threshold are present. Intended call site: a warm-up / CI step
run *before* an inference server loads a pulled model, so a poisoned artifact is
rejected before its ``__reduce__`` ever executes.

Exit codes:
    0  PASS   -- load allowed
    1  BLOCK  -- unsafe, at/above threshold
    2  ERROR  -- path missing, scan failed, or modelscan reported errors

The decision logic (``decide``) is pure and import-safe: it needs neither
``modelscan`` nor any ML library, so it can be unit-tested in isolation.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class ScanError(RuntimeError):
    """Raised when the scan cannot be trusted to have completed."""


def scan(path: str, timeout: int = 300) -> dict:
    """Run ``modelscan`` on *path* and return its parsed JSON report.

    modelscan exits non-zero when it finds issues, so the return code is
    ignored on purpose -- the report is parsed regardless. A genuinely failed
    run surfaces as a missing/invalid report file and raises ``ScanError``.
    """
    fd, report = tempfile.mkstemp(suffix=".json", prefix="modelscan_")
    os.close(fd)
    try:
        try:
            subprocess.run(
                ["modelscan", "-p", path, "-r", "json", "-o", report],
                capture_output=True, text=True, timeout=timeout,
            )
        except FileNotFoundError as exc:  # modelscan not installed
            raise ScanError("modelscan executable not found on PATH") from exc
        try:
            with open(report, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"could not read modelscan report: {exc}") from exc
    finally:
        if os.path.exists(report):
            os.unlink(report)


def has_scan_errors(report: dict) -> bool:
    """True when modelscan itself recorded errors (result must not be trusted)."""
    return bool(report.get("errors"))


def decide(report: dict, block_on: str = "HIGH") -> dict:
    """Turn a modelscan report into a block/pass verdict (pure).

    *block_on* is the lowest severity that counts as blocking; every issue at
    that severity or higher is summed. Unknown severities in the report are
    ignored for the blocking count but still surface in ``by_severity`` totals
    that modelscan provided.
    """
    if block_on not in SEV_ORDER:
        raise ValueError(f"block_on must be one of {SEV_ORDER}, got {block_on!r}")
    summary = report.get("summary", {}) or {}
    sev = summary.get("total_issues_by_severity", {}) or {}
    threshold = SEV_ORDER.index(block_on)
    blocking = sum(int(sev.get(s, 0) or 0) for s in SEV_ORDER[threshold:])
    total = int(summary.get("total_issues", 0) or 0)
    return {
        "decision": "BLOCK" if blocking else "PASS",
        "block_on": block_on,
        "blocking_issues": blocking,
        "total_issues": total,
        "by_severity": {s: int(sev.get(s, 0) or 0) for s in SEV_ORDER},
        "modelscan_version": summary.get("modelscan_version"),
    }


def _emit(verdict: dict, path: str, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"path": path, **verdict}))
        return
    flag = "BLOCK" if verdict["decision"] == "BLOCK" else "PASS"
    print(f"[modelscan-gate] {flag} {path} "
          f"(block_on>={verdict['block_on']}: {verdict['blocking_issues']} blocking / "
          f"{verdict['total_issues']} total | {verdict['by_severity']})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Block unsafe model files before load.")
    ap.add_argument("model_path")
    ap.add_argument("--block-on", default="HIGH", choices=SEV_ORDER,
                    help="lowest severity treated as blocking (default: HIGH)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable verdict")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args(argv)

    if not os.path.exists(args.model_path):
        print(f"[modelscan-gate] ERROR: path not found: {args.model_path}", file=sys.stderr)
        return 2

    try:
        report = scan(args.model_path, timeout=args.timeout)
    except (ScanError, subprocess.TimeoutExpired) as exc:
        # A scan that did not complete must NEVER be treated as a pass.
        print(f"[modelscan-gate] ERROR: scan failed: {exc}", file=sys.stderr)
        return 2

    if has_scan_errors(report):
        print(f"[modelscan-gate] ERROR: modelscan reported errors: {report['errors']}",
              file=sys.stderr)
        return 2

    verdict = decide(report, args.block_on)
    _emit(verdict, args.model_path, args.json)
    return 1 if verdict["decision"] == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
