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
    2  ERROR  -- path missing, scan failed, or report incomplete/errored

FAIL CLOSED: a scan that cannot be proven to have completed (missing binary,
timeout, unreadable JSON, an error field, or a report whose expected summary
schema is absent) raises ``ScanError`` and exits 2. A syntactically valid but
incomplete document is NOT accepted as a pass -- that was the whole attack.

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


def has_scan_errors(report: dict) -> bool:
    """True when modelscan recorded an error (result must not be trusted).

    Catches both the list form (``errors``) and any singular ``error`` field a
    failed/incompatible scanner might emit.
    """
    if not isinstance(report, dict):
        return True
    return bool(report.get("errors")) or bool(report.get("error"))


def validate_report(report) -> dict:
    """Ensure *report* is a completed modelscan document, else raise ScanError.

    A completed scan always carries a ``summary`` object with a severity
    breakdown, a total count, and completion metadata. An empty object,
    ``{"error": ...}``, or any document missing that structure means the scan
    did not finish -- treating it as a pass is the fail-open bug this guards.
    """
    if not isinstance(report, dict):
        raise ScanError("report is not a JSON object")
    if has_scan_errors(report):
        raise ScanError(f"modelscan reported errors: "
                        f"{report.get('errors') or report.get('error')}")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise ScanError("report has no summary object (scan did not complete)")
    if not isinstance(summary.get("total_issues_by_severity"), dict):
        raise ScanError("report summary lacks total_issues_by_severity")
    if "total_issues" not in summary:
        raise ScanError("report summary lacks total_issues")
    # A finished run stamps at least one NON-EMPTY completion marker. Presence
    # alone is not enough: a forged {"modelscan_version": null} must be rejected.
    if not any(bool(summary.get(k)) for k in ("scanned", "modelscan_version", "timestamp")):
        raise ScanError("report summary lacks a non-empty completion marker "
                        "(scanned/modelscan_version/timestamp)")
    # Internal consistency: modelscan's severity counts sum to total_issues. A
    # mismatch means a truncated or tampered summary -- do not trust it.
    sev = summary["total_issues_by_severity"]
    try:
        counts = {k: int(v or 0) for k, v in sev.items()}
        total = int(summary.get("total_issues", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ScanError(f"non-numeric issue counts in summary: {exc}")
    # Counts must be non-negative. A negative count (e.g. HIGH=-1, CRITICAL=1)
    # can cancel a real issue out of the blocking sum and forge a PASS.
    if total < 0 or any(v < 0 for v in counts.values()):
        raise ScanError(f"negative issue count in summary: {counts} total={total}")
    if sum(counts.values()) != total:
        raise ScanError(f"summary inconsistent: severities sum to {sum(counts.values())} "
                        f"but total_issues={total}")
    return report


def scan(path: str, timeout: int = 300) -> dict:
    """Run ``modelscan`` on *path* and return its validated JSON report.

    modelscan exits non-zero when it finds issues, so the return code is
    ignored on purpose -- the report is parsed regardless. A genuinely failed
    or incomplete run surfaces via ``validate_report`` and raises ``ScanError``.
    """
    fd, report_path = tempfile.mkstemp(suffix=".json", prefix="modelscan_")
    os.close(fd)
    try:
        try:
            proc = subprocess.run(
                ["modelscan", "-p", path, "-r", "json", "-o", report_path],
                capture_output=True, text=True, timeout=timeout,
            )
        except FileNotFoundError as exc:  # modelscan not installed
            raise ScanError("modelscan executable not found on PATH") from exc
        # modelscan's CLI contract: 0 = completed, no issues; 1 = completed, issues
        # found. Any other code (2/3/4: scan error, unsupported/invalid input) means
        # the scan did NOT complete -- a clean-looking report from such a run must
        # not be trusted as a pass.
        if proc.returncode not in (0, 1):
            raise ScanError(f"modelscan exited {proc.returncode} (not a completed scan): "
                            f"{(proc.stderr or '').strip()[:200]}")
        try:
            with open(report_path, encoding="utf-8") as fh:
                report = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"could not read modelscan report: {exc}") from exc
        return validate_report(report)
    finally:
        if os.path.exists(report_path):
            os.unlink(report_path)


def decide(report: dict, block_on: str = "HIGH") -> dict:
    """Turn a *validated* modelscan report into a block/pass verdict (pure).

    *block_on* is the lowest severity that counts as blocking; every issue at
    that severity or higher is summed. This function is strict: it re-validates
    the report so a direct caller cannot bypass the fail-closed contract.
    """
    if block_on not in SEV_ORDER:
        raise ValueError(f"block_on must be one of {SEV_ORDER}, got {block_on!r}")
    validate_report(report)
    summary = report["summary"]
    sev = summary["total_issues_by_severity"]
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
        verdict = decide(report, args.block_on)
    except (ScanError, subprocess.TimeoutExpired) as exc:
        # A scan that did not complete must NEVER be treated as a pass.
        print(f"[modelscan-gate] ERROR: scan failed: {exc}", file=sys.stderr)
        return 2

    _emit(verdict, args.model_path, args.json)
    return 1 if verdict["decision"] == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
