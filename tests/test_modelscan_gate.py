import json
import subprocess

import pytest

from llm_security_gates import modelscan_gate as mg


def _report(by_severity, total=None, version="0.8.8", errors=None, error=None):
    summary = {"total_issues_by_severity": by_severity,
               "total_issues": total if total is not None else sum(by_severity.values()),
               "modelscan_version": version}  # version = completion marker
    rep = {"summary": summary}
    if errors is not None:
        rep["errors"] = errors
    if error is not None:
        rep["error"] = error
    return rep


# ---- decide() ----

def test_decide_blocks_at_and_above_threshold():
    v = mg.decide(_report({"LOW": 3, "MEDIUM": 2, "HIGH": 1, "CRITICAL": 0}), "HIGH")
    assert v["decision"] == "BLOCK"
    assert v["blocking_issues"] == 1  # HIGH + CRITICAL


def test_decide_passes_below_threshold():
    v = mg.decide(_report({"LOW": 5, "MEDIUM": 4, "HIGH": 0, "CRITICAL": 0}), "HIGH")
    assert v["decision"] == "PASS"
    assert v["blocking_issues"] == 0
    assert v["total_issues"] == 9


def test_decide_critical_threshold_ignores_high():
    v = mg.decide(_report({"HIGH": 4, "CRITICAL": 0}), "CRITICAL")
    assert v["decision"] == "PASS"
    v2 = mg.decide(_report({"HIGH": 0, "CRITICAL": 1}), "CRITICAL")
    assert v2["decision"] == "BLOCK"


def test_decide_medium_threshold_counts_medium_up():
    v = mg.decide(_report({"LOW": 9, "MEDIUM": 1}), "MEDIUM")
    assert v["decision"] == "BLOCK"
    assert v["blocking_issues"] == 1


def test_decide_rejects_bad_threshold():
    with pytest.raises(ValueError):
        mg.decide(_report({"HIGH": 0}), "SEVERE")


def test_decide_coerces_stringy_counts():
    rep = {"summary": {"total_issues_by_severity": {"CRITICAL": "2"},
                       "total_issues": "2", "modelscan_version": "0.8.8"}}
    v = mg.decide(rep, "HIGH")
    assert v["blocking_issues"] == 2
    assert v["total_issues"] == 2


# ---- FAIL-CLOSED regression: incomplete reports must NOT pass ----

def test_decide_rejects_empty_report():
    # {} used to default to a PASS -- the fail-open bug. Now it must raise.
    with pytest.raises(mg.ScanError):
        mg.decide({}, "HIGH")


def test_decide_rejects_error_only_report():
    with pytest.raises(mg.ScanError):
        mg.decide({"error": "scanner blew up"}, "HIGH")


def test_decide_rejects_summary_without_severity_map():
    with pytest.raises(mg.ScanError):
        mg.decide({"summary": {"total_issues": 0, "modelscan_version": "0.8.8"}}, "HIGH")


def test_decide_rejects_summary_without_completion_marker():
    # severity map + total present but no scanned/version/timestamp => not completed
    with pytest.raises(mg.ScanError):
        mg.decide({"summary": {"total_issues_by_severity": {}, "total_issues": 0}}, "HIGH")


def test_validate_report_accepts_scanned_marker():
    rep = {"summary": {"total_issues_by_severity": {}, "total_issues": 0,
                       "scanned": {"total_scanned": 1}}}
    assert mg.validate_report(rep) is rep


def test_decide_rejects_null_completion_marker():
    # presence of the key is not enough; a null/empty marker must be rejected
    rep = {"summary": {"total_issues_by_severity": {}, "total_issues": 0,
                       "modelscan_version": None}}
    with pytest.raises(mg.ScanError):
        mg.decide(rep, "HIGH")


def test_decide_rejects_inconsistent_summary():
    # severity counts must sum to total_issues; a mismatch = truncated/tampered
    rep = {"summary": {"total_issues_by_severity": {"CRITICAL": 5}, "total_issues": 0,
                       "modelscan_version": "0.8.8"}}
    with pytest.raises(mg.ScanError):
        mg.decide(rep, "HIGH")


# ---- has_scan_errors() ----

def test_has_scan_errors_list_and_singular():
    assert mg.has_scan_errors(_report({"HIGH": 0}, errors=["boom"])) is True
    assert mg.has_scan_errors(_report({"HIGH": 0}, error="boom")) is True
    assert mg.has_scan_errors(_report({"HIGH": 0})) is False


# ---- scan() ----

def test_scan_parses_written_report(monkeypatch):
    def fake_run(cmd, **kw):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(_report({"HIGH": 1}), fh)
        return subprocess.CompletedProcess(cmd, 1, "", "")
    monkeypatch.setattr(mg.subprocess, "run", fake_run)
    rep = mg.scan("/some/model.pkl")
    assert rep["summary"]["total_issues_by_severity"]["HIGH"] == 1


def test_scan_missing_binary_raises(monkeypatch):
    def boom(cmd, **kw):
        raise FileNotFoundError("modelscan")
    monkeypatch.setattr(mg.subprocess, "run", boom)
    with pytest.raises(mg.ScanError):
        mg.scan("/some/model.pkl")


def test_scan_invalid_report_raises(monkeypatch):
    def fake_run(cmd, **kw):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write("not json{{{")
        return subprocess.CompletedProcess(cmd, 1, "", "")
    monkeypatch.setattr(mg.subprocess, "run", fake_run)
    with pytest.raises(mg.ScanError):
        mg.scan("/some/model.pkl")


def test_scan_rejects_failure_exit_code(monkeypatch):
    # A clean-looking report emitted with a failure exit code (2/3/4) must not pass.
    def fake_run(cmd, **kw):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(_report({"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}), fh)
        return subprocess.CompletedProcess(cmd, 2, "", "scan error: unsupported input")
    monkeypatch.setattr(mg.subprocess, "run", fake_run)
    with pytest.raises(mg.ScanError):
        mg.scan("/some/model.pkl")


def test_scan_accepts_issues_exit_code(monkeypatch):
    # rc=1 means "completed, issues found" -- a valid completed scan.
    def fake_run(cmd, **kw):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(_report({"CRITICAL": 1}), fh)
        return subprocess.CompletedProcess(cmd, 1, "", "")
    monkeypatch.setattr(mg.subprocess, "run", fake_run)
    rep = mg.scan("/some/model.pkl")
    assert mg.decide(rep, "HIGH")["decision"] == "BLOCK"


def test_scan_incomplete_report_raises(monkeypatch):
    # A scanner that writes an empty/garbled-but-valid JSON must not pass.
    def fake_run(cmd, **kw):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump({}, fh)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(mg.subprocess, "run", fake_run)
    with pytest.raises(mg.ScanError):
        mg.scan("/some/model.pkl")


# ---- main() exit codes ----

def test_main_missing_path_returns_2():
    assert mg.main(["/definitely/not/here.pkl"]) == 2


def test_main_block_returns_1(monkeypatch, tmp_path):
    model = tmp_path / "m.pkl"
    model.write_bytes(b"x")
    monkeypatch.setattr(mg, "scan", lambda p, timeout=300: _report({"CRITICAL": 1}))
    assert mg.main([str(model), "--block-on", "HIGH"]) == 1


def test_main_pass_returns_0(monkeypatch, tmp_path):
    model = tmp_path / "m.pkl"
    model.write_bytes(b"x")
    monkeypatch.setattr(mg, "scan", lambda p, timeout=300: _report({"LOW": 2}))
    assert mg.main([str(model), "--json"]) == 0


def test_main_scan_error_returns_2(monkeypatch, tmp_path):
    model = tmp_path / "m.pkl"
    model.write_bytes(b"x")
    def boom(p, timeout=300):
        raise mg.ScanError("no scanner")
    monkeypatch.setattr(mg, "scan", boom)
    assert mg.main([str(model)]) == 2


def test_main_incomplete_report_returns_2(monkeypatch, tmp_path):
    # End-to-end fail-closed: scan returns an empty doc -> decide raises -> exit 2.
    model = tmp_path / "m.pkl"
    model.write_bytes(b"x")
    monkeypatch.setattr(mg, "scan", lambda p, timeout=300: {})
    assert mg.main([str(model)]) == 2
