import json
import subprocess

import pytest

from llm_security_gates import modelscan_gate as mg


def _report(by_severity, total=None, version="0.8.8", errors=None):
    rep = {"summary": {"total_issues_by_severity": by_severity,
                       "total_issues": total if total is not None else sum(by_severity.values()),
                       "modelscan_version": version}}
    if errors is not None:
        rep["errors"] = errors
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


def test_decide_handles_missing_summary():
    v = mg.decide({}, "HIGH")
    assert v["decision"] == "PASS"
    assert v["by_severity"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}


def test_decide_rejects_bad_threshold():
    with pytest.raises(ValueError):
        mg.decide(_report({}), "SEVERE")


def test_decide_coerces_stringy_counts():
    v = mg.decide({"summary": {"total_issues_by_severity": {"CRITICAL": "2"},
                               "total_issues": "2"}}, "HIGH")
    assert v["blocking_issues"] == 2
    assert v["total_issues"] == 2


# ---- has_scan_errors() ----

def test_has_scan_errors():
    assert mg.has_scan_errors(_report({}, errors=["boom"])) is True
    assert mg.has_scan_errors(_report({})) is False


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


def test_main_reports_modelscan_errors_returns_2(monkeypatch, tmp_path):
    model = tmp_path / "m.pkl"
    model.write_bytes(b"x")
    monkeypatch.setattr(mg, "scan", lambda p, timeout=300: _report({"LOW": 0}, errors=["parse fail"]))
    assert mg.main([str(model)]) == 2
