import pytest

from llm_security_gates import garak_harness as gh


def _eval(probe, detector, passed, total):
    return {"entry_type": "eval", "probe": probe, "detector": detector,
            "passed": passed, "total_evaluated": total}


# ---- score_from_evals() ----

def test_score_mean_and_weakest():
    evals = {
        ("a", "d"): _eval("a", "d", 8, 10),   # 0.8
        ("b", "d"): _eval("b", "d", 5, 10),   # 0.5  <- weakest
        ("c", "d"): _eval("c", "d", 10, 10),  # 1.0
    }
    s = gh.score_from_evals(evals)
    assert s["resilience_score"] == round((0.8 + 0.5 + 1.0) / 3, 4)
    assert s["attack_success_rate"] == round(1 - s["resilience_score"], 4)
    assert s["weakest_probe"] == "b"


def test_score_excludes_zero_total_from_mean():
    evals = {
        ("a", "d"): _eval("a", "d", 4, 8),    # 0.5 scorable
        ("z", "d"): _eval("z", "d", 0, 0),    # not scorable
    }
    s = gh.score_from_evals(evals)
    assert s["resilience_score"] == 0.5  # zero-total probe ignored
    assert any(p["pass_rate"] is None for p in s["probes"])


def test_score_all_zero_total_is_none():
    evals = {("z", "d"): _eval("z", "d", 0, 0)}
    s = gh.score_from_evals(evals)
    assert s["resilience_score"] is None
    assert s["attack_success_rate"] is None
    assert s["weakest_probe"] is None


def test_score_single_probe():
    s = gh.score_from_evals({("a", "d"): _eval("a", "d", 3, 4)})
    assert s["resilience_score"] == 0.75
    assert s["weakest_probe"] == "a"


# ---- parse_report() ----

def _write(tmp_path, prefix, lines):
    p = tmp_path / f"{prefix}.report.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_parse_report_reads_evals_and_dedupes(tmp_path):
    import json
    lines = [
        json.dumps({"entry_type": "start"}),
        json.dumps(_eval("a", "d", 1, 10)),   # superseded
        "   ",                                  # blank
        "broken json {{{",                      # malformed -> skipped
        json.dumps(_eval("a", "d", 9, 10)),   # last wins
        json.dumps(_eval("b", "d", 2, 5)),
    ]
    _write(tmp_path, "selftest_x_0", lines)
    evals = gh.parse_report("selftest_x_0", report_dir=str(tmp_path))
    assert evals[("a", "d")]["passed"] == 9   # last-wins dedup
    assert set(evals) == {("a", "d"), ("b", "d")}


def test_parse_report_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        gh.parse_report("nope", report_dir=str(tmp_path))


def test_parse_report_no_evals(tmp_path):
    import json
    _write(tmp_path, "empty_0", [json.dumps({"entry_type": "start"})])
    with pytest.raises(ValueError):
        gh.parse_report("empty_0", report_dir=str(tmp_path))


# ---- _safe() ----

def test_safe_sanitizes_model_name():
    assert gh._safe("vendor/model:v1 beta") == "vendor_model_v1_beta"


# ---- score_model() integration (garak stubbed) ----

def test_score_model_parses_after_run(monkeypatch, tmp_path):
    import json
    _write(tmp_path, "selftest_m_0", [json.dumps(_eval("a", "d", 7, 10))])

    class Proc:
        returncode = 0
    monkeypatch.setattr(gh, "_run_garak", lambda *a, **k: Proc())
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] == 0.7
    assert out["status"] == "OK"


def test_score_model_reports_missing_report(monkeypatch, tmp_path):
    class Proc:
        returncode = 0
    monkeypatch.setattr(gh, "_run_garak", lambda *a, **k: Proc())
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 9, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] is None
    assert out["status"].startswith("ERROR")
