import json

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
    assert s["resilience_score"] == 0.5
    assert any(p["pass_rate"] is None for p in s["probes"])


def test_score_all_zero_total_is_none():
    s = gh.score_from_evals({("z", "d"): _eval("z", "d", 0, 0)})
    assert s["resilience_score"] is None
    assert s["weakest_probe"] is None


def test_score_single_probe():
    s = gh.score_from_evals({("a", "d"): _eval("a", "d", 3, 4)})
    assert s["resilience_score"] == 0.75


# ---- parse_report() ----

def _write(tmp_path, prefix, lines):
    p = tmp_path / f"{prefix}.report.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def test_parse_report_reads_evals_and_dedupes(tmp_path):
    lines = [
        json.dumps({"entry_type": "start"}),
        json.dumps(_eval("a", "d", 1, 10)),
        "   ",
        "broken json {{{",
        json.dumps(_eval("a", "d", 9, 10)),   # last wins
        json.dumps(_eval("b", "d", 2, 5)),
    ]
    _write(tmp_path, "selftest_x_0", lines)
    evals = gh.parse_report("selftest_x_0", report_dir=str(tmp_path))
    assert evals[("a", "d")]["passed"] == 9
    assert set(evals) == {("a", "d"), ("b", "d")}


def test_parse_report_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        gh.parse_report("nope", report_dir=str(tmp_path))


def test_parse_report_no_evals(tmp_path):
    _write(tmp_path, "empty_0", [json.dumps({"entry_type": "start"})])
    with pytest.raises(ValueError):
        gh.parse_report("empty_0", report_dir=str(tmp_path))


def test_parse_report_rejects_stale(tmp_path):
    import os
    p = _write(tmp_path, "stale_0", [json.dumps(_eval("a", "d", 1, 1))])
    future = os.path.getmtime(p) + 1000  # require newer than the file
    with pytest.raises(gh.AssuranceError):
        gh.parse_report("stale_0", report_dir=str(tmp_path), min_mtime=future)


# ---- _safe() ----

def test_safe_sanitizes_model_name():
    assert gh._safe("vendor/model:v1 beta") == "vendor_model_v1_beta"


# ---- score_model(): fail-closed on rc!=0 and missing report ----

def _fake_garak_writing(tmp_path, lines, returncode):
    """Return a fake _run_garak that writes the report at the given prefix."""
    class Proc:
        pass
    def fake(model, base_url, api_key, probes, generations, prefix, timeout):
        _write(tmp_path, prefix, lines)
        p = Proc()
        p.returncode = returncode
        return p
    return fake


def test_score_model_scores_fresh_report(monkeypatch, tmp_path):
    monkeypatch.setattr(gh, "_run_garak",
                        _fake_garak_writing(tmp_path, [json.dumps(_eval("a", "d", 7, 10))], 0))
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] == 0.7
    assert out["status"] == "OK"


def test_score_model_nonzero_exit_is_error(monkeypatch, tmp_path):
    # Even with a perfect report present, a nonzero garak exit must NOT score OK.
    monkeypatch.setattr(gh, "_run_garak",
                        _fake_garak_writing(tmp_path, [json.dumps(_eval("a", "d", 10, 10))], 2))
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] is None
    assert out["status"].startswith("ERROR")


def test_score_model_missing_report_is_error(monkeypatch, tmp_path):
    class Proc:
        returncode = 0
    monkeypatch.setattr(gh, "_run_garak", lambda *a, **k: Proc())
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] is None
    assert out["status"].startswith("ERROR")


def test_score_model_rejects_backdated_report(monkeypatch, tmp_path):
    # End-to-end freshness: a report whose mtime predates the run start (a stale
    # leftover) must be rejected, with no time slack.
    import os
    def fake(model, base_url, api_key, probes, generations, prefix, timeout):
        p = _write(tmp_path, prefix, [json.dumps(_eval("a", "d", 10, 10))])
        os.utime(p, (1_000_000_000, 1_000_000_000))  # backdate to year 2001
        class Proc:
            returncode = 0
        return Proc()
    monkeypatch.setattr(gh, "_run_garak", fake)
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] is None
    assert out["status"].startswith("ERROR")
    assert "stale" in out["status"]


def test_new_prefix_is_unique():
    a = gh._new_prefix("m", 0)
    b = gh._new_prefix("m", 0)
    assert a != b  # uuid suffix prevents stale-report reuse across runs


def test_score_model_refuses_preexisting_report(monkeypatch, tmp_path):
    # Pin the prefix and pre-create its report: score_model must refuse to reuse it.
    monkeypatch.setattr(gh, "_new_prefix", lambda model, index: "pinned_0")
    _write(tmp_path, "pinned_0", [json.dumps(_eval("a", "d", 10, 10))])
    def _should_not_run(*a, **k):
        raise AssertionError("garak must not run when the report path already exists")
    monkeypatch.setattr(gh, "_run_garak", _should_not_run)
    out = gh.score_model("m", "http://x/v1", "key", "a", 1, 0, 60, report_dir=str(tmp_path))
    assert out["resilience_score"] is None
    assert "already exists" in out["status"]


# ---- main(): whole-fleet gate ----

def _canned(results_by_model):
    def fake(model, *a, **k):
        return {"model": model, "resilience_score": results_by_model[model],
                "attack_success_rate": None, "weakest_probe": None,
                "probes": [], "status": "OK"}
    return fake


def test_main_requires_all_models_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setattr(gh, "score_model", _canned({"a": 0.9, "b": None}))
    rc = gh.main(["--models", "a,b", "--out", str(tmp_path / "o.json")])
    assert rc == 1  # b unscored -> fleet gate fails


def test_main_all_scored_passes(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setattr(gh, "score_model", _canned({"a": 0.9, "b": 0.8}))
    rc = gh.main(["--models", "a,b", "--out", str(tmp_path / "o.json")])
    assert rc == 0


def test_main_allow_partial_passes_on_any(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "k")
    monkeypatch.setattr(gh, "score_model", _canned({"a": 0.9, "b": None}))
    rc = gh.main(["--models", "a,b", "--allow-partial", "--out", str(tmp_path / "o.json")])
    assert rc == 0


def test_main_missing_api_key_returns_2(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    rc = gh.main(["--models", "a", "--out", str(tmp_path / "o.json")])
    assert rc == 2
