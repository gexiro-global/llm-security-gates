import sys
import types

import pytest

from llm_security_gates import llmguard_scan as ls


# ---- parse_scanner_names() ----

def test_parse_scanner_names_trims_and_drops_blanks():
    assert ls.parse_scanner_names(" secrets , , invisible_text ") == ["secrets", "invisible_text"]
    assert ls.parse_scanner_names("") == []
    assert ls.parse_scanner_names(None) == []


# ---- _reject_unknown() ----

def test_reject_unknown_raises():
    with pytest.raises(ValueError):
        ls._reject_unknown(["secrets", "nope"], {"secrets": 1})


def test_reject_unknown_ok():
    ls._reject_unknown(["secrets"], {"secrets": 1, "invisible_text": 2})  # no raise


# ---- _shape() ----

def test_shape_blocked_when_any_invalid():
    res = ls._shape("input", "orig", "orig",
                    {"secrets": True, "prompt_injection": False},
                    {"secrets": 0.0, "prompt_injection": 1.0}, 5.0)
    assert res["blocked"] is True
    assert res["per_scanner"]["prompt_injection"]["risk"] == 1.0
    assert res["sanitized_changed"] is False
    assert res["mode"] == "input"


def test_shape_pass_when_all_valid():
    res = ls._shape("output", "orig", "redacted",
                    {"sensitive": True}, {"sensitive": 0.0}, 1.0)
    assert res["blocked"] is False
    assert res["sanitized_changed"] is True


def test_shape_empty_scanners_never_blocks():
    res = ls._shape("input", "orig", "orig", {}, {}, 0.0)
    assert res["blocked"] is False
    assert res["per_scanner"] == {}


def test_shape_missing_risk_is_none():
    res = ls._shape("input", "o", "o", {"secrets": True}, {}, 0.0)
    assert res["per_scanner"]["secrets"]["risk"] is None


# ---- scan_input()/scan_output_text() via an injected fake llm_guard ----

@pytest.fixture
def fake_llm_guard(monkeypatch):
    mod = types.ModuleType("llm_guard")

    def scan_prompt(scanners, text):
        # pretend a scanner sanitized the text and flagged one thing
        return text + "[san]", {"secrets": False}, {"secrets": 0.9}

    def scan_output(scanners, prompt, output):
        return output, {"sensitive": True}, {"sensitive": 0.0}

    mod.scan_prompt = scan_prompt
    mod.scan_output = scan_output
    monkeypatch.setitem(sys.modules, "llm_guard", mod)
    return mod


def test_scan_input_uses_library(fake_llm_guard):
    res = ls.scan_input("hello", scanners=["secrets"])
    assert res["blocked"] is True
    assert res["sanitized_changed"] is True
    assert res["per_scanner"]["secrets"]["risk"] == 0.9
    assert isinstance(res["elapsed_ms"], float)


def test_scan_output_uses_library(fake_llm_guard):
    res = ls.scan_output_text("prompt", "reply", scanners=["sensitive"])
    assert res["blocked"] is False
    assert res["mode"] == "output"
