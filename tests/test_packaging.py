"""Guard the dependency-pinning fix: every optional/dev dependency must keep an
upper bound so a future incompatible/compromised release cannot be auto-admitted.
"""
import os

import pytest

tomllib = pytest.importorskip("tomllib")  # stdlib on 3.11+; skip on 3.9/3.10

PYPROJECT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pyproject.toml")


def _load():
    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


def test_all_optional_deps_have_upper_bounds():
    data = _load()
    extras = data["project"]["optional-dependencies"]
    offenders = []
    for group, specs in extras.items():
        for spec in specs:
            # every declared dependency must constrain the top end
            if "<" not in spec:
                offenders.append(f"{group}: {spec}")
    assert not offenders, f"dependencies without an upper bound: {offenders}"


def test_extras_cover_each_gate():
    extras = _load()["project"]["optional-dependencies"]
    for required in ("modelscan", "llmguard", "proxy", "garak", "dev"):
        assert required in extras
