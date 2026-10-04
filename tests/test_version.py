"""Guards against the reported version drifting from the released version.

The CLI banner, the CBOM ``tools[].version`` field and the report header all come
from ``cryptoagility.VERSION``. If that drifts from ``pyproject.toml``, the tool
misreports its own version and every bug report filed against it is wrong -- which
is exactly what happened with the hardcoded ``0.1.0-mvp`` string.
"""
import pathlib
import re

import pytest

import cryptoagility
from cryptoagility import build_cbom, build_report, walk


def _declared_version() -> str:
    pyproject = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not present (installed package, not a source checkout)")
    text = pyproject.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    assert match, "no version field found in pyproject.toml"
    return match.group(1)


def test_fallback_version_matches_pyproject():
    """The source-checkout fallback must equal the version being released."""
    assert cryptoagility._FALLBACK_VERSION == _declared_version(), (
        f"cryptoagility._FALLBACK_VERSION is {cryptoagility._FALLBACK_VERSION!r} "
        f"but pyproject.toml declares {_declared_version()!r}"
    )


def test_reported_version_is_a_release_version_not_a_placeholder():
    """No '-mvp', '-dev' or empty version should ever reach a user."""
    assert cryptoagility.VERSION, "VERSION must not be empty"
    assert "-mvp" not in cryptoagility.VERSION
    assert re.match(r"^\d+\.\d+\.\d+", cryptoagility.VERSION), (
        f"VERSION {cryptoagility.VERSION!r} is not a release version"
    )


def test_version_appears_in_cbom_and_report(tmp_path):
    """Whatever VERSION says must be what the generated artefacts say."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")

    findings = walk(src)
    cbom = build_cbom(findings, str(src))
    assert cbom["metadata"]["tools"][0]["version"] == cryptoagility.VERSION

    report = build_report(findings, str(src))
    assert cryptoagility.VERSION in report
