"""Tests for the CryptoAgility discovery core."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runtime"))

import cryptoagility as ca          # noqa: E402
from cryptoagility import Finding   # noqa: E402


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("algo,quantum,classical", [
    ("RSA", "shor-broken", "broken"),
    ("ECDSA", "shor-broken", "ok"),
    ("ECDH", "shor-broken", "ok"),
    ("Ed25519", "shor-broken", "ok"),
    ("MD5", "grover-weakened", "broken"),
    ("SHA-1", "grover-weakened", "broken"),
    ("3DES", "grover-weakened", "broken"),
    ("AES-256", "resistant", "ok"),
    ("SHA-256", "resistant", "ok"),
    ("ML-KEM", "resistant", "ok"),
])
def test_classification(algo, quantum, classical):
    _, q, c, advice = ca.classify(algo)
    assert q == quantum, f"{algo} quantum risk"
    assert c == classical, f"{algo} classical risk"
    assert advice, f"{algo} must carry migration advice"


def test_every_public_key_algorithm_is_shor_broken():
    """No public-key algorithm may be classified as safe: Shor breaks them all."""
    for algo in ("RSA", "ECDSA", "ECDH", "DSA", "Ed25519", "X25519"):
        assert ca.classify(algo)[1] == "shor-broken"


# --------------------------------------------------------------------------- #
# Cipher-suite parsing
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cipher,expected", [
    ("ECDHE-RSA-AES256-GCM-SHA384", {"ECDH", "RSA", "AES-256", "SHA-384"}),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", {"ECDH", "ECDSA", "ChaCha20"}),
    ("DHE-RSA-AES128-SHA256", {"DH", "RSA", "AES-128", "SHA-256"}),
    ("AES128-SHA", {"AES-128", "SHA-1"}),
    ("TLS_AES_256_GCM_SHA384", {"AES-256", "SHA-384"}),
    ("TLS_CHACHA20_POLY1305_SHA256", {"ChaCha20", "SHA-256"}),
])
def test_parse_cipher_algorithms(cipher, expected):
    got = set(ca.parse_cipher_algorithms(cipher))
    assert got == expected, f"{cipher} -> {got}"


def test_tls13_suite_infers_no_key_exchange():
    """TLS 1.3 suite names omit the key exchange; we must not invent one."""
    got = ca.parse_cipher_algorithms("TLS_AES_256_GCM_SHA384")
    assert "RSA" not in got and "ECDH" not in got and "DH" not in got


def test_ecdh_does_not_leak_ecdsa_or_dh():
    got = ca.parse_cipher_algorithms("ECDHE-RSA-AES256-GCM-SHA384")
    assert "ECDSA" not in got, "'ECDHE' must not be read as 'ECDSA'"
    assert "DH" not in got, "'ECDHE' must not be read as plain 'DH'"


def test_chacha20_suite_does_not_claim_sha1():
    got = ca.parse_cipher_algorithms("ECDHE-ECDSA-CHACHA20-POLY1305")
    assert "SHA-1" not in got, "'POLY1305' must not be read as a bare SHA suffix"


# --------------------------------------------------------------------------- #
# Static detection
# --------------------------------------------------------------------------- #

def test_detects_rsa_in_python(tmp_path):
    f = tmp_path / "k.py"
    f.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                 "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    found = {x.algorithm for x in ca.scan_source(f)}
    assert "RSA" in found


def test_detects_md5_and_flags_it_broken(tmp_path):
    f = tmp_path / "h.py"
    f.write_text("import hashlib\nhashlib.md5(b'x').hexdigest()\n")
    hits = [x for x in ca.scan_source(f) if x.algorithm == "MD5"]
    assert hits and hits[0].classical == "broken" and hits[0].action_required


def test_no_findings_on_clean_file(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    assert ca.scan_source(f) == []


def test_unknown_extensions_are_skipped(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text("RSA-2048 was used historically\n")
    assert ca.scan_source(f) == []


# --------------------------------------------------------------------------- #
# Runtime ingestion
# --------------------------------------------------------------------------- #

def test_load_runtime_parses_negotiated_records(tmp_path):
    log = tmp_path / "rt.jsonl"
    log.write_text(json.dumps({
        "event": "negotiated", "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "version": "TLS1.2", "bits": 256, "detail": "Selected by server",
    }) + "\n")
    findings = ca.load_runtime(log)
    algos = {f.algorithm for f in findings}
    assert {"ECDH", "RSA", "AES-256", "SHA-384"} <= algos
    assert all(f.language == "runtime" for f in findings)


def test_load_runtime_ignores_malformed_lines(tmp_path):
    log = tmp_path / "rt.jsonl"
    log.write_text("not json\n{\"no_cipher\": true}\n\n")
    assert ca.load_runtime(log) == []


def test_load_runtime_missing_file_is_empty():
    assert ca.load_runtime("/nonexistent/path.jsonl") == []


# --------------------------------------------------------------------------- #
# CBOM
# --------------------------------------------------------------------------- #

def _findings():
    return [
        Finding("a.py", 1, "python", "x", "RSA", "pke", "shor-broken", "broken", "", "rsa"),
        Finding("b.js", 2, "javascript", "y", "MD5", "hash", "grover-weakened", "broken", "", "md5"),
        Finding("(runtime)", 0, "runtime", "z", "AES-256", "block-cipher", "resistant", "ok", "256", "tls"),
    ]


def test_cbom_is_valid_cyclonedx(tmp_path):
    cbom = ca.build_cbom(_findings(), str(tmp_path))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert cbom["components"], "CBOM must contain components"
    for c in cbom["components"]:
        assert c["type"] == "cryptographic-asset"
        assert "cryptoProperties" in c
        assert c["cryptoProperties"]["assetType"] == "algorithm"


def test_cbom_marks_observed_in_use():
    cbom = ca.build_cbom(_findings(), "/tmp")
    by_name = {c["name"]: c for c in cbom["components"]}
    def flag(name):
        return next(p["value"] for p in by_name[name]["properties"]
                    if p["name"] == "cryptoagility:observedInUse")
    assert flag("AES-256") == "true", "runtime-observed asset must be flagged"
    assert flag("RSA") == "false", "static-only asset must not be flagged as in use"
    assert flag("MD5") == "false", "static-only asset must not be flagged"


def test_cbom_quantum_level_for_shor_broken_is_zero():
    cbom = ca.build_cbom(_findings(), "/tmp")
    rsa = next(c for c in cbom["components"] if c["name"] == "RSA")
    props = rsa["cryptoProperties"]["algorithmProperties"]
    assert props["nistQuantumSecurityLevel"] == 0


def test_cbom_deduplicates():
    dupes = _findings() + _findings()
    cbom = ca.build_cbom(dupes, "/tmp")
    names = [c["name"] for c in cbom["components"]]
    assert len(names) == len(set(names)), "duplicate assets must be merged"


def test_cbom_is_json_serialisable():
    json.dumps(ca.build_cbom(_findings(), "/tmp"))


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def test_report_counts_and_advice():
    report = ca.build_report(_findings(), "/tmp")
    assert "Cryptographic Discovery Report" in report
    assert "ML-KEM" in report or "FIPS 203" in report
    assert "| RSA |" in report


def test_report_includes_runtime_section_only_when_present():
    assert "Observed in use" not in ca.build_report([_findings()[0]], "/tmp")
    assert "Observed in use" in ca.build_report(_findings(), "/tmp")


def test_report_runtime_section_carries_protocol_column():
    report = ca.build_report(_findings(), "/tmp")
    assert "TLS negotiated cipher" in report or "TLS1" in report or "(runtime)" in report


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #

def test_certificate_scan_reads_rsa_key_size():
    cert = ROOT / "sample" / "payments.pem"
    if not cert.exists():
        pytest.skip("sample certificate not present")
    found = ca.scan_certificate(cert)
    assert found, "certificate must yield a finding"
    assert found[0].algorithm == "RSA"
    assert found[0].key_size == "2048"
    assert found[0].quantum == "shor-broken"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def test_cli_produces_cbom_and_report(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    cbom, report = tmp_path / "c.json", tmp_path / "r.md"
    monkeypatch.setattr(sys, "argv", [
        "cryptoagility", str(src), "--cbom", str(cbom), "--report", str(report)])
    # MD5 is present, so the gate must fire
    assert ca.main() == 1
    assert json.loads(cbom.read_text())["bomFormat"] == "CycloneDX"
    assert "Discovery Report" in report.read_text()


def test_cli_exit_zero_flag_suppresses_the_gate(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setattr(sys, "argv", [
        "cryptoagility", str(src), "--cbom", str(tmp_path / "c.json"), "--exit-zero"])
    assert ca.main() == 0


def test_cli_clean_tree_exits_zero(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("def add(a, b):\n    return a + b\n")
    monkeypatch.setattr(sys, "argv", ["cryptoagility", str(src)])
    assert ca.main() == 0


def test_cli_missing_path_returns_2(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["cryptoagility", str(tmp_path / "nope")])
    assert ca.main() == 2
