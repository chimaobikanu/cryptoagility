"""Tests for the runtime TLS handshake observation layer."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime"))

import ca_probe  # noqa: E402


def _record(hs_type: int, body: bytes) -> bytes:
    """Wrap a handshake message in a TLS record."""
    hs = bytes([hs_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def _server_hello(suite: int, version: int | None = None, sid: bytes = b"") -> bytes:
    body = b"\x03\x03" + b"\x00" * 32 + bytes([len(sid)]) + sid
    body += suite.to_bytes(2, "big") + b"\x00"          # cipher + compression
    exts = b""
    if version is not None:
        exts += b"\x00\x2b" + (2).to_bytes(2, "big") + version.to_bytes(2, "big")
    body += len(exts).to_bytes(2, "big") + exts
    return _record(2, body)


def _client_hello(suites: list[int], version: int = 0x0303) -> bytes:
    body = version.to_bytes(2, "big") + b"\x00" * 32 + b"\x00"   # ver, random, no sid
    cs = b"".join(s.to_bytes(2, "big") for s in suites)
    body += len(cs).to_bytes(2, "big") + cs + b"\x01\x00"        # suites, compression
    return _record(1, body)


# --------------------------------------------------------------------------- #
# Cipher name mapping
# --------------------------------------------------------------------------- #

def test_known_ciphers_are_named():
    assert ca_probe.cipher_name(0x1302) == "TLS_AES_256_GCM_SHA384"
    assert ca_probe.cipher_name(0xC030) == "ECDHE-RSA-AES256-GCM-SHA384"
    assert ca_probe.cipher_name(0x000A) == "DES-CBC3-SHA"


def test_unknown_cipher_keeps_its_code_point():
    assert ca_probe.cipher_name(0x9999) == "UNKNOWN-0x9999"


# --------------------------------------------------------------------------- #
# Handshake parsing
# --------------------------------------------------------------------------- #

def test_parses_negotiated_tls12_cipher():
    hs = ca_probe.parse_handshake(_server_hello(0xC030))
    assert hs["kind"] == "server_hello"
    assert hs["negotiated_suite"] == "ECDHE-RSA-AES256-GCM-SHA384"
    assert hs["negotiated_version"] == "TLS1.2"


def test_parses_tls13_negotiated_version():
    """Regression: a TLS 1.3 ServerHello carries 0x0303 in legacy_version and the
    real version in the supported_versions extension. Reading the extension block
    from the wrong offset silently reports TLS 1.3 as TLS 1.2."""
    hs = ca_probe.parse_handshake(_server_hello(0x1302, version=0x0304))
    assert hs["negotiated_suite"] == "TLS_AES_256_GCM_SHA384"
    assert hs["negotiated_version"] == "TLS1.3", "TLS 1.3 must not be reported as 1.2"


def test_tls13_with_session_id_still_parses():
    """A non-empty session id must not shift the extension offset."""
    hs = ca_probe.parse_handshake(_server_hello(0x1301, version=0x0304, sid=b"\xab" * 32))
    assert hs["negotiated_version"] == "TLS1.3"
    assert hs["negotiated_suite"] == "TLS_AES_128_GCM_SHA256"


def test_parses_client_hello_offered_suites():
    hs = ca_probe.parse_handshake(_client_hello([0x1301, 0x1302, 0x1303]))
    assert hs["kind"] == "client_hello"
    assert hs["offered_suites"] == [
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
    assert hs["offered_count"] == 3


def test_scsv_markers_are_not_reported_as_ciphers():
    hs = ca_probe.parse_handshake(_client_hello([0x1301, 0x00FF, 0x5600]))
    assert "EMPTY_RENEGOTIATION_INFO_SCSV" not in hs["offered_suites"]
    assert "TLS_FALLBACK_SCSV" not in hs["offered_suites"]


def test_non_handshake_records_are_ignored():
    assert ca_probe.parse_handshake(b"\x17\x03\x03\x00\x05hello") is None


def test_truncated_records_do_not_raise():
    assert ca_probe.parse_handshake(b"\x16\x03\x03") is None
    assert ca_probe.parse_handshake(b"") is None


# --------------------------------------------------------------------------- #
# Bit mapping
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cipher,bits", [
    ("AES_256_GCM_SHA384", 256),
    ("ECDHE-RSA-AES128-GCM-SHA256", 128),
    ("ECDHE-RSA-CHACHA20-POLY1305", 256),
    ("DES-CBC3-SHA", 112),
])
def test_cipher_bits(cipher, bits):
    assert ca_probe._cipher_bits(cipher) == bits
