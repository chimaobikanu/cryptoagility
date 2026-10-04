#!/usr/bin/env python3
"""
CryptoAgility — cryptographic asset discovery + CBOM generator (MVP).

Scans a codebase and/or certificate store for cryptographic usage, classifies each
finding by its exposure to quantum attack, and emits:
  1. a CycloneDX 1.6 Cryptography Bill of Materials (CBOM), and
  2. a human-readable migration report.

This is the discovery layer of the product: static analysis across source and
configuration, plus certificate key inspection. Runtime (eBPF) and hardware/HSM
inventory are the layers that follow.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path

# The version reported to users and written into the CBOM. The installed
# distribution is authoritative; a source checkout falls back to the constant
# below. tests/test_version.py asserts that constant against pyproject.toml so
# the two cannot drift apart silently.
_FALLBACK_VERSION = "0.1.2"
try:
    from importlib.metadata import PackageNotFoundError as _PNF, version as _dist_version
    try:
        VERSION = _dist_version("cryptoagility")
    except _PNF:
        VERSION = _FALLBACK_VERSION
except Exception:                                    # pragma: no cover
    VERSION = _FALLBACK_VERSION

# --------------------------------------------------------------------------- #
# Classification model
# --------------------------------------------------------------------------- #

# quantum: shor-broken (public-key, broken outright) | grover-weakened (symmetric
# margin reduced) | resistant (PQC or sufficient symmetric margin)
# classical: broken (already unsafe) | legacy (deprecated) | ok
CLASSES = {
    "RSA":        ("pke",          "shor-broken",     "broken",  "Migrate to ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures"),
    "DSA":        ("signature",    "shor-broken",     "broken",  "Retire. Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"),
    "DH":         ("key-agree",    "shor-broken",     "legacy",  "Migrate to ML-KEM (FIPS 203) or a hybrid such as X25519MLKEM768"),
    "ECDH":       ("key-agree",    "shor-broken",     "ok",      "Migrate to ML-KEM (FIPS 203) or hybrid X25519MLKEM768"),
    "ECDSA":      ("signature",    "shor-broken",     "ok",      "Migrate to ML-DSA (FIPS 204)"),
    "EdDSA":      ("signature",    "shor-broken",     "ok",      "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"),
    "Ed25519":    ("signature",    "shor-broken",     "ok",      "Migrate to ML-DSA (FIPS 204)"),
    "X25519":     ("key-agree",    "shor-broken",     "ok",      "Migrate to hybrid X25519MLKEM768"),
    "AES-256":    ("block-cipher", "resistant",       "ok",      "Retain. 256-bit key retains adequate margin under Grover"),
    "AES-192":    ("block-cipher", "resistant",       "ok",      "Retain."),
    "AES-128":    ("block-cipher", "grover-weakened", "ok",      "Consider AES-256 for long-lived data"),
    "AES":        ("block-cipher", "grover-weakened", "ok",      "Confirm key size is 256-bit for long-lived data"),
    "ChaCha20":   ("stream-cipher","resistant",       "ok",      "Retain."),
    "3DES":       ("block-cipher", "grover-weakened", "broken",  "Retire. Migrate to AES-256-GCM"),
    "DES":        ("block-cipher", "grover-weakened", "broken",  "Retire. Migrate to AES-256-GCM"),
    "RC4":        ("stream-cipher","resistant",       "broken",  "Retire immediately."),
    "SHA-512":    ("hash",         "resistant",       "ok",      "Retain."),
    "SHA-384":    ("hash",         "resistant",       "ok",      "Retain."),
    "SHA-256":    ("hash",         "resistant",       "ok",      "Retain."),
    "SHA-1":      ("hash",         "grover-weakened", "broken",  "Retire. Migrate to SHA-256 or SHA-384"),
    "MD5":        ("hash",         "grover-weakened", "broken",  "Retire. Migrate to SHA-256"),
    "ML-KEM":     ("kem",          "resistant",       "ok",      "Post-quantum. Retain."),
    "Kyber":      ("kem",          "resistant",       "ok",      "Post-quantum (pre-standard name for ML-KEM). Retain."),
    "ML-DSA":     ("signature",    "resistant",       "ok",      "Post-quantum. Retain."),
    "Dilithium":  ("signature",    "resistant",       "ok",      "Post-quantum (pre-standard name for ML-DSA). Retain."),
    "SLH-DSA":    ("signature",    "resistant",       "ok",      "Post-quantum. Retain."),
    "SPHINCS":    ("signature",    "resistant",       "ok",      "Post-quantum. Retain."),
}

NIST_QSL = {"shor-broken": 0, "grover-weakened": 1, "resistant": 5}

RISK_ORDER = {"shor-broken": 0, "grover-weakened": 1, "resistant": 2}


@dataclass
class Finding:
    path: str
    line: int
    language: str
    api: str
    algorithm: str
    primitive: str
    quantum: str
    classical: str
    key_size: str = ""
    evidence: str = ""

    @property
    def recommendation(self) -> str:
        return CLASSES.get(self.algorithm, ("", "", "", "Review manually"))[3]

    @property
    def action_required(self) -> bool:
        return self.quantum == "shor-broken" or self.classical == "broken"


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    language: str
    regex: re.Pattern
    algorithm: str
    api: str
    key_group: str | None = None   # named group holding key size, if present


def R(lang: str, pattern: str, algorithm: str, api: str, key_group: str | None = None) -> Rule:
    return Rule(lang, re.compile(pattern), algorithm, api, key_group)


RULES: list[Rule] = [
    # --- Python ------------------------------------------------------------ #
    R("python", r"\brsa\.generate_private_key|\bRSA\.generate|\bRSA\.import_key|asymmetric\.rsa\b", "RSA", "Python cryptography RSA", r"bits=(?P<key>\d{3,4})"),
    R("python", r"\bec\.generate_private_key|asymmetric\.ec\b|EllipticCurve\(", "ECDSA", "Python cryptography EC"),
    R("python", r"\bed25519\.Ed25519PrivateKey|Ed25519", "Ed25519", "Python cryptography Ed25519"),
    R("python", r"\bx25519\.X25519PrivateKey|X25519", "X25519", "Python cryptography X25519"),
    R("python", r"\bdsa\.generate_private_key|asymmetric\.dsa\b", "DSA", "Python cryptography DSA"),
    R("python", r"\bCrypto\.PublicKey\.RSA|from\s+Crypto\.PublicKey\s+import\s+RSA", "RSA", "PyCryptodome RSA"),
    R("python", r"\bDES3\.new|\bDES\.new|Crypto\.Cipher\.DES", "3DES", "PyCryptodome DES/3DES"),
    R("python", r"\bARC4\.|\bRC4\b", "RC4", "PyCryptodome RC4"),
    R("python", r"hashlib\.md5|\bMD5\.new", "MD5", "Python hashlib MD5"),
    R("python", r"hashlib\.sha1|\bSHA1?\.new", "SHA-1", "Python hashlib SHA-1"),
    R("python", r"algorithms\.AES(?:\((?P<key>\d{3})\))?|AES\.MODE_GCM|AES\.MODE_CBC", "AES", "Python cryptography AES", r"\((?P<key>\d{3})\)"),
    R("python", r"rsa\.GenerateKey|ecdsa\.GenerateKey|ecdsa\.generate_private_key", "ECDSA", "Python ecdsa lib"),

    # --- JavaScript / TypeScript ------------------------------------------- #
    R("javascript", r"generateKeyPairSync\(\s*['\"]rsa['\"]|['\"]rsa['\"]\s*,\s*\{", "RSA", "Node crypto RSA"),
    R("javascript", r"generateKeyPairSync\(\s*['\"]ec['\"]|namedCurve", "ECDSA", "Node crypto EC"),
    R("javascript", r"ed25519|generateKeyPairSync\(\s*['\"]ed25519['\"]", "Ed25519", "Node crypto Ed25519"),
    R("javascript", r"createHash\(\s*['\"]md5['\"]", "MD5", "Node crypto MD5"),
    R("javascript", r"createHash\(\s*['\"]sha1['\"]", "SHA-1", "Node crypto SHA-1"),
    R("javascript", r"createHash\(\s*['\"]sha256['\"]", "SHA-256", "Node crypto SHA-256"),
    R("javascript", r"createCipheriv\(\s*['\"]aes-(?P<key>\d{3})", "AES", "Node crypto AES", r"aes-(?P<key>\d{3})"),
    R("javascript", r"des-ede3|createCipheriv\(\s*['\"]des", "3DES", "Node crypto DES/3DES"),
    R("javascript", r"algorithm\s*:\s*['\"]RS\d{3}['\"]|sign\(\s*['\"]RS\d{3}", "RSA", "JWT RS*/PS* signature"),
    R("javascript", r"['\"]ES\d{3}['\"]|algorithm\s*:\s*['\"]ES\d{3}", "ECDSA", "JWT ES* signature"),
    R("javascript", r"generateKey\(\s*\{[^}]*ECDSA|name:\s*['\"]ECDSA['\"]", "ECDSA", "WebCrypto ECDSA"),
    R("javascript", r"generateKey\(\s*\{[^}]*RSA", "RSA", "WebCrypto RSA"),

    # --- Java / Kotlin ------------------------------------------------------ #
    R("java", r"KeyPairGenerator\.getInstance\(\s*\"RSA\"", "RSA", "Java KeyPairGenerator RSA"),
    R("java", r"KeyPairGenerator\.getInstance\(\s*\"EC\"", "ECDSA", "Java KeyPairGenerator EC"),
    R("java", r"KeyPairGenerator\.getInstance\(\s*\"DSA\"", "DSA", "Java KeyPairGenerator DSA"),
    R("java", r"Signature\.getInstance\(\s*\"SHA1withRSA\"|\"SHA1with", "SHA-1", "Java SHA1withRSA signature"),
    R("java", r"Signature\.getInstance\(\s*\"SHA256withRSA\"", "RSA", "Java SHA256withRSA signature"),
    R("java", r"MessageDigest\.getInstance\(\s*\"MD5\"", "MD5", "Java MessageDigest MD5"),
    R("java", r"MessageDigest\.getInstance\(\s*\"SHA-1\"", "SHA-1", "Java MessageDigest SHA-1"),
    R("java", r"Cipher\.getInstance\(\s*\"AES(?:/(?P<key>\w+))?", "AES", "Java Cipher AES", "/(?P<key>[A-Za-z0-9]+)"),
    R("java", r"Cipher\.getInstance\(\s*\"DES|\"DESede", "3DES", "Java Cipher DES/3DES"),
    R("java", r"SecureRandom", "SHA-256", "Java SecureRandom (RNG - not quantum-vulnerable)"),

    # --- Go ---------------------------------------------------------------- #
    R("go", r"rsa\.GenerateKey|crypto/rsa", "RSA", "Go crypto/rsa"),
    R("go", r"ecdsa\.GenerateKey|crypto/ecdsa|elliptic\.P\d{3}", "ECDSA", "Go crypto/ecdsa"),
    R("go", r"ed25519\.GenerateKey|crypto/ed25519", "Ed25519", "Go crypto/ed25519"),
    R("go", r"crypto/dh|curve25519", "X25519", "Go curve25519"),
    R("go", r"crypto/md5", "MD5", "Go crypto/md5"),
    R("go", r"crypto/sha1", "SHA-1", "Go crypto/sha1"),
    R("go", r"sha256\.New|crypto/sha256", "SHA-256", "Go crypto/sha256"),
    R("go", r"aes\.NewCipher|crypto/aes", "AES", "Go crypto/aes"),
    R("go", r"des\.NewCipher|crypto/des", "3DES", "Go crypto/des"),

    # --- Configuration ----------------------------------------------------- #
    R("config", r"ssl_protocols\s+([^;]+)", "AES", "nginx ssl_protocols"),
    R("config", r"ssl_ciphers\s+([^;]+)", "AES", "nginx ssl_ciphers"),
    R("config", r"SSLProtocol\s+([^\n]+)", "AES", "Apache SSLProtocol"),
    R("config", r"SSLCipherSuite\s+([^\n]+)", "AES", "Apache SSLCipherSuite"),
    R("config", r"\bTLSv1(?:\.0|\.1)\b|SSLv3", "3DES", "Legacy TLS protocol version"),
]

LANG_BY_EXT = {
    ".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
    ".java": "java", ".kt": "java", ".go": "go",
    ".conf": "config", ".cnf": "config", ".cfg": "config", ".ini": "config",
    ".yaml": "config", ".yml": "config", ".json": "config", ".toml": "config",
    ".properties": "config",
}

SKIP_DIRS = {"node_modules", ".git", "venv", ".venv", "dist", "build", "target",
             "__pycache__", ".next", "vendor", "site-packages"}

# TLS protocol/cipher weakness patterns inside config evidence strings
WEAK_TLS = re.compile(r"TLSv1(?:\.[01])?\b|SSLv[23]", re.I)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #

def classify(algorithm: str) -> tuple[str, str, str, str]:
    return CLASSES.get(algorithm, ("unknown", "unknown", "unknown",
                                   "Unclassified — manual review required"))


def scan_source(path: Path, max_bytes: int = 2_000_000) -> list[Finding]:
    ext = path.suffix.lower()
    lang = LANG_BY_EXT.get(ext)
    if not lang:
        return []
    try:
        if path.stat().st_size > max_bytes:
            return []
        text = path.read_text(errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in RULES:
        if rule.language != lang:
            continue
        for lineno, line in enumerate(lines, 1):
            m = rule.regex.search(line)
            if not m:
                continue
            if rule.language == "config":
                if WEAK_TLS.search(line) or re.search(r"DES|RC4|NULL|EXPORT|MD5", line, re.I):
                    algo = "3DES"
                else:
                    algo = rule.algorithm
            else:
                algo = rule.algorithm
            key = ""
            if rule.key_group:
                try:
                    key = m.group(rule.key_group) or ""
                except (IndexError, KeyError, re.error):
                    key = ""
            prim, quantum, classical, _ = classify(algo)
            findings.append(Finding(
                path=str(path), line=lineno, language=lang, api=rule.api,
                algorithm=algo, primitive=prim, quantum=quantum,
                classical=classical, key_size=key, evidence=line.strip()[:160],
            ))
    return findings


def scan_certificate(path: Path) -> list[Finding]:
    """Inspect a PEM/DER certificate or key for algorithm and key size."""
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(path), "-noout", "-text"],
            capture_output=True, text=True, timeout=20,
        )
        if out.returncode != 0:
            out = subprocess.run(
                ["openssl", "x509", "-inform", "DER", "-in", str(path), "-noout", "-text"],
                capture_output=True, text=True, timeout=20,
            )
        if out.returncode != 0:
            return []
        text = out.stdout
    except (OSError, subprocess.SubprocessError):
        return []

    algo, key = "", ""
    if "id-ecPublicKey" in text or "ASN1 OID: prime256v1" in text or "ASN1 OID: secp" in text:
        algo = "ECDSA"
        m = re.search(r"ASN1 OID:\s*(\S+)", text)
        key = m.group(1) if m else ""
    elif "rsaEncryption" in text or "Public-Key:" in text:
        m = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
        algo = "RSA"
        key = m.group(1) if m else ""
    elif "ED25519" in text:
        algo = "Ed25519"
    prim, quantum, classical, _ = classify(algo or "RSA")
    subject = ""
    ms = re.search(r"Subject:\s*(.+)", text)
    if ms:
        subject = ms.group(1).strip()[:120]
    return [Finding(
        path=str(path), line=0, language="certificate", api="X.509 certificate",
        algorithm=algo, primitive=prim, quantum=quantum, classical=classical,
        key_size=key, evidence=subject,
    )] if algo else []


def walk(root: Path, include_certs: bool = True) -> list[Finding]:
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            findings.extend(scan_source(p))
            if include_certs and (fn.endswith((".pem", ".crt", ".cer", ".der"))):
                findings.extend(scan_certificate(p))
    return findings


# --------------------------------------------------------------------------- #
# Runtime observation ingestion
# --------------------------------------------------------------------------- #

_SYMMETRIC_TOKENS = [
    ("CHACHA20", "ChaCha20"), ("3DES", "3DES"), ("CBC3", "3DES"), ("RC4", "RC4"),
    ("AES_256", "AES-256"), ("AES256", "AES-256"),
    ("AES_128", "AES-128"), ("AES128", "AES-128"),
    ("SHA384", "SHA-384"), ("SHA_384", "SHA-384"),
    ("SHA256", "SHA-256"), ("SHA_256", "SHA-256"),
    ("MD5", "MD5"),
]


def parse_cipher_algorithms(name: str) -> list[str]:
    """Map a cipher-suite name to the algorithms it actually uses.

    Only what the name states is reported. TLS 1.3 suite names do not carry the key
    exchange (it is negotiated separately), so none is inferred for them.
    """
    u = name.upper()
    out: list[str] = []

    def add(a: str) -> None:
        if a not in out:
            out.append(a)

    if "ECDHE" in u or "ECDH" in u:
        add("ECDH")
    elif "DHE" in u or u.startswith("DH-") or "_DH_" in u:
        add("DH")
    if "ECDSA" in u:
        add("ECDSA")
    elif "RSA" in u:
        add("RSA")

    for tok, algo in _SYMMETRIC_TOKENS:
        if tok in u:
            add(algo)

    if "AES" in u and not any(a.startswith("AES") for a in out):
        add("AES")
    if "SHA" in u and not any(a.startswith("SHA") for a in out):
        add("SHA-1")          # a bare SHA suffix in a suite name is SHA-1
    return out


def load_runtime(path: str | Path) -> list[Finding]:
    """Load runtime observations (JSONL produced by ca_probe.py or the shim)."""
    findings: list[Finding] = []
    p = Path(path)
    if not p.exists():
        return findings
    for raw in p.read_text(errors="ignore").splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        cipher = rec.get("cipher") or ""
        if not cipher:
            continue
        version = rec.get("version") or ""
        bits = rec.get("bits") or 0
        for algo in parse_cipher_algorithms(cipher):
            prim, quantum, classical, _ = classify(algo)
            findings.append(Finding(
                path="(runtime)", line=0, language="runtime",
                api=f"TLS negotiated cipher ({version})" if version else "TLS negotiated cipher",
                algorithm=algo, primitive=prim, quantum=quantum, classical=classical,
                key_size=str(bits) if bits and algo == "AES" else "",
                evidence=f"{cipher} — {rec.get('detail', '')}".strip(" —"),
            ))
    return findings


# --------------------------------------------------------------------------- #
# Output: CBOM (CycloneDX 1.6) + report
# --------------------------------------------------------------------------- #

def build_cbom(findings: list[Finding], root: str) -> dict:
    components, seen = [], set()
    observed = {f.algorithm for f in findings if f.language == "runtime"}
    for f in sorted(findings, key=lambda x: (RISK_ORDER.get(x.quantum, 9), x.algorithm)):
        key = (f.algorithm, f.key_size)
        if key in seen:
            continue
        seen.add(key)
        name = f.algorithm
        if f.key_size and f.key_size not in f.algorithm:
            name = f"{f.algorithm}-{f.key_size}"
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto:{name.lower()}",
            "name": name,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": f.primitive if f.primitive in {
                        "pke", "signature", "hash", "block-cipher", "stream-cipher",
                        "key-agree", "kem", "xof", "mac", "kdf", "other"} else "other",
                    "parameterSetIdentifier": f.key_size or "unspecified",
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "unknown",
                    "certificationLevel": [],
                    "mode": "",
                    "padding": "",
                    "cryptoFunctions": [],
                    "classicalSecurityLevel": 0 if f.classical == "broken" else 128,
                    "nistQuantumSecurityLevel": NIST_QSL.get(f.quantum, 0),
                },
            },
            "properties": [
                {"name": "cryptoagility:quantumRisk", "value": f.quantum},
                {"name": "cryptoagility:classicalRisk", "value": f.classical},
                {"name": "cryptoagility:observedInUse", "value": "true" if f.algorithm in observed else "false"},
                {"name": "cryptoagility:migrationAdvice", "value": f.recommendation},
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(abs(hash(root)))[:8].ljust(8, "0") + "-0000-0000-0000-000000000000",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "CryptoAgility", "name": "cryptoagility", "version": VERSION}],
            "component": {"type": "application", "name": Path(root).name or "scan-root"},
            "properties": [{"name": "cryptoagility:scannedPath", "value": root}],
        },
        "components": components,
    }


def build_report(findings: list[Finding], root: str) -> str:
    total = len(findings)
    by_q: dict[str, int] = {}
    by_algo: dict[str, int] = {}
    by_file: dict[str, int] = {}
    for f in findings:
        by_q[f.quantum] = by_q.get(f.quantum, 0) + 1
        by_algo[f.algorithm] = by_algo.get(f.algorithm, 0) + 1
        by_file[f.path] = by_file.get(f.path, 0) + 1

    urgent = [f for f in findings if f.quantum == "shor-broken"]
    broken = [f for f in findings if f.classical == "broken"]

    L = []
    L.append("# Cryptographic Discovery Report\n")
    L.append(f"**Scan root:** `{root}`  \n**Generated:** {datetime.now(timezone.utc).isoformat()}  \n**Tool:** CryptoAgility {VERSION}\n")
    L.append("## Summary\n")
    L.append(f"- Cryptographic usages found: **{total}**")
    L.append(f"- Quantum-vulnerable (Shor-broken, requires migration): **{len(urgent)}**")
    L.append(f"- Classically broken (unsafe today): **{len(broken)}**")
    for k in ("shor-broken", "grover-weakened", "resistant"):
        if k in by_q:
            L.append(f"- `{k}`: {by_q[k]}")
    L.append("")

    L.append("## Algorithms observed\n")
    L.append("| Algorithm | Occurrences | Action |")
    L.append("|---|---|---|")
    for algo, n in sorted(by_algo.items(), key=lambda x: -x[1]):
        _, q, c, advice = classify(algo)
        flag = "**MIGRATE**" if (q == "shor-broken" or c == "broken") else ("review" if q == "grover-weakened" else "retain")
        L.append(f"| {algo} | {n} | {flag} — {advice} |")
    L.append("")

    rt = [f for f in findings if f.language == "runtime"]
    if rt:
        L.append("## Observed in use (runtime — negotiated on live connections)\n")
        L.append("| Negotiated cipher | Protocol | Algorithms | Action |")
        L.append("|---|---|---|---|")
        for line in sorted({f.evidence for f in rt}):
            grp = [g for g in rt if g.evidence == line]
            algs = sorted({g.algorithm for g in grp})
            bad = any(g.quantum == "shor-broken" or g.classical == "broken" for g in grp)
            verdict = "**MIGRATE**" if bad else "review"
            cipher = line.split(" —")[0]
            api = next((g.api for g in grp), "")
            proto = api.split("(")[1].split(")")[0] if "(" in api else ""
            L.append(f"| {cipher} | {proto} | {', '.join(algs)} | {verdict} |")
        L.append("")
        L.append("> These are ciphers the systems actually agreed in production, not ciphers found in source. "
                 "A finding here that also appears statically is confirmed in use; one that appears only here is "
                 "cryptography shipped inside a dependency or binary whose source was never visible.\n")

    if urgent:
        L.append("## Priority migration queue — quantum-vulnerable public-key usage\n")
        L.append("| File | Line | Algorithm | Evidence |")
        L.append("|---|---|---|---|")
        for f in urgent[:40]:
            L.append(f"| `{f.path}` | {f.line or '-'} | {f.algorithm}{'-'+f.key_size if f.key_size else ''} | `{f.evidence[:90]}` |")
        L.append("")
        L.append("> Public-key algorithms (RSA, ECC, DH, DSA) are broken outright by Shor's algorithm. "
                 "Data with a long confidentiality lifetime is exposed to harvest-now-decrypt-later today. "
                 "Migration targets: ML-KEM / FIPS 203 for key establishment, ML-DSA / FIPS 204 for signatures.\n")

    if broken:
        L.append("## Already-broken primitives (unsafe regardless of quantum)\n")
        seen = set()
        for f in broken:
            if f.algorithm in seen:
                continue
            seen.add(f.algorithm)
            L.append(f"- **{f.algorithm}** — {classify(f.algorithm)[3]} (first seen `{f.path}:{f.line or '-'}`)")
        L.append("")

    L.append("## Files by density\n")
    for p, n in sorted(by_file.items(), key=lambda x: -x[1])[:15]:
        L.append(f"- `{p}` — {n}")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="CryptoAgility — cryptographic discovery & CBOM generation")
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--cbom", help="write CycloneDX CBOM JSON here")
    ap.add_argument("--report", help="write markdown report here")
    ap.add_argument("--runtime", help="merge runtime observations (JSONL from ca_probe.py or the shim)")
    ap.add_argument("--exit-zero", action="store_true",
                    help="always exit 0, even when migration-required findings are present")
    args = ap.parse_args()

    root = Path(args.path)
    if not root.exists():
        print(f"error: {root} not found", file=sys.stderr)
        return 2

    findings = scan_source(root) if root.is_file() else walk(root)
    if args.runtime:
        rt = load_runtime(args.runtime)
        print(f"  runtime observations merged: {len(rt)} findings from {args.runtime}")
        findings += rt
    print(f"cryptoagility {VERSION}: scanned {root} -> {len(findings)} cryptographic usages")

    if args.cbom:
        Path(args.cbom).write_text(json.dumps(build_cbom(findings, str(root)), indent=2))
        print(f"  CBOM written: {args.cbom}")
    if args.report:
        Path(args.report).write_text(build_report(findings, str(root)))
        print(f"  report written: {args.report}")

    if not args.cbom and not args.report:
        print(build_report(findings, str(root)))

    actionable = sum(1 for f in findings if f.action_required)
    if actionable and not args.exit_zero:
        print(f"  {actionable} finding(s) require migration — exiting non-zero "
              f"(use --exit-zero to suppress)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
