# Changelog

All notable changes to CryptoAgility are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Planned
- Reconciliation engine: match statically-detected assets against runtime-observed ones so a single register
  distinguishes "declared in code", "confirmed in use", and "present in a binary with no source".
- Hardware/HSM key inventory via PKCS#11 and vendor APIs.
- Firmware cryptographic discovery.
- SARIF output for CI integration.

## [0.1.2] — 2026-10-04

### Fixed
- The CLI banner, the CBOM `tools[].version` field and the report header all announced a hardcoded `0.1.0-mvp`
  regardless of the package version. A tool that misreports its own version corrupts every bug report made against
  it, so the version now comes from the installed distribution metadata, with a source-checkout fallback.
- Added `tests/test_version.py`, which asserts that fallback against `pyproject.toml`, so the reported version cannot
  drift from the released version again.

## [0.1.1] — 2026-10-04

First version published to PyPI. Supersedes 0.1.0, which was tagged in the repository but never uploaded.

### Changed
- Licence metadata now uses the PEP 639 SPDX expression, so the index receives `License-Expression: AGPL-3.0-or-later`
  with both licence files attached. The previous `{ text = ... }` form is deprecated and will eventually fail the build.
- Package metadata URLs corrected. `Source` and `Issues` previously carried a `<your-account>` placeholder, which
  would have shipped onto the project page.

### Added
- Release workflow: pushing a `v*` tag publishes to PyPI through trusted publishing (OIDC), with no stored token.
  It runs the suite, builds the sdist and wheel, runs `twine check`, and refuses to upload if the tag disagrees with
  the version in `pyproject.toml`.
- Test suite expanded to 53 tests, covering the CLI exit-code gate and the `--exit-zero` escape hatch.

## [0.1.0] — 2026-10-04

First release. Open core published under AGPL-3.0-or-later; migration orchestration retained as commercial.

### Added
- Static discovery across Python, JavaScript/TypeScript, Java/Kotlin, Go and server configuration, with per-language
  detection rules covering public-key generation, signatures, key agreement, symmetric ciphers, hashes and legacy
  protocol versions.
- X.509 certificate inspection reporting algorithm and key size (`openssl`-backed, with DER fallback).
- Quantum-exposure classification for every finding: Shor-broken, Grover-weakened, or resistant, alongside a separate
  classical-safety verdict and named migration advice (ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205).
- CycloneDX 1.6 CBOM output with `cryptographic-asset` components, `nistQuantumSecurityLevel`, and a
  `cryptoagility:observedInUse` flag distinguishing assets seen at runtime from those seen only in source.
- Markdown migration report with a prioritised queue, algorithm summary and per-file density.
- Partial scan tolerance: unreadable files and oversized files are skipped rather than aborting the run.
- Non-zero exit code when quantum-vulnerable cryptography is found, so the CLI can gate a pipeline.
- Runtime observation layer (`runtime/ca_probe.py`): TLS handshake metadata parsing for ClientHello offers and
  ServerHello selection, in both observing-proxy and direct-probe modes. No root, no kernel probes, no decryption.
- Unprivileged LD_PRELOAD interposer for libssl and a bpftrace uprobe variant, sharing the runtime JSONL schema.
- Test suite of 51 tests, including regression coverage for TLS 1.3 version parsing.

### Fixed
- A TLS 1.3 ServerHello was reported as TLS 1.2: the extensions block was being read two bytes early, so the
  `supported_versions` extension was missed and the legacy `0x0303` field used instead. This would have understated
  a customer's protocol posture.
- CBOM components could be named redundantly (for example `AES-256-256`) when the algorithm name already carried its
  key size.

### Known limitations
- Detection rules are intentionally shallow; corpus depth is the commercial asset.
- No HSM, firmware or hardware key discovery.
- Runtime observation reports the negotiated cipher suite, not the key exchange for TLS 1.3, where the suite name
  does not carry it — no key exchange is inferred.
