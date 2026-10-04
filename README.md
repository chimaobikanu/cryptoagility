# CryptoAgility

**Find every cryptographic asset. Know what breaks, and in what order to fix it.**

CryptoAgility discovers cryptographic usage across your source, configuration, certificates and — critically — on
live connections, grades each finding by its exposure to quantum attack, and produces an audit-ready migration
register as a CycloneDX CBOM.

It is built to run **inside your own network**. It makes no outbound calls and carries no telemetry. Your code never
leaves your perimeter.

Product page, pricing and the honest limitations: **https://mainnoltd.com/cryptoagility/**

```
$ cryptoagility ./src --runtime live.jsonl --cbom cbom.json --report report.md
  runtime observations merged: 8 findings from live.jsonl
  cryptoagility 0.1.2: scanned ./src -> 37 cryptographic usages

## Summary
- Cryptographic usages found: 37
- Quantum-vulnerable (Shor-broken, requires migration): 12
- Classically broken (unsafe today): 19

## Observed in use (runtime — negotiated on live connections)
| Negotiated cipher             | Protocol | Algorithms                  | Action  |
|-------------------------------|----------|-----------------------------|---------|
| AES128-SHA                    | TLS1.2   | AES-128, SHA-1              | MIGRATE |
| ECDHE-RSA-AES256-GCM-SHA384   | TLS1.2   | AES-256, ECDH, RSA, SHA-384 | MIGRATE |
| TLS_AES_256_GCM_SHA384        | TLS1.3   | AES-256, SHA-384            | review  |
```

## Why discovery, and why now

NCSC guidance expects cryptographic discovery complete by **2028**, priority upgrades by 2031 and full migration by
**2035**. Discovery is the step that cannot be skipped and the step almost nobody has done, because cryptography is
the one dependency enterprises have never inventoried. Separately, every RSA, ECDSA, ECDH and Ed25519 usage in an
estate is quantum-vulnerable regardless of key size, and long-lived confidential data is exposed to
harvest-now-decrypt-later today.

## Two discovery layers

**Static** — source, configuration and X.509 certificates across Python, JavaScript/TypeScript, Java/Kotlin, Go and
server configuration. Certificate inspection reports algorithm and key size.

**Runtime** — what systems *actually* negotiate on live TLS connections, read off the wire with no root, no kernel
probes and no decryption:

```bash
python3 runtime/ca_probe.py proxy --listen 127.0.0.1:14444 --target host:443
python3 runtime/ca_probe.py probe --target host:443
```

This is the layer that finds cryptography inside dependencies and vendor binaries whose source you will never see —
and the layer point scanners reading only source cannot reach. An asset found by both layers is confirmed in use;
`cryptoagility:observedInUse` marks it in the CBOM.

## Install

```bash
git clone <repo> && cd cryptoagility
python3 -m venv .venv && ./.venv/bin/pip install -e .
./.venv/bin/cryptoagility --help
```

Requires Python 3.10+. No third-party runtime dependencies.

## Usage

```bash
cryptoagility <path>                          # report to stdout
cryptoagility <path> --cbom cbom.json         # CycloneDX 1.6 CBOM
cryptoagility <path> --report report.md       # migration report
cryptoagility <path> --runtime live.jsonl     # merge runtime observations
```

The CLI exits non-zero when quantum-vulnerable cryptography is found, so it can gate a pipeline exactly as a linter
would.

## What is in this repository, and what is not

This repository is the **open core**: discovery, classification, CBOM generation and the runtime observer.

It is not the whole product. Migration orchestration — sequencing, effort estimation, drift tracking and the evidence
pack an auditor accepts — is commercial, along with the reconciliation engine that matches static findings against
runtime observations. See [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).

## Testing

```bash
./.venv/bin/pip install pytest
./.venv/bin/python -m pytest tests -q
```

The suite includes regression tests for the parsing bugs that matter — a TLS 1.3 ServerHello carries `0x0303` in its
legacy version field, and reading the extensions block from the wrong offset silently reports 1.3 as 1.2.

## Not yet built

Hardware and HSM key inventory, and firmware cryptographic discovery — the third discovery layer, and the hardest.
That is the honest boundary of this release.

## Licence

GNU Affero General Public License v3.0 or later — see [LICENSE](LICENSE).

Using CryptoAgility internally is unrestricted. To embed it in a product, or offer it to third parties as a service,
a commercial licence is available: **c.kanu@mainnoltd.com**.

## Status

Early. Detection rules are deliberately shallow here; the depth of a detection corpus is the commercial asset.

---

A product of [Maobyte Innovations Ltd](https://mainnoltd.com), trading as Mainno.
Product page: https://mainnoltd.com/cryptoagility/
