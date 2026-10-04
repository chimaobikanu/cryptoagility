# Cryptographic Discovery Report

**Scan root:** `sample`  
**Generated:** 2026-10-04T12:04:01.777014+00:00  
**Tool:** CryptoAgility 0.1.0-mvp

## Summary

- Cryptographic usages found: **37**
- Quantum-vulnerable (Shor-broken, requires migration): **14**
- Classically broken (unsafe today): **21**
- `shor-broken`: 14
- `grover-weakened`: 18
- `resistant`: 5

## Algorithms observed

| Algorithm | Occurrences | Action |
|---|---|---|
| RSA | 7 | **MIGRATE** — Migrate to ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures |
| 3DES | 6 | **MIGRATE** — Retire. Migrate to AES-256-GCM |
| SHA-1 | 5 | **MIGRATE** — Retire. Migrate to SHA-256 or SHA-384 |
| ECDSA | 4 | **MIGRATE** — Migrate to ML-DSA (FIPS 204) |
| MD5 | 3 | **MIGRATE** — Retire. Migrate to SHA-256 |
| AES | 3 | review — Confirm key size is 256-bit for long-lived data |
| Ed25519 | 2 | **MIGRATE** — Migrate to ML-DSA (FIPS 204) |
| AES-256 | 2 | retain — Retain. 256-bit key retains adequate margin under Grover |
| SHA-384 | 2 | retain — Retain. |
| SHA-256 | 1 | retain — Retain. |
| AES-128 | 1 | review — Consider AES-256 for long-lived data |
| ECDH | 1 | **MIGRATE** — Migrate to ML-KEM (FIPS 203) or hybrid X25519MLKEM768 |

## Observed in use (runtime — negotiated on live connections)

| Negotiated cipher | Protocol | Algorithms | Action |
|---|---|---|---|
| AES128-SHA | TLS1.2 | AES-128, SHA-1 | **MIGRATE** |
| ECDHE-RSA-AES256-GCM-SHA384 | TLS1.2 | AES-256, ECDH, RSA, SHA-384 | **MIGRATE** |
| TLS_AES_256_GCM_SHA384 | TLS1.3 | AES-256, SHA-384 | review |

> These are ciphers the systems actually agreed in production, not ciphers found in source. A finding here that also appears statically is confirmed in use; one that appears only here is cryptography shipped inside a dependency or binary whose source was never visible.

## Priority migration queue — quantum-vulnerable public-key usage

| File | Line | Algorithm | Evidence |
|---|---|---|---|
| `sample/LegacyCrypto.java` | 9 | RSA | `KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");` |
| `sample/LegacyCrypto.java` | 13 | ECDSA | `KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");` |
| `sample/payments.js` | 18 | RSA | `return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }); // quantum-vulnerable` |
| `sample/payments.js` | 22 | ECDSA | `return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); // quantum-vulnerab` |
| `sample/payments.js` | 26 | Ed25519 | `return crypto.generateKeyPairSync('ed25519'); // quantum-vulnerable` |
| `sample/payments.js` | 40 | RSA | `return jwt.sign(payload, key, { algorithm: 'RS256' }); // RSA` |
| `sample/python_service.py` | 12 | RSA | `return rsa.generate_private_key(public_exponent=65537, key_size=2048)` |
| `sample/python_service.py` | 17 | ECDSA | `return ec.generate_private_key(ec.SECP256R1())` |
| `sample/python_service.py` | 22 | Ed25519 | `return ed25519.Ed25519PrivateKey.generate()` |
| `sample/python_service.py` | 6 | RSA | `from Crypto.PublicKey import RSA` |
| `sample/payments.pem` | - | RSA-2048 | `CN=payments.internal.example, O=Example Ltd` |
| `sample/legacy-ec.pem` | - | ECDSA-prime256v1 | `CN=legacy.internal.example, O=Example Ltd` |
| `(runtime)` | - | ECDH | `ECDHE-RSA-AES256-GCM-SHA384 — Selected by server on live connection` |
| `(runtime)` | - | RSA | `ECDHE-RSA-AES256-GCM-SHA384 — Selected by server on live connection` |

> Public-key algorithms (RSA, ECC, DH, DSA) are broken outright by Shor's algorithm. Data with a long confidentiality lifetime is exposed to harvest-now-decrypt-later today. Migration targets: ML-KEM / FIPS 203 for key establishment, ML-DSA / FIPS 204 for signatures.

## Already-broken primitives (unsafe regardless of quantum)

- **3DES** — Retire. Migrate to AES-256-GCM (first seen `sample/nginx.conf:9`)
- **RSA** — Migrate to ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures (first seen `sample/LegacyCrypto.java:9`)
- **SHA-1** — Retire. Migrate to SHA-256 or SHA-384 (first seen `sample/LegacyCrypto.java:28`)
- **MD5** — Retire. Migrate to SHA-256 (first seen `sample/LegacyCrypto.java:18`)

## Files by density

- `sample/payments.js` — 9
- `sample/python_service.py` — 8
- `(runtime)` — 8
- `sample/LegacyCrypto.java` — 7
- `sample/nginx.conf` — 3
- `sample/payments.pem` — 1
- `sample/legacy-ec.pem` — 1
