# Cryptographic Discovery Report

**Scan root:** `sample`  
**Generated:** 2026-10-04T13:50:46.664412+00:00  
**Tool:** CryptoAgility 0.1.2

## Summary

- Cryptographic usages found: **29**
- Quantum-vulnerable (Shor-broken, requires migration): **12**
- Classically broken (unsafe today): **19**
- `shor-broken`: 12
- `grover-weakened`: 16
- `resistant`: 1

## Algorithms observed

| Algorithm | Occurrences | Action |
|---|---|---|
| 3DES | 6 | **MIGRATE** — Retire. Migrate to AES-256-GCM |
| RSA | 6 | **MIGRATE** — Migrate to ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures |
| ECDSA | 4 | **MIGRATE** — Migrate to ML-DSA (FIPS 204) |
| SHA-1 | 4 | **MIGRATE** — Retire. Migrate to SHA-256 or SHA-384 |
| MD5 | 3 | **MIGRATE** — Retire. Migrate to SHA-256 |
| AES | 3 | review — Confirm key size is 256-bit for long-lived data |
| Ed25519 | 2 | **MIGRATE** — Migrate to ML-DSA (FIPS 204) |
| SHA-256 | 1 | retain — Retain. |

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

> Public-key algorithms (RSA, ECC, DH, DSA) are broken outright by Shor's algorithm. Data with a long confidentiality lifetime is exposed to harvest-now-decrypt-later today. Migration targets: ML-KEM / FIPS 203 for key establishment, ML-DSA / FIPS 204 for signatures.

## Already-broken primitives (unsafe regardless of quantum)

- **3DES** — Retire. Migrate to AES-256-GCM (first seen `sample/nginx.conf:9`)
- **RSA** — Migrate to ML-KEM (FIPS 203) for key establishment; ML-DSA (FIPS 204) for signatures (first seen `sample/LegacyCrypto.java:9`)
- **SHA-1** — Retire. Migrate to SHA-256 or SHA-384 (first seen `sample/LegacyCrypto.java:28`)
- **MD5** — Retire. Migrate to SHA-256 (first seen `sample/LegacyCrypto.java:18`)

## Files by density

- `sample/payments.js` — 9
- `sample/python_service.py` — 8
- `sample/LegacyCrypto.java` — 7
- `sample/nginx.conf` — 3
- `sample/payments.pem` — 1
- `sample/legacy-ec.pem` — 1
