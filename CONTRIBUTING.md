# Contributing to CryptoAgility

Thanks for considering it. This is a security tool, so the bar for evidence is deliberately high: a change that
cannot be tested will not be merged.

## Getting set up

```bash
python3 -m venv .venv
./.venv/bin/pip install -e .
./.venv/bin/pip install pytest
./.venv/bin/python -m pytest tests -q
```

51 tests should pass. If they do not on a clean checkout, that is a bug worth reporting before anything else.

## Before you open a pull request

- **Add a test.** Every new detection rule, classification, or parser change needs one. Bug fixes need a regression
  test that fails on the old code — see the TLS 1.3 version test for the pattern.
- **Run the whole suite.** `./.venv/bin/python -m pytest tests -q`. A green subset is not a green suite.
- **Check the CLI still works.** `./.venv/bin/cryptoagility sample --cbom /tmp/c.json --report /tmp/r.md`.
- **Keep the tool offline.** CryptoAgility must make no outbound network calls and must not add telemetry. A
  dependency that phones home is a rejected pull request, however useful it is.
- **Be accurate about risk.** Do not classify a public-key algorithm as quantum-safe. Shor's algorithm breaks RSA,
  DSA, DH, ECDH, ECDSA and EdDSA outright. If you are unsure, add it as unknown rather than guessing — a wrong
  "safe" verdict in a security tool is worse than no verdict.

## Adding a detection rule

Rules live in the `RULES` list in `cryptoagility.py`:

```python
R("python", r"\brsa\.generate_private_key", "RSA", "Python cryptography RSA"),
R("java",   r"Cipher\.getInstance\(\"AES", "AES", "Java Cipher AES", "/(?P<key>\w+)"),
```

- The first argument is the language key, which must match `LANG_BY_EXT`.
- Give the rule a key-size capture group in the fifth argument where the API exposes one.
- Add the algorithm to `CLASSES` if it is new, with its primitive, quantum risk, classical risk and migration advice.
- Add a test that a realistic snippet is detected, and a test that clean code is not.

False positives cost more than false negatives here. A rule that flags every use of the word "hash" makes the report
unusable and the tool untrustworthy.

## Contribution licence

This project is dual-licensed (AGPL-3.0-or-later plus a commercial licence — see
[LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). By submitting a contribution you agree that Maobyte Innovations Ltd
may distribute it under both. If you would rather not, open an issue describing the change instead of sending a
patch, and we will consider implementing it.

## Reporting a security problem in CryptoAgility itself

Do not open a public issue. See [SECURITY.md](SECURITY.md).
