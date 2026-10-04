# Commercial Licensing

CryptoAgility is **dual-licensed**. This document explains which licence applies to what, and when you need to talk
to us.

## The open core — AGPL-3.0-or-later

Everything in this public repository is licensed under the **GNU Affero General Public License, version 3 or later**
(see [LICENSE](LICENSE)):

- static cryptographic discovery (`cryptoagility.py`)
- certificate inspection
- quantum-exposure classification
- CycloneDX CBOM generation
- the runtime TLS observer (`runtime/ca_probe.py`)
- the unprivileged and kernel observation variants (`runtime/ca_shim.c`, `runtime/ca_ebpf.bt`)

### What the AGPL permits without paying anything

- Running CryptoAgility **internally**, on your own systems, for your own organisation. This includes running it
  commercially and using its output in your own work.
- Using it to deliver **professional services to your clients**, provided you are not distributing the software or
  offering it to third parties as a hosted service.
- Modifying it, forking it, and redistributing your changes — provided the AGPL's terms are honoured, including
  making your modified source available.

### What the AGPL does not permit without a commercial licence

- Distributing CryptoAgility, or a derivative, as part of a product you sell, without releasing that product's
  corresponding source under the AGPL.
- Offering CryptoAgility, or a derivative, to third parties **as a service** over a network, without releasing your
  modified source under the AGPL.

If either of those describes your intended use, you need a commercial licence — or you can accept the AGPL and
release your source. Both are legitimate choices; the licence simply makes you choose.

## The commercial layer

The following components are **not** in this repository and are proprietary to Maobyte Innovations Ltd. They are not
covered by the AGPL:

- the reconciliation engine that matches statically-detected assets against runtime-observed ones
- migration orchestration: sequencing, effort estimation, dependency ordering
- drift tracking and scheduled re-scanning
- the evidence pack format produced for audit
- any hosted dashboard or managed service

Copyright (c) 2026 Maobyte Innovations Ltd. All rights reserved. No permission is granted to use, copy, modify or
distribute these components except under a separate written agreement.

## Commercial licences available

| Licence | Covers | Indicative price |
|---|---|---|
| **Embed** | Including CryptoAgility in a product you distribute or sell | from £4,000 / year |
| **Service** | Offering CryptoAgility, or a derivative, to third parties as a hosted service | from £4,000 / year |
| **White-label** | Our engine inside your own assessment service, under your brand | from £6,000 / year |
| **Assessment** | A delivered post-quantum readiness assessment, including the commercial tooling | from $8,500 per engagement |

Prices are indicative and depend on scope. Nothing here is an offer capable of acceptance; terms are set by a signed
agreement.

## Contributor licence

By submitting a contribution to this repository you agree that Maobyte Innovations Ltd may license your contribution
under both the AGPL and any commercial licence it offers. See [CONTRIBUTING.md](CONTRIBUTING.md). If you are not
comfortable with that, please open an issue describing the change instead of submitting a patch.

## Why dual licensing

The open core exists to be used. Discovery is commodity work and hiding it would only slow its adoption. What is
worth paying for is the part above it — turning an inventory into a sequenced, evidenced migration — and that is
where the commercial licence applies.

## Enquiries

**c.kanu@mainnoltd.com**
