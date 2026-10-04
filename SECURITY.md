# Security Policy

## Reporting a vulnerability in CryptoAgility

Do **not** open a public issue for a security problem in this tool.

Email **c.kanu@mainnoltd.com** with:

- the version and platform,
- what you did, what happened, and what you expected,
- a minimal reproduction if you can produce one,
- and whether you intend to publish.

**Response times.** Acknowledgement within 5 working days. Assessment within 15. We will tell you whether we consider
it a vulnerability, and if we do, agree a disclosure date with you — 90 days by default, shorter if a fix ships
sooner and you are content with that.

**Credit.** We will credit you in the release notes unless you ask us not to.

## Scope

In scope:

- the discovery core (`cryptoagility.py`) — a wrong verdict, a parser that can be crashed, a path that writes outside
  the requested output files
- the runtime observer (`runtime/ca_probe.py`) — a parsing bug that misreports negotiated cryptography
- the LD_PRELOAD shim and the eBPF probe

The most serious class of bug here is a **silent wrong answer**. A tool that reports an estate as quantum-safe when
it is not is worse than no tool, because somebody will make a migration decision on it. Report those even if they do
not look like conventional vulnerabilities — they are the ones that matter most.

## What is not in scope

- Missing detection coverage. That is a feature request; open an issue.
- The tool failing to detect cryptography in a language it does not claim to support.
- Anything requiring an attacker who can already modify the scanned source or the machine running the scan.

## Design commitments

These are properties of the tool, and a change that breaks one of them is a security bug:

1. **No outbound network calls.** The scanner never transmits anything about the estate it scanned. The runtime
   observer listens and connects only to the target you point it at.
2. **No telemetry.**
3. **No execution of scanned code.** Discovery is static analysis and certificate parsing only.
4. **No modification of the scanned tree.**
5. **Certificate verification is deliberately disabled in the runtime probe**, because it must connect to internal,
   development and self-signed endpoints to record what they negotiate. It reads handshake metadata only, never
   application data, and validates nothing about identity by design. This is a documented design decision, not an
   oversight.
