#!/usr/bin/env python3
"""
ca_probe.py — CryptoAgility runtime observation layer (unprivileged, pure Python).

Observes the cryptography a process ACTUALLY negotiates, by reading TLS handshake
metadata off the wire. No root, no kernel probes, no decryption: only the ClientHello
(what was offered) and the ServerHello (what was chosen).

Two modes:
  1. Observing proxy — point any application at it and see what it really negotiates:
        python3 ca_probe.py proxy --listen 14444 --target host:443
  2. Direct probe — ask an endpoint what it will agree to:
        python3 ca_probe.py probe --target host:443

Both append JSON Lines in the same schema as the LD_PRELOAD shim, so the results
merge straight into the CBOM via `cryptoagility.py --runtime`.

Companion artefacts (need a compiler / root, not available in this build env):
  runtime/ca_shim.c   — LD_PRELOAD interposer for libssl (in-process observation)
  runtime/ca_ebpf.bt  — bpftrace uprobes on libssl (host-wide observation)
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# Common IANA cipher-suite code points -> name
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
    0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0xC013: "ECDHE-RSA-AES128-SHA",
    0xC014: "ECDHE-RSA-AES256-SHA",
    0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA",
    0xC027: "ECDHE-RSA-AES128-SHA256",
    0xC028: "ECDHE-RSA-AES256-SHA384",
    0xC023: "ECDHE-ECDSA-AES128-SHA256",
    0xC024: "ECDHE-ECDSA-AES256-SHA384",
    0xC012: "ECDHE-RSA-DES-CBC3-SHA",
    0xC008: "ECDHE-ECDSA-DES-CBC3-SHA",
    0x009C: "AES128-GCM-SHA256",
    0x009D: "AES256-GCM-SHA384",
    0x002F: "AES128-SHA",
    0x0035: "AES256-SHA",
    0x003C: "AES128-SHA256",
    0x003D: "AES256-SHA256",
    0x000A: "DES-CBC3-SHA",
    0x0005: "RC4-SHA",
    0x0004: "RC4-MD5",
    0x0067: "DHE-RSA-AES128-SHA256",
    0x006B: "DHE-RSA-AES256-SHA256",
    0x0033: "DHE-RSA-AES128-SHA",
    0x0039: "DHE-RSA-AES256-SHA",
    0x009E: "DHE-RSA-AES128-GCM-SHA256",
    0x009F: "DHE-RSA-AES256-GCM-SHA384",
    0x5600: "TLS_FALLBACK_SCSV",
    0x00FF: "EMPTY_RENEGOTIATION_INFO_SCSV",
}

TLS_VERSIONS = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2",
                0x0304: "TLS1.3", 0x0300: "SSL3.0"}


def cipher_name(code: int) -> str:
    return CIPHER_NAMES.get(code, f"UNKNOWN-0x{code:04X}")


def _log_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    import os
    return Path(os.environ.get("CA_LOG", "/tmp/ca-runtime.jsonl"))


def emit(path: Path, event: str, **fields) -> None:
    rec = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "event": event}
    rec.update(fields)
    with path.open("a") as f:
        f.write(json.dumps(rec) + "\n")


# --------------------------------------------------------------------------- #
# TLS handshake parsing
# --------------------------------------------------------------------------- #

def _parse_extensions(buf: bytes, start: int) -> dict:
    """Extract supported_versions (0x002b) selection from a ServerHello."""
    out = {}
    i = start
    while i + 4 <= len(buf):
        etype = int.from_bytes(buf[i:i + 2], "big")
        elen = int.from_bytes(buf[i + 2:i + 4], "big")
        data = buf[i + 4:i + 4 + elen]
        if etype == 0x002B and len(data) >= 2:      # supported_versions
            out["version"] = int.from_bytes(data[:2], "big")
        i += 4 + elen
    return out


def parse_handshake(record: bytes) -> dict | None:
    """Parse one TLS handshake record. Returns ClientHello/ServerHello metadata."""
    if len(record) < 6 or record[0] != 0x16:        # 0x16 = handshake
        return None
    hs_type = record[5]
    body = record[9:]
    if hs_type == 1:                                 # ClientHello
        if len(body) < 38:
            return None
        offered_ver = int.from_bytes(body[0:2], "big")
        i = 2 + 32
        sid_len = body[i]; i += 1 + sid_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2
        suites = [int.from_bytes(body[j:j + 2], "big")
                  for j in range(i, min(i + cs_len, len(body)), 2)]
        return {"kind": "client_hello",
                "legacy_version": TLS_VERSIONS.get(offered_ver, hex(offered_ver)),
                "offered_suites": [cipher_name(s) for s in suites if s not in (0x00FF, 0x5600)],
                "offered_count": len(suites)}
    if hs_type == 2:                                 # ServerHello
        if len(body) < 38:
            return None
        i = 2 + 32
        sid_len = body[i]; i += 1 + sid_len
        if i + 2 > len(body):
            return None
        suite = int.from_bytes(body[i:i + 2], "big")
        ext_start = i + 3
        # ServerHello extensions: 2-byte total length, then (type, len, data) entries
        ext = _parse_extensions(body, ext_start + 2) if ext_start + 2 < len(body) else {}
        ver = ext.get("version") or int.from_bytes(body[0:2], "big")
        return {"kind": "server_hello",
                "negotiated_suite": cipher_name(suite),
                "negotiated_version": TLS_VERSIONS.get(ver, hex(ver))}
    return None


def sniff(sock: socket.socket, stop_kind: str = "client_hello", timeout: float = 8.0) -> tuple[list[dict], bytes]:
    """Read TLS records, returning parsed handshakes AND every raw byte read.

    Stops as soon as a handshake of `stop_kind` is seen (client_hello when reading
    from a client, server_hello when reading from a server). The raw bytes matter: a
    proxy must forward exactly what it consumed, or the handshake it is observing
    will never complete.
    """
    sock.settimeout(timeout)
    out, buf, raw = [], b"", b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(o["kind"] == stop_kind for o in out):
            break
        try:
            chunk = sock.recv(16384)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        raw += chunk
        buf += chunk
        while len(buf) >= 5:
            rec_len = int.from_bytes(buf[3:5], "big")
            if len(buf) < 5 + rec_len:
                break
            rec, buf = buf[:5 + rec_len], buf[5 + rec_len:]
            try:
                hs = parse_handshake(rec)
            except Exception:
                hs = None
            if hs:
                out.append(hs)
    return out, raw


# --------------------------------------------------------------------------- #
# Mode 1: observing proxy
# --------------------------------------------------------------------------- #

def proxy(listen: str, target: str, log: Path, max_conns: int = 0) -> None:
    lhost, lport = listen.rsplit(":", 1)
    thost, tport = target.rsplit(":", 1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lhost, int(lport)))
    srv.listen(16)
    print(f"ca_probe: observing proxy {lhost}:{lport} -> {thost}:{tport} (log {log})")
    conns = 0
    while True:
        client, addr = srv.accept()
        conns += 1
        threading.Thread(target=_handle, args=(client, thost, int(tport), log), daemon=True).start()
        if max_conns and conns >= max_conns:
            break


def _handle(client: socket.socket, thost: str, tport: int, log: Path) -> None:
    try:
        upstream = socket.create_connection((thost, tport), timeout=8)
    except OSError as e:
        emit(log, "proxy_error", error=str(e))
        client.close()
        return

    try:
        # observe the client's offer, then hand it onward unchanged
        hs, raw = sniff(client, stop_kind="client_hello")
        if raw:
            upstream.sendall(raw)
        ch = next((h for h in hs if h["kind"] == "client_hello"), None)
        if ch:
            emit(log, "client_offered", detail=f"{ch['offered_count']} suites offered",
                 version=ch["legacy_version"], offered=ch["offered_suites"][:24])

        # observe the server's choice, then hand it back unchanged
        shs, shraw = sniff(upstream, stop_kind="server_hello")
        if shraw:
            client.sendall(shraw)
        for h in shs:
            if h["kind"] == "server_hello":
                emit(log, "negotiated", detail="Selected by server on live connection",
                     version=h["negotiated_version"], cipher=h["negotiated_suite"],
                     bits=_cipher_bits(h["negotiated_suite"]))

        # from here the proxy is a blind pipe: it never decrypts
        _pipe(client, upstream)
    except Exception as e:
        emit(log, "proxy_error", error=str(e))
    finally:
        for s in (client, upstream):
            try:
                s.close()
            except OSError:
                pass


def _pipe(a: socket.socket, b: socket.socket) -> None:
    def pump(src, dst):
        try:
            while True:
                data = src.recv(16384)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    t1 = threading.Thread(target=pump, args=(a, b), daemon=True)
    t2 = threading.Thread(target=pump, args=(b, a), daemon=True)
    t1.start(); t2.start(); t1.join(); t2.join()


def _cipher_bits(name: str) -> int:
    if "AES_256" in name or "AES256" in name:
        return 256
    if "AES_128" in name or "AES128" in name:
        return 128
    if "CHACHA20" in name:
        return 256
    if "3DES" in name or "CBC3" in name:
        return 112
    if "RC4" in name:
        return 128
    return 0


# --------------------------------------------------------------------------- #
# Mode 2: direct probe
# --------------------------------------------------------------------------- #

def probe(target: str, log: Path, server_hostname: str | None = None) -> dict:
    """Ask an endpoint what it will negotiate.

    Certificate verification is deliberately disabled: this is a discovery tool that
    must connect to internal, dev and self-signed endpoints to record what they
    negotiate. It reads no secrets and validates nothing about identity by design.
    """
    thost, tport = target.rsplit(":", 1)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((thost, int(tport)), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname or thost) as s:
            chosen = s.cipher() or ("", "TLS", 0)
            info = {"version": s.version(), "cipher": chosen[0], "bits": chosen[2]}
    emit(log, "negotiated", detail="Direct TLS probe", version=info["version"],
         cipher=info["cipher"], bits=info["bits"])
    print(json.dumps(info, indent=2))
    return info


def main() -> int:
    ap = argparse.ArgumentParser(description="CryptoAgility runtime TLS observation")
    sub = ap.add_subparsers(dest="mode", required=True)

    p1 = sub.add_parser("proxy", help="observing TLS proxy")
    p1.add_argument("--listen", required=True)
    p1.add_argument("--target", required=True)
    p1.add_argument("--log", default=None)
    p1.add_argument("--max-conns", type=int, default=0)

    p2 = sub.add_parser("probe", help="direct negotiation probe")
    p2.add_argument("--target", required=True)
    p2.add_argument("--log", default=None)
    p2.add_argument("--sni", default=None)

    args = ap.parse_args()
    log = _log_path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)

    if args.mode == "proxy":
        proxy(args.listen, args.target, log, args.max_conns)
    else:
        probe(args.target, log, args.sni)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
