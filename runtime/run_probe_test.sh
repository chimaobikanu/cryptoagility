#!/usr/bin/env bash
# Live test of the runtime observation layer (no root, no compiler required).
set -u
cd "$(dirname "$0")"

SPORT=14433
PPORT=14444
LOG=/tmp/ca-runtime.jsonl
: > "$LOG"

[ -f srv.pem ] || openssl req -x509 -newkey rsa:2048 -keyout srv.key -out srv.pem \
    -days 2 -nodes -subj "/CN=runtime.test" >/dev/null 2>&1

SRV_CIPHERS='ECDHE-RSA-AES256-GCM-SHA384:AES256-GCM-SHA384:AES128-SHA:@SECLEVEL=0'

openssl s_server -quiet -accept $SPORT -cert srv.pem -key srv.key \
    -cipher "$SRV_CIPHERS" -www >/dev/null 2>&1 &
SRV=$!
sleep 1

python3 ca_probe.py proxy --listen 127.0.0.1:$PPORT --target 127.0.0.1:$SPORT --log "$LOG" >/dev/null 2>&1 &
PRX=$!
sleep 1

run () {
  echo "--- $1 ---"
  printf 'GET / HTTP/1.0\r\n\r\n' | timeout 20 openssl s_client -connect 127.0.0.1:$PPORT \
      ${@:2} 2>&1 | grep -Ei 'Cipher is|Protocol *:|error|alert|no cipher|handshake' | head -4
  sleep 0.5
}

run "connection 1: client asks for legacy static-RSA CBC (no forward secrecy)" -tls1_2 -cipher 'AES128-SHA:@SECLEVEL=0'
run "connection 2: client asks for AES-256-GCM"  -tls1_2 -cipher 'ECDHE-RSA-AES256-GCM-SHA384'
run "connection 3: client negotiates TLS 1.3"    -tls1_3

kill $PRX $SRV 2>/dev/null
wait $PRX $SRV 2>/dev/null

echo
echo "=== runtime observation log ($LOG) ==="
cat "$LOG"
