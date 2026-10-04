#!/usr/bin/env bash
# Observe negotiated cryptography on a live TLS connection using the shim.
# Usage: ./run_runtime_test.sh
set -u
cd "$(dirname "$0")"

PORT=14433
LOG=/tmp/ca-runtime.jsonl
: > "$LOG"

command -v gcc >/dev/null || { echo "gcc missing"; exit 1; }
[ -f ca_shim.so ] || gcc -shared -fPIC -O2 -o ca_shim.so ca_shim.c -ldl || exit 1

# throwaway cert/key for the test server
openssl req -x509 -newkey rsa:2048 -keyout srv.key -out srv.pem \
    -days 2 -nodes -subj "/CN=runtime.test" >/dev/null 2>&1

export CA_LOG="$LOG"
export LD_PRELOAD="$PWD/ca_shim.so"

# 1) server offering a modern TLS 1.2 suite list
openssl s_server -quiet -accept $PORT -cert srv.pem -key srv.key \
    -cipher 'ECDHE-RSA-AES256-GCM-SHA384' >/dev/null 2>&1 &
SRV=$!
sleep 1

# 2) client forcing a legacy 3DES suite — the negotiated result is what we capture
echo "hello" | openssl s_client -connect 127.0.0.1:$PORT -tls1_2 \
    -cipher 'DES-CBC3-SHA' -quiet >/dev/null 2>&1
echo "hello2" | openssl s_client -connect 127.0.0.1:$PORT -tls1_2 \
    -cipher 'ECDHE-RSA-AES256-GCM-SHA384' -quiet >/dev/null 2>&1
echo "hello3" | openssl s_client -connect 127.0.0.1:$PORT -tls1_3 -quiet >/dev/null 2>&1

kill $SRV 2>/dev/null
wait $SRV 2>/dev/null

echo "=== observed runtime crypto ($LOG) ==="
cat "$LOG"
