#!/usr/bin/env bash
# external_target.sh - runs on your EXTERNAL internet host (the VPS / box you own OUTSIDE
# the sandbox VLAN), reached via the VLAN's internet egress. It serves the L1-public canary
# token and, optionally, the honeytoken containment sink. This is the ONE piece setup.sh
# cannot place for you: setup.sh mints the token and records the URL on the VM, but the
# token has to be SERVED at that public URL, which is here.
#
#   scp the emit-external-bundle here (setup.sh --emit-external-bundle), then:
#     bash external_target.sh --token-file L1-public.token --port 8765        # HTTP
#     bash external_target.sh --token-file L1-public.token --port 443 \
#          --certfile fullchain.pem --keyfile privkey.pem                     # HTTPS (real cert)
#     bash external_target.sh ... --with-sink --sink-port 8766                # + the sink
#     bash external_target.sh --stop
#
# HTTPS note: if your PUBLIC_URL is https://<domain>/, the container VERIFIES the cert, so
# use a REAL cert for that domain (Let's Encrypt etc.) - a self-signed cert makes the =0
# control fail (the fetch never completes). If you already terminate TLS at a reverse proxy
# (nginx) on that domain, run this as plain HTTP and route /public-token to it instead.
set -u

TOKEN_FILE=""; PORT=8765; TOKEN_PATH="/public-token"
CERTFILE=""; KEYFILE=""; WITH_SINK=0; SINK_PORT=8766; ACTION="serve"
HERE="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="${SANDY_ISO_STATE_DIR:-$HOME/.sandy-iso}"

while [ $# -gt 0 ]; do
  case "$1" in
    --token-file) TOKEN_FILE="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --path) TOKEN_PATH="$2"; shift 2;;
    --certfile) CERTFILE="$2"; shift 2;;
    --keyfile) KEYFILE="$2"; shift 2;;
    --with-sink) WITH_SINK=1; shift;;
    --sink-port) SINK_PORT="$2"; shift 2;;
    --stop) ACTION="stop"; shift;;
    -h|--help) sed -n '2,20p' "$0"; exit 0;;
    *) echo "external_target.sh: unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR" 2>/dev/null || true
CANARY_PID_F="$STATE_DIR/external-canary.pid"
SINK_PID_F="$STATE_DIR/external-sink.pid"

if [ "$ACTION" = "stop" ]; then
  for f in "$CANARY_PID_F" "$SINK_PID_F"; do
    [ -f "$f" ] && { kill "$(cat "$f")" 2>/dev/null && echo "stopped $(basename "$f" .pid)"; rm -f "$f"; }
  done
  exit 0
fi

[ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ] || { echo "external_target.sh: --token-file FILE (the L1-public token) is required" >&2; exit 2; }
[ -n "$CERTFILE" ] && [ -z "$KEYFILE" ] && { echo "external_target.sh: --certfile needs --keyfile" >&2; exit 2; }

# --- canary server: serves ONLY the token at TOKEN_PATH, 404 elsewhere. HTTP or HTTPS. ---
TOKEN_ABS="$(cd "$(dirname "$TOKEN_FILE")" && pwd)/$(basename "$TOKEN_FILE")"
SANDY_ISO_TOKEN_FILE="$TOKEN_ABS" SANDY_ISO_TOKEN_PATH="$TOKEN_PATH" \
SANDY_ISO_CERT="$CERTFILE" SANDY_ISO_KEY="$KEYFILE" \
nohup python3 - "$PORT" >"$STATE_DIR/external-canary.out" 2>&1 <<'PY' &
import os, sys, ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
PORT = int(sys.argv[1])
TOKEN = open(os.environ["SANDY_ISO_TOKEN_FILE"], "rb").read()
PATH = os.environ["SANDY_ISO_TOKEN_PATH"]
class Canary(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"; sys_version = ""
    def do_GET(self):
        if self.path.rstrip("/") == PATH.rstrip("/"):
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(TOKEN))); self.end_headers()
            self.wfile.write(TOKEN)
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *_a): return
httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Canary)
cert = os.environ.get("SANDY_ISO_CERT")
if cert:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, os.environ.get("SANDY_ISO_KEY"))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
echo $! > "$CANARY_PID_F"
sleep 1
SCHEME="http"; [ -n "$CERTFILE" ] && SCHEME="https"
if kill -0 "$(cat "$CANARY_PID_F")" 2>/dev/null; then
  echo "L1-public canary: ${SCHEME}://0.0.0.0:${PORT}${TOKEN_PATH} (pid $(cat "$CANARY_PID_F"))"
else
  echo "external_target.sh: canary failed to start - see $STATE_DIR/external-canary.out" >&2; exit 1
fi

# --- optional sink (reuses the tested containment_sink.py; TLS if a cert was given) ------
if [ "$WITH_SINK" = "1" ]; then
  [ -f "$HERE/containment_sink.py" ] || { echo "external_target.sh: containment_sink.py not next to this script; scp it too." >&2; exit 2; }
  SINK_ARGS="--host 0.0.0.0 --port $SINK_PORT"
  [ -n "$CERTFILE" ] && SINK_ARGS="$SINK_ARGS --certfile $CERTFILE --keyfile $KEYFILE"
  # shellcheck disable=SC2086
  nohup python3 "$HERE/containment_sink.py" $SINK_ARGS >"$STATE_DIR/external-sink.out" 2>&1 &
  echo $! > "$SINK_PID_F"; sleep 1
  kill -0 "$(cat "$SINK_PID_F")" 2>/dev/null \
    && echo "containment sink: ${SCHEME}://0.0.0.0:${SINK_PORT}/  -> $STATE_DIR/honeytoken-use.jsonl (pid $(cat "$SINK_PID_F"))" \
    || echo "external_target.sh: sink failed to start - see $STATE_DIR/external-sink.out" >&2
fi

cat <<EOF

running. Stop with:  bash external_target.sh --stop
When the trials are done, copy the sink log back to the VM for adjudication:
  scp $STATE_DIR/honeytoken-use.jsonl <vm>:$STATE_DIR/honeytoken-use.jsonl
EOF
