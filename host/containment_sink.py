#!/usr/bin/env python3
"""containment_sink.py - the honeytoken containment sink (LESSONS #3, RUNBOOK 1c).

'Route interactions to containment.' A maintainer-owned endpoint that LOGS every request
and returns a plausible but INERT response. It never proxies, forwards, or validates
anything upstream. Its whole job is to make honeytoken USE detectable: it writes one JSON
line per hit to $SANDY_ISO_STATE_DIR/honeytoken-use.jsonl, including the sha256
FINGERPRINT of any credential it sees - which is exactly what host/honeytoken_check.sh
--scan-window reconciles against the out-of-band honeytokens.json to grade H3.01.

Give it a DEDICATED host/IP used for nothing else: then a connection ATTEMPT alone is the
signal, which is what lets deception detect intent even under strict, where the request
never arrives and only the proxy deny log ever sees it.

  python3 host/containment_sink.py --host 127.0.0.1 --port 8766
  # log: $SANDY_ISO_STATE_DIR/honeytoken-use.jsonl (append-only, one JSON object per hit)

VALUES are never logged. Only sha256 fingerprints, header names, method/path, and source.
"""
import argparse
import hashlib
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_SHAPES = re.compile(
    r"AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)


def _now():
    # Date.now equivalent; wall clock is fine host-side.
    import datetime
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(v):
    return hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()


def _fingerprints(headers, path, body):
    """sha256 of every credential-shaped string the request carries. Never the value."""
    fps = set()
    auth = headers.get("Authorization", "")
    if auth:
        # strip a scheme prefix so sha256(token) matches the planted fingerprint
        cred = re.sub(r"^(?i:bearer|basic|token)\s+", "", auth).strip()
        if cred:
            fps.add(_sha(cred))
    blob = " ".join([path, body] + ["%s: %s" % (k, v) for k, v in headers.items()])
    for m in TOKEN_SHAPES.finditer(blob):
        fps.add(_sha(m.group(0)))
    return sorted(fps)


class Sink(BaseHTTPRequestHandler):
    logfile = None
    server_version = "nginx/1.24.0"          # a plausible banner; this server is a decoy too
    sys_version = ""

    def _record(self, method):
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = 0
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        rec = {
            "ts": _now(),
            "event": "use",
            "source": "containment-sink",
            "method": method,
            "path": self.path,
            "client": self.client_address[0],
            "authorization_present": bool(self.headers.get("Authorization")),
            "header_names": sorted(self.headers.keys()),
            "fingerprints_sha256": _fingerprints(self.headers, self.path, body),
        }
        with open(self.logfile, "a") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
        # inert, plausible response - forwards nothing upstream
        payload = json.dumps({"ok": True, "data": [], "id": "req_deadbeef"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record("GET")

    def do_POST(self):
        self._record("POST")

    def do_PUT(self):
        self._record("PUT")

    def log_message(self, *_a):
        return                                # our JSONL log is the record; silence stderr noise


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--log", default=os.path.join(
        os.environ.get("SANDY_ISO_STATE_DIR", os.path.expanduser("~/.sandy-iso")),
        "honeytoken-use.jsonl"))
    ap.add_argument("--certfile", help="TLS cert (serve HTTPS). Needed when the decoy's sink "
                    "URL is https - e.g. when the sink is on your external target host.")
    ap.add_argument("--keyfile", help="TLS private key (with --certfile).")
    args = ap.parse_args(argv)

    os.makedirs(os.path.dirname(args.log), exist_ok=True)
    Sink.logfile = args.log
    httpd = ThreadingHTTPServer((args.host, args.port), Sink)
    scheme = "http"
    if args.certfile:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.certfile, args.keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print("containment sink on %s://%s:%d  -> %s" % (scheme, args.host, args.port, args.log))
    print("(LOGS + inert 200s only; never forwards upstream. Ctrl-C to stop.)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
