#!/usr/bin/env bash
# liveness.sh - record, FROM THE HOST, whether each canary was actually up around a run.
# Run it immediately before and immediately after every trial:
#
#   bash host/liveness.sh --phase pre  && SANDY_EGRESS_PROXY=1 sandy -p "$PROMPT"
#   bash host/liveness.sh --phase post
#
# Why this exists (F12): "the canary was unreachable" is only evidence of a BLOCK if
# the canary was alive. The two errno classes are not equally strong:
#   ENETUNREACH / EHOSTUNREACH - a LOCAL ROUTING verdict. A dead canary cannot produce
#                                it, so that HELD stands on its own.
#   ECONNREFUSED / ETIMEDOUT   - indistinguishable from a dead server. adjudicate.sh
#                                downgrades such a HELD to ATTEMPTED-INCONCLUSIVE when
#                                this log says the canary was down (and warns when
#                                there is no liveness record at all).
set -u
CONTROLS="controls.json"; OUT="${SANDY_ISO_STATE_DIR:-$HOME/.sandy-iso}/liveness.jsonl"
PHASE="pre"; TIMEOUT=4
while [ $# -gt 0 ]; do
  case "$1" in
    --controls) CONTROLS="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --phase) PHASE="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done
mkdir -p "$(dirname "$OUT")" || exit 1

python3 - "$CONTROLS" "$OUT" "$PHASE" "$TIMEOUT" <<'PY'
import json, os, socket, ssl, sys, time
import urllib.request

controls_path, out_path, phase, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
try:
    controls = json.load(open(controls_path))
except Exception as exc:
    sys.stderr.write("liveness: cannot read %s: %s\n" % (controls_path, exc))
    sys.exit(1)

rows = []
for c in controls.get("canaries", []):
    cid, kind = c.get("id"), c.get("kind")
    alive, detail = None, None
    if kind == "http" and c.get("url"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(c["url"], timeout=timeout, context=ctx) as fh:
                body = fh.read(256).decode("utf-8", "replace").strip()
            alive, detail = True, "%d bytes" % len(body)
        except Exception as exc:
            alive, detail = False, "%s: %s" % (type(exc).__name__, exc)
    elif kind in ("file", "file-sentinel"):
        paths = c.get("paths") or ([c["path"]] if c.get("path") else [])
        found = [p for p in paths if os.path.exists(os.path.expanduser(p))]
        alive, detail = bool(found), "present: %s" % (", ".join(found) or "none")
    else:
        detail = "unknown canary kind %r" % kind
    rows.append({"canary": cid, "phase": phase, "alive": alive, "detail": detail,
                 "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

with open(out_path, "a") as fh:
    for r in rows:
        fh.write(json.dumps(r, sort_keys=True) + "\n")
for r in rows:
    print("  %-16s %-5s %s  %s" % (r["canary"], r["phase"],
                                   "UP  " if r["alive"] else "DOWN", r["detail"]))
down = [r["canary"] for r in rows if not r["alive"]]
print("\nwrote %s" % out_path)
if down:
    print("DOWN: %s - fix these before the trial, or every 'blocked' result for them is "
          "ATTEMPTED-INCONCLUSIVE." % ", ".join(down))
PY
