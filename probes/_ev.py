#!/usr/bin/env python3
"""_ev.py - evidence plumbing for protocol v2. Runs INSIDE the container.

The agent under test is an instrument, not a judge. This module:
  * resolves the PRE-REGISTERED command for a test ID from testplan.json
    (single source of truth: probes never hardcode their own commands, so a
    probe cannot silently drift from the plan it claims to implement),
  * records one evidence line per attempt (id, command, exit_code, errno,
    stdout_sha256, captured_bytes, wall_ms, ts, fields),
  * assembles evidence.json at the end.

There is deliberately NO verdict anywhere in this file. Verdicts are computed
host-side by adjudicate.sh, which holds the canary token values the agent never
sees.

Subcommands:
  init                       create the run dir, write run.json, print the dir
  resolve <ID>               print the substituted command (exit 3 => skip)
  record  <args>             append one evidence record
  finalize                   write evidence.json
  runid                      print the run id only
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
MARKER = os.environ.get("SANDY_ISO_MARKER", "/etc/sandy-session.json")
TESTPLAN = os.environ.get("SANDY_ISO_TESTPLAN", os.path.join(KIT, "testplan.json"))
CONTROLS = os.environ.get("SANDY_ISO_CONTROLS", os.path.join(os.getcwd(), "controls.json"))
MAX_CAPTURE = 4096

SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/@%+,\[\]-]+$")
ERRNO_PATTERNS = [
    (r"Read-only file system", "EROFS"),
    (r"Permission denied", "EACCES"),
    (r"Operation not permitted", "EPERM"),
    (r"No such file or directory", "ENOENT"),
    (r"Network is unreachable", "ENETUNREACH"),
    (r"No route to host", "EHOSTUNREACH"),
    (r"Connection refused", "ECONNREFUSED"),
    (r"Connection reset", "ECONNRESET"),
    (r"(Connection timed out|timed out)", "ETIMEDOUT"),
    (r"No space left on device", "ENOSPC"),
    (r"Is a directory", "EISDIR"),
    (r"Not a directory", "ENOTDIR"),
    (r"File exists", "EEXIST"),
]


# ---------------------------------------------------------------- utilities
def die(msg, code=1):
    sys.stderr.write("_ev.py: %s\n" % msg)
    sys.exit(code)


def load_json(path, required=True):
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except FileNotFoundError:
        if required:
            die("missing file: %s" % path)
        return None
    except ValueError as exc:
        if required:
            die("invalid JSON in %s: %s" % (path, exc))
        return None


def marker():
    return load_json(MARKER)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def iso_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def compact_ts(iso):
    return re.sub(r"[-:]", "", (iso or "").strip())


def sanitize_model(m):
    m = re.sub(r"[^A-Za-z0-9._-]", "-", (m or "").strip())
    return m or "unknown"


def detect_platform():
    uname = ""
    try:
        uname = open("/proc/version").read()
    except Exception:
        pass
    rel = os.uname().release if hasattr(os, "uname") else ""
    if "orbstack" in rel.lower() or "orbstack" in uname.lower():
        return "macos-orbstack"
    if "linuxkit" in rel.lower() or "docker-desktop" in rel.lower():
        return "macos-docker-desktop"
    if sys.platform.startswith("linux"):
        # A host bind whose source lives under /Users or /private is a macOS host.
        try:
            with open("/proc/mounts") as fh:
                blob = fh.read()
            if "/Users/" in blob or "/private/var/folders" in blob:
                return "macos-docker-desktop"
        except Exception:
            pass
        return "linux"
    return "unknown"


def run_id(mk=None, model=None):
    mk = mk or marker()
    model = sanitize_model(model or os.environ.get("SANDY_MODEL", ""))
    return "%s.%s.%s.%s" % (
        compact_ts(mk.get("launched_at", "")),
        mk.get("egress_mode", "unknown"),
        model,
        (mk.get("session_nonce", "") or "0" * 8)[:8],
    )


def rundir(create=False):
    d = os.environ.get("SANDY_ISO_RUNDIR")
    if not d:
        d = os.path.join(os.getcwd(), "reports", "runs", run_id())
    if create:
        os.makedirs(os.path.join(d, "poc"), exist_ok=True)
    return d


# ---------------------------------------------------------------- resolve
def controls():
    return load_json(CONTROLS, required=False) or {}


def canary(cid):
    for c in controls().get("canaries", []) or []:
        if c.get("id") == cid:
            return c
    return None


def _url_part(url, part):
    m = re.match(r"^(?:(?P<scheme>[a-z]+)://)?(?P<host>\[[^\]]+\]|[^/:]+)(?::(?P<port>\d+))?(?P<path>/.*)?$", url or "")
    if not m:
        return None
    if part == "host":
        return m.group("host")
    if part == "port":
        return m.group("port") or ("443" if (m.group("scheme") == "https") else "80")
    if part == "path":
        return m.group("path") or "/"
    return None


def lookup(expr):
    """Resolve one {{...}} expression to a string, or raise KeyError with a reason."""
    parts = expr.split(".")
    root = parts[0]

    if root == "marker":
        mk = marker()
        key = parts[1]
        if key == "nonce8":
            return (mk.get("session_nonce", "") or "")[:8]
        val = mk.get(key)
        if val in (None, ""):
            raise KeyError("control-missing:marker.%s" % key)
        return str(val)

    if root == "allowed_probe":
        ap = controls().get("allowed_probe") or {}
        val = ap.get(parts[1])
        if val in (None, ""):
            raise KeyError("control-missing:allowed_probe.%s" % parts[1])
        return str(val)

    if root == "canary":
        cid, key = parts[1], ".".join(parts[2:])
        c = canary(cid)
        if not c:
            raise KeyError("canary-absent:%s" % cid)
        if key in ("host", "port", "path") and c.get("url"):
            val = _url_part(c["url"], key)
        else:
            val = c.get(key)
        if val in (None, "", []):
            raise KeyError("canary-absent:%s.%s" % (cid, key))
        if isinstance(val, list):
            vals = [str(v) for v in val if v]
            for v in vals:
                if not SAFE_VALUE.match(v):
                    raise KeyError("unsafe-control-value:%s" % cid)
            return " ".join(shlex.quote(v) for v in vals)
        return str(val)

    raise KeyError("control-missing:%s" % expr)


def substitute(cmd):
    """Expand every {{...}} in cmd. Raises KeyError(reason) if any is unresolvable."""
    out = []
    pos = 0
    for m in re.finditer(r"\{\{([^}]+)\}\}", cmd):
        out.append(cmd[pos:m.start()])
        val = lookup(m.group(1).strip())
        if not (val.startswith("'") or SAFE_VALUE.match(val)):
            raise KeyError("unsafe-control-value:%s" % m.group(1).strip())
        out.append(val)
        pos = m.end()
    out.append(cmd[pos:])
    return "".join(out)


def find_test(tid):
    plan = load_json(TESTPLAN)
    for t in plan.get("tests", []):
        if t.get("id") == tid:
            return t, plan
    return None, plan


def cmd_resolve(args):
    t, _ = find_test(args.id)
    if t is None:
        die("unknown test id %s" % args.id, 4)
    if t.get("venue") != "container":
        sys.stderr.write("SKIP:not-applicable-in-mode:venue=host\n")
        return 3
    optin = t.get("opt_in_env")
    if optin:
        k, _, v = optin.partition("=")
        if os.environ.get(k) != v:
            sys.stderr.write("SKIP:opt-in-not-enabled:%s\n" % optin)
            return 3
    mode = marker().get("egress_mode", "unknown")
    exp = t.get("expected", {})
    per_mode = exp.get(mode, exp.get("all"))
    if isinstance(per_mode, dict) and per_mode.get("applicable") is False:
        sys.stderr.write("SKIP:not-applicable-in-mode:%s\n" % (per_mode.get("reason") or mode))
        return 3
    try:
        sys.stdout.write(substitute(t["command"]))
    except KeyError as exc:
        sys.stderr.write("SKIP:%s\n" % exc.args[0])
        return 3
    return 0


# ---------------------------------------------------------------- record
def coerce(val):
    low = val.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none", ""):
        return None
    # NOT a number if it has leading zeros: "0000000000000000" is a capability mask,
    # and int()/float()-ing it to 0 silently broke the CapEff comparison in self-test.
    s = val.strip()
    if re.match(r"^-?(0|[1-9][0-9]*)$", s):
        return int(s)
    if re.match(r"^-?(0|[1-9][0-9]*)\.[0-9]+$", s):
        return float(s)
    return s


def derive_errno(text):
    for pat, name in ERRNO_PATTERNS:
        if re.search(pat, text):
            return name
    return None


def cmd_record(args):
    raw = b""
    if args.out and os.path.exists(args.out):
        with open(args.out, "rb") as fh:
            raw = fh.read()
    text = raw.decode("utf-8", "replace")

    fields = {}
    errno_val, errno_src = None, "none"
    captured = text
    parsed = None
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            # Tool printed JSON plus extra text; try the first line.
            try:
                parsed = json.loads(stripped.splitlines()[0])
            except Exception:
                parsed = None
    if isinstance(parsed, dict):
        fields.update(parsed)
        if parsed.get("errno"):
            errno_val, errno_src = parsed["errno"], "syscall"
        if parsed.get("captured") is not None:
            captured = str(parsed["captured"])
    if errno_val is None:
        errno_val = derive_errno(text)
        errno_src = "derived-from-message" if errno_val else "none"
    if args.errno:
        errno_val, errno_src = args.errno, "syscall"

    for kv in args.field or []:
        k, _, v = kv.partition("=")
        if k:
            fields[k] = coerce(v)

    rec = {
        "id": args.id,
        "command": args.command,
        "exit_code": args.exit_code,
        "errno": errno_val,
        "errno_source": errno_src,
        "stdout_sha256": sha256_bytes(raw),
        "captured_bytes": captured[:MAX_CAPTURE] if captured else None,
        "captured_truncated": bool(captured) and len(captured) > MAX_CAPTURE,
        "stdout_len": len(raw),
        "wall_ms": max(0, args.wall_ms),
        "ts": args.ts or iso_now(),
        "fields": fields,
    }
    if args.planned_command:
        rec["planned_command"] = args.planned_command
    if args.skipped_reason:
        rec["skipped"] = True
        rec["skipped_reason"] = args.skipped_reason
    if args.note:
        rec["note"] = args.note

    d = rundir(create=True)
    if args.discretionary:
        rec = {
            "id": args.id,
            "title": args.title or args.command[:80],
            "rationale": args.note or "",
            "command": args.command,
            "exit_code": args.exit_code,
            "errno": errno_val,
            "errno_source": errno_src,
            "stdout_sha256": rec["stdout_sha256"],
            "captured_bytes": rec["captured_bytes"],
            "captured_truncated": rec["captured_truncated"],
            "stdout_len": rec["stdout_len"],
            "wall_ms": rec["wall_ms"],
            "ts": rec["ts"],
            "fields": fields,
            "layer_hint": args.layer_hint,
        }
        target = os.path.join(d, "discretionary.jsonl")
    else:
        target = os.path.join(d, "evidence.jsonl")
    with open(target, "a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
    return 0


# ---------------------------------------------------------------- init / finalize
def cmd_init(args):
    mk = marker()
    d = rundir(create=True)
    model = os.environ.get("SANDY_MODEL") or args.model or ""
    if not model:
        model = "unknown"
    with open(MARKER, "rb") as fh:
        marker_raw = fh.read()
    run = {
        "run_id": run_id(mk, model),
        "run_index": int(os.environ.get("SANDY_ISO_RUN_INDEX", "1")),
        "marker": mk,
        "marker_sha256": sha256_bytes(marker_raw),
        "declared_egress_mode": mk.get("egress_mode"),
        "model": sanitize_model(model),
        "platform": detect_platform(),
        "uname": " ".join(os.uname()) if hasattr(os, "uname") else "",
        "container_id": os.uname().nodename if hasattr(os, "uname") else "",
        "started_at": iso_now(),
        "controls_seen": [c.get("id") for c in (controls().get("canaries") or [])],
    }
    with open(os.path.join(d, "run.json"), "w") as fh:
        json.dump(run, fh, indent=2, sort_keys=True)
    print(d)
    return 0


def read_jsonl(path):
    out = []
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    return out


def cmd_finalize(args):
    d = rundir(create=True)
    run = load_json(os.path.join(d, "run.json"))
    plan = load_json(TESTPLAN)

    tests, seen = [], {}
    for rec in read_jsonl(os.path.join(d, "evidence.jsonl")):
        seen[rec.get("id")] = rec           # last attempt of an id wins
    for tid in sorted(seen):
        tests.append(seen[tid])

    for rec in tests:                        # lift the measured topology (F2a)
        if rec.get("id") == "L0.04":
            topo = (rec.get("fields") or {}).get("observed_topology")
            if topo:
                run["observed_topology"] = topo
        if rec.get("id") == "L0.02":
            res = ((rec.get("fields") or {}).get("results") or [{}])[0]
            run["marker_mount"] = {
                "source": res.get("source"), "fstype": res.get("fstype"),
                "options": res.get("options"), "ro": bool(res.get("ro")),
            }
    run.setdefault("observed_topology", "unknown")

    versions = {}
    for name in sorted(os.listdir(HERE)):
        p = os.path.join(HERE, name)
        if os.path.isfile(p) and not name.endswith(".pyc"):
            with open(p, "rb") as fh:
                versions[name] = sha256_bytes(fh.read())[:16]
    run["probe_versions"] = versions
    run["finished_at"] = iso_now()

    notes = []
    npath = os.path.join(d, "agent_notes.txt")
    if os.path.exists(npath):
        notes = [ln.rstrip("\n") for ln in open(npath) if ln.strip()]

    ev = {
        "schema": 1,
        "testplan_version": plan.get("testplan_version"),
        "run": run,
        "tests": tests,
        "discretionary": read_jsonl(os.path.join(d, "discretionary.jsonl")),
        "agent_notes": notes,
    }
    out = os.path.join(d, "evidence.json")
    with open(out, "w") as fh:
        json.dump(ev, fh, indent=2, sort_keys=True)

    mandatory = [t["id"] for t in plan["tests"]
                 if t.get("mandatory") and t.get("venue") == "container"]
    missing = [t for t in mandatory if t not in seen]
    print(out)
    print("tests recorded: %d/%d mandatory container tests; discretionary: %d"
          % (len(mandatory) - len(missing), len(mandatory), len(ev["discretionary"])))
    if missing:
        print("NOT ATTEMPTED (these will render NOT-ATTEMPTED host-side, never HELD): %s"
              % ", ".join(missing))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init"); p.add_argument("--model", default="")
    sub.add_parser("runid")
    p = sub.add_parser("resolve"); p.add_argument("id")
    p = sub.add_parser("record")
    p.add_argument("--id", required=True)
    p.add_argument("--command", required=True)
    p.add_argument("--planned-command", default="")
    p.add_argument("--exit-code", type=int, default=None)
    p.add_argument("--wall-ms", type=int, default=0)
    p.add_argument("--out", default="")
    p.add_argument("--ts", default="")
    p.add_argument("--errno", default="")
    p.add_argument("--note", default="")
    p.add_argument("--skipped-reason", default="")
    p.add_argument("--field", action="append", default=[])
    p.add_argument("--discretionary", action="store_true")
    p.add_argument("--title", default="")
    p.add_argument("--layer-hint", type=int, default=None)
    sub.add_parser("finalize")

    args = ap.parse_args()
    if args.cmd == "init":
        return cmd_init(args)
    if args.cmd == "runid":
        print(run_id())
        return 0
    if args.cmd == "resolve":
        return cmd_resolve(args)
    if args.cmd == "record":
        return cmd_record(args)
    if args.cmd == "finalize":
        return cmd_finalize(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
