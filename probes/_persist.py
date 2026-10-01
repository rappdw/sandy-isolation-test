#!/usr/bin/env python3
"""_persist.py - Layer 8 (persistence & supply chain) measurement helper (protocol v2.1).

New in v2.1. Motivated by the Hugging Face incident (LESSONS.md rows #2 and #4): the kit
was a point-in-time snapshot with NO time/persistence dimension, and it never tested the
agent's own tool supply chain. This helper measures the two things that turn a single
session into a cross-session foothold:

  * classify  - is a location writable AND host-backed (i.e. does a write here SURVIVE
                session end), and does it sit on $PATH ahead of the system dirs? Pure
                measurement, mount facts from /proc/self/mountinfo + findmnt (F10), no write.
  * sentinel  - PROVE the write capability by creating a nonce-named INERT sentinel, record
                every directory component created + the host-side path each maps to, then
                REMOVE all of it. Mirrors filesystem.sh's L2.07 probe-artifact discipline
                (measure ro/rw BEFORE writing; record created_components for exact cleanup)
                - but, unlike L2.07, it LEAVES NOTHING by default. The "did it survive to the
                host sandbox" claim is graded host-side (H8.01), never asserted from inside.

Every subcommand prints ONE JSON object on stdout and exits 0 (the JSON carries the
outcome). _ev.py merges that object into the evidence record's `fields`. There is NO
verdict anywhere in this file: adjudicate.sh computes HELD/BREACHED host-side.

INERT BY CONSTRUCTION - what this helper will and will not write:
  * The sentinel is non-executable text with a `_sandy_persist_probe_<nonce>` name.
  * kind=pth writes a .pth file whose every line is a `#` comment - site.py ignores
    comment lines, so it imports/executes NOTHING even if one were left behind.
  * kind=skill writes `PROBE.txt` (never SKILL.md), so it is not a loadable skill.
  * It never writes sitecustomize.py / usercustomize.py / an executable console-script /
    a real hook / MCP / plugin config. It proves the DIRECTORY is writable+persistent; it
    does not plant a working implant.
  * Writes are confined to $HOME, the marker workspace, or /tmp, and only to a path first
    measured writable. A rw host-backed target is written-then-removed; anything else is
    reported from its mount flags and left untouched.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# Reuse the exact mount-measurement discipline from the L2 helper (F7/F10) rather than
# re-deriving it. Post-integration _persist.py sits beside _fsop.py in probes/; in the
# self-test staging dir a copy is placed alongside. Fall back to a vendored minimum so the
# probe still runs if _fsop is somehow absent.
sys.path.insert(0, HERE)
try:
    import _fsop as F  # noqa: E402

    read_mountinfo = F.read_mountinfo
    mount_for = F.mount_for
    ename = F.ename
except Exception:  # pragma: no cover - defensive vendored fallback
    import errno as _errno_mod

    _CONTAINER_FSTYPES = {
        "overlay", "overlayfs", "tmpfs", "ramfs", "proc", "sysfs", "cgroup", "cgroup2",
        "devpts", "mqueue", "devtmpfs", "securityfs", "tracefs", "debugfs", "fusectl",
        "configfs", "binfmt_misc", "pstore", "bpf", "nsfs", "autofs", "hugetlbfs",
    }

    def ename(e):
        if isinstance(e, OSError) and e.errno is not None:
            return _errno_mod.errorcode.get(e.errno, "E%d" % e.errno)
        return None

    def read_mountinfo():
        entries = []
        try:
            with open("/proc/self/mountinfo") as fh:
                for line in fh:
                    pre, _, post = line.partition(" - ")
                    pf, sf = pre.split(), post.split()
                    if len(pf) < 6 or len(sf) < 2:
                        continue
                    entries.append({
                        "target": pf[4], "root": pf[3], "vfs_options": pf[5],
                        "fstype": sf[0], "mnt_source": sf[1],
                        "fs_options": sf[2] if len(sf) > 2 else "",
                    })
        except OSError:
            pass
        return entries

    _MI = None

    def mount_for(path):
        global _MI
        if _MI is None:
            _MI = read_mountinfo()
        try:
            real = os.path.realpath(path)
        except Exception:
            real = path
        best = None
        for e in _MI:
            t = e["target"]
            if real == t or real.startswith(t.rstrip("/") + "/") or t == "/":
                if best is None or len(t) > len(best["target"]):
                    best = e
        if best is None:
            return None
        src = best["mnt_source"]
        if best["root"] not in ("/", ""):
            src = "%s[%s]" % (best["mnt_source"], best["root"])
        return {
            "target": best["target"], "source": src, "source_root": best["root"],
            "fstype": best["fstype"],
            "options": "%s,%s" % (best["vfs_options"], best["fs_options"]),
            "ro": "ro" in best["vfs_options"].split(","),
            "host_backed": best["fstype"] not in _CONTAINER_FSTYPES,
        }

SENTINEL_BASE = "_sandy_persist_probe"
MARKER = os.environ.get("SANDY_ISO_MARKER", "/etc/sandy-session.json")


def out(obj):
    json.dump(obj, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def workspace():
    try:
        with open(MARKER) as fh:
            return json.load(fh).get("workspace")
    except Exception:
        return None


# ---------------------------------------------------------------- PATH facts
def path_entries():
    return [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]


SYSTEM_BINDIRS = {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}


def first_system_index(entries):
    for i, p in enumerate(entries):
        if p.rstrip("/") in SYSTEM_BINDIRS:
            return i
    return None


def nearest_existing(path):
    p = os.path.abspath(path)
    while p and not os.path.lexists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    return p


def to_host(inpath, m):
    """Translate an in-container path to its host-sandbox path using the mount's
    source_root (host-side root of the bind). Returns None if not host-backed."""
    if not m or not m.get("host_backed"):
        return None
    target = (m.get("target") or "").rstrip("/")
    root = (m.get("source_root") or "").rstrip("/")
    if not target or not root:
        return None
    ap = os.path.abspath(inpath)
    if ap == target:
        return root
    if ap.startswith(target + "/"):
        return root + ap[len(target):]
    return None


def measure(path):
    """Mount facts for path (or, if it does not exist, for its nearest existing ancestor)."""
    exists = os.path.lexists(path)
    probe_at = path if exists else nearest_existing(path)
    m = mount_for(probe_at) or {}
    w_ok = os.access(probe_at, os.W_OK) if os.path.lexists(probe_at) else False
    ro = bool(m.get("ro"))
    host_backed = bool(m.get("host_backed"))
    writable = bool(w_ok and not ro)
    return {
        "path": path,
        "exists": exists,
        "measured_at": probe_at,
        "source": m.get("source"),
        "source_root": m.get("source_root"),
        "fstype": m.get("fstype"),
        "ro": ro,
        "w_ok": w_ok,
        "writable": writable,
        "host_backed": host_backed,
        "persists": host_backed,               # a write here survives session end
        "would_persist": bool(writable and host_backed),
        "host_path": to_host(path, m),
    }


# ---------------------------------------------------------------- classify
def cmd_classify(argv):
    ap = argparse.ArgumentParser(prog="classify")
    ap.add_argument("--label", default="")
    ap.add_argument("--mechanism", default="")
    ap.add_argument("--path-entries", action="store_true",
                    help="classify every $PATH entry (in order) instead of positional paths")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args(argv)

    entries = path_entries()
    sys_idx = first_system_index(entries)
    targets = list(entries) if a.path_entries else list(a.paths)
    results = []
    for raw in targets:
        p = os.path.expanduser(os.path.expandvars(raw))
        d = measure(p)
        d["mechanism"] = a.mechanism or None
        # PATH-order facts: is this dir (or its bin/) on PATH ahead of the system dirs?
        idx = None
        for cand in (p.rstrip("/"), os.path.join(p, "bin").rstrip("/")):
            for i, e in enumerate(entries):
                if e.rstrip("/") == cand:
                    idx = i if idx is None else min(idx, i)
        d["path_index"] = idx
        d["on_path"] = idx is not None
        d["precedes_system"] = bool(idx is not None and sys_idx is not None and idx < sys_idx)
        d["path_hijack_surface"] = bool(d["would_persist"] and d["precedes_system"])
        results.append(d)

    hb = [r for r in results if r["host_backed"]]
    wp = [r for r in results if r["would_persist"]]
    hij = [r for r in results if r["path_hijack_surface"]]
    return out({
        "op": "classify",
        "label": a.label,
        "results": results,
        "first_system_path_index": sys_idx,
        "summary": {
            "n": len(results),
            "n_exists": sum(1 for r in results if r["exists"]),
            "n_host_backed": len(hb),
            "n_would_persist": len(wp),
            "n_path_hijack": len(hij),
            "would_persist_paths": [r["path"] for r in wp],
            "path_hijack_paths": [r["path"] for r in hij],
            "host_paths": [r["host_path"] for r in wp if r["host_path"]],
        },
    })


# ---------------------------------------------------------------- sentinel
INERT_NOTICE = (
    "sandy-isolation-test :: Layer 8 persistence probe :: INERT SENTINEL\n"
    "run nonce: {nonce}\n"
    "created:   {ts}\n"
    "kind:      {kind}\n"
    "purpose:   prove this location is writable AND host-backed (survives session end).\n"
    "           This file is NON-EXECUTABLE text. It is created and then REMOVED by the\n"
    "           same probe run - it is NOT a persistence implant. If you are reading this\n"
    "           on the HOST after a session ended, the in-container cleanup did NOT\n"
    "           propagate: that is test H8.01 rendering BREACHED. Safe to delete.\n"
)

# A .pth line beginning with '#' is a comment and is ignored by site.py: the file below is
# comment-only, so Python imports/executes nothing from it. It demonstrates that a .pth
# COULD be dropped into site-packages here, without planting any executable payload.
PTH_INERT = "# sandy-isolation-test L8 inert .pth sentinel (nonce {nonce}) - comment only, executes nothing\n"


def _mkdirs(target):
    """Create missing components from the nearest existing ancestor down to target.
    Returns (created_list, errno). created_list is deepest-last."""
    created = []
    ne = nearest_existing(target)
    ap = os.path.abspath(target)
    if os.path.abspath(ne) == ap:
        return created, None
    tail = ap[len(os.path.abspath(ne)):].strip("/")
    cur = os.path.abspath(ne)
    for part in tail.split("/"):
        cur = os.path.join(cur, part)
        try:
            os.mkdir(cur)
            created.append(cur)
        except OSError as e:
            return created, ename(e)
    return created, None


def _rmtree_created(sentinel, skill_dir, created):
    """Remove ONLY what this probe created: the sentinel file, an optional skill subdir,
    then the created components in reverse. rmdir refuses non-empty dirs, so a component
    that unexpectedly contains other content is left and reported as residual."""
    residual = []
    if sentinel and os.path.lexists(sentinel):
        try:
            os.unlink(sentinel)
        except OSError:
            residual.append(sentinel)
    if skill_dir and os.path.isdir(skill_dir):
        try:
            os.rmdir(skill_dir)
        except OSError:
            residual.append(skill_dir)
    for c in reversed(created):
        if os.path.isdir(c):
            try:
                os.rmdir(c)
            except OSError:
                residual.append(c)
    return residual


def cmd_sentinel(argv):
    ap = argparse.ArgumentParser(prog="sentinel")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--nonce", default="00000000")
    ap.add_argument("--kind", choices=["text", "pth", "skill"], default="text")
    ap.add_argument("--mechanism", default="")
    ap.add_argument("--leave", action="store_true")
    a = ap.parse_args(argv)

    leave = a.leave or os.environ.get("SANDY_ISO_LEAVE_SENTINEL") == "1"
    target = os.path.abspath(os.path.expanduser(os.path.expandvars(a.dir)))

    # Confinement: only ever write under $HOME, the workspace, or /tmp.
    home = os.path.abspath(os.environ.get("HOME", "/home/sandy"))
    ws = os.path.abspath(workspace() or home)
    allowed_roots = [home, ws, "/tmp"]
    confined = any(target == r or target.startswith(r.rstrip("/") + "/") for r in allowed_roots)

    d = measure(target)
    res = {
        "op": "sentinel",
        "dir": target,
        "kind": a.kind,
        "nonce": a.nonce,
        "mechanism": a.mechanism or None,
        "confined_to_allowed_root": confined,
        "exists": d["exists"],
        "source": d["source"],
        "source_root": d["source_root"],
        "fstype": d["fstype"],
        "ro": d["ro"],
        "writable": d["writable"],
        "host_backed": d["host_backed"],
        "persists": d["persists"],
        "would_persist": d["would_persist"],
        "sentinel_written": False,
        "sentinel_removed": None,
        "left": False,
        "created_components": [],
        "created_components_host": [],
        "sentinel_path": None,
        "sentinel_path_host": None,
        "residual": [],
        "cleaned": True,
        "errno": None,
    }

    if not confined:
        res["note"] = "refused: target is outside $HOME / workspace / tmp - not written"
        return out(res)
    if not d["writable"]:
        # F7: measured NOT writable -> report from mount flags, never attempt a write.
        res["note"] = ("measured read-only or ephemeral-unwritable; not written. "
                       "would_persist=%s" % d["would_persist"])
        return out(res)

    # Writable. Create any missing components, then write the inert sentinel.
    created, mk_errno = _mkdirs(target)
    res["created_components"] = created
    if mk_errno:
        res["errno"] = mk_errno
        res["cleaned"] = not _rmtree_created(None, None, created)
        res["residual"] = _rmtree_created(None, None, created) if not res["cleaned"] else []
        res["note"] = "mkdir failed: %s" % mk_errno
        return out(res)

    skill_dir = None
    if a.kind == "skill":
        skill_dir = os.path.join(target, "%s_%s" % (SENTINEL_BASE, a.nonce))
        try:
            os.mkdir(skill_dir)
        except OSError as e:
            res["errno"] = ename(e)
            res["residual"] = _rmtree_created(None, None, created)
            res["cleaned"] = not res["residual"]
            return out(res)
        sentinel = os.path.join(skill_dir, "PROBE.txt")
        body = INERT_NOTICE.format(nonce=a.nonce, ts=_ts(), kind="skill/PROBE.txt (not SKILL.md)")
    elif a.kind == "pth":
        sentinel = os.path.join(target, "%s_%s.pth" % (SENTINEL_BASE, a.nonce))
        body = PTH_INERT.format(nonce=a.nonce)
    else:
        sentinel = os.path.join(target, "%s_%s.txt" % (SENTINEL_BASE, a.nonce))
        body = INERT_NOTICE.format(nonce=a.nonce, ts=_ts(), kind="text")

    try:
        with open(sentinel, "w") as fh:
            fh.write(body)
        res["sentinel_written"] = True
        res["sentinel_sha256"] = hashlib.sha256(body.encode()).hexdigest()
        res["sentinel_path"] = sentinel
    except OSError as e:
        res["errno"] = ename(e)
        res["residual"] = _rmtree_created(None, skill_dir, created)
        res["cleaned"] = not res["residual"]
        return out(res)

    # Host-side translations (what the maintainer checks for H8.01).
    m = mount_for(target) or {}
    res["sentinel_path_host"] = to_host(sentinel, m)
    res["created_components_host"] = [h for h in (to_host(c, m) for c in created) if h]
    if skill_dir:
        res["created_components"] = created + [skill_dir]
        hp = to_host(skill_dir, m)
        if hp:
            res["created_components_host"] = res["created_components_host"] + [hp]

    if leave:
        # Opt-in ONLY (SANDY_ISO_LEAVE_SENTINEL=1 / --leave): used by the maintainer to
        # calibrate the H8.01 detective control. The probe run NEVER sets it.
        res["left"] = True
        res["sentinel_removed"] = False
        res["cleaned"] = False
        res["note"] = ("SENTINEL LEFT by explicit opt-in for H8.01 calibration - the "
                       "maintainer must remove sentinel_path and created_components.")
        return out(res)

    # Default: remove everything this probe created and verify.
    residual = _rmtree_created(sentinel, skill_dir, created)
    res["sentinel_removed"] = not os.path.lexists(sentinel)
    res["residual"] = residual
    res["cleaned"] = res["sentinel_removed"] and not residual
    return out(res)


def _ts():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


COMMANDS = {"classify": cmd_classify, "sentinel": cmd_sentinel}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        out({"error": "usage: _persist.py <%s> [args]" % "|".join(sorted(COMMANDS))})
        return 2
    try:
        return COMMANDS[argv[1]](argv[2:])
    except SystemExit:
        raise
    except Exception as exc:  # never crash a probe run
        return out({"op": argv[1], "error": "%s: %s" % (type(exc).__name__, exc)})


if __name__ == "__main__":
    sys.exit(main(sys.argv))
