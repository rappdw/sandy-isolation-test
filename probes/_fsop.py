#!/usr/bin/env python3
"""_fsop.py - filesystem / credential / cgroup measurement helper (protocol v2).

Every subcommand prints ONE JSON object on stdout and exits 0 (the JSON carries
the outcome; a non-zero exit would only duplicate it). _ev.py merges that object
into the evidence record's `fields` and lifts `errno`/`captured` to the top.

Why a helper instead of shell one-liners:
  * real symbolic errno from a real syscall - ENETUNREACH vs ECONNREFUSED vs
    EROFS is load-bearing (F12), and text-matching stderr is a guess;
  * mount facts BEFORE any write, so the probe can refuse to write to a rw host
    bind instead of discovering it by landing a write on the maintainer's file (F7);
  * mount SOURCE resolution that works where /proc/mounts is uninformative -
    on OrbStack every host bind shows up as `mac` (F10). /proc/self/mountinfo
    carries the host-side root path; findmnt is used as a cross-check when present.

Nothing here decides HELD/BREACHED.
"""
import errno as errno_mod
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

MAX_HEAD = 4096

CONTAINER_FSTYPES = {
    "overlay", "overlayfs", "tmpfs", "ramfs", "proc", "sysfs", "cgroup", "cgroup2",
    "devpts", "mqueue", "devtmpfs", "securityfs", "tracefs", "debugfs", "fusectl",
    "configfs", "binfmt_misc", "pstore", "bpf", "nsfs", "autofs", "hugetlbfs",
}

PROTECTED_SUFFIXES = [
    ".bashrc", ".bash_profile", ".profile", ".zshrc", ".gitconfig", ".netrc", ".npmrc",
    ".pypirc", ".git/config", ".git/HEAD", ".git/hooks", ".git/info", ".git/info/exclude",
    ".github/workflows", ".github", ".vscode", ".devcontainer", ".sandy", ".aws",
    ".docker/config.json", ".ssh",
]

PACKAGE_DIR_SUFFIXES = [
    "/.cargo", "/.npm-global", "/.pip-packages", "/.local/share/uv", "/go", "/.rustup",
    "/.bun", "/.deno", "/.local/share/pnpm",
]

MKTEMP_RE = re.compile(r"(/tmp/tmp\.[A-Za-z0-9]|/var/folders/.+/T/tmp\.|/private/var/folders/|/tmp/[a-z]*tmp[A-Za-z0-9_]{6,})")
SANDBOX_RE = re.compile(r"/\.sandy/sandboxes/")
CRED_NAMES = {
    ".credentials.json", "auth.json", "oauth_creds.json", "tokens.json", "credentials",
    ".netrc", "token.json", "client_secret.json",
}
CRED_NAME_RE = re.compile(r"(credential|oauth|token|\.netrc$|id_rsa$|id_ed25519$|id_ecdsa$|\.pem$)", re.I)
# Source/doc files whose NAME merely mentions credentials are not credential stores.
NON_CRED_SUFFIXES = (".sh", ".py", ".md", ".txt", ".rst", ".yml", ".yaml", ".example",
                     ".ts", ".js", ".go", ".rs", ".c", ".h", ".lock", ".log", ".bak",
                     ".sample", ".tmpl", ".template", ".html")
PRUNE_DIRS = {
    "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/nix",
    "/snap", "/var/lib", "/var/cache",
}
PRUNE_NAMES = {
    "node_modules", "objects", "registry", "site-packages", "dist-packages", ".venv",
    "__pycache__", ".mypy_cache", "pkg", "lib", "share", ".cache", "target", "build",
}
CAP_NAMES = [
    "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
    "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
    "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
    "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
    "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
]
DOCUMENTED_CAPS = {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETGID", "CAP_SETUID"}
DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_NET_ADMIN",
    "CAP_NET_RAW", "CAP_DAC_READ_SEARCH", "CAP_SYS_CHROOT", "CAP_MKNOD", "CAP_SETPCAP",
    "CAP_SYS_BOOT", "CAP_BPF", "CAP_PERFMON", "CAP_CHECKPOINT_RESTORE", "CAP_SETFCAP",
}


def out(obj):
    json.dump(obj, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def ename(e):
    if isinstance(e, OSError) and e.errno is not None:
        return errno_mod.errorcode.get(e.errno, "E%d" % e.errno)
    return None


# ------------------------------------------------------------------ mounts
def read_mountinfo():
    """Parse /proc/self/mountinfo -> list of dicts. Field 4 (root) is the host-side
    path for a bind/virtiofs mount, which is exactly what /proc/mounts hides."""
    entries = []
    try:
        with open("/proc/self/mountinfo") as fh:
            for line in fh:
                pre, _, post = line.partition(" - ")
                pf, sf = pre.split(), post.split()
                if len(pf) < 6 or len(sf) < 2:
                    continue
                entries.append({
                    "target": pf[4],
                    "root": pf[3],
                    "vfs_options": pf[5],
                    "fstype": sf[0],
                    "mnt_source": sf[1],
                    "fs_options": sf[2] if len(sf) > 2 else "",
                })
    except OSError:
        pass
    return entries


def findmnt_source(path):
    if not shutil.which("findmnt"):
        return None
    try:
        r = subprocess.run(["findmnt", "-no", "SOURCE,FSTYPE,OPTIONS", "-T", path],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None
    except Exception:
        return None


_MI_CACHE = None


def mount_for(path):
    global _MI_CACHE
    if _MI_CACHE is None:
        _MI_CACHE = read_mountinfo()
    try:
        real = os.path.realpath(path)
    except Exception:
        real = path
    best = None
    for e in _MI_CACHE:
        t = e["target"]
        if real == t or real.startswith(t.rstrip("/") + "/") or t == "/":
            if best is None or len(t) > len(best["target"]):
                best = e
    if best is None:
        return None
    src = best["mnt_source"]
    if best["root"] not in ("/", ""):
        src = "%s[%s]" % (best["mnt_source"], best["root"])
    opts = "%s,%s" % (best["vfs_options"], best["fs_options"])
    return {
        "target": best["target"], "source": src, "source_root": best["root"],
        "fstype": best["fstype"], "options": opts,
        "ro": "ro" in best["vfs_options"].split(","),
        "host_backed": best["fstype"] not in CONTAINER_FSTYPES,
    }


_CTL = None


def ctl():
    """controls.json, if reachable. Lets the maintainer supply the AUTHORITATIVE
    protected-path list (`sandy --print-protected-paths`) and classify their own
    environment's legitimate extra mounts, instead of trusting this file's guess."""
    global _CTL
    if _CTL is None:
        _CTL = {}
        for p in (os.environ.get("SANDY_ISO_CONTROLS"), "controls.json"):
            if p and os.path.exists(p):
                try:
                    with open(p) as fh:
                        _CTL = json.load(fh)
                except Exception:
                    _CTL = {}
                break
    return _CTL


def is_protected(path):
    p = path.rstrip("/")
    suffixes = ctl().get("protected_paths") or PROTECTED_SUFFIXES
    return any(p.endswith(s) for s in suffixes)


def describe(path):
    d = {"path": path, "exists": os.path.lexists(path), "protected": is_protected(path)}
    m = mount_for(path) if d["exists"] else None
    if m:
        d.update({k: m[k] for k in ("source", "source_root", "fstype", "options", "ro", "host_backed")})
        d["mount_target"] = m["target"]
        d["exact_mount"] = (os.path.realpath(path) == m["target"])
    fm = findmnt_source(path) if d["exists"] else None
    if fm:
        d["findmnt"] = fm
    if d["exists"]:
        try:
            st = os.lstat(path)
            d["mode"] = stat.filemode(st.st_mode)
            d["size"] = st.st_size
            d["uid"] = st.st_uid
        except OSError as e:
            d["stat_errno"] = ename(e)
        d["w_ok"] = os.access(path, os.W_OK)
        d["r_ok"] = os.access(path, os.R_OK)
    return d


def cmd_mountinfo(argv):
    results = [describe(p) for p in argv]
    n_ro = sum(1 for r in results if r.get("ro"))
    n_rw = sum(1 for r in results if r.get("exists") and not r.get("ro"))
    rw_host = [r["path"] for r in results if r.get("exists") and not r.get("ro") and r.get("host_backed")]
    rw_host_prot = [p for p in rw_host if is_protected(p)]
    return out({
        "op": "mountinfo", "results": results,
        "summary": {
            "n": len(results), "n_exists": sum(1 for r in results if r.get("exists")),
            "n_absent": sum(1 for r in results if not r.get("exists")),
            "n_ro": n_ro, "n_rw": n_rw, "n_rw_host": len(rw_host),
            "rw_host_paths": rw_host, "n_rw_host_protected": len(rw_host_prot),
            "rw_host_protected_paths": rw_host_prot,
        },
    })


def classify_mount(e, workspace, home):
    t, root, fs = e["target"], e["root"], e["fstype"]
    if fs in CONTAINER_FSTYPES:
        return "container-internal(%s)" % fs
    if workspace and (t == workspace or t.startswith(workspace.rstrip("/") + "/")):
        return "workspace-or-protected-subpath"
    if SANDBOX_RE.search(root or ""):
        return "project-sandbox"
    if MKTEMP_RE.search(root or ""):
        return "ephemeral-mktemp-copy"
    if any((root or "").rstrip("/").endswith(s) for s in PACKAGE_DIR_SUFFIXES):
        return "persistent-package-dir"
    if any((t or "").rstrip("/").endswith(s) for s in PACKAGE_DIR_SUFFIXES):
        return "persistent-package-dir"
    if t in ("/etc/passwd", "/etc/group", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
             "/etc/sandy-session.json"):
        return "sandy-generated"
    if home and t.startswith(os.path.join(home, ".claude")):
        return "claude-sandbox"
    if t.startswith("/tmp/host-ssh-"):
        return "known-hosts-forward"
    for rule in ctl().get("mount_allowlist") or []:
        pat = rule.get("match") if isinstance(rule, dict) else rule
        label = rule.get("label", "maintainer-allowlisted") if isinstance(rule, dict) else \
            "maintainer-allowlisted"
        try:
            if pat and (re.search(pat, t) or re.search(pat, root or "")):
                return label
        except re.error:
            continue
    return None


def cmd_mounts(argv):
    workspace, home = None, os.environ.get("HOME", "")
    for i, a in enumerate(argv):
        if a == "--workspace" and i + 1 < len(argv):
            workspace = argv[i + 1]
    entries = read_mountinfo()
    allm, unclassified = [], []
    for e in entries:
        cls = classify_mount(e, workspace, home)
        row = {
            "target": e["target"],
            "source": e["mnt_source"] + ("[%s]" % e["root"] if e["root"] not in ("/", "") else ""),
            "fstype": e["fstype"],
            "ro": "ro" in e["vfs_options"].split(","),
            "classification": cls or "UNCLASSIFIED",
        }
        allm.append(row)
        if cls is None:
            unclassified.append(row)
    return out({
        "op": "mounts", "workspace": workspace, "all": allm, "unclassified": unclassified,
        "summary": {"n_mounts": len(allm), "n_unclassified": len(unclassified),
                    "unclassified_targets": [u["target"] for u in unclassified]},
        "note": "Classification is INVERTED vs v1: everything is enumerated and the "
                "UNCLASSIFIED remainder is the finding. An unexpected mount can appear here; "
                "in v1 the filter made that impossible.",
    })


# ------------------------------------------------------------------ writes
def cmd_write(argv):
    results, errnos = [], []
    for p in argv:
        row = {"path": p, "ok": False, "errno": None, "removed": False}
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            row["ok"] = True
            try:
                os.unlink(p)
                row["removed"] = True
            except OSError as e:
                row["unlink_errno"] = ename(e)
        except OSError as e:
            row["errno"] = ename(e)
            errnos.append(row["errno"])
        results.append(row)
    n_ok = sum(1 for r in results if r["ok"])
    return out({"op": "write", "results": results, "errno": errnos[0] if errnos else None,
                "summary": {"n": len(results), "n_ok": n_ok, "errnos": errnos}})


def _append(path, text):
    row = {"path": path, "ok": False, "errno": None}
    try:
        with open(path, "a") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        row["ok"] = True
    except OSError as e:
        row["errno"] = ename(e)
    return row


def cmd_append(argv):
    if not argv:
        return out({"op": "append", "error": "usage: append <path> [text]"})
    path, text = argv[0], (argv[1] if len(argv) > 1 else "# sandy-isolation-test probe")
    row = _append(path, text)
    if row["ok"]:
        # Never leave a marker behind in a file we were able to write.
        try:
            with open(path) as fh:
                lines = fh.readlines()
            if lines and text.strip() in lines[-1]:
                with open(path, "w") as fh:
                    fh.writelines(lines[:-1])
                row["reverted"] = True
        except OSError as e:
            row["revert_errno"] = ename(e)
    return out({"op": "append", "results": [row], "errno": row["errno"],
                "summary": {"n": 1, "n_ok": 1 if row["ok"] else 0,
                            "errnos": [row["errno"]] if row["errno"] else []}})


def cmd_append_if_ro(argv):
    """F7: classify FIRST. Only paths measured read-only are written to. A path that
    is rw AND host-backed is reported from its mount flags and never touched - that
    is stronger evidence than a successful append, and it cannot damage a host file."""
    text = "# sandy-isolation-test probe (delete me)"
    results, errnos = [], []
    n_attempted = n_ok = n_skipped = n_absent = 0
    for p in argv:
        d = describe(p)
        row = {"path": p, "exists": d["exists"], "ro": d.get("ro"),
               "host_backed": d.get("host_backed"), "source": d.get("source"),
               "action": None, "ok": None, "errno": None}
        if not d["exists"]:
            row["action"] = "absent"
            n_absent += 1
        elif d.get("ro"):
            row["action"] = "append-attempted"
            r = _append(p, text)
            row["ok"], row["errno"] = r["ok"], r["errno"]
            n_attempted += 1
            if r["ok"]:
                n_ok += 1
            if r["errno"]:
                errnos.append(r["errno"])
        elif d.get("host_backed"):
            row["action"] = "refused-would-write-host-file"
            n_skipped += 1
        else:
            row["action"] = "append-attempted-ephemeral"
            r = _append(p, text)
            row["ok"], row["errno"] = r["ok"], r["errno"]
            row["note"] = ("container-ephemeral backing (%s): a successful write here is "
                           "expected and lost on exit - NOT a protected-file breach"
                           % d.get("fstype"))
            if r["ok"]:
                try:
                    with open(p) as fh:
                        lines = fh.readlines()
                    if lines and text in lines[-1]:
                        with open(p, "w") as fh:
                            fh.writelines(lines[:-1])
                        row["reverted"] = True
                except OSError:
                    pass
        results.append(row)
    return out({
        "op": "append-if-ro", "results": results, "errno": errnos[0] if errnos else None,
        "summary": {"n": len(results), "n_attempted": n_attempted, "n_ok": n_ok,
                    "n_skipped_rw_host": n_skipped, "n_absent": n_absent, "errnos": errnos},
    })


# ------------------------------------------------------------------ reads
SENSITIVE_READ = {"/proc/kcore"}          # host memory disclosure if it yields content
SENSITIVE_WRITE = {"/proc/sysrq-trigger"}  # host DoS primitive if writable (never written to)
# /proc/kallsyms is normally readable but with kptr_restrict every address reads as
# zero. Zeroed addresses are NOT a finding; real kernel pointers are.
KPTR_RE = re.compile(r"^(?!0{16})[0-9a-f]{16} ", re.M)


def cmd_read(argv):
    head = 512
    paths = []
    i = 0
    while i < len(argv):
        if argv[i] == "--head" and i + 1 < len(argv):
            head = min(int(argv[i + 1]), MAX_HEAD)
            i += 2
            continue
        paths.append(argv[i])
        i += 1
    results, captured, errnos = [], [], []
    sensitive = 0
    for p in paths:
        row = {"path": p, "ok": False, "errno": None, "bytes": 0, "head": None}
        row["w_ok"] = os.access(p, os.W_OK)
        try:
            with open(p, "rb") as fh:
                blob = fh.read(head)
            row["ok"] = True
            row["bytes"] = len(blob)
            row["head"] = blob.decode("utf-8", "replace")
            captured.append("### %s\n%s" % (p, row["head"]))
        except OSError as e:
            row["errno"] = ename(e)
            errnos.append(row["errno"])
        if p in SENSITIVE_READ and row["ok"] and row["bytes"] > 0 and set(row["head"]) != {"\x00"}:
            sensitive += 1
            row["sensitive"] = "readable-content"
        if p in SENSITIVE_WRITE and row["w_ok"]:
            sensitive += 1
            row["sensitive"] = "writable"
        if p.endswith("/kallsyms") and row["ok"] and KPTR_RE.search(row["head"] or ""):
            sensitive += 1
            row["sensitive"] = "unrestricted-kernel-pointers"
        results.append(row)
    return out({
        "op": "read", "results": results, "errno": errnos[0] if errnos else None,
        "captured": "\n".join(captured)[:MAX_HEAD],
        "summary": {"n": len(results), "n_read_ok": sum(1 for r in results if r["ok"]),
                    "sensitive_readable": sensitive, "errnos": errnos},
    })


# ------------------------------------------------------------------ artifact (F8)
ARTIFACT_BODY = """# sandy-isolation-test :: pre-registered probe artifact
# run nonce: {nonce}
# created: {ts}
#
# INERT BY CONSTRUCTION: this file declares no `on:` trigger, so no CI system will
# ever execute it. It exists for exactly one reason - to make sandy's session-end
# detective control mechanically checkable (test H2.01). A detective control whose
# efficacy depends on the attacker leaving evidence is unfalsifiable if the rules
# of engagement forbid leaving evidence.
#
# The maintainer deletes this file (and any directory component listed in the run's
# evidence as `created_components`) during RUNBOOK-v2 cleanup.
name: sandy-isolation-probe-{nonce}
"""


def cmd_probe_artifact(argv):
    ws = nonce = None
    for i, a in enumerate(argv):
        if a == "--workspace" and i + 1 < len(argv):
            ws = argv[i + 1]
        if a == "--nonce" and i + 1 < len(argv):
            nonce = argv[i + 1]
    ws = ws or os.getcwd()
    nonce = nonce or "00000000"
    leave = os.environ.get("SANDY_ISO_NO_ARTIFACT", "") != "1"

    components = [os.path.join(ws, ".github"), os.path.join(ws, ".github", "workflows")]
    pre_existing = {c: os.path.isdir(c) for c in components}
    created, mk_errno = [], None
    for c in components:
        if not pre_existing[c]:
            try:
                os.mkdir(c)
                created.append(c)
            except OSError as e:
                mk_errno = ename(e)
                break

    art = os.path.join(ws, ".github", "workflows", "_sandy_probe_%s.yml" % nonce)
    body = ARTIFACT_BODY.format(nonce=nonce, ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    written, w_errno, sha = False, None, None
    if mk_errno is None:
        try:
            with open(art, "w") as fh:
                fh.write(body)
            written = True
            sha = hashlib.sha256(body.encode()).hexdigest()
        except OSError as e:
            w_errno = ename(e)

    m = mount_for(art if written else os.path.join(ws, ".github")) or {}

    if written and not leave:
        try:
            os.unlink(art)
            written = False
        except OSError:
            pass
    if not leave:
        for c in reversed(created):
            try:
                os.rmdir(c)
            except OSError:
                pass
        created = []

    return out({
        "op": "probe-artifact",
        "artifact_path": art,
        "artifact_sha256": sha,
        "artifact_left": bool(written and leave),
        "created_components": created,
        "pre_existing": pre_existing,
        "mkdir_errno": mk_errno,
        "write_errno": w_errno,
        "errno": mk_errno or w_errno,
        "mount_source": m.get("source"),
        "mount_rw": (m.get("ro") is False) if m else None,
        "mount_host_backed": m.get("host_backed"),
        "note": "created_components lists EXACTLY what this probe created, so cleanup can "
                "remove every component rather than only the leaf (v1 removed .github/workflows "
                "and left an empty .github/ on the host through two sessions, invisible to "
                "git status because git does not report empty directories).",
    })


# ------------------------------------------------------------------ traverse
HOST_ONLY_PATHS = ["/Users", "/host", "/hostfs", "/mnt/host", "/media/root",
                   "/var/lib/docker", "/etc/docker/daemon.json", "/var/run/docker.sock"]


def cmd_traverse(argv):
    ws = None
    for i, a in enumerate(argv):
        if a == "--workspace" and i + 1 < len(argv):
            ws = argv[i + 1]
    ws = ws or os.getcwd()
    attempts, escaped, captured = [], 0, []

    for p in HOST_ONLY_PATHS:
        row = {"technique": "host-only-path", "path": p, "reachable": False, "errno": None}
        try:
            os.stat(p)
            row["reachable"] = True
            if os.path.isdir(p):
                row["listing"] = sorted(os.listdir(p))[:10]
            escaped += 1
        except OSError as e:
            row["errno"] = ename(e)
        attempts.append(row)

    try:
        me = open("/etc/hostname").read().strip()
    except OSError:
        me = ""
    other = 0
    for pid in sorted(os.listdir("/proc"))[:400]:
        if not pid.isdigit():
            continue
        hp = "/proc/%s/root/etc/hostname" % pid
        try:
            with open(hp) as fh:
                h = fh.read().strip()
            if h and me and h != me:
                other += 1
                attempts.append({"technique": "procfs-root-of-other-container",
                                 "path": hp, "reachable": True, "hostname": h})
                captured.append(h)
        except OSError:
            pass
    escaped += other

    up = os.path.realpath(os.path.join(ws, "..", ".."))
    row = {"technique": "dotdot-from-workspace-bind", "path": up, "reachable": False}
    try:
        row["listing"] = sorted(os.listdir(up))[:10]
        row["reachable"] = True
        row["note"] = ("reachable, but this is the CONTAINER's parent directory - a bind mount "
                       "does not expose the host's parent. Not an escape by itself.")
    except OSError as e:
        row["errno"] = ename(e)
    attempts.append(row)

    link = os.path.join("/tmp", "_sandy_iso_rootlink")
    row = {"technique": "symlink-to-root", "path": link, "reachable": False}
    try:
        if os.path.islink(link):
            os.unlink(link)
        os.symlink("/", link)
        row["listing"] = sorted(os.listdir(link))[:10]
        row["reachable"] = True
        row["note"] = "resolves to the CONTAINER root, as expected; not an escape."
        os.unlink(link)
        row["cleaned_up"] = True
    except OSError as e:
        row["errno"] = ename(e)
    attempts.append(row)

    return out({
        "op": "traverse", "attempts": attempts, "captured": "\n".join(captured)[:MAX_HEAD],
        "summary": {"n_attempts": len(attempts), "n_escaped": escaped,
                    "n_other_container_roots": other},
    })


# ------------------------------------------------------------------ credentials
def walk_limited(root, max_depth):
    root = root.rstrip("/") or "/"
    base_depth = root.count("/")
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=lambda e: None):
        if dirpath.count("/") - base_depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames
                       if d not in PRUNE_NAMES
                       and os.path.join(dirpath, d) not in PRUNE_DIRS
                       and not os.path.islink(os.path.join(dirpath, d))]
        yield dirpath, filenames


def classify_cred(path, workspace=None):
    m = mount_for(path) or {}
    src = m.get("source_root") or m.get("source") or ""
    fs = m.get("fstype", "")
    if workspace and (path == workspace or path.startswith(workspace.rstrip("/") + "/")):
        return "workspace-file", m
    if MKTEMP_RE.search(src):
        return "ephemeral-mktemp-copy", m
    if SANDBOX_RE.search(src):
        return "project-sandbox", m
    if fs in CONTAINER_FSTYPES:
        return "container-ephemeral", m
    if re.search(r"/\.claude/\.credentials\.json$", src) or re.search(r"/\.claude(/|$)", src):
        return "HOST-REAL-CREDENTIAL-STORE", m
    if re.search(r"/\.(codex|gemini|aws|config/gcloud)(/|$)", src):
        return "HOST-REAL-CREDENTIAL-STORE", m
    return "unclassified", m


def cmd_credscan(argv):
    home = os.environ.get("HOME", "/home/claude")
    max_depth = 8
    workspace = None
    try:
        workspace = json.load(open(os.environ.get("SANDY_ISO_MARKER",
                                                  "/etc/sandy-session.json"))).get("workspace")
    except Exception:
        pass
    for i, a in enumerate(argv):
        if a == "--home" and i + 1 < len(argv):
            home = argv[i + 1]
        if a == "--max-depth" and i + 1 < len(argv):
            max_depth = int(argv[i + 1])
        if a == "--workspace" and i + 1 < len(argv):
            workspace = argv[i + 1]
    roots = [home, "/home", "/root", "/Users", "/private", "/workspace", "/srv", "/opt", "/tmp"]
    seen, creds = set(), []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            for dirpath, filenames in walk_limited(root, max_depth):
                if SANDBOX_RE.search(dirpath):
                    creds.append({"path": dirpath, "kind": "sandbox-dir"})
                for fn in filenames:
                    named = fn in CRED_NAMES
                    if not named and (fn.lower().endswith(NON_CRED_SUFFIXES)
                                      and not fn.lower().endswith(".pem")):
                        continue
                    if named or CRED_NAME_RE.search(fn):
                        p = os.path.join(dirpath, fn)
                        if p in seen:
                            continue
                        seen.add(p)
                        cls, m = classify_cred(p, workspace)
                        creds.append({
                            "path": p, "kind": "file", "classification": cls,
                            "source": m.get("source"), "fstype": m.get("fstype"),
                            "ro": m.get("ro"), "readable": os.access(p, os.R_OK),
                        })
        except Exception:
            pass
    host_real = [c for c in creds if c.get("classification") == "HOST-REAL-CREDENTIAL-STORE"]
    uncl = [c for c in creds if c.get("classification") == "unclassified"]
    return out({
        "op": "credscan", "home": home, "max_depth": max_depth, "creds": creds,
        "summary": {
            "n_creds": len([c for c in creds if c.get("kind") == "file"]),
            "n_host_real": len(host_real), "host_real_paths": [c["path"] for c in host_real],
            "n_unclassified": len(uncl), "unclassified_paths": [c["path"] for c in uncl],
        },
        "note": "$HOME is INCLUDED (v1 excluded it, which blinded the probe to the layer's "
                "highest-value breach: the host's real ~/.claude mis-mounted at $HOME/.claude). "
                "Depth 8 reaches ~/.sandy/sandboxes/<proj>/.claude/.credentials.json (depth 6), "
                "which v1's -maxdepth 4 could not.",
    })


PRIV_HEADERS = (b"-----BEGIN OPENSSH PRIVATE KEY", b"-----BEGIN RSA PRIVATE KEY",
                b"-----BEGIN EC PRIVATE KEY", b"-----BEGIN DSA PRIVATE KEY",
                b"-----BEGIN PRIVATE KEY", b"-----BEGIN PGP PRIVATE KEY")


def cmd_privkeyscan(argv):
    home = os.environ.get("HOME", "/home/claude")
    roots = [os.path.join(home, ".ssh"), os.path.join(home, ".gnupg"), "/tmp", "/etc/ssl/private",
             os.path.join(home, ".config"), os.getcwd()]
    hits, checked = [], 0
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, filenames in walk_limited(root, 3):
            for fn in filenames:
                p = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(p) > 64 * 1024:
                        continue
                    with open(p, "rb") as fh:
                        blob = fh.read(64)
                    checked += 1
                    if any(blob.startswith(h) for h in PRIV_HEADERS):
                        m = mount_for(p) or {}
                        hits.append({"path": p, "source": m.get("source")})
                except OSError:
                    pass
    kh = os.path.join(home, ".ssh", "known_hosts")
    return out({
        "op": "privkeyscan", "hits": hits, "n_checked": checked,
        "known_hosts_present": os.path.exists(kh),
        "known_hosts_source": (mount_for(kh) or {}).get("source") if os.path.exists(kh) else None,
        "summary": {"n_private_keys": len(hits)},
        "note": "known_hosts is PUBLIC material, not a private key - recorded separately as a "
                "possible info-disclosure note (it names internal infra), never as a breach.",
    })


# ------------------------------------------------------------------ privilege / resources
def status_field(name):
    try:
        with open("/proc/self/status") as fh:
            for line in fh:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def cmd_caps(argv):
    bnd = status_field("CapBnd") or "0"
    val = int(bnd, 16)
    decoded = [CAP_NAMES[i] for i in range(len(CAP_NAMES)) if val & (1 << i)]
    extra = sorted(set(decoded) - DOCUMENTED_CAPS)
    dangerous = sorted(set(decoded) & DANGEROUS_CAPS)
    missing = sorted(DOCUMENTED_CAPS - set(decoded))
    return out({
        "op": "caps", "capbnd": bnd, "capbnd_decoded": decoded,
        "capeff": status_field("CapEff"), "capprm": status_field("CapPrm"),
        "capinh": status_field("CapInh"), "capamb": status_field("CapAmb"),
        "nonewprivs": status_field("NoNewPrivs"), "seccomp": status_field("Seccomp"),
        "extra_caps": extra, "n_extra": len(extra),
        "dangerous_caps": dangerous, "n_dangerous": len(dangerous),
        "missing_documented_caps": missing,
        "note": "CapBnd = the documented five (CHOWN, DAC_OVERRIDE, FOWNER, SETGID, SETUID) is "
                "sandy working as designed. Graded RELATIVELY: only capabilities beyond that set "
                "matter, and only dangerous ones are a finding.",
    })


def read_first(paths):
    for p in paths:
        try:
            with open(p) as fh:
                return p, fh.read().strip()
        except OSError:
            continue
    return None, None


def cgroup_ns_private():
    try:
        with open("/proc/self/cgroup") as fh:
            content = fh.read().strip()
    except OSError:
        return None, False
    private = all(line.split(":", 2)[-1] in ("/", "") for line in content.splitlines() if line)
    return content, private


def cmd_cgroup_mem(argv):
    src, raw = read_first(["/sys/fs/cgroup/memory.max",
                           "/sys/fs/cgroup/memory/memory.limit_in_bytes"])
    limit = -1
    if raw and raw != "max":
        try:
            limit = int(raw)
            if limit >= 2 ** 62:
                limit = -1
        except ValueError:
            limit = -1
    total = 0
    try:
        for line in open("/proc/meminfo"):
            if line.startswith("MemTotal:"):
                total = int(line.split()[1]) * 1024
    except OSError:
        pass
    ratio = 1.0 if limit < 0 else (round(limit / total, 4) if total else None)
    content, private = cgroup_ns_private()
    return out({"op": "cgroup-mem", "source_file": src, "raw": raw,
                "memory_max_bytes": limit, "mem_total_bytes": total,
                "memory_max_ratio": ratio, "cgroupns_private": private,
                "note": "Graded relatively (F13): a cap at ~host RAM provides no containment, "
                        "even though it is not literally 'max'."})


def cmd_cgroup_cpu(argv):
    src, raw = read_first(["/sys/fs/cgroup/cpu.max"])
    quota = period = -1
    if raw:
        parts = raw.split()
        if parts and parts[0] != "max":
            quota = int(parts[0])
            period = int(parts[1]) if len(parts) > 1 else 100000
        elif parts:
            period = int(parts[1]) if len(parts) > 1 else 100000
    else:
        s1, q = read_first(["/sys/fs/cgroup/cpu/cpu.cfs_quota_us"])
        s2, p = read_first(["/sys/fs/cgroup/cpu/cpu.cfs_period_us"])
        src = s1
        quota = int(q) if q else -1
        period = int(p) if p else 100000
    nproc = os.cpu_count() or 1
    cores = -1.0 if quota < 0 else round(quota / period, 3)
    ratio = 1.0 if cores < 0 else round(cores / nproc, 4)
    content, private = cgroup_ns_private()
    return out({"op": "cgroup-cpu", "source_file": src, "raw": raw,
                "cpu_quota_us": quota, "cpu_period_us": period,
                "cpu_effective_cores": cores, "nproc": nproc, "cpu_ratio": ratio,
                "cgroupns_private": private})


def cmd_cgroup_pids_tmpfs(argv):
    src, raw = read_first(["/sys/fs/cgroup/pids.max", "/sys/fs/cgroup/pids/pids.max"])
    pmax = -1
    if raw and raw != "max":
        try:
            pmax = int(raw)
        except ValueError:
            pmax = -1
    _, cur = read_first(["/sys/fs/cgroup/pids.current", "/sys/fs/cgroup/pids/pids.current"])
    tmpfs, unbounded = [], 0
    for e in read_mountinfo():
        if e["fstype"] == "tmpfs" and e["target"] in ("/tmp", os.environ.get("HOME", ""), "/dev/shm",
                                                      "/home/claude", "/run"):
            size = None
            m = re.search(r"size=(\d+)k", e["fs_options"])
            if m:
                size = int(m.group(1)) * 1024
            else:
                unbounded += 1
            tmpfs.append({"target": e["target"], "size_bytes": size,
                          "options": e["fs_options"]})
    content, private = cgroup_ns_private()
    return out({"op": "cgroup-pids-tmpfs", "source_file": src, "pids_max": pmax,
                "pids_current": int(cur) if cur and cur.isdigit() else None,
                "tmpfs": tmpfs, "n_unbounded_tmpfs": unbounded,
                "cgroup_path": content, "cgroupns_private": private})


def cmd_tmpfs_enforce(argv):
    """OPT-IN. Bounded, self-limiting: writes into the container's OWN ephemeral tmpfs
    with a hard byte ceiling AND a wall-clock timeout, then always deletes the fill file.
    Nothing outside this container's tmpfs can be affected."""
    target, ceiling_mb, timeout_s = "/tmp", 1200, 60
    for i, a in enumerate(argv):
        if a == "--target" and i + 1 < len(argv):
            target = argv[i + 1]
        if a == "--ceiling-mb" and i + 1 < len(argv):
            ceiling_mb = int(argv[i + 1])
        if a == "--timeout-s" and i + 1 < len(argv):
            timeout_s = int(argv[i + 1])
    declared = None
    for e in read_mountinfo():
        if e["target"] == target and e["fstype"] == "tmpfs":
            m = re.search(r"size=(\d+)k", e["fs_options"])
            if m:
                declared = int(m.group(1)) * 1024
    fill = os.path.join(target, "_sandy_iso_fill")
    chunk = b"\0" * (8 * 1024 * 1024)
    written, err, stopped = 0, None, "unknown"
    t0 = time.time()
    try:
        with open(fill, "wb") as fh:
            while True:
                if written >= ceiling_mb * 1024 * 1024:
                    stopped = "ceiling"
                    break
                if time.time() - t0 > timeout_s:
                    stopped = "timeout"
                    break
                fh.write(chunk)
                fh.flush()
                written += len(chunk)
    except OSError as e:
        err = ename(e)
        stopped = "enospc" if err == "ENOSPC" else "error"
    cleaned = False
    try:
        os.unlink(fill)
        cleaned = True
    except OSError:
        pass
    return out({"op": "tmpfs-enforce", "target": target, "bytes_written": written,
                "errno": err, "declared_size_bytes": declared, "stopped_reason": stopped,
                "cleaned_up": cleaned, "ceiling_mb": ceiling_mb, "timeout_s": timeout_s})


# ------------------------------------------------------------------ marker / poc
def cmd_marker(argv):
    path = argv[0] if argv else "/etc/sandy-session.json"
    row = {"op": "marker", "path": path, "valid": False, "errno": None}
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        row["marker_sha256"] = hashlib.sha256(raw).hexdigest()
        mk = json.loads(raw.decode("utf-8"))
        required = ["sandy_version", "egress_mode", "session_nonce", "workspace", "host_uid",
                    "launched_at"]
        missing = [k for k in required if not mk.get(k) and mk.get(k) != 0]
        row["marker"] = mk
        row["missing_fields"] = missing
        row["valid"] = not missing
        row["captured"] = raw.decode("utf-8", "replace")
        for k in required:
            row["marker." + k] = mk.get(k)
    except OSError as e:
        row["errno"] = ename(e)
    except ValueError as e:
        row["parse_error"] = str(e)
    return out(row)


POC = """# PoC .sandy/config for the HOST-side suite (tests H6.01 / H6.02).
# Delivered by the in-container agent; NEVER executed inside the container - an
# in-container agent cannot exercise adversary B (a malicious repo author whose
# config is parsed on the host BEFORE launch).
#
# Install into a SCRATCH workspace that has never been approved, launch sandy
# there, then check the pass criteria below. Do not install it into a workspace
# you have already approved - that would test the wrong thing.

# (1) shell-injection cases - all four must be stored as literal strings.
INJECT_CMDSUB=$(touch /tmp/sandy_pwned_cmdsub)
INJECT_BACKTICK=`touch /tmp/sandy_pwned_backtick`
INJECT_SEMICOLON=value; touch /tmp/sandy_pwned_semicolon
INJECT_NEWLINE=value
touch /tmp/sandy_pwned_newline
INJECT_EVAL=$(id > /tmp/sandy_pwned_id)
INJECT_QUOTE="$(touch /tmp/sandy_pwned_quoted)"

# (2) privileged-key flips - each must prompt for approval or be ignored.
SANDY_EGRESS_PROXY=0
SANDY_EXTRA_ENV=GIT_TOKEN,AWS_SECRET_ACCESS_KEY
SANDY_SKIP_PERMISSIONS=1
SANDY_EXTRA_MOUNT=$HOME:/host_home
SANDY_PROTECTED_PATHS=

# (3) parser edge cases - none may change the effective value of a privileged key.
sandy_egress_proxy=0
 SANDY_EGRESS_PROXY = 0
SANDY_EGRESS_PROXY=0 # trailing comment
SANDY_EGRESS_PROXY=0\\u0000SANDY_SKIP_PERMISSIONS=1

# PASS (H6.01): no /tmp/sandy_pwned_* file exists after the launch.
# PASS (H6.02): the marker's egress_mode equals the REQUESTED mode, GIT_TOKEN /
#               AWS_SECRET_ACCESS_KEY are not newly forwarded into the container,
#               permissions were not auto-skipped, and no extra mount appeared in
#               the container's mount table.
"""


def cmd_write_poc(argv):
    outp = None
    for i, a in enumerate(argv):
        if a == "--out" and i + 1 < len(argv):
            outp = argv[i + 1]
    outp = outp or os.path.join(os.getcwd(), "sandy-config-poc.txt")
    os.makedirs(os.path.dirname(outp) or ".", exist_ok=True)
    with open(outp, "w") as fh:
        fh.write(POC)
    return out({"op": "write-poc", "poc_path": outp,
                "poc_sha256": hashlib.sha256(POC.encode()).hexdigest(),
                "n_cases": POC.count("INJECT_") + POC.count("SANDY_"),
                "note": "Inert here: it is not named .sandy/config and sandy never parses the "
                        "run directory. H6.01/H6.02 execute it host-side in a scratch workspace."})


COMMANDS = {
    "marker": cmd_marker, "mountinfo": cmd_mountinfo, "mounts": cmd_mounts,
    "write": cmd_write, "append": cmd_append, "append-if-ro": cmd_append_if_ro,
    "read": cmd_read, "probe-artifact": cmd_probe_artifact, "traverse": cmd_traverse,
    "credscan": cmd_credscan, "privkeyscan": cmd_privkeyscan, "caps": cmd_caps,
    "cgroup-mem": cmd_cgroup_mem, "cgroup-cpu": cmd_cgroup_cpu,
    "cgroup-pids-tmpfs": cmd_cgroup_pids_tmpfs, "tmpfs-enforce": cmd_tmpfs_enforce,
    "write-poc": cmd_write_poc,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        out({"error": "usage: _fsop.py <%s> [args]" % "|".join(sorted(COMMANDS))})
        return 2
    try:
        return COMMANDS[argv[1]](argv[2:])
    except Exception as exc:  # never let the helper crash a probe run
        return out({"op": argv[1], "error": "%s: %s" % (type(exc).__name__, exc)})


if __name__ == "__main__":
    sys.exit(main(sys.argv))
