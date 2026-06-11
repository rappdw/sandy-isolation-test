#!/usr/bin/env bash
# Layer 2 — filesystem isolation. Benign read-mostly probe: it ATTEMPTS writes to
# places that should be read-only and reports whether they were blocked (good) or
# succeeded (a finding). It destroys nothing — protected files are appended-to
# with a marker comment that, if the mount is :ro, never lands.
set -u
ok(){ printf '  [HELD]   %s\n' "$1"; }
bad(){ printf '  [!!!!]   %s\n' "$1"; }
note(){ printf '  [info]   %s\n' "$1"; }
TAG="# sandy-isolation-test $$ (delete me)"

echo "== Layer 2: filesystem =="

echo "-- read-only root filesystem (writes to / should fail) --"
for p in /etc/_iso_probe /usr/_iso_probe /bin/_iso_probe; do
  if (set -C; : > "$p") 2>/dev/null; then bad "WROTE $p — root FS is NOT read-only"; rm -f "$p"; else ok "$p write blocked"; fi
done

echo "-- ephemeral tmpfs (writable, but lost on exit) --"
if : > /tmp/_iso_probe 2>/dev/null; then note "/tmp writable (ephemeral tmpfs, expected)"; rm -f /tmp/_iso_probe; else bad "/tmp not writable (unexpected)"; fi

echo "-- workspace (writing the mounted workspace is EXPECTED) --"
if : > ./_iso_probe 2>/dev/null; then note "workspace writable (expected — it's the mounted project dir)"; rm -f ./_iso_probe; else note "workspace not writable"; fi

echo "-- protected files should be read-only (append should fail) --"
for f in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.gitconfig" "./.git/config" "./.git/HEAD"; do
  [ -e "$f" ] || { note "absent: $f (not mounted/protected this session)"; continue; }
  # A protected file is a host :ro bind (virtiofs/etc). A file on ephemeral tmpfs/overlay
  # is a throwaway copy seeded into the sandbox, NOT a protected host bind — a successful
  # write there is expected (lost on exit), not a breach. Detect the backing first so we
  # don't false-positive on e.g. an ephemeral ~/.gitconfig.
  fstype="$(findmnt -no FSTYPE -T "$f" 2>/dev/null || stat -f -c %T "$f" 2>/dev/null)"
  case "$fstype" in
    tmpfs|overlay|overlayfs)
      note "$f is ephemeral $fstype backing (throwaway copy, not a protected host bind) — write here is expected and lost on exit; skipping" ;;
    *)
      if echo "$TAG" >> "$f" 2>/dev/null; then bad "APPENDED to protected $f (backing=${fstype:-unknown}) — it is NOT read-only"; else ok "protected $f is read-only"; fi ;;
  esac
done

echo "-- absent protected dirs: can one be CREATED and persist to the host? --"
# sandy only DETECTS these at session end; creating one that lands on the host
# workspace is a real finding. We create + immediately remove to avoid leaving it.
for d in ./.github/workflows ./.git/hooks ./.vscode; do
  if [ -e "$d" ]; then note "exists already: $d"; continue; fi
  if mkdir -p "$d" 2>/dev/null; then bad "CREATED $d (absent protected dir is writable — verify on host whether it persisted)"; rm -rf "$d" 2>/dev/null; else ok "$d creation blocked"; fi
done

echo "-- what is actually mounted (host reach) --"
note "mounts (rw on host paths outside the workspace = a leak to investigate):"
grep -E ' / | /home/claude| '"${SANDY_WORKSPACE:-/nonexistent}"'| /etc/(passwd|group)' /proc/mounts 2>/dev/null | sed 's/^/      /' || cat /proc/mounts | sed 's/^/      /' | head -25

echo "-- can we see host paths OUTSIDE the workspace? --"
for p in /home /root /Users /etc/shadow; do
  if [ -e "$p" ]; then
    if [ -r "$p" ] 2>/dev/null; then note "visible: $p ($(ls -ld "$p" 2>/dev/null | awk '{print $1,$3,$4}'))"; else note "present but unreadable: $p"; fi
  else note "absent: $p"; fi
done
echo "== end Layer 2 =="
