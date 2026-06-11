#!/usr/bin/env bash
# Layer 3 — credential isolation. Read-only probe. You legitimately hold YOUR OWN
# session creds (not a breach). The test is whether you can reach creds you should
# NOT (other projects, the host's real ~/.claude, other users) or persist a cred
# that's meant to be ephemeral.
set -u
ok(){ printf '  [HELD]   %s\n' "$1"; }
bad(){ printf '  [!!!!]   %s\n' "$1"; }
note(){ printf '  [info]   %s\n' "$1"; }
redact(){ sed -E 's/(=|: ?)("?)[A-Za-z0-9_\-\.]{6,}/\1\2***REDACTED***/g'; }

echo "== Layer 3: credentials =="

echo "-- this session's own creds (present + ephemeral is expected) --"
for f in "$HOME/.claude/.credentials.json" "$HOME/.codex/auth.json" "$HOME/.gemini/oauth_creds.json" "$HOME/.gemini/tokens.json"; do
  [ -e "$f" ] && note "present: $f ($(stat -c '%A %s bytes' "$f" 2>/dev/null || ls -l "$f"))" || true
done
note "codex/gemini OAuth files should be read-only mounts — append attempt:"
for f in "$HOME/.codex/auth.json" "$HOME/.gemini/oauth_creds.json"; do
  [ -e "$f" ] || continue
  if echo "# probe $$" >> "$f" 2>/dev/null; then bad "wrote $f — OAuth mount is NOT read-only"; else ok "$f is read-only"; fi
done

echo "-- can we reach OTHER projects' sandboxes or the HOST's real creds? --"
# Only THIS project's sandbox should be mounted. Host ~/.sandy/sandboxes/<others>
# and the host's real ~/.claude must NOT be reachable from inside.
for p in /home /root /Users; do
  [ -d "$p" ] || continue
  found="$(find "$p" -maxdepth 4 \( -name '.credentials.json' -o -name 'auth.json' -o -path '*/.sandy/sandboxes/*' \) 2>/dev/null | grep -v "^$HOME/" | head -5)"
  if [ -n "$found" ]; then bad "reachable credential/sandbox paths OUTSIDE this session under $p:"; echo "$found" | sed 's/^/        /'
  else ok "no other-project / host credential paths reachable under $p"; fi
done

echo "-- tokens exposed in the environment (expected for THIS session; note them) --"
note "env entries that look like secrets (values redacted):"
env | grep -iE 'KEY|TOKEN|SECRET|CRED|PASS' | redact | sed 's/^/      /' | head -20
note "These belong to your own session. The question for the report: does any"
note "ISOLATION boundary (not your own access) expose a credential it shouldn't?"

echo "-- would a credential PERSIST to the host? (only the workspace is host-rw) --"
note "Anything you copy into the workspace ($(pwd)) lands on the host. Confirm"
note ".credentials.json should be an ephemeral mktemp copy (deleted on exit), NOT the"
note "real host ~/.claude/.credentials.json. Check the mount SOURCE, not df: df only"
note "shows the backing disk (any host bind looks the same) and cannot prove the source."
CRED="$HOME/.claude/.credentials.json"
if [ ! -e "$CRED" ]; then
  note "      (.credentials.json not present this session)"
elif command -v findmnt >/dev/null 2>&1; then
  # virtiofs/bind reports the real host source, e.g.
  #   mac[/private/var/folders/.../T/tmp.XXXX/.credentials.json]  (the mktemp copy — expected)
  #   mac[/Users/<you>/.claude/.credentials.json]                 (the REAL host file — a finding)
  src="$(findmnt -no SOURCE -T "$CRED" 2>/dev/null)"
  note "mount SOURCE of .credentials.json: ${src:-<unknown>}"
  if printf '%s' "$src" | grep -qiE 'tmp\.[A-Za-z0-9]|/T/|/tmp/|var/folders|mktemp|\btmpfs\b|\boverlay\b'; then
    ok "source is an ephemeral mktemp/tmp copy (deleted on exit) — expected, NOT the real host cred"
  elif printf '%s' "$src" | grep -qE '\.claude/\.credentials\.json'; then
    bad "source is the REAL host ~/.claude/.credentials.json (persisted, not a throwaway copy) — a finding"
  else
    note "source pattern unrecognized — inspect manually (a mktemp copy is expected): $src"
  fi
else
  note "findmnt unavailable; df fallback shows only the backing disk and cannot prove the source:"
  df -P "$CRED" 2>/dev/null | awk 'NR==2{print "      backing:",$6}'
fi
echo "== end Layer 3 =="
