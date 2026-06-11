#!/usr/bin/env bash
# preflight.sh — confirm this agent is actually inside a sandy session.
#
# The ONLY authoritative signal is the read-only marker sandy bind-mounts at
# /etc/sandy-session.json on every launch. uid, capabilities, mount labels, and
# env vars are NOT evidence — on macOS/OrbStack a real sandy container is
# surface-identical to the bare host VM. A prior run false-negatived by reasoning
# from those surface signals; this gate exists to prevent that.
#
# Exit 0  → marker present & valid: prints the marker, you ARE in sandy, proceed.
# Exit 1  → marker absent/invalid: you are NOT in sandy (or it's too old). STOP —
#           do not run the layer probes; report a harness/launch failure.
set -u

MARKER="/etc/sandy-session.json"

fail() { printf '✗ PRE-FLIGHT FAILED — %s\n' "$1" >&2
         printf '  Not inside a sandy session (or sandy too old to emit the marker).\n' >&2
         printf '  STOP: do not run the layer probes. Report a harness/launch failure.\n' >&2
         exit 1; }

[ -r "$MARKER" ] || fail "$MARKER is absent or unreadable"

raw="$(cat "$MARKER")" || fail "could not read $MARKER"

# Prefer jq for a real parse; fall back to grep so the gate works without jq.
if command -v jq >/dev/null 2>&1; then
    echo "$raw" | jq -e . >/dev/null 2>&1 || fail "$MARKER is not valid JSON"
    ver="$(echo "$raw"   | jq -r '.sandy_version // empty')"
    mode="$(echo "$raw"  | jq -r '.egress_mode   // empty')"
    nonce="$(echo "$raw" | jq -r '.session_nonce // empty')"
    ws="$(echo "$raw"    | jq -r '.workspace     // empty')"
else
    _get() { echo "$raw" | grep -oE "\"$1\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/'; }
    ver="$(_get sandy_version)"; mode="$(_get egress_mode)"
    nonce="$(_get session_nonce)"; ws="$(_get workspace)"
fi

[ -n "$ver" ] && [ -n "$mode" ] && [ -n "$nonce" ] || fail "$MARKER is missing required fields"

cat <<EOF
✓ PRE-FLIGHT PASSED — inside sandy.
  sandy_version: $ver
  egress_mode:   $mode      <-- judge every layer against THIS, not env vars
  workspace:     $ws
  session_nonce: $nonce     <-- record verbatim; maintainer matches it to the launch

Marker (verbatim):
$raw
EOF
exit 0
