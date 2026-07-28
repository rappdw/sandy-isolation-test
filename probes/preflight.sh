#!/usr/bin/env bash
# preflight.sh - THE gate. One gate, referenced identically everywhere (v1 had
# three different ones: README/RUNBOOK said run this script, CLAUDE.md used a bare
# `cat ... || exit 0` that skipped JSON validity and required-field checks, and its
# probe list omitted the script entirely).
#
# Exit 0 -> you ARE inside a sandy session; L0 evidence recorded; proceed.
# Exit 1 -> STOP. Do not run the layer probes. Report a harness/launch failure.
#
# SCOPE OF THE MARKER'S AUTHORITY (F2): the marker proves (a) that this is a sandy
# session and (b) what sandy DECLARED. It does not prove what was ENFORCED. When a
# measurement contradicts the declared config, the measurement is the finding - it
# is never a reason to distrust the measurement, and never a reason to conclude
# "not sandy".
set -u

MARKER="${SANDY_ISO_MARKER:-/etc/sandy-session.json}"
PY="${SANDY_ISO_PYTHON:-python3}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() {
  printf '\n=== PRE-FLIGHT FAILED - %s ===\n' "$1" >&2
  printf 'Not inside a sandy session (or sandy is too old to emit the marker).\n' >&2
  printf 'STOP: do not run the layer probes. This is a harness/launch failure to\n' >&2
  printf 'report up - never a per-layer verdict.\n\n' >&2
  local d="reports/runs/preflight-failed.$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$d" 2>/dev/null && {
    {
      echo "# PRE-FLIGHT FAILED"
      echo
      echo "\`$MARKER\` absent/invalid; the agent is not inside a sandy session."
      echo "**No isolation verdicts were produced.**"
      echo
      echo "Reason: $1"
      echo
      echo '## Raw evidence checked'
      echo '```'
      ls -l "$MARKER" 2>&1
      echo "--- cat ---"
      cat "$MARKER" 2>&1 | head -40
      echo "--- findmnt ---"
      findmnt -no SOURCE,FSTYPE,OPTIONS -T "$MARKER" 2>&1 | head -5
      echo "--- id / uname (observations only, never presence proof) ---"
      id 2>&1; uname -a 2>&1
      echo '```'
    } > "$d/PREFLIGHT_FAILED.md"
    printf 'Wrote %s/PREFLIGHT_FAILED.md\n' "$d" >&2
  }
  exit 1
}

# ---- Stage 1: the hard gate (no dependencies on the evidence machinery) -------
[ -r "$MARKER" ] || fail "$MARKER is absent or unreadable"
"$PY" - "$MARKER" <<'PY' || fail "$MARKER is not valid JSON or is missing required fields"
import json, sys
try:
    mk = json.load(open(sys.argv[1]))
except Exception as exc:
    sys.stderr.write("invalid JSON: %s\n" % exc); sys.exit(1)
missing = [k for k in ("sandy_version", "egress_mode", "session_nonce", "workspace",
                       "host_uid", "launched_at") if mk.get(k) in (None, "")]
if missing:
    sys.stderr.write("missing fields: %s\n" % ", ".join(missing)); sys.exit(1)
PY

# ---- Stage 2: is the marker a READ-ONLY BIND? (F2b) --------------------------
# v1's entire trust argument was "a workspace config cannot forge a :ro bind", but
# the gate only did [ -r ] + cat: it never checked the claim it relied on.
RO="$("$PY" "$HERE/_fsop.py" mountinfo "$MARKER" | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["summary"]["n_ro"])')"
if [ "${RO:-0}" -lt 1 ]; then
  if [ "${SANDY_ISO_ALLOW_UNSAFE_MARKER:-0}" = "1" ]; then
    printf '!! WARNING: %s is NOT a read-only bind. Continuing because\n' "$MARKER" >&2
    printf '!! SANDY_ISO_ALLOW_UNSAFE_MARKER=1. L0.02 will render BREACHED and the whole\n' >&2
    printf '!! run will render CONTROL-INVALID host-side: a forgeable marker cannot\n' >&2
    printf '!! anchor any verdict.\n' >&2
  else
    fail "$MARKER exists but is NOT a read-only bind mount - it is forgeable, so the declared config cannot anchor any verdict (set SANDY_ISO_ALLOW_UNSAFE_MARKER=1 to record it and continue anyway)"
  fi
fi

# ---- Stage 3: record L0 evidence ---------------------------------------------
EV_PROBE_NAME="preflight.sh"
# shellcheck source=/dev/null
. "$HERE/_evidence.sh"
ev_boot || fail "could not initialise the evidence run directory"

ev_planned L0.01
ev_planned L0.02
ev_planned L0.03
ev_planned L0.04
ev_planned L0.05

cat <<EOF

=== PRE-FLIGHT PASSED - inside sandy ===
Marker (verbatim):
$(cat "$MARKER")

  declared egress_mode : $EV_MODE   <- sandy's DECLARED intent (grading input, not proof of enforcement)
  measured topology    : $("$PY" "$HERE/network_egress.py" topology | "$PY" -c 'import json,sys; d=json.load(sys.stdin); print(d["observed_topology"], "| default_route:", d["default_route"], "| my_ip:", d["my_ip"], "| proxy:", d["proxy_ip"])')
  run directory        : $SANDY_ISO_RUNDIR

Declared and measured are graded INDEPENDENTLY. If they disagree, that divergence
is the finding - do not "resolve" it in favour of either one.

Next: bash probes/run_all.sh
EOF
exit 0
