#!/usr/bin/env bash
# Layer 3 - credentials. Runs the pre-registered L3 tests and records evidence.
#
# What changed from v1, and why:
#  * v1's search did `find ... | grep -v "^$HOME/"`, which blinded the probe to the
#    layer's highest-value breach by construction: if sandy mis-mounted the host's
#    real ~/.claude at $HOME/.claude, the filter removed it. Both v1 runs cited that
#    probe's negative as their Layer-3 HELD basis. $HOME is now IN scope.
#  * v1 used -maxdepth 4, too shallow to reach
#    <host home>/.sandy/sandboxes/<proj>/.claude/.credentials.json (depth 6). Now 8.
#  * Credential SOURCES are classified via findmnt / mountinfo. Holding your own
#    session's ephemeral mktemp copy is expected and is not a finding; the source
#    being the real host credential store is.
#  * L3.02/L3.03 are canary-anchored (F3): without a planted subject, "find returned
#    nothing" is equally consistent with "isolation works" and "nothing was there".
set -u
EV_PROBE_NAME="credentials.sh"
# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_evidence.sh"
ev_boot || exit 1

echo "== Layer 3: credentials =="
ev_planned L3.01     # inventory + mount-source classification (incl. $HOME)
ev_planned L3.02     # CANARY: another project's sandbox credential
ev_planned L3.03     # CANARY: the host's real ~/.claude
ev_planned L3.04     # OAuth mounts: measured ro, then attempted
ev_planned L3.05     # private key material
ev_planned L3.06     # env secrets (names only, values redacted)

ev_note "Holding THIS session's own credentials is expected and is not a breach. The graded question is whether any credential's mount SOURCE is something other than the ephemeral mktemp copy / this project's sandbox."
echo "== end Layer 3 (verdicts are computed host-side by adjudicate.sh) =="
