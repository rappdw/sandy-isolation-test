#!/usr/bin/env bash
# Layer 2 - filesystem. Runs the pre-registered L2 tests and records evidence.
# No verdicts here: there is no ok()/bad() in this file by design.
#
# What changed from v1, and why:
#  * v1 inferred "protected" from "not tmpfs" and then APPENDED. A rw host bind -
#    exactly the regression the probe exists to catch - fell through to the write
#    branch, so the append SUCCEEDED, landed on the maintainer's real file, and was
#    never reverted. L2.02 now measures ro/rw + host-backing FIRST (mount flags are
#    stronger evidence than a successful append) and L2.03 only writes where the
#    mount is already known to be read-only.
#  * v1's mount enumeration FILTERED /proc/mounts down to the expected mounts, so an
#    unexpected mount could never appear. L2.04 inverts it: enumerate everything,
#    classify, print the unclassified remainder.
#  * /proc/mounts is uninformative on the primary platform (every host bind shows as
#    `mac`). Source resolution now uses findmnt / /proc/self/mountinfo throughout.
#  * L2.07 leaves ONE pre-registered, inert artifact so the session-end detective
#    control can finally be graded (H2.01) - and records every directory component
#    it created so cleanup removes all of them, not just the leaf.
set -u
EV_PROBE_NAME="filesystem.sh"
# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_evidence.sh"
ev_boot || exit 1

echo "== Layer 2: filesystem =="
ev_planned L2.01     # write the read-only root
ev_planned L2.02     # classify protected paths (no writes)
ev_planned L2.03     # append only where measured ro
ev_planned L2.04     # enumerate all mounts -> unclassified remainder
ev_planned L2.05     # CANARY: host file outside the mount set
ev_planned L2.06     # CANARY: sentinel proving the :ro file is the host's
ev_planned L2.07     # absent protected dir + the pre-registered artifact
ev_planned L2.08     # traversal / symlink / procfs escapes
ev_planned L2.09     # /proc and /sys masking
ev_planned L2.10     # writable-mount flags (measurement)
ev_planned L2.11     # /etc/passwd and /etc/group

if [ "${SANDY_ISO_NO_ARTIFACT:-0}" = "1" ]; then
  ev_note "L2.07 ran with SANDY_ISO_NO_ARTIFACT=1: no artifact was left, so H2.01 (the session-end detective control) cannot be graded for this run."
else
  ev_note "L2.07 left the pre-registered probe artifact by design (RoE carve-out). The maintainer removes it during RUNBOOK-v2 cleanup using created_components from the evidence."
fi
echo "== end Layer 2 (verdicts are computed host-side by adjudicate.sh) =="
