#!/usr/bin/env bash
# Layers 4 & 5 - process/privilege and resources. Records evidence only.
#
# What changed from v1, and why:
#  * v1's header said "should be non-root, uid 1001-ish" - the precise wrong
#    expectation that produced the original false negative, shipped in the file the
#    agent runs. L4.01 now asserts uid == the marker's host_uid (501 on a Mac).
#  * Capabilities are graded RELATIVELY: CapBnd = the documented five is sandy
#    working as designed; only capabilities beyond that set, and only dangerous
#    ones, are a finding.
#  * seccomp / AppArmor / SELinux and the PID namespace are measured at all for the
#    first time (never mentioned anywhere in v1).
#  * L5's rubric was a string comparison against 'max'. Verified in a real run:
#    memory.max = 89.4% of host RAM and cpu.max = 100% of cores, both graded HELD.
#    A cap at ~host capacity provides no containment, so L5.02/L5.03 are graded as
#    a RATIO of host capacity, with the thresholds written down in testplan.json.
#  * L5.01 verifies the cgroup NAMESPACE first: with cgroupns=host the probe reads
#    the host root cgroup and can produce both false BREACHED and false HELD.
#  * Limits are still READ, never exhausted. The one enforcement probe (L5.05) is
#    opt-in, bounded by bytes AND time, confined to this container's own tmpfs, and
#    deletes what it wrote.
set -u
EV_PROBE_NAME="privilege.sh"
# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_evidence.sh"
ev_boot || exit 1

ev_parse_L4_01() {
  awk '/^uid=/{print "uid=" substr($0,5)} /^gid=/{print "gid=" substr($0,5)}' "$1" \
    | sed 's/[^0-9=a-z_]*$//'
}
ev_parse_L4_02() {
  awk -F'[: \t]+' '
    /^CapInh/{print "capinh=" $2} /^CapPrm/{print "capprm=" $2}
    /^CapEff/{print "capeff=" $2} /^CapBnd/{print "capbnd=" $2}
    /^CapAmb/{print "capamb=" $2} /^NoNewPrivs/{print "nonewprivs=" $2}
    /^Seccomp:/{print "seccomp=" $2} /^Seccomp_filters/{print "seccomp_filters=" $2}' "$1"
}
ev_parse_L4_04() { awk -F'[: \t]+' '/^NoNewPrivs/{print "nonewprivs=" $2}' "$1"; }
ev_parse_L4_05() {
  awk -F'[: \t]+' '/^Seccomp:/{print "seccomp=" $2} /^Seccomp_filters/{print "seccomp_filters=" $2}' "$1"
  local lsm; lsm="$(sed -n '2p' "$1" | tr -d '\0' | tr -d '\n')"
  [ -n "$lsm" ] && echo "lsm_label=$lsm" || echo "lsm_label=none"
}
ev_parse_L4_10() {
  echo "pid1_cmdline=$(head -1 "$1" | tr -d '\n' | cut -c1-120)"
  awk -F= '/^NPROCS=/{print "nprocs=" $2}' "$1"
}
ev_parse_L5_01() {
  local priv=true line path
  while IFS= read -r line; do
    path="${line##*:}"
    [ "$path" = "/" ] || priv=false
  done < <(grep -E '^[0-9]+:' "$1")
  echo "cgroup_path=$(grep -E '^[0-9]+:' "$1" | head -1)"
  echo "cgroupns_private=$priv"
}

echo "== Layer 4: process / privilege =="
ev_planned L4.01     # uid == marker.host_uid, non-root
ev_planned L4.02     # CapEff/CapPrm/CapInh == 0
ev_planned L4.03     # bounding set vs the documented five
ev_planned L4.04     # NoNewPrivs
ev_planned L4.05     # seccomp + LSM (measurement)
ev_planned L4.06     # actively attempt privilege regain
ev_planned L4.07     # docker/containerd socket surface
ev_planned L4.08     # docker daemon over TCP
ev_planned L4.09     # setuid inventory (measurement)
ev_planned L4.10     # PID namespace

echo "== Layer 5: resources (read the ceilings; never exhaust them) =="
ev_planned L5.01     # GATE: cgroup namespace
ev_planned L5.02     # memory cap, graded relatively
ev_planned L5.03     # cpu cap, graded relatively
ev_planned L5.04     # pids + tmpfs sizes
ev_planned L5.05     # OPT-IN bounded enforcement probe (skipped unless SANDY_ISO_ENFORCEMENT=1)

echo "== end Layers 4 & 5 (verdicts are computed host-side by adjudicate.sh) =="
