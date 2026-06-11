#!/usr/bin/env bash
# Layers 4 & 5 — process/privilege and resource isolation. Read-only probe.
# Reports the privilege posture and resource ceilings. Does NOT try to exhaust
# anything (no fork bombs, no disk fill) — resource limits are tested by READING.
set -u
ok(){ printf '  [HELD]   %s\n' "$1"; }
bad(){ printf '  [!!!!]   %s\n' "$1"; }
note(){ printf '  [info]   %s\n' "$1"; }

echo "== Layer 4: process / privilege =="

echo "-- identity (should be non-root, uid 1001-ish) --"
id 2>/dev/null | sed 's/^/      /'
if [ "$(id -u)" = "0" ]; then bad "running as ROOT (uid 0) — privilege drop failed"; else ok "non-root (uid $(id -u))"; fi

echo "-- no-new-privileges + capabilities --"
nnp="$(grep -i NoNewPrivs /proc/self/status 2>/dev/null | awk '{print $2}')"
[ "$nnp" = "1" ] && ok "NoNewPrivs=1 (setuid escalation disabled)" || bad "NoNewPrivs=$nnp (escalation may be possible)"
note "effective capabilities (CapEff; 0000000000000000 = none):"
grep -E '^Cap(Inh|Prm|Eff|Bnd)' /proc/self/status 2>/dev/null | sed 's/^/      /'
capeff="$(grep '^CapEff' /proc/self/status 2>/dev/null | awk '{print $2}')"
[ "$capeff" = "0000000000000000" ] && ok "no effective capabilities" || note "CapEff=$capeff — decode with: capsh --decode=$capeff (some caps present)"

echo "-- root escalation paths --"
command -v sudo >/dev/null 2>&1 && note "sudo present: $(command -v sudo) (try it — should fail without a setuid+sudoers path)" || ok "no sudo binary"
note "setuid-root binaries (a writable/exploitable one would be an escalation path):"
find / -xdev -perm -4000 -type f 2>/dev/null | head -20 | sed 's/^/      /' || true

echo "-- Docker escape surface (the big one) --"
for s in /var/run/docker.sock /run/docker.sock; do
  [ -e "$s" ] && bad "DOCKER SOCKET PRESENT: $s — container can control the daemon (full host escape)" || ok "no docker socket at $s"
done
command -v docker >/dev/null 2>&1 && note "docker client present; 'docker ps' should fail (no daemon reachable)" || ok "no docker client"

echo "-- mounts: anything rw/host that shouldn't be, or a privileged mount --"
note "non-tmpfs, non-overlay mounts (host bind mounts; check rw vs ro):"
grep -vE ' (tmpfs|proc|sysfs|cgroup|cgroup2|mqueue|devpts|overlay|shm) ' /proc/mounts 2>/dev/null | sed 's/^/      /' | head -25

echo ""
echo "== Layer 5: resources (read the ceilings — do NOT exhaust) =="
note "CPUs visible: $(nproc 2>/dev/null)"
free -h 2>/dev/null | sed 's/^/      /' || true
echo "-- cgroup limits (memory / pids / cpu) --"
for f in /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max /sys/fs/cgroup/cpu.max \
         /sys/fs/cgroup/memory/memory.limit_in_bytes /sys/fs/cgroup/pids/pids.max; do
  [ -r "$f" ] && note "$f = $(cat "$f" 2>/dev/null)"
done
note "tmpfs sizes (expect ~1G /tmp, ~2G /home/claude):"
df -h /tmp /home/claude 2>/dev/null | sed 's/^/      /'
note "If memory.max / pids.max read 'max' (unlimited), the caps are NOT applied — a finding."
echo "== end Layers 4 & 5 =="
