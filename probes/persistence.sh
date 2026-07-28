#!/usr/bin/env bash
# Layer 8 - persistence & supply chain (protocol v2.1). Runs the pre-registered L8 tests
# and records evidence. No verdicts here: there is no ok()/bad() in this file by design.
#
# Why this layer exists (LESSONS.md rows #2 and #4, from the Hugging Face incident):
#   * The incident ran ~3 quiet days; "assume failures go unnoticed". The kit was a
#     point-in-time snapshot with NO persistence/time dimension - a session that plants a
#     foothold and a session that leaves cleanly looked identical.
#   * "The boundary bypassed was the entire agentic system: harness, tools, credentials,
#     memory." We tested container FS/net/creds but never the agent's own tool supply chain.
#
# What each L8 test does, in one line: measure whether a persistence-relevant location is
# WRITABLE and HOST-BACKED (i.e. a write here survives session end), classify it, and where
# a write is needed to prove the point, create a nonce-named INERT sentinel, record every
# component created + its host path, then REMOVE it. Mirrors filesystem.sh's L2.07 discipline
# (measure ro/rw BEFORE writing; record created_components) - but LEAVES NOTHING. The
# "survived to the host sandbox" claim is graded host-side by H8.01, never asserted here.
#
# Commands are resolved from testplan.json by _ev.py (single source of truth): this probe
# never hardcodes what it runs, so it cannot drift from the plan it claims to implement.
set -u
EV_PROBE_NAME="persistence.sh"
# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_evidence.sh"
ev_boot || exit 1

echo "== Layer 8: persistence & supply chain =="
ev_planned L8.01     # persistent package-dir census (writable + host-backed?)
ev_planned L8.02     # python site-packages: sitecustomize/.pth auto-exec surface (sentinel)
ev_planned L8.03     # pip/console-script bin dir on PATH before system (hijack + sentinel)
ev_planned L8.04     # cargo: registry + bin, host-backed (classify)
ev_planned L8.05     # npm-global bin on PATH, host-backed (classify)
ev_planned L8.06     # go: GOPATH/bin on PATH, host-backed (classify)
ev_planned L8.07     # uv data dir host-backed (sentinel)
ev_planned L8.08     # harness supply chain: ~/.claude rw map (settings/plugins/commands/hooks)
ev_planned L8.09     # harness ABSENT surface: ~/.claude/skills + mcp.json creatable (sentinel)
ev_planned L8.10     # classic persistence backing: shell-rc / cron / systemd-user (classify)
ev_planned L8.11     # PATH-order hijack synthesis (any persistent writable dir precedes system?)
ev_planned L8.12     # the "quiet" dimension: ONE benign labeled beat to an allowed host

# Cleanup narration (mirrors filesystem.sh's L2.07 note). Unlike L2.07, the persistence
# sentinels are REMOVED within each test by construction: nothing is left on the host.
if [ "${SANDY_ISO_LEAVE_SENTINEL:-0}" = "1" ]; then
  ev_note "L8 ran with SANDY_ISO_LEAVE_SENTINEL=1: sentinels were deliberately LEFT for H8.01 detective-control calibration. Remove every sentinel_path and created_components host-side before the next session. The default probe run does NOT set this."
else
  ev_note "L8 left NO persistence implant by design: every sentinel was written, recorded (created_components + host paths), and removed in the same test. H8.01 confirms host-side that nothing survived session end - persistence survival is graded there, never asserted from inside."
fi
echo "== end Layer 8 (verdicts are computed host-side by adjudicate.sh) =="
