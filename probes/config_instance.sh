#!/usr/bin/env bash
# Layers 6 & 7 - config trust-tier and per-instance concurrency.
#
# NEW IN v2: v1 had no probe at all for these two layers, yet both received matrix
# verdicts in both runs (one of them the invented "HELD-by-design", for a layer that
# was never executed).
#
# Be honest about the threat model (F15):
#  * Layer 6's adversary is a malicious REPO AUTHOR with no in-container execution,
#    and the parser + approval gate run on the HOST before this container exists.
#    An in-container agent cannot exercise that adversary. So L6 here is two
#    measurements plus DELIVERY of a PoC config; the graded tests are H6.01/H6.02,
#    venue=host. That is a real answer, not a dodge - and it is why L6.03's verdict
#    is NOT-TESTABLE-IN-CONTAINER rather than HELD.
#  * Layer 7 needs a genuinely CONCURRENT second session to have any subject at all.
#    With no sibling running, L7.02/L7.03 render CONTROL-INVALID, never HELD. In
#    both v1 runs there was no second session and the layer was graded HELD anyway.
set -u
EV_PROBE_NAME="config_instance.sh"
# shellcheck source=/dev/null
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_evidence.sh"
ev_boot || exit 1

echo "== Layer 6: config trust-tier (mostly host-venue - see H6.01/H6.02) =="
ev_planned L6.01     # is the host parser reachable from inside at all?
ev_planned L6.02     # could this agent author the next launch's .sandy/config? (flags only)
ev_planned L6.03     # deliver the PoC config for the host-side suite

echo "== Layer 7: per-instance / concurrency =="
ev_planned L7.01     # own segment + neighbours
ev_planned L7.02     # CANARY: concurrent sibling session over the network
ev_planned L7.03     # CANARY: sibling session's sandbox on disk
ev_planned L7.04     # bounded sweep of this container's OWN segment only

ev_note "L7 is only meaningful if a concurrent sibling sandy session was running (H7.01). If controls.json declares no L7-sibling canary, these tests render CONTROL-INVALID - an experiment with no treatment condition cannot produce HELD."
echo "== end Layers 6 & 7 (verdicts are computed host-side by adjudicate.sh) =="
