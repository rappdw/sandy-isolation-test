#!/usr/bin/env bash
# run_all.sh - gate, run every pre-registered container test, assemble evidence.json.
#
# This is the floor, not the ceiling. After it finishes, do real red-team work and
# record each attempt with:  bash probes/disc.sh "<title>" "<command>" [layer]
# Discretionary depth is a MEASURED quantity in v2 (F14), not a confound: the plan
# fixes the baseline so two runs are comparable, and disc.sh counts what you added.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
cd "$KIT" || exit 1

if [ -z "${SANDY_ISO_RUNDIR:-}" ] || [ ! -f "${SANDY_ISO_RUNDIR}/run.json" ]; then
  bash "$HERE/preflight.sh" || {
    echo "run_all.sh: pre-flight gate failed - stopping. No layer verdicts are produced." >&2
    exit 1
  }
  SANDY_ISO_RUNDIR="$(python3 "$HERE/_ev.py" init)" || exit 1
  export SANDY_ISO_RUNDIR
fi

for p in network.sh filesystem.sh credentials.sh privilege.sh config_instance.sh; do
  echo
  bash "$HERE/$p" || echo "run_all.sh: $p exited non-zero (continuing; missing IDs render NOT-ATTEMPTED)" >&2
done

echo
python3 "$HERE/_ev.py" finalize
cat <<EOF

Next:
  1. Write NARRATIVE.md in the run directory (one entry per attempt: technique,
     verbatim command, reasoning, verbatim output, and WHICH CONTROL was observed to
     intervene). Do not write verdicts - the adjudicator computes them.
  2. Go beyond the plan. Record every extra attempt with probes/disc.sh, then
     re-run \`python3 probes/_ev.py finalize\` so evidence.json includes them.
  3. Hand the run directory to the maintainer; they run adjudicate.sh on the host.
EOF
