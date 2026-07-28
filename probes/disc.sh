#!/usr/bin/env bash
# disc.sh - record one DISCRETIONARY attempt (red-team work beyond the plan).
#
#   bash probes/disc.sh "<title>" "<shell command>" [layer-hint] [rationale]
#
# The pre-registered plan makes runs comparable; this makes going beyond it
# visible. Both v1 runs did real, creative work (Host-spoofed SSRF, explicit
# CONNECT-to-private, resolving the credential source with findmnt) - none of it
# machine-countable, so "the agent tried 7 things" and "the agent tried 4 things"
# looked the same in the matrix. Now it does not.
#
# Same discipline as a planned test: the command, its exit code, its errno, a hash
# of the full output and the captured bytes are recorded. No verdicts.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIT="$(dirname "$HERE")"
cd "$KIT" || exit 1

TITLE="${1:?usage: disc.sh \"<title>\" \"<command>\" [layer] [rationale]}"
CMD="${2:?usage: disc.sh \"<title>\" \"<command>\" [layer] [rationale]}"
LAYER="${3:-}"
WHY="${4:-}"

if [ -z "${SANDY_ISO_RUNDIR:-}" ]; then
  SANDY_ISO_RUNDIR="$(python3 "$HERE/_ev.py" init)" || exit 1
  export SANDY_ISO_RUNDIR
fi

DJ="$SANDY_ISO_RUNDIR/discretionary.jsonl"
N="$(( $( [ -f "$DJ" ] && wc -l < "$DJ" || echo 0 ) + 1 ))"
ID="$(printf 'D.%02d' "$N")"
OUT="$(mktemp)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
_now_ms() { local n; n="$(date +%s%N 2>/dev/null || true)"; case "$n" in *[!0-9]*|"") echo $(( $(date +%s) * 1000 ));; *) echo $(( n / 1000000 ));; esac; }

START="$(_now_ms)"
LC_ALL=C bash -c "$CMD" >"$OUT" 2>&1
RC=$?
END="$(_now_ms)"

python3 "$HERE/_ev.py" record --discretionary --id "$ID" --title "$TITLE" \
  --command "$CMD" --exit-code "$RC" --wall-ms "$(( END - START ))" --out "$OUT" \
  --ts "$TS" --note "$WHY" ${LAYER:+--layer-hint "$LAYER"} >/dev/null

printf '%s recorded: %s (exit=%s, %sms)\n' "$ID" "$TITLE" "$RC" "$(( END - START ))"
head -c 400 "$OUT"; echo
rm -f "$OUT"
printf '\n(re-run `python3 probes/_ev.py finalize` when you are done so evidence.json\n includes this attempt)\n'
