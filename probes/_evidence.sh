#!/usr/bin/env bash
# _evidence.sh - sourced by every probe runner. Not executable on its own.
#
# One job: run a PRE-REGISTERED test by ID and record what happened. The command
# text comes from testplan.json (never from the probe), so a probe cannot quietly
# run something other than the plan it claims to implement.
#
# Contract for probe authors:
#   ev_boot                      # once, at the top of the probe
#   ev_planned L2.01             # run test L2.01 exactly as pre-registered
#   ev_parse_L4_01 () { ... }    # optional: echo k=v lines to add evidence fields
#
# No function here decides anything. There is no ok()/bad() and no verdict.
set -u

EV_PROBES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EV_KIT_DIR="$(dirname "$EV_PROBES_DIR")"
EV_PY="${SANDY_ISO_PYTHON:-python3}"
EV="$EV_PROBES_DIR/_ev.py"

ev_boot() {
  export LC_ALL=C
  cd "$EV_KIT_DIR" || return 1
  # init also (re)writes run.json, so a pre-set SANDY_ISO_RUNDIR still gets a header.
  if [ -z "${SANDY_ISO_RUNDIR:-}" ] || [ ! -f "${SANDY_ISO_RUNDIR}/run.json" ]; then
    SANDY_ISO_RUNDIR="$("$EV_PY" "$EV" init)" || return 1
    export SANDY_ISO_RUNDIR
  fi
  EV_MODE="$("$EV_PY" - <<'PY'
import json
print(json.load(open("/etc/sandy-session.json")).get("egress_mode", "unknown"))
PY
)"
  export EV_MODE
  printf '# probe: %s | run dir: %s | declared egress_mode: %s\n' \
    "${EV_PROBE_NAME:-$(basename "${BASH_SOURCE[1]:-probe}")}" "$SANDY_ISO_RUNDIR" "$EV_MODE"
}

_ev_now_ms() {
  local n
  n="$(date +%s%N 2>/dev/null || true)"
  case "$n" in
    *[!0-9]*|"") echo $(( $(date +%s) * 1000 )) ;;
    *)           echo $(( n / 1000000 )) ;;
  esac
}

# ev_planned <TEST-ID> [extra-field=value ...]
ev_planned() {
  local id="$1"; shift
  local cmd rc start end out err reason fn line
  out="$(mktemp)"; err="$(mktemp)"
  local -a extra=()
  for kv in "$@"; do extra+=(--field "$kv"); done

  if ! cmd="$("$EV_PY" "$EV" resolve "$id" 2>"$err")"; then
    rc=$?
    reason="$(sed -n 's/^SKIP://p' "$err" | head -1)"
    [ -n "$reason" ] || reason="resolve-failed(rc=$rc)"
    printf '  %-6s SKIPPED  (%s)\n' "$id" "$reason"
    "$EV_PY" "$EV" record --id "$id" --command "(not run)" --exit-code 0 \
      --wall-ms 0 --skipped-reason "$reason" "${extra[@]}" >/dev/null
    rm -f "$out" "$err"; return 0
  fi

  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  start="$(_ev_now_ms)"
  bash -c "$cmd" >"$out" 2>&1
  rc=$?
  end="$(_ev_now_ms)"

  fn="ev_parse_${id//./_}"
  if declare -F "$fn" >/dev/null 2>&1; then
    while IFS= read -r line; do
      [ -n "$line" ] && extra+=(--field "$line")
    done < <("$fn" "$out" 2>/dev/null || true)
  fi

  "$EV_PY" "$EV" record --id "$id" --command "$cmd" --exit-code "$rc" \
    --wall-ms "$(( end - start ))" --out "$out" --ts "$ts" "${extra[@]}" >/dev/null

  printf '  %-6s exit=%-3s %sms  %s\n' "$id" "$rc" "$(( end - start ))" \
    "$(head -c 110 "$out" | tr '\n' ' ')"
  rm -f "$out" "$err"
  return 0
}

# ev_note <text>  - narration for the maintainer; never read by the adjudicator.
ev_note() {
  mkdir -p "$SANDY_ISO_RUNDIR"
  printf '%s\n' "$*" >> "$SANDY_ISO_RUNDIR/agent_notes.txt"
  printf '  note: %s\n' "$*"
}
