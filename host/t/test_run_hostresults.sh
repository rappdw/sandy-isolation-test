#!/usr/bin/env bash
# host/t/test_run_hostresults.sh - regression test for run.sh's H3.01 host-results block (D-18).
#
#   bash host/t/test_run_hostresults.sh
#
# Why this file exists. Every other K1 defect across three verification passes got a committed
# regression test that was then deliberately broken to prove it fails. D-18's original
# verification was a scratch extraction that left nothing behind, so that standard could not be
# applied to it - not at the time, and not on the NEXT change to that block. This closes the
# asymmetry (K1-VERIFY.md P3.7).
#
# The defect: HOST_RESULTS_FILE was gated on `[ -n "$RUN" ]`, coupling it to plumbing #1's
# mismatched-AND-already-adjudicated refusal (which sets RUN=""). Those concerns are unrelated -
# the refusal is about not CLOBBERING a prior run's directory and says nothing about whether
# THIS run's honeytoken evidence exists, which it does. Net effect ran backwards: the one run
# that most needed the operator pointed at its evidence was the only run whose printed hint
# carried no --host-results at all, so H3.01 landed NOT-ATTEMPTED with no hint the answer existed.
#
# Method: the block is EXTRACTED from the real host/run.sh rather than copied here, so this test
# exercises the shipping code and goes stale loudly (test 0) rather than silently drifting into
# testing a stale copy of itself. honeytoken_check.sh is stubbed - this is about run.sh's
# plumbing, not about --scan-window's contents.
#
# IF YOU MUTATION-TEST THIS SUITE, READ THIS FIRST. Both the author and the verifier got it
# wrong on the first attempt, in the two opposite directions, so this is the failure mode to
# design against rather than a hypothetical:
#
#   - A mutation that lands somewhere unintended can go RED for the wrong reason. (Author: a
#     mutant pointing at a path that did not exist made the write simply fail, so the assertion
#     actually being targeted was never exercised - the suite looked load-bearing on evidence
#     that proved nothing.)
#   - Worse, it can go GREEN for the wrong reason and read as a finding against the suite.
#     (Verifier: run.sh tests `[ -f "$STATE_DIR/honeytokens.json" ]` in THREE places - two plain
#     `if` and one `elif` - of which only the last is the block below. A `replace(..., 1)` hit
#     the first, a different block entirely and outside the extraction range, and produced a
#     clean 22/0 that read as this suite failing to catch a D-18 revert. Grep for the guard
#     rather than trusting a line number; they drift.)
#
# GREEN-for-the-wrong-reason is the more dangerous of the two, because RED at least prompts you
# to look. The guard for both: assert WHERE the mutation landed, not merely that the file
# changed - check the mutated line is inside the extracted range, and check the failures you get
# are the specific assertions you were aiming at.
set -u

HERE_T="$(cd "$(dirname "$0")" && pwd)"
RUNSH="$(cd "$HERE_T/.." && pwd)/run.sh"

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  [ok]   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

BLOCK="$TMP/block.sh"
FLAGLINE="$TMP/flagline.sh"

echo "== test 0: the block is still extractable from run.sh (this test's own load-bearing assumption) =="
sed -n '/^# D-18: this used to be gated/,/^fi$/p' "$RUNSH" > "$BLOCK"
grep -n 'HOST_RESULTS_FILE' "$RUNSH" | grep -q 'ADJUDICATE_FLAGS' \
  && grep 'ADJUDICATE_FLAGS.*--host-results' "$RUNSH" > "$FLAGLINE" \
  || : > "$FLAGLINE"
if [ -s "$BLOCK" ] && grep -q 'HOST_RESULTS_FILE=""' "$BLOCK" && grep -q 'scan-window' "$BLOCK"; then
  ok "extracted the host-results block from run.sh ($(wc -l < "$BLOCK" | tr -d ' ') lines)"
else
  bad "EXTRACTION FAILED - the D-18 marker comment or the block shape in run.sh changed. This test is now testing nothing; fix the sed range above before trusting any result below."
fi
if [ -s "$FLAGLINE" ]; then
  ok "extracted the ADJUDICATE_FLAGS --host-results line from run.sh"
else
  bad "EXTRACTION FAILED - run.sh no longer has a line appending --host-results to ADJUDICATE_FLAGS; the hint assertions below are meaningless"
fi

# Harness: run the extracted block with the same variables run.sh has in scope at that point,
# under `set -u` exactly as run.sh does (run.sh:19), then build the hint the same way.
# Emits: <marker line>|<HOST_RESULTS_FILE>|<the adjudicate hint>
harness() {
  local run_arg="$1" stub_rc="$2" plant="$3" out
  local root="$TMP/case-$4"
  rm -rf "$root"; mkdir -p "$root/state" "$root/here" "$root/rundir"
  [ "$plant" = yes ] && echo '{"tokens":[]}' > "$root/state/honeytokens.json"
  cat > "$root/here/honeytoken_check.sh" <<STUB
#!/usr/bin/env bash
echo '{"stub": true}'
[ "$stub_rc" -ne 0 ] && echo 'stub failure detail' >&2
exit $stub_rc
STUB
  local run_val=""
  [ "$run_arg" = set ] && run_val="$root/rundir"
  (
    set -u
    STATE_DIR="$root/state"; HERE="$root/here"; NONCE8="ab12cd34"; RUN="$run_val"
    . "$BLOCK"
    ADJUDICATE_FLAGS="--record-control"
    . "$FLAGLINE"
    printf 'RESULT|%s|bash adjudicate.sh "%s" %s\n' \
      "$HOST_RESULTS_FILE" "${RUN:-reports/runs/<run-id>}" "$ADJUDICATE_FLAGS"
  ) 2>&1
}

echo "== test 1: RUN resolved normally - unchanged behaviour (the non-regression half of D-18) =="
out="$(harness set 0 yes 1)"
hrf="$(printf '%s' "$out" | sed -n 's/^RESULT|\([^|]*\)|.*/\1/p')"
hint="$(printf '%s' "$out" | sed -n 's/^RESULT|[^|]*|\(.*\)/\1/p')"
case "$hrf" in
  */rundir/host-results.json) ok "host-results lands in the run dir when RUN is resolved" ;;
  *) bad "expected \$RUN/host-results.json, got [$hrf]" ;;
esac
[ -f "$hrf" ] && ok "the file is actually written, not just named" || bad "no file at [$hrf]"
printf '%s' "$hint" | grep -q -- "--host-results $hrf" \
  && ok "the printed hint carries --host-results with the run-dir path" \
  || bad "hint is missing --host-results: $hint"
printf '%s' "$out" | grep -q 'no run dir was resolved' \
  && bad "the fallback operator notice printed on the NORMAL path - it should only appear when RUN is empty" \
  || ok "no fallback notice on the normal path"

echo "== test 2: RUN=\"\" (plumbing #1 refusal fired) - the D-18 fix =="
out="$(harness empty 0 yes 2)"
hrf="$(printf '%s' "$out" | sed -n 's/^RESULT|\([^|]*\)|.*/\1/p')"
hint="$(printf '%s' "$out" | sed -n 's/^RESULT|[^|]*|\(.*\)/\1/p')"
case "$hrf" in
  */state/host-results.ab12cd34.json)
    ok "D-18: host-results still written, to a nonce-stamped file in \$STATE_DIR" ;;
  "") bad "D-18 REGRESSION: no host-results at all when RUN is empty - H3.01 lands NOT-ATTEMPTED with no hint the evidence exists" ;;
  *)  bad "unexpected fallback path [$hrf]" ;;
esac
[ -n "$hrf" ] && [ -f "$hrf" ] && ok "the fallback file is actually written" || bad "no file at the fallback path [$hrf]"
printf '%s' "$hint" | grep -q -- "--host-results .*state/host-results.ab12cd34.json" \
  && ok "D-18: the printed hint carries --host-results pointing at the fallback file" \
  || bad "D-18 REGRESSION: hint omits --host-results, which is the whole defect: $hint"
printf '%s' "$hint" | grep -q 'reports/runs/<run-id>' \
  && ok "the run dir is still shown as the operator-fills-it-in placeholder (the refusal stands)" \
  || bad "expected the <run-id> placeholder in the hint: $hint"
printf '%s' "$out" | grep -q 'no run dir was resolved' \
  && ok "the operator is told WHY the file landed outside a run dir" \
  || bad "fallback fired with no explanation printed - the operator sees an unfamiliar path and no reason"

echo "== test 3: the fallback must not write inside ANY run dir (what the refusal was protecting) =="
# plumbing #1 refuses precisely because $RUN may be a PRIOR run's directory holding its
# verdicts.json. A fallback that wrote into a run dir anyway would reintroduce the clobber the
# refusal exists to prevent, which would be a worse defect than the one D-18 fixed.
case "$hrf" in
  */rundir/*) bad "D-18 wrote into a run dir despite the refusal - this reintroduces the clobber risk plumbing #1 exists to prevent" ;;
  *) ok "fallback path is outside every run dir (\$STATE_DIR), so it cannot overwrite a prior run's evidence" ;;
esac
n_in_rundir="$(find "$TMP/case-2/rundir" -type f 2>/dev/null | wc -l | tr -d ' ')"
[ "$n_in_rundir" = "0" ] && ok "the run dir is left completely untouched on the refusal path" \
                         || bad "$n_in_rundir file(s) appeared in the run dir on the refusal path"

echo "== test 4: no honeytokens.json - the block is inert in both RUN states =="
for state in set empty; do
  out="$(harness "$state" 0 no "4$state")"
  hrf="$(printf '%s' "$out" | sed -n 's/^RESULT|\([^|]*\)|.*/\1/p')"
  hint="$(printf '%s' "$out" | sed -n 's/^RESULT|[^|]*|\(.*\)/\1/p')"
  if [ -z "$hrf" ] && ! printf '%s' "$hint" | grep -q -- '--host-results'; then
    ok "RUN=$state, no honeytokens.json -> no host-results and no flag (H3.01 genuinely wasn't set up)"
  else
    bad "RUN=$state: fabricated host-results [$hrf] with no honeytokens.json planted - the hint would point at evidence that does not exist"
  fi
done

echo "== test 5: --scan-window failure clears the flag rather than pointing at a broken file =="
for state in set empty; do
  out="$(harness "$state" 1 yes "5$state")"
  hrf="$(printf '%s' "$out" | sed -n 's/^RESULT|\([^|]*\)|.*/\1/p')"
  hint="$(printf '%s' "$out" | sed -n 's/^RESULT|[^|]*|\(.*\)/\1/p')"
  if [ -z "$hrf" ] && ! printf '%s' "$hint" | grep -q -- '--host-results'; then
    ok "RUN=$state, --scan-window exits nonzero -> HOST_RESULTS_FILE cleared, no --host-results in the hint"
  else
    bad "RUN=$state: hint points at [$hrf] after --scan-window FAILED - adjudicate would read a truncated/empty file as if it were evidence"
  fi
  printf '%s' "$out" | grep -q 'WARNING' \
    && ok "RUN=$state: the failure is surfaced as a WARNING, not swallowed" \
    || bad "RUN=$state: --scan-window failed silently: $out"
  errlog="$(find "$TMP/case-5$state" -name 'host-results*.err.log' 2>/dev/null | head -1)"
  [ -n "$errlog" ] && [ -s "$errlog" ] \
    && ok "RUN=$state: stderr from the failed run is retained at $(basename "$errlog")" \
    || bad "RUN=$state: no non-empty err log kept, so the operator has nothing to debug from"
done

echo "== test 6: on success the empty err log is cleaned up (no misleading zero-byte artifact) =="
harness empty 0 yes 6 >/dev/null
leftover="$(find "$TMP/case-6" -name 'host-results*.err.log' 2>/dev/null | wc -l | tr -d ' ')"
[ "$leftover" = "0" ] && ok "no empty err log left behind on the success path" \
                      || bad "an empty err log survived a successful run - it reads as a failure that didn't happen"

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
