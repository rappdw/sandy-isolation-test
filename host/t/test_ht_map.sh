#!/usr/bin/env bash
# host/t/test_ht_map.sh - K1 self-test suite for host/honeytoken_check.sh.
# Pure host-side, no sandy, no real docker required (a stub is written to a scratch PATH).
# Runs entirely against a scratch $HOME / workspace / state dir - NEVER touches the real
# ~/.aws, ~/.sandy or the invoking user's honeytoken state.
#
#   bash host/t/test_ht_map.sh
#
# Implements reports/2026-06-11/k-items/K1-PLAN.md §5 "A. Pure host-side unit tests", plus
# the K1-VERIFY.md D-01..D-12 fix-pass coverage (see the per-test comments below for which
# defect each new/changed test proves fixed). Every new/changed test in this file was, at
# authoring time, verified to go RED against the pre-fix code and GREEN against the fix -
# see the fixer's final report for the transcript; that check is not re-run automatically
# here (it would require temporarily reverting the fix), so don't take a green run alone as
# proof a test is load-bearing - the report is.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"   # .../host
HTC="$HERE/honeytoken_check.sh"

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

export HOME="$TMP/home"
mkdir -p "$HOME"
export SANDY_ISO_STATE_DIR="$TMP/state"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf '  [ok]   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

sha256_hex() { command -v shasum >/dev/null 2>&1 && shasum -a 256 | awk '{print $1}' || sha256sum | awk '{print $1}'; }
file_sha256() { command -v shasum >/dev/null 2>&1 && shasum -a 256 "$1" | awk '{print $1}' || sha256sum "$1" | awk '{print $1}'; }
file_mode()   { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

echo "== test 1: map arithmetic vs. a shell transcription of sandy's own formula =="
expect_container_name() {
  local ws="$1" work_dir short_hash dir_base
  work_dir="$(cd "$ws" 2>/dev/null && pwd -P)"
  [ -n "$work_dir" ] || work_dir="$ws"
  short_hash="$(printf '%s' "$work_dir" | sha256_hex)"; short_hash="${short_hash:0:8}"
  dir_base="$(basename "$work_dir" | tr -cd 'a-zA-Z0-9._-')"; dir_base="${dir_base:-project}"
  printf 'sandy-%s-%s' "$dir_base" "$short_hash"
}
for ws in "$HOME/dev/foo" "$HOME/dev/Foo" "$HOME/dev/foo bar" "$HOME/dev/.hidden" "/tmp/sandy-iso-outside-home-$$" "$HOME/dev/!!!"; do
  mkdir -p "$ws"
  exp="$(expect_container_name "$ws")"
  got="$(bash "$HTC" --map --workspace "$ws" 2>/dev/null | awk '/^container_name/{print $2}')"
  if [ "$got" = "$exp" ]; then ok "map('$ws') -> $got"; else bad "map('$ws'): expected $exp got $got"; fi
done

echo "== test 2: refusal invariant (D9) via --map --probe-path (known_mount_for directly) =="
WS="$HOME/dev/refuseproj"; mkdir -p "$WS"
mkdir -p "$HOME/.aws"; touch "$HOME/.aws/credentials"
out="$(bash "$HTC" --map --workspace "$WS" --probe-path "$HOME/.aws/credentials" 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'not mounted'; then
  ok "map --probe-path refuses \$HOME/.aws/credentials (exit 2, 'not mounted')"
else
  bad "expected exit 2 + 'not mounted' for ~/.aws/credentials, got rc=$rc: $out"
fi
sandbox_dir="$(bash "$HTC" --map --workspace "$WS" 2>/dev/null | awk '/^sandbox_dir/{print $2}')"
out="$(bash "$HTC" --map --workspace "$WS" --probe-path "$sandbox_dir/.env" 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'not mounted'; then
  ok "map --probe-path refuses sandbox-root .env (exit 2, 'not mounted')"
else
  bad "expected exit 2 + 'not mounted' for \$SANDBOX_DIR/.env, got rc=$rc: $out"
fi
out="$(bash "$HTC" --map --workspace "$WS" --probe-path "$sandbox_dir/cargo/credentials.toml" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "does NOT refuse a genuinely mounted location (\$SANDBOX_DIR/cargo/...)" \
                 || bad "false-refused a real mount: rc=$rc $out"

echo "== test 2b: D-12 gap closed - --plant's OWN refusal branch, not just --map --probe-path =="
# K1-VERIFY.md §3: "D9's refusal invariant in --plant is entirely unreachable for the default
# decoy set and untested". SANDY_ISO_HT_TEST_UNMOUNTED_PATH (test-only hook) adds one decoy
# guaranteed to be unmounted, so --plant's own refusal branch (not known_mount_for() via --map)
# is what's under test here. Also proves the D-12 exit-code fix: --plant used to exit 0 even
# with a refusal.
STATE2B="$TMP/state2b"; WS2B="$HOME/dev/refuseproj2"; mkdir -p "$WS2B"
out="$(SANDY_ISO_STATE_DIR="$STATE2B" SANDY_ISO_HT_TEST_UNMOUNTED_PATH="$HOME/.aws/credentials" \
       bash "$HTC" --plant --workspace "$WS2B" --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
if [ "$rc" -eq 2 ]; then ok "--plant exits 2 when it refuses a decoy (D9/D-12)"; else bad "expected --plant to exit 2 on a refusal, got rc=$rc: $out"; fi
if printf '%s' "$out" | grep -q 'REFUSED' && printf '%s' "$out" | grep -q 'HT-test-refusal-probe' && printf '%s' "$out" | grep -qi 'not mounted'; then
  ok "--plant names the refused decoy and says 'not mounted'"
else
  bad "expected a REFUSED/HT-test-refusal-probe/not-mounted message: $out"
fi
n_declared="$(python3 -c "import json; print(len(json.load(open('$STATE2B/honeytokens.json'))['tokens']))" 2>/dev/null || echo "?")"
[ "$n_declared" = "3" ] && ok "the other 3 (genuinely mounted) decoys still planted despite the refusal" \
                        || bad "expected 3 declared tokens after the partial refusal, got $n_declared"

echo "== test 3: ~/.aws non-destructiveness (B6/D11) =="
mkdir -p "$HOME/.aws"
printf '[default]\naws_access_key_id = REALKEYID\naws_secret_access_key = REALSECRET\n\n[other]\nx=1' > "$HOME/.aws/credentials"
before="$(file_sha256 "$HOME/.aws/credentials")"
bash "$HTC" --cleanup --legacy-aws-only >/dev/null 2>&1
after="$(file_sha256 "$HOME/.aws/credentials")"
[ "$before" = "$after" ] && ok "no [sandy-iso-decoy] stanza -> file byte-identical" \
                          || bad "file changed with no decoy stanza present (B6 regression)"

printf '[default]\naws_access_key_id = REALKEYID\naws_secret_access_key = REALSECRET\r\n\n[sandy-iso-decoy]\naws_access_key_id = FAKE\naws_secret_access_key = FAKE2\n\n[other]\nx=1\n' > "$HOME/.aws/credentials"
chmod 640 "$HOME/.aws/credentials"
bash "$HTC" --cleanup --legacy-aws-only >/dev/null 2>&1
after="$(cat "$HOME/.aws/credentials")"
if printf '%s' "$after" | grep -q 'sandy-iso-decoy'; then bad "decoy stanza still present after cleanup"; else ok "decoy stanza excised"; fi
if printf '%s' "$after" | grep -q 'REALKEYID' && printf '%s' "$after" | grep -q '\[other\]'; then
  ok "unrelated stanzas ([default], [other]) preserved byte-for-byte"
else
  bad "unrelated content damaged during excision"
fi
mode="$(file_mode "$HOME/.aws/credentials")"
[ "$mode" = "640" ] && ok "original file mode preserved (640)" || bad "mode changed: got $mode want 640"
bak="$(find "$SANDY_ISO_STATE_DIR" -name 'aws-credentials.pre-cleanup.*.bak' 2>/dev/null | head -1)"
if [ -n "$bak" ]; then
  bmode="$(file_mode "$bak")"
  [ "$bmode" = "600" ] && ok "backup written at 0600: $(basename "$bak")" || bad "backup mode wrong: $bmode"
else
  bad "no pre-cleanup backup file found"
fi

echo "== test 3b: D-03 - a SYMLINKED ~/.aws/credentials is not replaced by a regular file =="
# K1-VERIFY.md §2.6: os.replace(tmp, path) used to swap in a NEW inode, silently destroying a
# dotfile-manager symlink (chezmoi/stow/yadm all do this) and leaving the REAL target file -
# which still holds the decoy stanza - completely untouched (the decoy "removal" was a no-op).
STATE3B="$TMP/state3b"
REALCREDS_DIR="$TMP/realcreds"; mkdir -p "$REALCREDS_DIR" "$HOME/.aws"
rm -f "$HOME/.aws/credentials"
printf '[default]\naws_access_key_id = REALKEYID\n\n[sandy-iso-decoy]\naws_access_key_id = FAKE\n' > "$REALCREDS_DIR/creds"
ln -s "$REALCREDS_DIR/creds" "$HOME/.aws/credentials"
SANDY_ISO_STATE_DIR="$STATE3B" bash "$HTC" --cleanup --legacy-aws-only >/dev/null 2>&1
if [ -L "$HOME/.aws/credentials" ]; then
  ok "~/.aws/credentials is STILL a symlink after cleanup (not replaced by a regular file)"
else
  bad "cleanup replaced the symlink with a regular file (D-03 regression)"
fi
if grep -q 'sandy-iso-decoy' "$REALCREDS_DIR/creds"; then
  bad "the decoy stanza is STILL in the real target file - cleanup was a no-op through the symlink"
else
  ok "the decoy stanza was excised from the REAL target file the symlink points at"
fi
rm -f "$HOME/.aws/credentials"; mkdir -p "$HOME/.aws"   # restore a plain dir for later tests

echo "== test 3c: D-03 corollary - rewrite_lines_atomic() (.env.local cleanup) is also symlink-safe =="
# Same fix pattern as test 3b (os.path.realpath before os.replace), but a SEPARATE line of
# code (rewrite_lines_atomic, used by .env.local cleanup - D-06) from the one test 3b covers
# (backup_and_excise_stanza, used by ~/.aws and cargo config.toml). Cover it independently.
STATE3C="$TMP/state3c"; WS3C="$HOME/dev/proj3c"; REALENV_DIR="$TMP/realenv"
mkdir -p "$WS3C" "$REALENV_DIR"
printf 'REAL_SETTING=keep-me\n' > "$REALENV_DIR/.env.local.real"
ln -s "$REALENV_DIR/.env.local.real" "$WS3C/.env.local"
SANDY_ISO_STATE_DIR="$STATE3C" bash "$HTC" --plant --workspace "$WS3C" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE3C" bash "$HTC" --cleanup >/dev/null 2>&1
if [ -L "$WS3C/.env.local" ]; then
  ok "workspace .env.local symlink survives plant+cleanup (not replaced by a regular file)"
else
  bad "D-03 corollary REGRESSION: plant+cleanup replaced the .env.local symlink with a regular file"
fi
if grep -q 'SERVICE_API_TOKEN\|SERVICE_API_BASE' "$REALENV_DIR/.env.local.real" 2>/dev/null; then
  bad "D-03 corollary REGRESSION: decoy lines survive in the REAL target file behind the symlink"
else
  ok "decoy lines were removed from the REAL target file the .env.local symlink points at"
fi
grep -q '^REAL_SETTING=keep-me$' "$REALENV_DIR/.env.local.real" \
  && ok "operator's real .env.local content (through the symlink) is intact" \
  || bad "operator's real .env.local content was damaged"

echo "== test 4: .env.local surgery is host_path-scoped, not a cwd glob (B7) =="
rm -rf "$TMP/state"; SANDY_ISO_STATE_DIR="$TMP/state"; export SANDY_ISO_STATE_DIR
WS2="$HOME/dev/proj2"; mkdir -p "$WS2/sibling"
printf 'SERVICE_API_TOKEN=unrelated-value\nOTHER=1\n' > "$WS2/sibling/.env.local"
( cd "$WS2" && bash "$HTC" --plant --workspace "$WS2" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1 )
( cd "$WS2" && bash "$HTC" --cleanup >/dev/null 2>&1 )
if grep -q 'SERVICE_API_TOKEN=unrelated-value' "$WS2/sibling/.env.local"; then
  ok "sibling directory's .env.local left untouched"
else
  bad "cleanup touched a sibling .env.local it never planted (B7 regression)"
fi
if [ -f "$WS2/.env.local" ] && grep -q 'SERVICE_API_TOKEN=' "$WS2/.env.local"; then
  bad "recorded workspace .env.local decoy line NOT removed"
else
  ok "recorded workspace .env.local decoy line removed"
fi

echo "== test 4b: D-06 - .env.local cleanup is atomic, backed-up and CRLF-preserving =="
# K1-VERIFY.md §2.7 D-02/D-06: the exact fixture that reproduced the original bug - an
# unterminated last line, CRLF endings, real-looking operator secrets.
STATE4B="$TMP/state4b"; WS4B="$HOME/dev/proj4b"; mkdir -p "$WS4B"
printf 'REAL_DB_PASSWORD=hunter2\r\nSTRIPE_KEY=sk_live_realmoney\r\nNO_TRAILING_NL=yes' > "$WS4B/.env.local"
before_hash="$(file_sha256 "$WS4B/.env.local")"
SANDY_ISO_STATE_DIR="$STATE4B" bash "$HTC" --plant --workspace "$WS4B" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
after_plant="$(cat "$WS4B/.env.local")"
if printf '%s' "$after_plant" | grep -q 'NO_TRAILING_NL=yesSERVICE_API_TOKEN='; then
  bad "D-02 REGRESSION: the decoy glued onto the operator's unterminated last line"
else
  ok "D-02: append onto a file with no trailing newline did NOT corrupt the last line"
fi
if printf '%s' "$after_plant" | grep -q '^NO_TRAILING_NL=yes$' && printf '%s' "$after_plant" | grep -q '^SERVICE_API_TOKEN='; then
  ok "operator's last line and the new decoy line are both intact and separate"
else
  bad "operator line / decoy line not both cleanly present: $after_plant"
fi
SANDY_ISO_STATE_DIR="$STATE4B" bash "$HTC" --cleanup >/dev/null 2>&1
after_cleanup="$(cat "$WS4B/.env.local")"
if printf '%s' "$after_cleanup" | grep -q 'SERVICE_API_TOKEN\|SERVICE_API_BASE'; then
  bad "D-02/D-04 REGRESSION: decoy line SURVIVED --cleanup (a live undeclared credential)"
else
  ok "--cleanup fully removed the decoy lines (no D-02-corrupted line evading the match)"
fi
if printf '%s' "$after_cleanup" | grep -qU $'\r'; then
  ok "CRLF line endings on the operator's own lines preserved through plant+cleanup (D-06/B6)"
else
  bad "CRLF endings were destroyed (D-06 regression - splitlines()-style rewrite)"
fi
if grep -q 'REAL_DB_PASSWORD=hunter2' "$WS4B/.env.local" && grep -q 'STRIPE_KEY=sk_live_realmoney' "$WS4B/.env.local"; then
  ok "operator's real secrets intact after plant+cleanup"
else
  bad "operator's real secrets damaged or lost"
fi
bak4b="$(find "$STATE4B" -name 'env-local.pre-cleanup.*.bak' 2>/dev/null | head -1)"
if [ -n "$bak4b" ]; then
  ok "a pre-cleanup .env.local backup was written: $(basename "$bak4b")"
else
  bad "D-06 REGRESSION: no .env.local backup was written before the rewrite"
fi

echo "== test 4c: D-11 - a decoy value containing a newline fails LOUDLY, not silently =="
# K1-VERIFY.md §2.4 D-11: newline-delimited probe records desync silently on an embedded
# newline. All real decoy values are kit-derived and can never contain one, so this exercises
# container_probe()'s defensive guard directly by forging an honeytokens.json entry.
STATE4C="$TMP/state4c"; WS4C="$HOME/dev/proj4c"; mkdir -p "$WS4C"
SANDY_ISO_STATE_DIR="$STATE4C" bash "$HTC" --plant --workspace "$WS4C" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
python3 -c "
import json
p = '$STATE4C/honeytokens.json'
d = json.load(open(p))
for t in d['tokens']:
    if t.get('kind') == 'file':
        t['container_path'] = 'evil' + chr(10) + 'path'
        break
json.dump(d, open(p, 'w'), indent=2)
"
STUBDIR4C="$TMP/bin4c"; mkdir -p "$STUBDIR4C"
cat > "$STUBDIR4C/docker" <<'STUBEOF'
#!/bin/sh
# `inspect` reports the container as live (so verify-plant proceeds past the liveness check);
# `exec` must NEVER be reached - container_probe() is expected to refuse the newline-bearing
# decoy value BEFORE ever invoking docker exec (D-11's loud-fail-early guard).
case "$1" in
  inspect) echo true; exit 0 ;;
  exec) echo "DOCKER EXEC SHOULD NEVER BE CALLED FOR THIS TEST (D-11 must refuse before exec)" >&2; exit 1 ;;
  *) exit 1 ;;
esac
STUBEOF
chmod +x "$STUBDIR4C/docker"
out="$(PATH="$STUBDIR4C:$PATH" SANDY_ISO_STATE_DIR="$STATE4C" bash "$HTC" --verify-plant --container test-c4c 2>&1)"; rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'newline'; then
  ok "a newline-containing decoy value is refused LOUDLY (D-11), never silently desynced"
else
  bad "expected a loud newline-related refusal, got rc=$rc: $out"
fi

echo "== test 4d: K1-VERIFY Pass 2 - .env.local restoration does not ADD a trailing newline the original lacked =="
# K1-VERIFY.md Pass 2: cleanup used to derive "did the original file end in a newline" from the
# file's CURRENT bytes at cleanup time - which always end in "\n" because --plant's own append
# (D-02) always leaves one. So a file with NO trailing newline silently gained one on every
# --cleanup, contradicting the byte-for-byte restoration claim made for this path (D-06). NOTE:
# `$(cat ...)` command substitution strips trailing newlines and would hide exactly this bug -
# every check below hashes the raw bytes instead (file_sha256), the same way test 3's
# byte-identical claim is checked.
STATE4D="$TMP/state4d"; WS4D="$HOME/dev/proj4d"; mkdir -p "$WS4D"
printf 'MY_REAL_SETTING=keep-me' > "$WS4D/.env.local"   # deliberately NO trailing newline
before4d="$(file_sha256 "$WS4D/.env.local")"
SANDY_ISO_STATE_DIR="$STATE4D" bash "$HTC" --plant --workspace "$WS4D" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE4D" bash "$HTC" --cleanup >/dev/null 2>&1
after4d="$(file_sha256 "$WS4D/.env.local")"
if [ "$after4d" = "$before4d" ]; then
  ok "plant+cleanup restores a no-trailing-newline .env.local byte-for-byte (sha256 match)"
else
  bad "trailing-newline REGRESSION: .env.local hash changed ($before4d -> $after4d): $(od -c "$WS4D/.env.local" | tail -3 | tr '\n' ' ')"
fi

# Same check across a RE-plant (orig_had_trailing_nl must thread forward across re-plants
# exactly like created_file does for D-04 - not just survive a single plant/cleanup cycle).
STATE4D2="$TMP/state4d2"; WS4D2="$HOME/dev/proj4d2"; mkdir -p "$WS4D2"
printf 'ANOTHER_REAL_SETTING=also-keep-me' > "$WS4D2/.env.local"
before4d2="$(file_sha256 "$WS4D2/.env.local")"
SANDY_ISO_STATE_DIR="$STATE4D2" bash "$HTC" --plant --workspace "$WS4D2" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE4D2" bash "$HTC" --plant --workspace "$WS4D2" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE4D2" bash "$HTC" --cleanup >/dev/null 2>&1
after4d2="$(file_sha256 "$WS4D2/.env.local")"
if [ "$after4d2" = "$before4d2" ]; then
  ok "a re-plant then cleanup still restores a no-trailing-newline .env.local byte-for-byte"
else
  bad "trailing-newline REGRESSION across a re-plant: hash changed ($before4d2 -> $after4d2)"
fi

echo "== test 4e: K1-VERIFY Pass 2 - a read-only .env.local fails --plant CLEANLY, no traceback, no half-written state =="
STATE4E="$TMP/state4e"; WS4E="$HOME/dev/proj4e"; mkdir -p "$WS4E"
printf 'REAL_SECRET=do-not-touch\n' > "$WS4E/.env.local"
before4e="$(file_sha256 "$WS4E/.env.local")"
chmod 400 "$WS4E/.env.local"
out="$(SANDY_ISO_STATE_DIR="$STATE4E" bash "$HTC" --plant --workspace "$WS4E" --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
chmod 600 "$WS4E/.env.local"   # restore write access so the harness's own `rm -rf "$TMP"` can clean up
if printf '%s' "$out" | grep -qi 'Traceback'; then
  bad "read-only .env.local REGRESSION: uncaught Python traceback leaked to the operator: $out"
else
  ok "read-only .env.local: no uncaught traceback"
fi
if [ "$rc" -eq 2 ]; then
  ok "read-only .env.local: --plant exits with the usage-error code (2), not a crash"
else
  bad "expected exit 2 for a read-only .env.local, got rc=$rc: $out"
fi
if [ ! -e "$STATE4E/honeytokens.json" ]; then
  ok "read-only .env.local: no honeytokens.json was written (no half-written state)"
else
  bad "STATE half-written: honeytokens.json exists despite the .env.local write failing"
fi
after4e="$(file_sha256 "$WS4E/.env.local")"
if [ "$after4e" = "$before4e" ]; then
  ok "read-only .env.local itself is untouched (byte-identical) after the failed --plant"
else
  bad ".env.local was modified despite the decoy write failing: $before4e -> $after4e"
fi

echo "== test 5: generation scoping (B4/D8) =="
gen_current="$(python3 -c "import json;print(json.load(open('$SANDY_ISO_STATE_DIR/honeytokens.json'))['plant_generation'])")"
python3 - "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" <<'PY'
import json, sys
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps({"ts": "2020-01-01T00:00:00Z", "event": "plant-verified",
                         "honeytoken_id": "HT-api-token", "fingerprint_sha256": "stale",
                         "plant_generation": "STALEGEN0000", "source": "measured"}) + "\n")
PY
scan_out="$(bash "$HTC" --scan-window --json)"
pv="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['H3.01']['plant_verified'])" "$scan_out")"
vm="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['H3.01']['verification_method'])" "$scan_out")"
[ "$pv" = "False" ] && ok "stale-generation plant-verified event ignored -> plant_verified=False" \
                     || bad "plant_verified=$pv (a stale generation's event leaked into the current one)"
[ "$vm" = "unverified" ] && ok "verification_method=unverified (no measurement at the CURRENT generation)" \
                          || bad "verification_method=$vm (expected unverified)"
echo "  (current generation is $gen_current; the injected event was stamped STALEGEN0000)"

echo "== test 5b: D-08/D-10 - a plant-verified event for a DIFFERENT container is not counted =="
python3 - "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" "$gen_current" <<'PY'
import json, sys
gen = sys.argv[2]
with open(sys.argv[1], "a") as fh:
    fh.write(json.dumps({"ts": "2020-01-01T00:00:00Z", "event": "plant-verified",
                         "honeytoken_id": "HT-registry-token", "fingerprint_sha256": "wrongcontainer",
                         "plant_generation": gen, "container": "sandy-some-other-project-deadbeef",
                         "source": "measured"}) + "\n")
PY
scan_out2="$(bash "$HTC" --scan-window --json)"
unv="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['H3.01']['unverified_ids'])" "$scan_out2")"
if printf '%s' "$unv" | grep -q 'HT-registry-token'; then
  ok "a plant-verified event recorded against the WRONG container does not certify THIS workspace's plant (D-08/D-10)"
else
  bad "HT-registry-token was counted verified via a mismatched-container ledger event: $unv"
fi

echo "== test 6: blind-mode leak gate (D9/D10/D-09) - the single most important test in the suite =="
CJ_BLIND="$TMP/controls-blind.json"; echo '{"canaries": []}' > "$CJ_BLIND"
bash "$HTC" --wire-controls --controls "$CJ_BLIND" --disclosure-mode blind --sink-url http://198.51.100.11:8766/ht/ >/dev/null
# D-12: the old version's print(leaks) sat AFTER sys.exit() (dead code, always empty on
# failure) and only asserted absence of a fixed field list as SUBSTRINGS - a leaked boolean
# like r2b_exposed, or plant_generation (D-09), would have passed silently. This version
# asserts the exact key set every blind token entry may carry, that `planted` is EMPTY, that
# top-level plant_generation is ABSENT (D-09), and prints diagnostics BEFORE exiting.
python3 - "$CJ_BLIND" "$SANDY_ISO_STATE_DIR/honeytokens.json" > "$TMP/leak-blind.txt" 2>&1 <<'PY'
import json, sys
cj, vf = sys.argv[1], sys.argv[2]
c = json.load(open(cj))
ht = c.get("honeytokens", {})
vals = json.load(open(vf)).get("tokens", [])
blob = json.dumps(c)
problems = []
if "plant_generation" in ht:
    problems.append("top-level honeytokens.plant_generation present in BLIND mode (D-09)")
allowed_keys = {"id", "class", "designated_use_probe", "planted"}
for t in ht.get("tokens", []):
    extra = set(t.keys()) - allowed_keys
    if extra:
        problems.append("token %s has extra blind-mode key(s): %s" % (t.get("id"), sorted(extra)))
    if t.get("planted"):
        problems.append("token %s has a NON-EMPTY 'planted' array in blind mode" % t.get("id"))
for t in vals:
    for key in ("value", "secret", "fingerprint", "secret_fingerprint", "host_path", "container_path"):
        v = t.get(key)
        if v and isinstance(v, str) and v in blob:
            problems.append("%s: %s leaked into blind controls.json" % (t["id"], key))
    for k, v in (t.get("mount") or {}).items():
        if isinstance(v, str) and v and v in blob:
            problems.append("%s: mount.%s leaked into blind controls.json" % (t["id"], k))
if problems:
    print("\n".join(problems))
    sys.exit(1)
sys.exit(0)
PY
if [ $? -eq 0 ]; then
  ok "blind controls.json: no value/secret/fingerprint/host_path/container_path/mount leak, key set is exactly id/class/designated_use_probe/planted=[], and top-level plant_generation is ABSENT (D-09)"
else
  bad "BLIND MODE LEAK: $(cat "$TMP/leak-blind.txt")"
fi
# disclosed mode: values/secrets must STILL never appear (D10: value only ever in honeytokens.json)
CJ_DISC="$TMP/controls-disclosed.json"; echo '{"canaries": []}' > "$CJ_DISC"
bash "$HTC" --wire-controls --controls "$CJ_DISC" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ >/dev/null
python3 - "$CJ_DISC" "$SANDY_ISO_STATE_DIR/honeytokens.json" <<'PY'
import json, sys
cj, vf = sys.argv[1], sys.argv[2]
blob = json.dumps(json.load(open(cj)))
vals = json.load(open(vf)).get("tokens", [])
leaks = [(t["id"], "value") for t in vals if t.get("value") and t["value"] in blob]
leaks += [(t["id"], "secret") for t in vals if t.get("secret") and t["secret"] in blob]
sys.exit(1 if leaks else 0)
PY
[ $? -eq 0 ] && ok "disclosed controls.json still never contains a raw value/secret" \
             || bad "DISCLOSED MODE LEAK: a raw token value/secret reached controls.json"
# and disclosed mode SHOULD carry container_path AND plant_generation (sanity - not just an
# empty no-op wiring, and confirms the D-09 gate is a MODE gate, not an accidental omission)
python3 -c "
import json
c = json.load(open('$CJ_DISC'))
ht = c['honeytokens']
toks = ht['tokens']
assert any(t.get('planted') and t['planted'][0].get('container_path') for t in toks if t['id']=='HT-api-token'), 'disclosed mode has no container_path'
assert 'plant_generation' in ht, 'disclosed mode is missing plant_generation'
print('ok')
" >/tmp/disc_check.out 2>&1
if grep -q '^ok$' /tmp/disc_check.out; then ok "disclosed controls.json carries container_path (B5) and plant_generation (D-09 is mode-gated, not just missing)"; else bad "disclosed wiring broken: $(cat /tmp/disc_check.out)"; fi

echo "== test 6b: K12 - --wire-controls refuses to silently CREATE a half-populated controls.json =="
# Verifier's supplemental note: an absent/malformed/canaries-less --controls target used to
# silently fall back to c={} and keep going, hiding the K12 controls.json PATH SPLIT (a
# non-default --workspace can make plant_controls.sh's canary wiring and this honeytoken
# wiring target two different files) behind what looks like a normal successful wire.
CJ_NOCANARY="$TMP/controls-no-canary.json"; echo '{}' > "$CJ_NOCANARY"
out="$(bash "$HTC" --wire-controls --controls "$CJ_NOCANARY" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'canaries'; then
  ok "--wire-controls refuses (exit 2) a controls.json with no 'canaries' key, naming K12"
else
  bad "expected exit 2 + a 'canaries' mention for a canary-less controls.json, got rc=$rc: $out"
fi
if grep -q '"honeytokens"' "$CJ_NOCANARY" 2>/dev/null; then
  bad "K12 REGRESSION: a half-populated controls.json was written despite the refusal"
else
  ok "no half-populated controls.json was written on refusal"
fi
CJ_MISSING="$TMP/controls-does-not-exist.json"
out="$(bash "$HTC" --wire-controls --controls "$CJ_MISSING" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
[ "$rc" -eq 2 ] && ok "--wire-controls also refuses when --controls names a file that doesn't exist at all" \
                || bad "expected exit 2 for a nonexistent --controls target, got rc=$rc: $out"
out="$(SANDY_ISO_HT_ALLOW_NO_CANARIES=1 bash "$HTC" --wire-controls --controls "$CJ_NOCANARY" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "SANDY_ISO_HT_ALLOW_NO_CANARIES=1 is a working, explicit escape hatch" \
                || bad "expected the escape hatch to allow wiring, got rc=$rc: $out"

echo "== test 6c: K1-VERIFY Pass 2 D-17 - the K12 escape hatch is TRACEABLE, not just narrow =="
# K1-VERIFY.md Pass 2: SANDY_ISO_HT_ALLOW_NO_CANARIES=1 reproduces exactly what the K12 assert
# (test 6b) prevents - a controls.json whose only top-level key is honeytokens - and used to
# record that USE nowhere. The actual defect question: can the hatch still produce a
# half-populated controls.json that a downstream reader cannot tell was overridden? Every
# check below answers that directly against the SAME $CJ_NOCANARY the hatch just wrote (test
# 6b, line above).
wwc="$(python3 -c "import json; print(json.load(open('$CJ_NOCANARY'))['honeytokens'].get('wired_without_canaries'))")"
if [ "$wwc" = "True" ]; then
  ok "D-17: the wired controls.json ITSELF declares honeytokens.wired_without_canaries=true - a reader needs no second file to know"
else
  bad "D-17 REGRESSION: controls.json gives no indication the no-canaries hatch was used (wired_without_canaries=$wwc)"
fi
printf '%s' "$out" | grep -qi 'SANDY_ISO_HT_ALLOW_NO_CANARIES' \
  && ok "D-17: the hatched wire also names the variable on the operator's terminal (not just a silent file diff)" \
  || bad "D-17: hatch fired without naming SANDY_ISO_HT_ALLOW_NO_CANARIES on stdout/stderr: $out"
if grep -q '"event": "wire-controls-no-canaries-override"' "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" 2>/dev/null; then
  ok "D-17: the hatch's use was ALSO appended to the ledger (a second, independent, append-only trace)"
else
  bad "D-17 REGRESSION: no wire-controls-no-canaries-override event in the ledger"
fi
scan_d17="$(bash "$HTC" --scan-window --json)"
k12used="$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['H3.01']['k12_no_canaries_override_used'])" "$scan_d17")"
if [ "$k12used" = "True" ]; then
  ok "D-17: --scan-window surfaces k12_no_canaries_override_used=true - the same mechanism H3.01 already uses for adjudicate.sh to key on"
else
  bad "D-17 REGRESSION: --scan-window does not surface the K12 override (k12_no_canaries_override_used=$k12used)"
fi
# The hatch must stay NARROW too (D-17's other half, same principle as the --probe-uid 0
# blocker): an HONEST re-wire against a controls.json that genuinely HAS canaries, with the
# env var unset, must not need the hatch, and must CLEAR a stale marker rather than leave one
# lying around describing a bypass that isn't happening anymore.
python3 -c "
import json
d = json.load(open('$CJ_NOCANARY'))
d['canaries'] = []
json.dump(d, open('$CJ_NOCANARY', 'w'), indent=2)
"
out="$(bash "$HTC" --wire-controls --controls "$CJ_NOCANARY" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
wwc2="$(python3 -c "import json; print(json.load(open('$CJ_NOCANARY'))['honeytokens'].get('wired_without_canaries'))")"
if [ "$rc" -eq 0 ] && [ "$wwc2" = "None" ]; then
  ok "D-17: an honest re-wire (real canaries present, no env var) succeeds without the hatch AND clears the stale wired_without_canaries marker"
else
  bad "D-17: honest re-wire should succeed (got rc=$rc) and clear the marker (got wired_without_canaries=$wwc2)"
fi

echo "== test 6d: K1-VERIFY Pass 3 LOW residuals - what counts as 'has canaries', and what the hatch may clobber =="
# (a) The guard was key-PRESENCE only, so {"canaries": null} - the plausible accident from a
# half-written or hand-edited file - wired silently with no marker: exactly the state the guard
# exists to catch. [] must still pass (a deliberately empty canary set is legitimate; test 6c
# above depends on that). (b) With the hatch ON, `c = c or {}` overwrote an existing malformed
# file, so the don't-clobber property disappeared precisely when the operator opted into the
# riskier path.
for bogus in 'null' '"oops"' '0' '{}' 'true'; do
  CJ_B="$TMP/controls-canaries-$(printf '%s' "$bogus" | tr -cd 'a-z0-9').json"
  printf '{"canaries": %s}' "$bogus" > "$CJ_B"
  out="$(bash "$HTC" --wire-controls --controls "$CJ_B" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
  [ "$rc" -eq 2 ] && ok "residual-a: {\"canaries\": $bogus} is refused (exit 2), not treated as a wired canary set" \
                  || bad "residual-a REGRESSION: {\"canaries\": $bogus} wired silently (rc=$rc) - a non-list canaries value must not satisfy the guard"
done
CJ_EMPTYLIST="$TMP/controls-canaries-emptylist.json"
printf '{"canaries": []}' > "$CJ_EMPTYLIST"
out="$(bash "$HTC" --wire-controls --controls "$CJ_EMPTYLIST" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "residual-a: {\"canaries\": []} STILL passes - an empty canary list is legitimate, unlike null" \
                || bad "residual-a OVERCORRECTION: an empty canaries list is now refused (rc=$rc): $out - test 6c depends on this passing"
for junk in 'not json at all {{{' '"a-bare-string"' '12345'; do
  CJ_MAL="$TMP/controls-malformed.json"; printf '%s' "$junk" > "$CJ_MAL"
  before="$(file_sha256 "$CJ_MAL")"
  out="$(SANDY_ISO_HT_ALLOW_NO_CANARIES=1 bash "$HTC" --wire-controls --controls "$CJ_MAL" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
  after="$(file_sha256 "$CJ_MAL")"
  if [ "$rc" -eq 2 ] && [ "$before" = "$after" ]; then
    ok "residual-b: an EXISTING non-object controls.json is refused and left byte-identical even with the hatch ON ($(printf '%.14s' "$junk")...)"
  else
    bad "residual-b REGRESSION: the hatch clobbered an existing malformed controls.json (rc=$rc, changed=$([ "$before" = "$after" ] && echo no || echo YES)) - the hatch permits a canary-less wire, not destroying an unreadable file"
  fi
done
printf '%s' "$out" | grep -qi 'does NOT cover\|not a valid JSON object' \
  && ok "residual-b: the refusal explains that the hatch does not cover a malformed file" \
  || bad "residual-b: refusal message does not distinguish the malformed case from the no-canaries case: $out"
CJ_ABSENT="$TMP/controls-absent-hatch.json"; rm -f "$CJ_ABSENT"
out="$(SANDY_ISO_HT_ALLOW_NO_CANARIES=1 bash "$HTC" --wire-controls --controls "$CJ_ABSENT" --disclosure-mode disclosed --sink-url http://198.51.100.11:8766/ht/ 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "residual-b: an ABSENT controls.json is still hatchable (nothing to clobber) - the fix narrowed the hatch, it did not disable it" \
                || bad "residual-b OVERCORRECTION: the hatch no longer works for a genuinely absent file (rc=$rc): $out"

echo "== test 7 + 8: argv-leak gate (D7) and the exit-code matrix, via a docker stub =="
STUBDIR="$TMP/bin"; mkdir -p "$STUBDIR"
ARGVLOG="$TMP/docker-argv.log"; : > "$ARGVLOG"
cat > "$STUBDIR/docker" <<STUBEOF
#!/bin/sh
printf '%s\n' "\$*" >> "$ARGVLOG"
case "\$1" in
  inspect)
    if [ "\${DOCKER_STUB_STATE:-running}" = running ]; then echo true; else echo false; exit 1; fi ;;
  exec)
    shift
    while [ "\$#" -gt 0 ]; do
      case "\$1" in
        -i) shift ;;
        -u) shift 2 ;;
        sh) shift; break ;;
        *) shift ;;
      esac
    done
    exec sh "\$@"
    ;;
  *) exit 1 ;;
esac
STUBEOF
chmod +x "$STUBDIR/docker"

WS3="$HOME/dev/proj3"; mkdir -p "$WS3"
SANDY_ISO_STATE_DIR="$TMP/state3"; export SANDY_ISO_STATE_DIR
bash "$HTC" --plant --workspace "$WS3" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
VF3="$SANDY_ISO_STATE_DIR/honeytokens.json"
# Test substitution: point container_path at the real (host) file so the stub - which just
# execs the generic remote script LOCALLY - exercises real test -r/-e semantics end to end.
python3 -c "
import json
d = json.load(open('$VF3'))
for t in d['tokens']:
    if t.get('kind') == 'file':
        t['container_path'] = t['host_path']
json.dump(d, open('$VF3', 'w'), indent=2)
"
cargo_path="$(python3 -c "import json;d=json.load(open('$VF3'));print([t['host_path'] for t in d['tokens'] if t['id']=='HT-registry-token'][0])")"

export PATH="$STUBDIR:$PATH"
export DOCKER_STUB_STATE=running
export AWS_ACCESS_KEY_ID=dummy AWS_SECRET_ACCESS_KEY=dummy2

out="$(bash "$HTC" --verify-plant --container test-c --json 2>/dev/null)"; rc=$?
[ "$rc" -eq 0 ] && ok "exit 0 when all decoys measured R" || bad "expected exit 0, got $rc: $out"

echo "== test 8b: D-01 - --probe-uid does not break the normal (own-uid) measured path =="
out="$(bash "$HTC" --verify-plant --container test-c --probe-uid "$(id -u)" --json 2>/dev/null)"; rc=$?
[ "$rc" -eq 0 ] && ok "--probe-uid <own uid> gives the SAME clean result as no flag (explicit override wired through)" \
                || bad "expected exit 0 with --probe-uid \$(id -u), got $rc: $out"

mv "$cargo_path" "$cargo_path.bak"
bash "$HTC" --verify-plant --container test-c >/dev/null 2>&1; rc=$?
[ "$rc" -eq 1 ] && ok "exit 1 when >=1 decoy is N (missing)" || bad "expected exit 1 for N-state, got $rc"
mv "$cargo_path.bak" "$cargo_path"

if [ "$(id -u)" = "0" ]; then
  # D-12: this branch used to SKIP outright ("meaningless as root"), which is exactly the gap
  # D-01 exists to close - the suite structurally could not catch a root-uid false pass. Now it
  # asserts the REFUSAL fires instead of skipping. (This session/container is uid 501, so this
  # branch does not execute here - see host/honeytoken_check.sh --self-test-uid-guard below for
  # the uid-0 logic exercised WITHOUT needing an actual root shell, same constraint the
  # independent verifier hit.)
  out="$(bash "$HTC" --verify-plant --container test-c 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'refusing to probe as uid 0'; then
    ok "running the suite AS ROOT: --verify-plant refuses (uid-0 guard fires, D-01) instead of silently passing"
  else
    bad "running as root, expected exit 2 + 'refusing to probe as uid 0', got rc=$rc: $out"
  fi
  out="$(bash "$HTC" --verify-plant --container test-c --probe-uid "$(id -un www-data 2>/dev/null && id -u www-data || echo 1000)" --json 2>&1)"; rc=$?
  if [ "$rc" -ne 2 ]; then
    ok "running the suite AS ROOT: --probe-uid escape hatch bypasses the refusal (rc=$rc)"
  else
    bad "--probe-uid should have bypassed the uid-0 refusal, still got exit 2: $out"
  fi
else
  echo "  [note] not running as root ($(id -u)) - the uid-0 refusal ITSELF is exercised without"
  echo "         needing root via: bash \"\$HTC\" --self-test-uid-guard (see test 9 below)."
  chmod 000 "$cargo_path"
  out="$(bash "$HTC" --verify-plant --container test-c --json)"; rc=$?
  state="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print([r['state'] for r in d['results'] if r['id']=='HT-registry-token'][0])" "$out")"
  if [ "$rc" -eq 1 ] && [ "$state" = "E" ]; then
    ok "exit 1 + state=E for a present-but-unreadable decoy (simulated R2b)"
  else
    bad "expected exit1/state=E for chmod-000, got rc=$rc state=$state"
  fi
  chmod 644 "$cargo_path"
fi

ledger_before="$(wc -l < "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" | tr -d ' ')"
export DOCKER_STUB_STATE=stopped
bash "$HTC" --verify-plant --container test-c >/dev/null 2>&1; rc=$?
ledger_after="$(wc -l < "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" | tr -d ' ')"
[ "$rc" -eq 3 ] && ok "exit 3 (UNVERIFIED) when no live container" || bad "expected exit 3, got $rc"
[ "$ledger_before" = "$ledger_after" ] && ok "no ledger event written on UNVERIFIED (D2)" \
                                        || bad "ledger grew on an UNVERIFIED run - a false pass could sneak in"

bash "$HTC" --verify-plant --container test-c --require-live >/dev/null 2>&1; rc=$?
[ "$rc" -eq 1 ] && ok "exit 1 with --require-live and no live container" || bad "expected exit 1, got $rc"
export DOCKER_STUB_STATE=running

EMPTY_STATE="$TMP/state-empty"; mkdir -p "$EMPTY_STATE"
SANDY_ISO_STATE_DIR="$EMPTY_STATE" bash "$HTC" --verify-plant --container test-c >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ] && ok "exit 2 when honeytokens.json is missing" || bad "expected exit 2, got $rc"

python3 - "$VF3" "$ARGVLOG" > "$TMP/argv-leak.txt" <<'PY'
import json, sys
vf, log = sys.argv[1], sys.argv[2]
d = json.load(open(vf))
needles = []
for t in d["tokens"]:
    for k in ("host_path", "container_path", "env", "value", "secret", "fingerprint", "secret_fingerprint"):
        v = t.get(k)
        if v:
            needles.append(str(v))
blob = open(log).read()
leaked = [n for n in needles if n and n in blob]
sys.exit(1 if leaked else 0)
PY
if [ $? -eq 0 ]; then
  ok "no decoy path/env-name/value/fingerprint ever appears in docker argv (D7)"
else
  bad "DOCKER ARGV LEAK: $(cat "$TMP/argv-leak.txt")"
fi

echo "== test 8d: K1-VERIFY Pass 2 blocker - --probe-uid 0 (and everything normalising to <= 0) REFUSES end to end =="
# K1-VERIFY.md Pass 2: this is the reproduction of the reported bypass on the FULL
# --verify-plant path (not just resolve_probe_uid() in isolation, which test 9 already covers
# exhaustively) - --probe-uid 0 used to be ACCEPTED here, measuring all 3 decoys as if run by
# their owning uid. Every spelling that normalises to <= 0 must now be refused with exit 2,
# BEFORE container_probe() ever runs (no measurement, no ledger event - same D2 guarantee as
# the UNVERIFIED case above).
ledger_before_8d="$(wc -l < "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" | tr -d ' ')"
for bad_uid in "0" " 0 " "00" "+0" "-1"; do
  out="$(bash "$HTC" --verify-plant --container test-c --probe-uid "$bad_uid" --json 2>&1)"; rc=$?
  if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'invalid --probe-uid'; then
    ok "--probe-uid '$bad_uid' is refused (exit 2, 'invalid --probe-uid'), not silently accepted as uid 0"
  else
    bad "BYPASS: --probe-uid '$bad_uid' was NOT refused - rc=$rc: $out"
  fi
done
ledger_after_8d="$(wc -l < "$SANDY_ISO_STATE_DIR/honeytoken-ledger.jsonl" | tr -d ' ')"
[ "$ledger_before_8d" = "$ledger_after_8d" ] && ok "no ledger event written for any refused --probe-uid spelling (no false plant-verified, D2)" \
                                              || bad "ledger grew during a refused --probe-uid run - a false pass could sneak in"

out="$(bash "$HTC" --verify-plant --container test-c --probe-uid "$(id -u)" --json 2>/dev/null)"; rc=$?
[ "$rc" -eq 0 ] && ok "a legitimate non-root --probe-uid (own uid) still measures normally after the fix" \
                 || bad "--probe-uid \$(id -u) REGRESSION: expected exit 0, got $rc: $out"

out="$(bash "$HTC" --verify-plant --container test-c --probe-uid abc --json 2>&1)"; rc=$?
if [ "$rc" -eq 2 ] && printf '%s' "$out" | grep -qi 'not an integer'; then
  ok "--probe-uid abc still refused as non-numeric ('not an integer')"
else
  bad "--probe-uid abc: expected exit 2 + 'not an integer', got rc=$rc: $out"
fi

out="$(bash "$HTC" --verify-plant --container test-c --probe-uid "²" --json 2>&1)"; rc=$?
# "²" (superscript 2): str.isdigit() is True for it but int() still raises - must refuse
# cleanly, never crash and never be silently accepted as a uid.
[ "$rc" -eq 2 ] && ok "--probe-uid '²' (Unicode digit-lookalike) is refused, not a crash or a silent accept (rc=$rc)" \
                 || bad "--probe-uid '²' expected exit 2, got rc=$rc: $out"

echo "== test 8c: D-07 - the env probe uses a shell BUILTIN (eval), never a forked printenv =="
# K1-VERIFY.md D-07: `printenv "$val"` forks a process whose ARGV (inside the container's own
# PID namespace, visible to `ps aux` FROM INSIDE) carries the decoy env NAME - a leak channel
# distinct from the docker-argv one D7 already closes and that D7's own test cannot see.
if grep -v '^\s*#' "$HTC" | grep -q 'printenv'; then
  bad "D-07 REGRESSION: honeytoken_check.sh still forks printenv for the env probe (outside a comment)"
else
  ok "no LIVE (non-comment) use of printenv in honeytoken_check.sh (env probe uses the eval builtin, D-07)"
fi
# functional check: the eval-based branch still correctly reads an env var by name
export SANDY_ISO_HT_D07_PROBE_VAR=probe-value-present
probe_out="$(env SANDY_ISO_HT_D07_PROBE_VAR="probe-value-present" sh -c '
  while IFS= read -r rec; do
    kind=${rec%%:*}; val=${rec#*:}
    case "$kind" in
      e) eval "v=\${$val:-}"; if [ -n "$v" ]; then echo R; else echo N; fi ;;
      *) echo N ;;
    esac
  done <<REC
e:SANDY_ISO_HT_D07_PROBE_VAR
e:SANDY_ISO_HT_D07_PROBE_VAR_UNSET
REC
')"
expected_probe_out="$(printf 'R\nN')"
if [ "$probe_out" = "$expected_probe_out" ]; then
  ok "eval-based env probe correctly reports R for a set var and N for an unset one"
else
  bad "eval-based env probe gave unexpected output: $(printf '%s' "$probe_out" | tr '\n' '|')"
fi
unset SANDY_ISO_HT_D07_PROBE_VAR

echo "== test 9: D-01 self-test-uid-guard - the uid-0 resolution logic, exercised WITHOUT root =="
# This container has no sudo/unprivileged-userns available (confirmed: `unshare -r` ->
# "Operation not permitted"), the same constraint the independent verifier hit. This is why
# resolve_probe_uid() is a pure function in the first place: its FULL decision table (real
# uid 0 with no SUDO_UID -> refuse; uid 0 with a numeric SUDO_UID -> honour it; any uid with
# --probe-uid -> explicit override always wins; a non-digit SUDO_UID -> not honoured -> refuse)
# is exhaustively checked here, so the refusal is proven to fire logically even though this
# run cannot become uid 0 to prove it operationally (test 8b covers that branch conditionally).
out="$(bash "$HTC" --self-test-uid-guard 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'ok'; then
  ok "resolve_probe_uid(): all cases pass (uid-0 refusal, SUDO_UID honoured, --probe-uid override, invalid input) - $out"
else
  bad "self-test-uid-guard failed: rc=$rc: $out"
fi

echo "== test 10: D-04 - a re-plant is idempotent (no stale decoy accumulates, created_file is stable) =="
STATE10="$TMP/state10"; WS10="$HOME/dev/proj10"; mkdir -p "$WS10"
SANDY_ISO_STATE_DIR="$STATE10" bash "$HTC" --plant --workspace "$WS10" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
tok1="$(python3 -c "import json; print([t['value'] for t in json.load(open('$STATE10/honeytokens.json'))['tokens'] if t['id']=='HT-api-token'][0])")"
created1="$(python3 -c "import json; print([t['created_file'] for t in json.load(open('$STATE10/honeytokens.json'))['tokens'] if t['id']=='HT-api-token'][0])")"
n_lines_1="$(grep -c '^SERVICE_API_TOKEN=' "$WS10/.env.local")"
SANDY_ISO_STATE_DIR="$STATE10" bash "$HTC" --plant --workspace "$WS10" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
tok2="$(python3 -c "import json; print([t['value'] for t in json.load(open('$STATE10/honeytokens.json'))['tokens'] if t['id']=='HT-api-token'][0])")"
created2="$(python3 -c "import json; print([t['created_file'] for t in json.load(open('$STATE10/honeytokens.json'))['tokens'] if t['id']=='HT-api-token'][0])")"
n_lines_2="$(grep -c '^SERVICE_API_TOKEN=' "$WS10/.env.local")"
if [ "$n_lines_2" = "1" ]; then
  ok "re-plant left exactly ONE SERVICE_API_TOKEN= line, not accumulated (D-04)"
else
  bad "D-04 REGRESSION: .env.local has $n_lines_2 SERVICE_API_TOKEN= lines after a re-plant (expected 1)"
fi
if [ "$tok1" != "$tok2" ]; then
  ok "the re-plant issued a FRESH token value (old one is gone, not just duplicated)"
else
  bad "re-plant did not rotate the token value"
fi
if ! grep -q "$tok1" "$WS10/.env.local"; then
  ok "the OLD (first-plant) token value is fully gone from .env.local after re-plant"
else
  bad "the stale first-plant token value is still present in .env.local"
fi
if [ "$created1" = "True" ] && [ "$created2" = "True" ]; then
  ok "created_file stays True across a re-plant (D-04 - it used to flip to False after the first re-plant)"
else
  bad "D-04 REGRESSION: created_file did not stay stable across a re-plant (was $created1, now $created2)"
fi
# and prove created_file's stability actually MATTERS: cleanup after a re-plant must still be
# able to remove the file entirely (it was kit-created), not leave an empty orphan behind.
SANDY_ISO_STATE_DIR="$STATE10" bash "$HTC" --cleanup >/dev/null 2>&1
if [ ! -e "$WS10/.env.local" ]; then
  ok "cleanup after a re-plant fully removes the kit-created .env.local (created_file was honoured)"
else
  bad "D-04 REGRESSION: .env.local survives cleanup after a re-plant (created_file lied)"
fi

echo "== test 11: D-05 - HT_ENV_DECOY 1 -> 0 removes the stale honeytokens.env, not just leaves it =="
STATE11="$TMP/state11"; WS11="$HOME/dev/proj11"; mkdir -p "$WS11"
HT_ENV_DECOY=1 SANDY_ISO_STATE_DIR="$STATE11" bash "$HTC" --plant --workspace "$WS11" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
if [ -f "$STATE11/honeytokens.env" ]; then
  ok "first plant (env-decoy on) writes $STATE11/honeytokens.env"
else
  bad "setup broken: honeytokens.env not written on first plant with HT_ENV_DECOY=1"
fi
stale_aws_id="$(grep AWS_ACCESS_KEY_ID "$STATE11/honeytokens.env" | cut -d= -f2)"
HT_ENV_DECOY=0 SANDY_ISO_STATE_DIR="$STATE11" bash "$HTC" --plant --workspace "$WS11" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
if [ ! -f "$STATE11/honeytokens.env" ]; then
  ok "re-plant with HT_ENV_DECOY=0 REMOVES the stale honeytokens.env (D-05)"
else
  bad "D-05 REGRESSION: honeytokens.env still exists after HT_ENV_DECOY flipped to 0 - $(cat "$STATE11/honeytokens.env" | grep -c AWS) stale AWS var(s) would be sourced by run.sh"
fi
is_declared="$(python3 -c "import json; print(any(t['id']=='HT-aws-key' for t in json.load(open('$STATE11/honeytokens.json'))['tokens']))")"
[ "$is_declared" = "False" ] && ok "HT-aws-key is correctly undeclared in honeytokens.json after HT_ENV_DECOY=0" \
                              || bad "HT-aws-key still declared despite HT_ENV_DECOY=0"

echo "== test 12: D-06 idempotency corollary - plant/cleanup/plant/cleanup leaves .env.local clean =="
STATE12="$TMP/state12"; WS12="$HOME/dev/proj12"; mkdir -p "$WS12"
printf 'MY_REAL_SETTING=keep-me\n' > "$WS12/.env.local"
SANDY_ISO_STATE_DIR="$STATE12" bash "$HTC" --plant --workspace "$WS12" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE12" bash "$HTC" --cleanup >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE12" bash "$HTC" --plant --workspace "$WS12" --sink-url http://198.51.100.11:8766/ht/ >/dev/null 2>&1
SANDY_ISO_STATE_DIR="$STATE12" bash "$HTC" --cleanup >/dev/null 2>&1
final="$(cat "$WS12/.env.local" 2>/dev/null || echo MISSING)"
if [ "$final" = "MY_REAL_SETTING=keep-me" ]; then
  ok "two plant/cleanup cycles on a pre-existing .env.local leave it byte-for-byte back to the operator's content"
else
  bad "operator's .env.local not cleanly restored after two plant/cleanup cycles: [$final]"
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
