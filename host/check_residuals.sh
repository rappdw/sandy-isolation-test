#!/usr/bin/env bash
# check_residuals.sh - K3 drift check: is testplan.json's pinned `residuals` registry still
# in sync with sandy's OWN "5. Residual risks (honest)" table in THREAT_MODEL.md?
#
# Why this exists: K3 (2026-08-02) added `residual_ref` mappings in testplan.json that quote
# sandy's THREAT_MODEL.md section 5 verbatim, so a matrix can say "this BREACHED confirms a
# residual sandy already conceded" instead of reading as a fresh defect. That mapping is a
# PRE-REGISTRATION (K3-PLAN.md Rule 2: the maintainer commits to the concession BEFORE seeing
# a run's outcome) - so when sandy's own document changes underneath it, the mapping must not
# silently keep claiming a concession sandy may have retracted, narrowed, or fixed. This
# script is the standalone pre-flight for that; `adjudicate.sh --sandy <path>` runs the same
# comparison inline, at adjudication time, and prints it in the run header.
#
# Row-level hashes, not a whole-document hash: hashing all of THREAT_MODEL.md would make
# every unrelated typo fix in section 7 trip "drift", the check would get ignored, and it
# would stop working. Hashing each normalized section-5 row makes drift per-residual and
# actionable - and uses the EXACT SAME normalization adjudicate.sh uses to grade a live run,
# so a `--sandy`-checked run and a standalone `check_residuals.sh` run never disagree.
#
# Usage:
#   check_residuals.sh [--sandy PATH] [--testplan PATH] [--json]
#   check_residuals.sh --sandy PATH --update      # rewrites row_sha256 in testplan.json,
#                                                  # prints the diff, and NOTHING ELSE - a new
#                                                  # or removed residual still needs a human
#                                                  # to hand-author title/status/status_class/
#                                                  # hardening_ref; --update never invents one.
#
# Exit: 0 registry in sync | 4 drift detected | 1 usage / IO / parse error.
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SANDY_PATH="./sandy"
TESTPLAN="$HERE/testplan.json"
UPDATE=0
AS_JSON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --sandy) SANDY_PATH="$2"; shift 2;;
    --testplan) TESTPLAN="$2"; shift 2;;
    --update) UPDATE=1; shift;;
    --json) AS_JSON=1; shift;;
    -h|--help) sed -n '1,25p' "$0"; exit 0;;
    *) echo "check_residuals.sh: unknown arg: $1" >&2; exit 1;;
  esac
done

TM_PATH="$SANDY_PATH/docs/security/THREAT_MODEL.md"
[ -f "$TM_PATH" ] || { echo "check_residuals.sh: no THREAT_MODEL.md at $TM_PATH (pass --sandy <path to a sandy checkout>)" >&2; exit 1; }
[ -f "$TESTPLAN" ] || { echo "check_residuals.sh: no testplan at $TESTPLAN" >&2; exit 1; }

exec python3 - "$TM_PATH" "$TESTPLAN" "$SANDY_PATH" "$UPDATE" "$AS_JSON" <<'PYEOF'
import json, os, re, sys, hashlib

TM_PATH, TESTPLAN, SANDY_PATH, UPDATE, AS_JSON = sys.argv[1:6]
UPDATE, AS_JSON = bool(int(UPDATE)), bool(int(AS_JSON))

RESIDUAL_IDS = ["R1", "R2", "R2b", "R2c", "R3", "R4", "R5", "R6", "R7"]


# ---- SAME normalization adjudicate.sh uses (residual_normalize_row/residual_row_sha256) -
# keep these two copies byte-identical; a divergence here would make a "--sandy"-checked run
# and a standalone check_residuals.sh run disagree about whether the registry is in sync.
def normalize_row(row):
    s = row.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    s = re.sub(r"[*`_]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s.lower()


def row_sha256(row):
    return hashlib.sha256(normalize_row(row).encode()).hexdigest()


def parse_residual_table(path):
    try:
        text = open(os.path.expanduser(path)).read()
    except OSError as exc:
        sys.stderr.write("check_residuals.sh: cannot read %s: %s\n" % (path, exc))
        sys.exit(1)
    in_section = False
    rows = {}
    for line in text.splitlines():
        if line.startswith("#"):
            in_section = bool(re.match(r"#+\s*5\.", line.strip()))
            continue
        if not in_section or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and re.fullmatch(r"R\d+[a-z]?", cells[0]):
            rows[cells[0]] = {"row": line, "row_sha256": row_sha256(line)}
    if not rows:
        sys.stderr.write("check_residuals.sh: found no '# | Residual | ...' rows under a "
                         "'5.' heading in %s - is this really THREAT_MODEL.md, and does it "
                         "still have a section 5?\n" % path)
        sys.exit(1)
    return rows


def sandy_version(sandy_path):
    try:
        text = open(os.path.join(os.path.expanduser(sandy_path), "sandy")).read()
    except OSError:
        return None
    m = re.search(r'^SANDY_VERSION="([^"]+)"', text, re.M)
    return m.group(1) if m else None


plan = json.load(open(TESTPLAN))
registry = plan.get("residuals") or {}
parsed = parse_residual_table(TM_PATH)

missing_from_doc = [rid for rid in RESIDUAL_IDS if rid in registry and rid not in parsed]
new_in_doc = [rid for rid in parsed if rid not in RESIDUAL_IDS]
changed = [rid for rid in RESIDUAL_IDS
           if rid in registry and rid in parsed
           and registry[rid].get("row_sha256") != parsed[rid]["row_sha256"]]
unpinned = [rid for rid in RESIDUAL_IDS if rid in parsed and rid not in registry]

drift = bool(missing_from_doc or new_in_doc or changed or unpinned)

report = {
    "sandy_path": SANDY_PATH, "threat_model": TM_PATH, "testplan": TESTPLAN,
    "sandy_version": sandy_version(SANDY_PATH),
    "residuals_parsed": sorted(parsed), "residuals_pinned": sorted(k for k in registry if k in RESIDUAL_IDS),
    "missing_from_doc": missing_from_doc, "new_in_doc": new_in_doc,
    "changed": changed, "unpinned": unpinned, "in_sync": not drift,
}

if AS_JSON:
    print(json.dumps(report, indent=2, sort_keys=True))
else:
    print("THREAT_MODEL.md : %s" % TM_PATH)
    print("sandy_version   : %s" % (report["sandy_version"] or "unknown (no SANDY_VERSION= line found)"))
    print("testplan        : %s (pinned_against_sandy_version=%s, pinned_at=%s)" % (
        TESTPLAN, registry.get("pinned_against_sandy_version", "?"), registry.get("pinned_at", "?")))
    print("residuals in doc (%d): %s" % (len(parsed), ", ".join(sorted(parsed))))
    if not drift:
        print("IN SYNC - all %d pinned residual rows match THREAT_MODEL.md section 5." % len(RESIDUAL_IDS))
    else:
        print("DRIFT DETECTED:")
        for rid in changed:
            print("  %s: section-5 row text changed since it was pinned" % rid)
            print("    was : %s" % registry[rid].get("row_sha256"))
            print("    now : %s" % parsed[rid]["row_sha256"])
            print("    row : %s" % parsed[rid]["row"].strip())
        for rid in missing_from_doc:
            print("  %s: pinned in testplan.json but NO LONGER PRESENT in THREAT_MODEL.md "
                 "section 5 - sandy may have retired or renumbered it" % rid)
        for rid in unpinned:
            print("  %s: present in THREAT_MODEL.md section 5 but NOT YET in testplan.json's "
                 "registry - run --update, then hand-author title/status_class/hardening_ref"
                 % rid)
            print("    row : %s" % parsed[rid]["row"].strip())
        for rid in new_in_doc:
            print("  %s: a residual id in THREAT_MODEL.md that is not in RESIDUAL_IDS=%s - "
                 "the enum in adjudicate.sh/testplan.json needs a maintainer decision before "
                 "this can be tracked" % (rid, RESIDUAL_IDS))
            print("    row : %s" % parsed[rid]["row"].strip())

if UPDATE:
    if not drift:
        print("\n--update: nothing to do, already in sync.")
    else:
        changes_applied = []
        for rid in changed + [r for r in unpinned if r in RESIDUAL_IDS]:
            old = (registry.get(rid) or {}).get("row_sha256")
            registry.setdefault(rid, {})["row_sha256"] = parsed[rid]["row_sha256"]
            changes_applied.append((rid, old, parsed[rid]["row_sha256"]))
        if changes_applied:
            plan["residuals"] = registry
            # D9 (K3-VERIFY.md): ensure_ascii=False so a re-pin does not rewrite every non-ASCII
            # character (e.g. section-sign "§") elsewhere in the file into a \uXXXX escape -
            # that turned one hash update into a dozen unrelated diff lines in a file whose
            # git-diff reviewability is Rule 2's entire argument. Write via a temp file + os.replace
            # so a failed/interrupted write cannot truncate testplan.json.
            _tmp = TESTPLAN + ".tmp"
            with open(_tmp, "w") as _fh:
                json.dump(plan, _fh, indent=2, ensure_ascii=False)
            os.replace(_tmp, TESTPLAN)
            print("\n--update: rewrote row_sha256 for %s in %s. REVIEW THIS DIFF (git diff "
                 "%s) before committing - a re-pin is a claim that the mapping's `scope` text "
                 "still describes what sandy's row says now:" % (
                     ", ".join(r for r, _o, _n in changes_applied), TESTPLAN, TESTPLAN))
            for rid, old, new in changes_applied:
                print("  %s: %s -> %s" % (rid, old, new))
        if unpinned:
            print("\n--update does NOT add new residual entries automatically (title/status/"
                 "status_class/hardening_ref need a human to read the row and decide - Rule 2, "
                 "pre-registration). Add them to testplan.json's `residuals` object by hand for: "
                 "%s" % ", ".join(unpinned))
        if missing_from_doc:
            print("\n--update does NOT remove a residual whose row disappeared from "
                 "THREAT_MODEL.md - decide by hand whether it was retired, renamed, or the "
                 "parse missed it: %s" % ", ".join(missing_from_doc))

sys.exit(4 if drift else 0)
PYEOF
