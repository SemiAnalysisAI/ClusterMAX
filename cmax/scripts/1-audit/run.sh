#!/bin/bash
# Cluster audit script entrypoint.
#
# The `cmax audit` command executes this script. It selects one harness
# collector, runs the audit checks, and writes audit.values.json.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
REPO_ROOT="${CLUSTERMAX_REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

# bench's normal launcher exports RESULT_DIR; the audit prologue exports
# RUN_RESULTS_DIR. plan_audit.py keys off RUN_RESULTS_DIR, so bridge the two.
if [[ -z "${RUN_RESULTS_DIR:-}" && -n "${RESULT_DIR:-}" ]]; then
    export RUN_RESULTS_DIR="$RESULT_DIR"
fi

tee_to() {
    local out="$1"
    [[ -z "$out" ]] && { echo "tee_to: missing path" >&2; return 1; }
    exec > >(tee "$out") 2>&1
}

TMPDIR_AUDIT=$(mktemp -d)
LEGACY_CWD=""
cleanup() {
    rm -rf "$TMPDIR_AUDIT" "${LEGACY_CWD:-}"
}
trap cleanup EXIT
trap 'trap - INT TERM HUP; cleanup; exit 143' INT TERM HUP

PLAN_ENV="$TMPDIR_AUDIT/audit-plan.env"
python3 "$SCRIPT_DIR/plan_audit.py" \
    "$REPO_ROOT" \
    "$PLAN_ENV"
# shellcheck disable=SC1090
. "$PLAN_ENV"

mkdir -p "$OUT_DIR"
tee_to "$OUT_DIR/audit.out"

echo "Cluster slug: $SLUG"
echo "Harness:      $HARNESS"
echo "Audit script: ${AUDIT_SCRIPT#$REPO_ROOT/}"
echo "Output dir:   $OUT_DIR"
echo ""

AUDIT_JSON_PATH="$TMPDIR_AUDIT/raw-audit.path"
export CLUSTERMAX_VIRTIO_NET_CHECK_CACHE="$TMPDIR_AUDIT/virtio-net-check.json"
LEGACY_CWD="$TMPDIR_AUDIT/legacy-cwd"
mkdir -p "$LEGACY_CWD"
export CLUSTERMAX_AUDIT_LEGACY_CWD="$LEGACY_CWD"
python3 "$SCRIPT_DIR/run_legacy_audit.py" \
    "$AUDIT_ROOT" \
    "$AUDIT_SCRIPT" \
    "$SLUG" \
    "$TMPDIR_AUDIT" \
    "$AUDIT_JSON_PATH"
AUDIT_JSON=$(<"$AUDIT_JSON_PATH")

python3 "$SCRIPT_DIR/validate_audit.py" "$AUDIT_JSON" "$HARNESS"

# Give checks the worker GPU model that the completed collector observed.
export CLUSTERMAX_AUDIT_GPU_MODEL
CLUSTERMAX_AUDIT_GPU_MODEL="$(python3 -c 'import json, sys; print((json.load(open(sys.argv[1])).get("gpus") or {}).get("model") or "")' "$AUDIT_JSON")"

CHECK_DATA_JSON="$TMPDIR_AUDIT/check-data.json"
# The `─── name ───` shape is the same one print_section uses, so the live
# progress display in cmax/progress.py reads the phases run.sh owns from the
# same stream as the collector's own checks.
echo ""
printf '\033[0;36m─── Audit checks ───\033[0m\n'
python3 "$SCRIPT_DIR/run_checks.py" \
    "$SCRIPT_DIR/checks" \
    "$CHECK_DATA_JSON" \
    "$HARNESS" \
    "${CLUSTERMAX_AUDIT_SCOPE:-full}"

echo ""
printf '\033[0;36m─── Writing audit values ───\033[0m\n'
python3 "$SCRIPT_DIR/merge_audit.py" \
    "$AUDIT_JSON" \
    "$OUT_DIR/audit.values.json" \
    "$SLUG" \
    "$HARNESS" \
    "$CHECK_DATA_JSON"

# Immediate findings report: surface every detected missing / not-OK component
# at the end of the run, with evidence, so it can be screenshotted and confronted
# with the vendor while cluster access is live. Report-only; never fails the run.
if [[ "${CLUSTERMAX_AUDIT_SCOPE:-full}" == "full" ]]; then
    echo ""
    printf '\033[0;36m─── Audit findings ───\033[0m\n'
    python3 "$SCRIPT_DIR/audit_findings.py" "$OUT_DIR/audit.values.json" || true
fi

echo ""
echo "Results: $OUT_DIR"
