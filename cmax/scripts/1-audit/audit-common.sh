# audit-common.sh - shared helpers sourced by the per-harness audit collectors
# (cluster-audit-slurm.sh, cluster-audit-standalone.sh). Sourced, not executed.
# Keeping these in one place avoids the copy-paste drift the collectors had.

# Directory of this library. The generated minimum version table
# (minimum-versions.json) and its reader (minimum_versions.py) are siblings, so
# every collector that sources this file resolves them the same way, whatever
# directory the collector was launched from.
AUDIT_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINIMUM_VERSIONS_READER="${AUDIT_COMMON_DIR}/minimum_versions.py"

# host-check.sh is delivered to the worker over stdin (`bash -s`) by the slurm
# and k8s collectors, and copied to /tmp by the standalone collector, so it
# cannot find its own siblings. Export the reader path for the collectors whose
# check runs on a filesystem that holds this checkout. The k8s collector cannot
# rely on that (the check runs in a container), so it passes the resolved minimum
# to the check instead; see host_check_stdin in cluster-audit-k8s.sh.
export CLUSTERMAX_MINIMUM_VERSIONS_READER="$MINIMUM_VERSIONS_READER"

print_header() {
    echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "${CYAN}─── $1 ───${NC}"
}

print_info() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_detail() {
    echo -e "    $1"
}

# sanitize_git_remote_url - retain repository identity without serializing
# credentials that Git may embed in an HTTPS remote or scp-style URL.
sanitize_git_remote_url() {
    local remote="${1:-}"
    local scheme rest authority path

    case "$remote" in
        *://*)
            scheme="${remote%%://*}"
            rest="${remote#*://}"
            authority="${rest%%/*}"
            path=""
            [[ "$rest" == */* ]] && path="/${rest#*/}"
            authority="${authority##*@}"
            path="${path%%\?*}"
            path="${path%%\#*}"
            printf '%s://%s%s\n' "$scheme" "$authority" "$path"
            ;;
        *@*:*)
            printf '%s\n' "${remote#*@}"
            ;;
        *)
            printf '%s\n' "$remote"
            ;;
    esac
}

version_ge() {
    local version="${1%%[-+~]*}"
    local required="${2%%[-+~]*}"
    local version_major=0 version_minor=0 version_patch=0
    local required_major=0 required_minor=0 required_patch=0
    version="${version##*:}"
    required="${required##*:}"
    version=$(printf '%s' "$version" | sed 's/^[^0-9]*//; s/[^0-9.].*$//')
    required=$(printf '%s' "$required" | sed 's/^[^0-9]*//; s/[^0-9.].*$//')
    IFS=. read -r version_major version_minor version_patch <<< "$version"
    IFS=. read -r required_major required_minor required_patch <<< "$required"
    version_major=${version_major:-0}
    version_minor=${version_minor:-0}
    version_patch=${version_patch:-0}
    required_major=${required_major:-0}
    required_minor=${required_minor:-0}
    required_patch=${required_patch:-0}

    if (( version_major > required_major )); then return 0; fi
    if (( version_major < required_major )); then return 1; fi
    if (( version_minor > required_minor )); then return 0; fi
    if (( version_minor < required_minor )); then return 1; fi
    (( version_patch >= required_patch ))
}

# minimum_version - read one value out of the generated minimum version table.
#
# $1 is a dotted path accepted by minimum_versions.py --get. $2 is the value to
# print when the lookup cannot be completed, and defaults to "unknown".
#
# The fallback is deliberately a non-numeric, non-version string. python3 can be
# absent, the reader can be missing, the table can be corrupt, and the key can
# be gone after an upstream schema change; in every one of those cases the
# caller must report an explicit unknown. Substituting a permissive minimum (0, an
# empty string, or a stale literal) would grade a vulnerable host as a pass,
# which is worse than reporting that the minimum could not be read.
minimum_version() {
    local dotted="$1"
    local fallback="${2:-unknown}"
    local value=""
    if [[ -f "$MINIMUM_VERSIONS_READER" ]] && command -v python3 >/dev/null 2>&1; then
        value=$(python3 "$MINIMUM_VERSIONS_READER" --get "$dotted" 2>/dev/null) || value=""
    fi
    [[ -n "$value" ]] || value="$fallback"
    printf '%s\n' "$value"
}

# minimum_version_grace - print the active bulletin grace record for one minimum.
#
# A missing reader, timestamp, component, selector, or active window returns
# nonzero. The caller keeps the original audit status in every such case.
minimum_version_grace() {
    local component="$1"
    local selector="${2:-}"
    [[ -f "$MINIMUM_VERSIONS_READER" ]] && command -v python3 >/dev/null 2>&1 || return 1
    if [[ -n "$selector" ]]; then
        python3 "$MINIMUM_VERSIONS_READER" \
            --grace-period "$component" --selector "$selector" 2>/dev/null
    else
        python3 "$MINIMUM_VERSIONS_READER" --grace-period "$component" 2>/dev/null
    fi
}

# build_security_advisory_json - emit the Ubuntu Noble advisory members that
# every collector reports: fragnesia, januscape, qemuCve20243446, and vmscape.
#
# The CVE identifiers, the fixed package versions, the Fragnesia kernel ABI, and
# the Ubuntu fix status all come from the generated minimum table through
# minimum_version(). The slurm/standalone JSON and the k8s JSON therefore read one
# source and cannot drift apart the way the two hardcoded copies did. Check
# results stay caller-supplied because each collector names them differently
# (WORKER_* on slurm and standalone, HP_* on k8s).
#
# Output is a run of JSON object members, each terminated with a comma, meant to
# be spliced into a "security" object that still emits members of its own.
#
# Every option is optional and takes a value:
#   --fragnesia-status         graded Fragnesia state from the check
#   --fragnesia-compared-abi   ABI minimum the check actually compared against
#   --januscape-cpu-exposed    JSON bool: guest-visible svm/vmx
#   --januscape-kvm-exposed    JSON bool: /dev/kvm present
#   --januscape-module         loaded KVM module name
#   --januscape-nested-enabled nested KVM parameter state
#   --januscape-exposed        JSON bool or already-quoted "unknown"
#   --januscape-status         graded Januscape state from the check
#   --qemu-status              graded CVE-2024-3446 state from the check
#   --vmscape-status           graded VMSCAPE state from the check
#
# An omitted check status becomes "unknown", and an unresolved minimum becomes
# "unknown" as well. Neither ever becomes a value that reads as a pass.
build_security_advisory_json() {
    local fragnesia_status="unknown" fragnesia_compared_abi="unknown"
    local januscape_cpu="false" januscape_kvm="false" januscape_module="none"
    local januscape_nested="unknown" januscape_exposed='"unknown"'
    local januscape_status="unknown"
    local qemu_status="unknown" vmscape_status="unknown"

    # Every option carries a value, so requiring two remaining words keeps a
    # truncated argument list from spinning here instead of shifting.
    while [[ $# -gt 1 ]]; do
        case "$1" in
            --fragnesia-status) fragnesia_status="$2"; shift 2 ;;
            --fragnesia-compared-abi) fragnesia_compared_abi="$2"; shift 2 ;;
            --januscape-cpu-exposed) januscape_cpu="$2"; shift 2 ;;
            --januscape-kvm-exposed) januscape_kvm="$2"; shift 2 ;;
            --januscape-module) januscape_module="$2"; shift 2 ;;
            --januscape-nested-enabled) januscape_nested="$2"; shift 2 ;;
            --januscape-exposed) januscape_exposed="$2"; shift 2 ;;
            --januscape-status) januscape_status="$2"; shift 2 ;;
            --qemu-status) qemu_status="$2"; shift 2 ;;
            --vmscape-status) vmscape_status="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    local frag_cve frag_related frag_fixed frag_abi frag_fix_status
    local frag_grace="null"
    local jan_cve jan_fixed jan_fix_status
    local qemu_cve qemu_fixed qemu_fix_status
    local vmscape_cve vmscape_fixed vmscape_fix_status
    local frag_key="components.ubuntuNoble.packages.linuxFragnesia"
    local jan_key="components.ubuntuNoble.packages.linuxJanuscape"
    local qemu_key="components.ubuntuNoble.packages.qemu"
    local vmscape_key="components.ubuntuNoble.packages.linuxVmscape"

    frag_cve=$(minimum_version "${frag_key}.cve")
    frag_related=$(minimum_version "${frag_key}.relatedCves" "[]")
    frag_fixed=$(minimum_version "${frag_key}.fixed")
    frag_abi=$(minimum_version "${frag_key}.abi")
    frag_fix_status=$(minimum_version "${frag_key}.status")
    if [[ "$fragnesia_status" == "fail" ]] && \
        frag_grace=$(minimum_version_grace ubuntuNoble linuxFragnesia); then
        fragnesia_status="pass"
    else
        frag_grace="null"
    fi
    jan_cve=$(minimum_version "${jan_key}.cve")
    jan_fixed=$(minimum_version "${jan_key}.fixed")
    jan_fix_status=$(minimum_version "${jan_key}.status")
    qemu_cve=$(minimum_version "${qemu_key}.cve")
    qemu_fixed=$(minimum_version "${qemu_key}.fixed")
    qemu_fix_status=$(minimum_version "${qemu_key}.status")
    vmscape_cve=$(minimum_version "${vmscape_key}.cve")
    vmscape_fixed=$(minimum_version "${vmscape_key}.fixed")
    vmscape_fix_status=$(minimum_version "${vmscape_key}.status")

    # ubuntuNobleFixStatus carries the Ubuntu tracker state for the fix itself.
    # Januscape reads "pending" today: Canonical tracks the fix as 6.8.0-137.137
    # for Noble but has not released it. The version is reported as
    # ubuntuNobleKernelFix (a tracked fix), not as a "Minimum" (a released
    # minimum), and the pair replaces the retired "no fix available" claim.
    cat <<EOF
    "fragnesia": {
      "cve": "${frag_cve}",
      "relatedCves": ${frag_related},
      "status": "${fragnesia_status}",
      "gracePeriod": ${frag_grace},
      "ubuntuNoblePackageMinimum": "${frag_fixed}",
      "ubuntuNoblePackageMinimumAbi": "${frag_abi}",
      "ubuntuNobleFixStatus": "${frag_fix_status}",
      "comparedAbiFloor": "${fragnesia_compared_abi}"
    },
    "januscape": {
      "cve": "${jan_cve}",
      "cpuVirtualizationExposed": ${januscape_cpu},
      "kvmDeviceExposed": ${januscape_kvm},
      "module": "${januscape_module}",
      "nestedEnabled": "${januscape_nested}",
      "exposed": ${januscape_exposed},
      "status": "${januscape_status}",
      "ubuntuNobleKernelFix": "${jan_fixed}",
      "ubuntuNobleFixStatus": "${jan_fix_status}"
    },
    "qemuCve20243446": {
      "cve": "${qemu_cve}",
      "status": "${qemu_status}",
      "ubuntuNobleMinimum": "${qemu_fixed}",
      "ubuntuNobleFixStatus": "${qemu_fix_status}"
    },
    "vmscape": {
      "cve": "${vmscape_cve}",
      "status": "${vmscape_status}",
      "ubuntuNobleKernelMinimum": "${vmscape_fixed}",
      "ubuntuNobleFixStatus": "${vmscape_fix_status}"
    },
EOF
}

# version_meets_minimum - grade an observed version against a minimum, and refuse to
# grade at all when either side is unknown.
#
# version_ge() strips non-numeric text before comparing, so an "unknown" minimum
# collapses to 0.0.0 and every observed version compares greater. A collector
# that fed an unresolved minimum straight into version_ge would therefore report a
# host as meeting a recommendation nobody could read. Callers use this wrapper
# for every minimum that comes from the generated table: a minimum with no digits,
# or a missing observed version, returns non-zero and leaves the caller's
# not-verified default in place.
version_meets_minimum() {
    local observed="${1:-unknown}"
    local minimum="${2:-unknown}"
    [[ -n "$observed" && "$observed" != "unknown" ]] || return 1
    [[ "$minimum" != "unknown" && "$minimum" =~ [0-9] ]] || return 1
    version_ge "$observed" "$minimum"
}

# Keys read out of the virtio-net check's --summary object, in the order
# virtio_net_check_facts assigns them. Append only: the index of every existing
# key is the contract between this list and the case statement below.
#
# The virtioNetWorstObserved* group and virtioNetObservedJson carry per-host
# facts past the cluster rollup. Without them a fleet where one node is proven
# below the minimum and another is unresolved reports the rollup's "unknown",
# which grades as a warning, instead of "fail", which grades as critical: a
# machine proven vulnerable would be softened because a different machine was
# unreadable.
VIRTIO_NET_SUMMARY_KEYS="virtioNet virtioNetLine virtioNetMode virtioNetSource virtioNetReason dpuIsolationJson state virtioNetWorstObserved virtioNetWorstObservedLine virtioNetWorstObservedMode virtioNetWorstObservedHost virtioNetObservedJson"

# virtio_net_check_facts - resolve the BlueField VIRTIO-Net controller state.
#
# Sets, for security_version_audit.py:
#   VIRTIO_NET_VERSION        --virtio-net         (a version, "not-installed", or "unknown")
#   VIRTIO_NET_LINE           --virtio-net-line    (release train; empty when unnamed)
#   VIRTIO_NET_MODE           --virtio-net-mode    (dpu / nic / absent)
#   VIRTIO_NET_SOURCE         --virtio-net-source  (how the version was read)
#   VIRTIO_NET_REASON         --virtio-net-reason  (why it was not read)
#   VIRTIO_NET_ISOLATION_JSON --dpu-isolation-json (the RShim posture evidence)
# plus VIRTIO_NET_STATE for the operator log.
#
# The check self-dispatches per node, because a DPU is per node and a head-node
# answer would be a false negative. It is run in --summary mode here because the
# audit runs the collectors before run_checks.py, so the full per-host evidence
# the check writes into check_data is not available yet.
#
# Every failure path yields "unknown" with empty evidence. A missing check, a
# missing python3, a non-zero exit, and unparseable output all mean the same
# thing: the controller version was not observed. Reporting "not-installed"
# there would grade a BlueField-3 in DPU mode as not applicable, which is the
# false pass this check exists to prevent. Empty isolation evidence likewise
# grades as unknown rather than as a clean host.
virtio_net_check_facts() {
    VIRTIO_NET_VERSION="unknown"
    VIRTIO_NET_LINE=""
    VIRTIO_NET_MODE=""
    VIRTIO_NET_SOURCE=""
    VIRTIO_NET_REASON="the virtio-net check did not run"
    VIRTIO_NET_ISOLATION_JSON=""
    VIRTIO_NET_STATE="incomplete"
    VIRTIO_NET_WORST=""
    VIRTIO_NET_WORST_LINE=""
    VIRTIO_NET_WORST_MODE=""
    VIRTIO_NET_WORST_HOST=""
    VIRTIO_NET_OBSERVED_JSON=""

    local check="${WORKLOAD_DIR:-$AUDIT_COMMON_DIR}/checks/fabric/virtio-net-check.py"
    [[ -f "$check" ]] || check="${AUDIT_COMMON_DIR}/checks/fabric/virtio-net-check.py"
    if [[ ! -f "$check" ]] || ! command -v python3 >/dev/null 2>&1; then
        VIRTIO_NET_REASON="virtio-net-check.py or python3 is unavailable"
        return 0
    fi

    # Relay the check's warnings the way run_checks.py relays every audit
    # check's: verbatim on stderr, with a non-zero exit treated as "no data"
    # rather than as a failed run. Command substitution captures fd 1 only, so
    # the check's stderr reaches the operator without any chance of corrupting
    # the JSON being parsed from stdout.
    #
    # Not 2>/dev/null. The fan-out degradation notice, which says the check
    # could not reach part of the fleet, exists only on stderr. The text
    # survives in virtioNetReason in the values file either way, but an
    # operator watching a live run would otherwise see nothing at all.
    local payload=""
    payload=$(python3 "$check" --summary) || payload=""
    [[ -n "$payload" ]] || return 0

    # One line per key, newlines flattened, so a JSON blob survives the read.
    local parsed=""
    parsed=$(printf '%s' "$payload" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except (ValueError, TypeError):
    raise SystemExit(1)
if not isinstance(data, dict):
    raise SystemExit(1)
for key in sys.argv[1:]:
    value = data.get(key)
    print("" if value is None else str(value).replace("\n", " "))
' $VIRTIO_NET_SUMMARY_KEYS 2>/dev/null) || return 0

    local index=0 line
    while IFS= read -r line; do
        case "$index" in
            0) [[ -n "$line" ]] && VIRTIO_NET_VERSION="$line" ;;
            1) VIRTIO_NET_LINE="$line" ;;
            2) VIRTIO_NET_MODE="$line" ;;
            3) VIRTIO_NET_SOURCE="$line" ;;
            4) VIRTIO_NET_REASON="$line" ;;
            5) VIRTIO_NET_ISOLATION_JSON="$line" ;;
            6) [[ -n "$line" ]] && VIRTIO_NET_STATE="$line" ;;
            7) VIRTIO_NET_WORST="$line" ;;
            8) VIRTIO_NET_WORST_LINE="$line" ;;
            9) VIRTIO_NET_WORST_MODE="$line" ;;
            10) VIRTIO_NET_WORST_HOST="$line" ;;
            11) VIRTIO_NET_OBSERVED_JSON="$line" ;;
        esac
        index=$((index + 1))
    done <<< "$parsed"
    return 0
}

# dcgm_versions_from_tag - split a dcgm-exporter image tag into its two versions.
#
# NVIDIA tags dcgm-exporter as <dcgm-version>-<exporter-version>-<os>, for
# example 4.4.2-4.7.1-ubuntu22.04, which is DCGM 4.4.2 and exporter 4.7.1.
# Position is the entire contract. Published tags exist in both orderings by
# magnitude (4.2.3-4.1.3 has DCGM ahead of the exporter, 4.4.0-4.5.0 has it
# behind), so the two fields must never be sorted, compared, or inferred from
# each other, only read in order.
#
# Prints "<dcgm> <exporter>". A tag that does not match the grammar prints
# "unknown unknown", never a partial read: both components are 4.x and grading
# one against the other's minimum would look entirely plausible while being wrong.
dcgm_versions_from_tag() {
    local tag="${1:-}"
    tag="${tag##*/}"    # drop any registry / repository prefix
    tag="${tag##*:}"    # keep the tag when a full image reference was passed
    tag="${tag%%@*}"    # drop a digest suffix
    # The trailing OS segment is required, so a truncated or reordered tag fails
    # the match instead of producing one confident field.
    if [[ "$tag" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+\.[0-9]+\.[0-9]+)-[A-Za-z] ]]; then
        printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        return 0
    fi
    printf 'unknown unknown\n'
}

# dcgm_version_from_check - the DCGM version the host check already collected.
#
# host-check.sh owns the `dcgmi --version` parse and emits WORKER_DCGM_VERSION
# as its first non-blank line ("dcgmi  version: 4.6.0"), or "not-found" when
# dcgmi is absent. This reads that one value; it does not add a second dcgmi
# call or a second parser.
dcgm_version_from_check() {
    local raw
    raw=$(printf '%s\n' "${1:-}" | grep '^WORKER_DCGM_VERSION=' | head -1 | cut -d= -f2- || true)
    if [[ "$raw" == "not-found" ]]; then
        printf 'not-installed\n'
    elif [[ "$raw" =~ ([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
        printf '%s\n' "${BASH_REMATCH[1]}"
    else
        printf 'unknown\n'
    fi
}

build_security_version_audit() {
    # $1 is raw host-check KEY=VALUE output. Remaining arguments are versions
    # collected from the worker container and GPU checks.
    local check_output="${1:-}"
    local driver="${2:-unknown}"
    local nct="${3:-unknown}"
    local runc="${4:-unknown}"
    local docker="${5:-unknown}"
    local gpu_vendor="${6:-nvidia}"
    local cuda="${7:-}"
    local harness="${8:-${CLUSTERMAX_AUDIT_HARNESS:-}}"
    local policy="${WORKLOAD_DIR}/security_version_audit.py"
    if [[ -z "$cuda" ]]; then
        cuda=$(printf '%s\n' "$check_output" | grep '^WORKER_NVCC_VERSION=' | head -1 | cut -d= -f2- || true)
    fi
    cuda="${cuda:-unknown}"
    local -a args=(--driver "$driver" --nct "$nct" --runc "$runc" --docker "$docker" --cuda "$cuda" --gpu-vendor "$gpu_vendor")
    local line dev fw vendor

    # BlueField VIRTIO-Net controller (NVIDIA a_id 5815, CVE-2026-65094). The
    # version lives on the DPU ARM side, so it comes from the fabric check
    # rather than from the host-check KEY=VALUE stream. The check reports
    # "unknown" for every state it could not resolve and "not-installed" only
    # for a completed scan that found no applicable DPU, so a check that cannot
    # run never reaches the evaluator as a pass.
    # DCGM and dcgm-exporter (NVIDIA a_id 5857, CVE-2026-47483). The DCGM
    # version comes from the host check's existing dcgmi parse. The exporter
    # version exists only in its container image tag, which is a Kubernetes
    # deployment detail, so the k8s collector supplies DCGM_EXPORTER_IMAGE and
    # DCGM_EXPORTER_PRESENT. The standalone collector also supplies
    # DCGM_EXPORTER_PRESENT, from its socket, systemd, and process scan, because
    # that one host is the whole fleet and the scan can therefore be complete.
    # Slurm has no fleet-wide discovery path for dcgm-exporter today: it scans
    # the head node while the exporter runs on the workers, so it reports
    # unknown rather than inventing one. "not-installed" is claimed only when a
    # scan positively found none.
    local dcgm dcgm_exporter tag_dcgm tag_exporter
    dcgm=$(dcgm_version_from_check "$check_output")
    dcgm_exporter="unknown"
    if [[ -n "${DCGM_EXPORTER_IMAGE:-}" ]]; then
        read -r tag_dcgm tag_exporter <<< "$(dcgm_versions_from_tag "$DCGM_EXPORTER_IMAGE")"
        dcgm_exporter="$tag_exporter"
        # The image tag also carries the DCGM version the exporter ships, which
        # is the only source on a k8s node with no dcgmi.
        #
        # "not-installed" defers to the tag as well as "unknown". The exporter
        # image being on this node is positive proof that DCGM is deployed here
        # as a container, so a host-level "no dcgmi binary" is not evidence of
        # absence. On a GPU Operator cluster, the common Kubernetes shape, the
        # host never has dcgmi, so gating on "unknown" alone meant the fallback
        # never fired on exactly the hosts it was written for: a node running
        # DCGM below the minimum graded not_applicable, saying DCGM was not
        # installed, while the tag proved otherwise.
        #
        # A real version read from the running host engine still wins, and a
        # malformed tag leaves "unknown" rather than restoring "not-installed",
        # because a deployed controller with an unreadable version is a warning
        # and not a clean host.
        case "$dcgm" in
            unknown|not-installed) dcgm="$tag_dcgm" ;;
        esac
    elif [[ "${DCGM_EXPORTER_PRESENT:-unknown}" == "false" ]]; then
        dcgm_exporter="not-installed"
    fi
    args+=(--dcgm "$dcgm" --dcgm-exporter "$dcgm_exporter")

    if [[ "$harness" == "standalone" ]]; then
        VIRTIO_NET_VERSION="not-installed"
        VIRTIO_NET_LINE=""
        VIRTIO_NET_MODE="absent"
        VIRTIO_NET_SOURCE="harness-policy"
        VIRTIO_NET_REASON="scale-out checks do not apply to standalone"
        VIRTIO_NET_STATE="complete"
        VIRTIO_NET_WORST=""
        VIRTIO_NET_WORST_LINE=""
        VIRTIO_NET_WORST_MODE=""
        VIRTIO_NET_WORST_HOST=""
        VIRTIO_NET_OBSERVED_JSON=""
        VIRTIO_NET_ISOLATION_JSON=""
    else
        virtio_net_check_facts
    fi
    args+=(--virtio-net "$VIRTIO_NET_VERSION")
    [[ -n "$VIRTIO_NET_LINE" ]] && args+=(--virtio-net-line "$VIRTIO_NET_LINE")
    [[ -n "$VIRTIO_NET_MODE" ]] && args+=(--virtio-net-mode "$VIRTIO_NET_MODE")
    [[ -n "$VIRTIO_NET_SOURCE" ]] && args+=(--virtio-net-source "$VIRTIO_NET_SOURCE")
    [[ -n "$VIRTIO_NET_REASON" ]] && args+=(--virtio-net-reason "$VIRTIO_NET_REASON")
    [[ -n "$VIRTIO_NET_STATE" ]] && args+=(--virtio-net-state "$VIRTIO_NET_STATE")
    # Per-host facts that must survive the cluster rollup. Each value is a
    # single quoted array element, so an embedded JSON array, spaces, brackets,
    # or quotes cannot split the argument list; this is the same handling
    # dpu-isolation-json already uses. Empty values are omitted so the
    # evaluator falls back to the rollup, which is the pre-existing behavior.
    [[ -n "$VIRTIO_NET_WORST" ]] && args+=(--virtio-net-worst "$VIRTIO_NET_WORST")
    [[ -n "$VIRTIO_NET_WORST_LINE" ]] \
        && args+=(--virtio-net-worst-line "$VIRTIO_NET_WORST_LINE")
    [[ -n "$VIRTIO_NET_WORST_MODE" ]] \
        && args+=(--virtio-net-worst-mode "$VIRTIO_NET_WORST_MODE")
    [[ -n "$VIRTIO_NET_WORST_HOST" ]] \
        && args+=(--virtio-net-worst-host "$VIRTIO_NET_WORST_HOST")
    [[ -n "$VIRTIO_NET_OBSERVED_JSON" ]] \
        && args+=(--virtio-net-observed-json "$VIRTIO_NET_OBSERVED_JSON")
    [[ -n "$VIRTIO_NET_ISOLATION_JSON" ]] \
        && args+=(--dpu-isolation-json "$VIRTIO_NET_ISOLATION_JSON")

    if [[ ! -f "$policy" ]] || ! command -v python3 >/dev/null 2>&1; then
        printf '%s\n' '{"nvidiaDriver":{"status":"unknown"},"nvidiaContainerToolkit":{"status":"unknown"},"cudaToolkit":{"status":"unknown"},"docker":{"status":"unknown"},"runc":{"status":"unknown"},"connectxFirmware":{"status":"unknown"},"dcgm":{"status":"unknown"},"dcgmExporter":{"status":"unknown"},"virtioNetBluefield":{"status":"unknown"},"dpuHostIsolation":{"status":"unknown"}}'
        return 0
    fi

    # host-check.sh reports "true" only when it actually read a bus (the RDMA
    # sysfs tree, or a PCI listing that names no NVIDIA device) and "false" when
    # it could not, and the key is absent from a check that never ran. Only the
    # positive claim may reach the evaluator, because a complete inventory with
    # no NVIDIA device grades not_applicable, which reads as a pass. Every other
    # value leaves the flag off, and the evaluator reports unknown.
    if grep -q '^WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true$' <<< "$check_output"; then
        args+=(--connectx-inventory-complete)
    fi

    # The NVIDIA driver minimum only applies where an NVIDIA GPU exists, and
    # absence graded not_applicable reads as a pass, so only a unanimous
    # positive claim reaches the evaluator: every host's GPU inventory read a
    # bus (a =true line with no =false line beside it) and no host saw a 10de
    # device. A mixed fleet, a host that could not read its bus, or a check
    # that never emitted the keys all leave the flag off, and the evaluator
    # keeps reporting unknown so the provider is asked to attest.
    if grep -q '^WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true$' <<< "$check_output" \
        && ! grep -q '^WORKER_SECURITY_GPU_INVENTORY_COMPLETE=false$' <<< "$check_output" \
        && ! grep -q '^WORKER_SECURITY_NVIDIA_GPU_PRESENT=true$' <<< "$check_output" \
        && ! grep -q '^WORKER_SECURITY_NVIDIA_GPU_PRESENT=unknown$' <<< "$check_output"; then
        args+=(--nvidia-gpu-absent)
    fi

    while IFS= read -r line; do
        [[ "$line" =~ ^WORKER_SECURITY_NIC_FW_VER_([^=]+)=(.*)$ ]] || continue
        dev="${BASH_REMATCH[1]}"
        fw="${BASH_REMATCH[2]}"
        vendor=$(printf '%s\n' "$check_output" \
            | grep "^WORKER_SECURITY_NIC_PCI_VENDOR_${dev}=" \
            | head -1 | cut -d= -f2- || true)
        if [[ "$vendor" == "0x15b3" ]]; then
            args+=(--connectx-firmware "${dev}=${fw}")
        elif [[ -z "$vendor" || "$vendor" == "unknown" ]]; then
            # A completed device scan is only not-applicable when every
            # observed device is positively identified as non-NVIDIA.
            args+=(--connectx-firmware "${dev}=unknown")
        fi
    done <<< "$check_output"

    python3 "$policy" "${args[@]}" 2>/dev/null \
        || printf '%s\n' '{"nvidiaDriver":{"status":"unknown"},"nvidiaContainerToolkit":{"status":"unknown"},"cudaToolkit":{"status":"unknown"},"docker":{"status":"unknown"},"runc":{"status":"unknown"},"connectxFirmware":{"status":"unknown"},"dcgm":{"status":"unknown"},"dcgmExporter":{"status":"unknown"},"virtioNetBluefield":{"status":"unknown"},"dpuHostIsolation":{"status":"unknown"}}'
}

amd_gpu_check_present() {
    local gpu_count="${1:-0}"
    local gpu_model="${2:-}"

    if [[ "$gpu_count" =~ ^[1-9][0-9]*$ ]]; then
        return 0
    fi
    [[ -n "$gpu_model" && "$gpu_model" != "unknown" ]]
}

rocm_counter_access_state() {
    local kfd_access="${1:-unknown}"
    local render_access="${2:-unknown}"

    if [[ "$kfd_access" == "allowed" && "$render_access" == "allowed" ]]; then
        printf '%s\n' "allowed"
    elif [[ "$kfd_access" == "denied" || "$kfd_access" == "absent" \
        || "$render_access" == "denied" || "$render_access" == "absent" ]]; then
        printf '%s\n' "denied"
    else
        printf '%s\n' "untested"
    fi
}

# List NCCL libraries installed on the host while excluding Enroot/Pyxis
# container data. A failed image import can leave a partial libnccl.so below an
# enroot-data tree; reporting that file as host NCCL makes the audit depend on
# which containers a previous job happened to attempt.
find_host_nccl_candidates() {
    local roots=("$@")
    (( ${#roots[@]} > 0 )) || roots=(/usr /opt /lib /lib64)
    find "${roots[@]}" \
        \( -path '*/enroot-data' -o -path '*/enroot-data/*' \
           -o -path '*/enroot-cache' -o -path '*/enroot-cache/*' \) -prune \
        -o -name 'libnccl.so*' -print 2>/dev/null
}

# Convert a Kubernetes resource.Quantity string to a plain number. Kubernetes
# canonicalizes large extended-resource counts with SI suffixes (for example,
# 1000 shared RDMA devices becomes "1k"), which jq's tonumber rejects.
k8s_quantity_to_number() {
    local quantity="${1:-0}"
    if [[ ! "$quantity" =~ ^([+-]?[0-9]+([.][0-9]+)?)([numkKMGTPE]|[KMGTPE]i|[eE][+-]?[0-9]+)?$ ]]; then
        echo "invalid Kubernetes quantity: $quantity" >&2
        return 1
    fi

    local number="${BASH_REMATCH[1]}"
    local suffix="${BASH_REMATCH[3]}"
    awk -v number="$number" -v suffix="$suffix" 'BEGIN {
        multiplier[""] = 1
        multiplier["n"] = 1e-9
        multiplier["u"] = 1e-6
        multiplier["m"] = 1e-3
        multiplier["k"] = 1e3
        multiplier["K"] = 1e3
        multiplier["M"] = 1e6
        multiplier["G"] = 1e9
        multiplier["T"] = 1e12
        multiplier["P"] = 1e15
        multiplier["E"] = 1e18
        multiplier["Ki"] = 1024
        multiplier["Mi"] = 1024 ^ 2
        multiplier["Gi"] = 1024 ^ 3
        multiplier["Ti"] = 1024 ^ 4
        multiplier["Pi"] = 1024 ^ 5
        multiplier["Ei"] = 1024 ^ 6
        if (suffix ~ /^[eE][+-]?[0-9]+$/) {
            value = number * (10 ^ (substr(suffix, 2) + 0))
        } else {
            value = number * multiplier[suffix]
        }
        printf "%.15g\n", value
    }'
}

# Render a Kubernetes memory quantity for operators. Keep the binary conversion
# used by Ki/Mi/Gi inputs, but cap the display at the familiar GB label so a
# multi-terabyte node reads as (for example) 2657.6 GB instead of raw Ki.
format_k8s_memory() {
    local quantity="${1:-N/A}"
    local bytes
    if ! bytes=$(k8s_quantity_to_number "$quantity" 2>/dev/null); then
        printf '%s\n' "$quantity"
        return 0
    fi
    awk -v bytes="$bytes" 'BEGIN {
        if (bytes >= 1024 ^ 3) {
            value = bytes / (1024 ^ 3); unit = "GB"
        } else if (bytes >= 1024 ^ 2) {
            value = bytes / (1024 ^ 2); unit = "MB"
        } else if (bytes >= 1024) {
            value = bytes / 1024; unit = "KB"
        } else {
            value = bytes; unit = "B"
        }
        rendered = sprintf("%.1f", value)
        sub(/[.]0$/, "", rendered)
        print rendered " " unit
    }'
}

sum_k8s_quantities() {
    local total=0 quantity number
    while IFS= read -r quantity; do
        [[ -z "$quantity" ]] && continue
        number=$(k8s_quantity_to_number "$quantity") || return 1
        total=$(awk -v total="$total" -v number="$number" 'BEGIN { printf "%.15g", total + number }')
    done
    printf '%s\n' "$total"
}

classify_nic_fabric() {
    local ll="$1" rate_raw="$2" vendor="$3" roce_flag="$4"
    local gb gen
    gb=$(echo "$rate_raw" | grep -oE '^[0-9]+' | head -1)
    [[ -z "$gb" ]] && gb=0
    gen=$(echo "$rate_raw" | grep -oE '\b(SDR|DDR|QDR|FDR|EDR|HDR|NDR|XDR)\b' | head -1)

    # AWS EFA. PCI vendor 0x1d0f is Amazon. EFA does not advertise an
    # IB/Ethernet generation in the same sysfs schema, so rely on rate alone.
    if [[ "$vendor" == "0x1d0f" ]]; then
        if [[ "$gb" -gt 0 ]]; then
            echo "EFA ${gb}G"
        else
            echo "EFA"
        fi
        return
    fi

    if [[ "$ll" == "InfiniBand" ]]; then
        if [[ -n "$gen" && "$gb" -gt 0 ]]; then
            # HDR100 = 2X HDR cable run at 100 Gb/s. Distinct from full HDR 200G.
            if [[ "$gen" == "HDR" && "$gb" -lt 200 ]]; then
                echo "HDR100 ${gb}G IB"
            else
                echo "${gen} ${gb}G IB"
            fi
        elif [[ "$gb" -gt 0 ]]; then
            echo "InfiniBand ${gb}G"
        else
            echo "InfiniBand (rate unknown)"
        fi
        return
    fi

    if [[ "$ll" == "Ethernet" ]]; then
        local suffix=""
        [[ "$roce_flag" == "true" ]] && suffix=" RoCEv2"
        if [[ "$gb" -gt 0 ]]; then
            echo "${gb}GbE${suffix}"
        else
            echo "Ethernet (rate unknown)${suffix}"
        fi
        return
    fi

    echo "other (link_layer=${ll:-unknown}, rate=${rate_raw:-unknown})"
}

add_netutil_status() {
    local key="$1"
    local label="$2"
    local path_var="WORKER_NETUTIL_${key}_PATH"
    local status_var="WORKER_NETUTIL_${key}_STATUS"
    local path="${!path_var:-}"
    local status="${!status_var:-untested}"
    local installed="false"
    if [[ -n "$path" ]]; then
        installed="true"
        case "$status" in
            pass) print_info "${label}: ${path}" ;;
            timeout) print_warn "${label}: ${path} (timed out)" ;;
            fail) print_warn "${label}: ${path} (command failed)" ;;
            *) print_warn "${label}: ${path} (${status})" ;;
        esac
    else
        print_warn "${label}: not found"
    fi
    NETUTILS_JSON_ENTRIES+=("\"${label}\": {\"installed\": ${installed}, \"path\": \"${path:-none}\", \"status\": \"${status}\"}")
}

audit_ufm_secured_profile() {
    local rdma_type="${1:-none}"
    local applicable="false"
    local verification_status="not_applicable"
    local -a required_controls=(
        "Full MAD key protection with randomized seeds: MKEY, VSKEY, PMKEY, CCKEY, Class C key (N2N), AM and job keys, SMKEY, and SAKEY"
        "GUID-based access control using the allowed_guid_list feature"
        "Service-level authentication via service_key (e.g., for AM services)"
        "Enhanced SA trust model applied to all commands"
        "MAD rate limiting (MAD Limiter) to protect against abuse and congestion"
        "DoS/DDoS protection: automatically identifies and limits excessive packet rates from individual nodes to protect the management node"
        "Source-based rate limiting: monitors and controls traffic based on the source LID address of each node"
    )

    print_section 'UFM "Secured Bare Metal Cloud" Profile'
    case "$rdma_type" in
        infiniband)
            applicable="true"
            verification_status="manual"
            print_warn 'Manual verification required: confirm the UFM "Secured Bare Metal Cloud" profile is enabled.'
            print_detail "Review the UFM Continuous Security Verification report and confirm:"
            for control in "${required_controls[@]}"; do
                print_detail "  - ${control}"
            done
            ;;
        roce|efa|none)
            print_info "Not applicable: native InfiniBand was not detected."
            ;;
        *)
            applicable="null"
            verification_status="unknown"
            print_warn "Applicability unknown: ${rdma_type} does not distinguish InfiniBand from other RDMA fabrics."
            print_detail "Confirm the fabric type with the provider; native InfiniBand requires the secured profile review."
            ;;
    esac

    UFM_SECURED_PROFILE_JSON=$(printf '%s\n' "${required_controls[@]}" | jq -R . | jq -s \
        --argjson applicable "$applicable" \
        --arg status "$verification_status" \
        '{
            applicable: $applicable,
            status: $status,
            profile: "Secured Bare Metal Cloud",
            verification: "Confirm in UFM and review the Continuous Security Verification report",
            requiredControls: .
        }')
}

summarize_gpu_nodes() {
    local nodes_json="${1:-[]}"
    jq -c '
        [.[] | select((.gpus // 0) > 0)] as $gpu_nodes
        | {
            nodeCount: ($gpu_nodes | length),
            totalGpus: ($gpu_nodes | map(.gpus) | add // 0),
            perNode: (
                $gpu_nodes
                | map(.gpus)
                | unique
                | if length == 1 then .[0] else 0 end
            ),
            totalCpus: ($gpu_nodes | map(.cpus) | add // 0),
            totalMemoryGB: (
                ($gpu_nodes | map(.memory) | add // 0) / 1024
                | floor
            )
        }
    ' <<< "$nodes_json"
}

# Count Slurm node states from `scontrol show nodes` state strings. Compare
# complete state tokens so POWERED_DOWN does not count as a DOWN base state.
count_slurm_node_states() {
    local nodes_json="${1:-[]}"
    jq -c '
        def tokens: (.state // "") | ascii_upcase | split("+");
        def base: (tokens | first) // "";
        def has_drain: (tokens | any(. == "DRAIN" or . == "DRAINED" or . == "DRAINING"));
        def is_down: (base == "DOWN" or base == "DOWN*" or has_drain);
        {
            total: length,
            idle: ([.[] | select((base | startswith("IDLE")) and (is_down | not))] | length),
            allocated: ([.[] | select((base | startswith("ALLOC")) and (is_down | not))] | length),
            downDrained: ([.[] | select(is_down)] | length),
            poweredDown: ([.[] | select(tokens | any(. == "POWERED_DOWN" or . == "POWERING_DOWN" or . == "POWER_DOWN"))] | length)
        }
    ' <<< "$nodes_json"
}

# Count states from `sinfo` or `snodes` table rows. Slurm appends one suffix
# character to the state word, including `~` for a powered-down idle node.
count_snodes_states() {
    local snodes_out="${1:-}"
    awk '
        NR == 1 { next }
        NF < 5 { next }
        {
            count = $4 + 0
            state = tolower($5)
            sub(/[~#%*$@!+]$/, "", state)
            total += count
            if (state == "down" || state == "drain" || state == "drng" \
                || state == "drained" || state == "draining") {
                down += count
            } else if (state == "idle") {
                idle += count
            } else if (state == "alloc" || state == "allocated") {
                alloc += count
            }
        }
        END {
            printf "{\"total\":%d,\"idle\":%d,\"allocated\":%d,\"downDrained\":%d}\n", \
                total + 0, idle + 0, alloc + 0, down + 0
        }
    ' <<< "$snodes_out"
}

select_gpu_partition() {
    local sinfo_rows="${1:-}"
    awk -F'|' '
        function has_gpu(gres) {
            return gres ~ /(^|[,[:space:]])gpu(:[A-Za-z0-9_.-]+)?:[0-9]+/
        }
        function has_gpu_name(partition) {
            return partition ~ /(^|[-_])(gpu|b[0-9][0-9][0-9]|gb[0-9][0-9][0-9]|h[0-9][0-9][0-9]|a[0-9][0-9][0-9]?|mi[0-9][0-9][0-9][A-Za-z]*)([-_]|$)/
        }
        {
            partition = $1
            sub(/^[[:space:]]+/, "", partition)
            sub(/[[:space:]]+$/, "", partition)
            sub(/\*$/, "", partition)
            node = $2
            sub(/^[[:space:]]+/, "", node)
            sub(/[[:space:]]+$/, "", node)
            if (partition == "" || node == "") {
                next
            }
            key = partition SUBSEP node
            if (seen[key]++) {
                next
            }
            node_count[partition]++
            if (has_gpu($3)) {
                gpu_count[partition]++
            }
        }
        END {
            for (partition in node_count) {
                if (gpu_count[partition] == 0) {
                    continue
                }
                gpu_only_rank = gpu_count[partition] == node_count[partition] ? 0 : 1
                name_rank = has_gpu_name(tolower(partition)) ? 0 : 1
                printf "%d|%d|%s\n", gpu_only_rank, name_rank, partition
            }
        }
    ' <<< "$sinfo_rows" \
        | sort -t'|' -k1,1n -k2,2n -k3,3 \
        | head -1 \
        | cut -d'|' -f3-
}

# Preserve three states in security JSON. Missing check evidence must never be
# serialized as a negative finding because that would turn an unverified host
# boundary into a false pass.
json_bool_or_unknown() {
    case "${1:-}" in
        true|false) printf '%s' "$1" ;;
        *) printf '"unknown"' ;;
    esac
}

gpu_error_scan_script() {
    cat <<'EOF'
journal_err=$(mktemp) || journal_err=/dev/null
logs=$(journalctl --no-pager --since "7 days ago" _TRANSPORT=kernel 2>"$journal_err"); rc=$?
warnings=$(cat "$journal_err" 2>/dev/null); [[ "$journal_err" == /dev/null ]] || rm -f "$journal_err"
if [[ $rc -eq 0 ]] && ! grep -qiE 'not seeing messages|permission denied|inaccessible system journals|failed to open|no journal files' <<< "$warnings"; then
    source=journalctl
elif logs=$(dmesg -T 2>/dev/null) && [[ -n "$logs" ]]; then
    source=dmesg
else
    source=unavailable; logs=
fi
xids=$(grep -iE 'NVRM:.*Xid' <<< "$logs" || true)
xid_count=$(grep -c . <<< "$xids" || true)
last_xid=$(tail -1 <<< "$xids" | grep -oE 'Xid \(PCI:[^)]*\): [0-9]+' | grep -oE '[0-9]+$' || true)
amd_count=$(grep -ciE 'amdgpu:.*(error|fault|fail)' <<< "$logs" || true)
printf 'GPU_ERROR\t%s\t%s\t%s\t%s\t%s\n' "$(hostname)" "$source" "${xid_count:-0}" "${last_xid:-none}" "${amd_count:-0}"
EOF
}

aggregate_gpu_error_history() {
    local rows="$1" checked
    checked=$(awk -F '\t' '$1 == "GPU_ERROR" && $3 != "unavailable" {n++} END {print n+0}' <<< "$rows")
    (( checked > 0 )) || return 1
    GPU_ERROR_NODES_CHECKED=$checked
    DMESG_XIDS_COUNT=$(awk -F '\t' '$1 == "GPU_ERROR" && $4 ~ /^[0-9]+$/ {n += $4} END {print n+0}' <<< "$rows")
    DMESG_XID_LAST=$(awk -F '\t' '$1 == "GPU_ERROR" && $5 ~ /^[0-9]+$/ {last=$5} END {print last ? last : "none"}' <<< "$rows")
    DMESG_AMDGPU_ERRORS_COUNT=$(awk -F '\t' '$1 == "GPU_ERROR" && $6 ~ /^[0-9]+$/ {n += $6} END {print n+0}' <<< "$rows")
}

# build_audit_json - emit the raw audit JSON consumed by merge_audit.py.
# Identical across slurm/standalone except the cluster type, so the per-harness
# collector sets AUDIT_TYPE before calling. (k8s has its own JSON shape.)
build_audit_json() {
    local januscape_exposed_json
    local nvlink_topology_coverage_complete=false
    local security_advisory_json
    local security_version_audit_json="${SECURITY_VERSION_AUDIT_JSON:-}"
    januscape_exposed_json=$(json_bool_or_unknown "${WORKER_JANUSCAPE_EXPOSED:-}")
    if [[ "${AUDIT_TYPE:-}" == "standalone" \
            && "${WORKER_NVLINK_TOPOLOGY_CHECKED:-false}" == "true" ]]; then
        nvlink_topology_coverage_complete=true
    fi
    [[ -n "$security_version_audit_json" ]] || security_version_audit_json="{}"
    security_advisory_json=$(build_security_advisory_json \
        --fragnesia-status "${WORKER_FRAGNESIA_STATUS:-unknown}" \
        --fragnesia-compared-abi "${WORKER_FRAGNESIA_ABI_FLOOR:-unknown}" \
        --januscape-cpu-exposed "${WORKER_NESTED_CPU_EXPOSED:-false}" \
        --januscape-kvm-exposed "${WORKER_KVM_DEVICE:-false}" \
        --januscape-module "${WORKER_NESTED_MODULE:-none}" \
        --januscape-nested-enabled "${WORKER_NESTED_ENABLED:-unknown}" \
        --januscape-exposed "$januscape_exposed_json" \
        --januscape-status "${WORKER_JANUSCAPE_STATUS:-unknown}" \
        --qemu-status "${WORKER_QEMU_CVE_2024_3446_STATUS:-unknown}" \
        --vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")
    cat <<EOF
{
  "audit": {
    "version": "2.1",
    "type": "${AUDIT_TYPE}",
    "timestamp": "${AUDIT_TIMESTAMP}",
    "clusterName": "${AUDIT_CLUSTER_NAME}",
    "hostname": "$(hostname)"
  },
  "serverLocation": {
    "externalIp": "${GEO_IP}",
    "city": "${GEO_CITY}",
    "region": "${GEO_REGION}",
    "country": "${GEO_COUNTRY}",
    "org": "${GEO_ORG}",
    "coordinates": "${GEO_LOC}"
  },
  "slurm": {
    "version": "${SLURM_VERSION_NUM}",
    "controlMachine": "${CONTROL_MACHINE}",
    "slurmUser": "${SLURM_USER}",
    "services": {
      "slurmctld": ${SLURMCTLD_RUNNING},
      "slurmd": ${SLURMD_RUNNING},
      "slurmdbd": ${SLURMDBD_RUNNING}
    },
    "accounting": {
      "storageType": "${ACCOUNTING_STORAGE:-none}",
      "sacctAvailable": ${SACCT_AVAILABLE}
    }
  },
  "nodes": {
    "total": ${TOTAL_NODES},
    "idle": ${IDLE_NODES},
    "allocated": ${ALLOCATED_NODES},
    "down": ${DOWN_NODES},
    "totalCpus": ${TOTAL_CPUS},
    "totalMemoryGB": ${TOTAL_MEMORY_GB}
  },
  "partitions": {
    "default": "${DEFAULT_PARTITION}",
    "gpuPartition": "${GPU_PARTITION:-none}",
    "list": ${PARTITIONS_JSON}
  },
  "gpus": {
    "total": ${TOTAL_GPUS},
    "nodeCount": ${GPU_NODE_COUNT:-0},
    "perNode": ${GPUS_PER_NODE:-0},
    "totalCpus": ${GPU_TOTAL_CPUS:-0},
    "totalMemoryGB": ${GPU_TOTAL_MEMORY_GB:-0},
    "model": "${GPU_MODEL}",
    "memoryMB": "${GPU_MEMORY:-0}",
    "driverVersion": "${DRIVER_VERSION}",
    "cudaVersion": "${CUDA_VERSION}",
    "gpuDirectRdma": ${GPUDIRECT_RDMA},
    "gpuDirectRdmaPath": {
      "dmaBuf": ${WORKER_NVIDIA_DMABUF:-false},
      "nvidiaOpen": ${WORKER_NVIDIA_OPEN:-false},
      "nvidiaPeermemLegacy": ${WORKER_PEERMEM_LEGACY:-false}
    },
    "pcieAcs": {
      "scoped": ${ACS_SCOPED:-false},
      "supported": ${ACS_SUPPORTED:-false},
      "bridges": ${ACS_BRIDGES:-0},
      "enabledCount": ${ACS_ENABLED_COUNT:-0},
      "totalBridges": ${ACS_TOTAL_BRIDGES:-0},
      "enabled": "${ACS_ENABLED:-unknown}",
      "method": "${ACS_METHOD:-config}",
      "functionalPair": "${ACS_FUNCTIONAL_PAIR:-none}",
      "functionalSyndrome": "${ACS_FUNCTIONAL_SYNDROME:-}"
    },
    "gdrcopy": {
      "installed": ${GDRCOPY_INSTALLED},
      "libraryPath": "${GDRCOPY_LIB_PATH:-not-found}",
      "gdrdrvLoaded": ${GDRCOPY_GDRDRV_LOADED}
    },
    "amd": {
      "present": ${AMD_GPUS_PRESENT},
      "model": "${WORKER_AMD_GPU_MODEL:-none}",
      "driverVersion": "${WORKER_AMD_DRIVER_VERSION:-unknown}",
      "rocmVersion": "${WORKER_ROCM_VERSION:-unknown}",
      "rocmSmi": ${ROCM_SMI_AVAILABLE},
      "amdSmi": ${AMD_SMI_AVAILABLE},
      "amdPeermem": ${AMD_PEERMEM_LOADED},
      "rocmContainerToolkit": ${ROCM_CONTAINER_TOOLKIT},
      "rdc": {
        "installed": ${RDC_INSTALLED},
        "path": "${WORKER_RDC_PATH:-none}",
        "version": "${WORKER_RDC_VERSION:-unknown}",
        "smokeTest": "${WORKER_RDC_SMOKE:-untested}"
      },
      "rocmBandwidthTest": {
        "installed": ${ROCM_BANDWIDTH_TEST_INSTALLED},
        "path": "${WORKER_ROCM_BANDWIDTH_TEST_PATH:-none}"
      },
      "rocprof": {
        "installed": ${ROCPROF_INSTALLED:-false},
        "path": "${WORKER_ROCPROF_PATH:-none}",
        "version": "${WORKER_ROCPROF_VERSION:-unknown}",
        "hardwareCounterAccess": "${ROCM_COUNTER_ACCESS:-untested}",
        "kfdAccess": "${WORKER_ROCM_KFD_ACCESS:-unknown}",
        "renderNodeAccess": "${WORKER_ROCM_RENDER_ACCESS:-unknown}",
        "profilingGroups": "${WORKER_ROCM_PROFILING_GROUPS:-none}"
      },
      "rvs": {
        "installed": ${RVS_INSTALLED:-false},
        "path": "${WORKER_RVS_PATH:-none}",
        "version": "${WORKER_RVS_VERSION:-unknown}",
        "confDir": "${WORKER_RVS_CONF_DIR:-none}"
      },
      "transferBench": {
        "installed": ${TRANSFERBENCH_INSTALLED:-false},
        "path": "${WORKER_TRANSFERBENCH_PATH:-none}"
      }
    },
    "thermals": {
      "idleTempMax": "${GPU_IDLE_TEMP_MAX}",
      "idlePowerMax": "${GPU_IDLE_POWER_MAX}"
    },
    "dmesgErrors": {
      "xidsCount": "${DMESG_XIDS_COUNT}",
      "lastXid": "${DMESG_XID_LAST}",
      "amdgpuErrorsCount": "${DMESG_AMDGPU_ERRORS_COUNT}",
      "nodesChecked": ${GPU_ERROR_NODES_CHECKED:-0},
      "nodesTotal": ${GPU_ERROR_NODES_TOTAL:-1}
    }
  },
  "software": {
    "ncu": {
      "installed": ${NCU_INSTALLED},
      "path": "${NCU_PATH:-none}",
      "version": "${NCU_VERSION}",
      "profilingEnabled": $(json_bool_or_unknown "${NCU_PROFILING_ENABLED:-}"),
      "hardwareCounterAccess": "${NCU_COUNTER_ACCESS}"
    },
    "cudaVisibleDevices": "${WORKER_CUDA_VISIBLE_DEVICES:-unknown}",
    "nvidiaVisibleDevices": "${WORKER_NVIDIA_VISIBLE_DEVICES:-unknown}",
    "perf": {
      "installed": ${PERF_INSTALLED},
      "perfEventParanoid": "${PERF_EVENT_PARANOID}",
      "kptrRestrict": "${PERF_KPTR_RESTRICT}",
      "statAccess": "${PERF_STAT_ACCESS}",
      "topAccess": "${PERF_TOP_ACCESS}"
    },
    "workerCheckOk": ${WORKER_CHECK_OK},
    "workerNode": "${WORKER_HOSTNAME}",
    "ncclVersion": "${NCCL_VERSION}",
    "ncclPath": "${NCCL_PATH}",
    "hpcxInPath": ${HPCX_IN_PATH},
    "nvccInPath": ${NVCC_IN_PATH},
    "cudaVersion": "${NVCC_VERSION}",
    "cuda": {
      "nvccPath": "${NVCC_PATH:-none}",
      "cudaHome": "${CUDA_HOME_VAL:-none}"
    },
    "nccl": {
      "installed": ${NCCL_INSTALLED},
      "version": "${NCCL_VERSION}",
      "path": "${NCCL_PATH}"
    },
    "mpi": {
      "installed": ${MPI_INSTALLED},
      "path": "${MPIRUN_PATH:-none}",
      "srunPmixAvailable": ${SRUN_MPI_PMIX}
    },
    "hpcx": {
      "installed": $([ -n "$HPCX_OPT_PATH" ] && echo "true" || echo "${HPCX_IN_PATH}"),
      "inPath": ${HPCX_IN_PATH},
      "path": "${HPCX_PATH:-none}"
    },
    "nvhpc": {
      "status": "${NVHPC_STATUS:-unknown}",
      "installed": ${NVHPC_INSTALLED:-false},
      "version": "${NVHPC_VERSION:-unknown}",
      "minimum": "${NVHPC_MINIMUM:-unknown}",
      "current": "${NVHPC_CURRENT:-unknown}",
      "path": "${WORKER_NVHPC_PATH:-none}",
      "onHead": ${NVHPC_ON_HEAD:-false},
      "onWorkers": ${NVHPC_ON_WORKERS:-false},
      "compilers": {
        "nvc": "${WORKER_NVHPC_NVC_VERSION:-not-found}",
        "nvcxx": "${WORKER_NVHPC_NVCXX_VERSION:-not-found}",
        "nvfortran": "${WORKER_NVHPC_NVFORTRAN_VERSION:-not-found}",
        "complete": ${WORKER_NVHPC_COMPILERS_OK:-false}
      },
      "components": {
        "complete": ${WORKER_NVHPC_COMPONENTS_OK:-false},
        "missing": "${NVHPC_COMPONENTS_MISSING:-not-checked}"
      }
    },
    "lmod": {
      "installed": ${LMOD_INSTALLED},
      "version": "${LMOD_VERSION:-none}"
    }
  },
  "lmod": {
    "installed": ${LMOD_INSTALLED},
    "hasCudaModule": ${HAS_CUDA_MODULE},
    "hasHpcxModule": ${HAS_HPCX_MODULE},
    "hasNcclModule": ${HAS_NCCL_MODULE}
  },
  "containers": {
    "runtimeScope": "${CONTAINER_RUNTIME_SCOPE:-${WORKER_CONTAINER_RUNTIME_SCOPE:-unknown}}",
    "pyxis": ${PYXIS_INSTALLED},
    "pyxisRuntimeWorks": ${PYXIS_RUNTIME_WORKS:-false},
    "pyxisVersion": "${PYXIS_VERSION:-unknown}",
    "enroot": ${ENROOT_INSTALLED},
    "enrootVersion": "${ENROOT_VERSION}",
    "enrootImportWorks": ${ENROOT_IMPORT_WORKS},
    "docker": ${DOCKER_INSTALLED},
    "dockerVersion": "${DOCKER_VERSION}",
    "dockerRecommendedMin": "${DOCKER_RECOMMENDED_MIN}",
    "dockerVersionOk": ${DOCKER_VERSION_OK},
    "dockerOnWorkers": ${DOCKER_ON_WORKERS},
    "workerCheckOk": ${CONTAINER_WORKER_CHECK_OK:-false},
    "workerNode": "${CONTAINER_WORKER_NODE:-unknown}",
    "nvidiaContainerToolkit": ${NVIDIA_CONTAINER_TOOLKIT},
    "nvidiaContainerToolkitVersion": "${NVIDIA_CT_VERSION}",
    "nvidiaContainerToolkitRecommendedMin": "${NVIDIA_CT_RECOMMENDED_MIN}",
    "nvidiaContainerToolkitVersionOk": ${NVIDIA_CT_VERSION_OK},
    "nvidiaContainerToolkitOnHead": ${NVIDIA_CT_ON_HEAD:-false},
    "nvidiaContainerToolkitOnWorkers": ${NVIDIA_CT_ON_WORKERS:-false},
    "dockerNvidiaRuntimeConfigured": ${DOCKER_NVIDIA_RUNTIME_CONFIGURED:-false},
    "runc": ${RUNC_INSTALLED:-false},
    "runcVersion": "${RUNC_VERSION:-unknown}",
    "singularity": ${SINGULARITY_INSTALLED},
    "singularityVersion": "${SINGULARITY_VERSION:-unknown}",
    "singularityOnHead": ${SINGULARITY_ON_HEAD:-false},
    "singularityOnWorkers": ${SINGULARITY_ON_WORKERS:-false}
  },
  "securityVersions": ${security_version_audit_json},
  "networking": {
    "rdmaType": "${RDMA_TYPE}",
    "infinibandInstalled": ${IB_INSTALLED},
    "mofedVersion": "${MOFED_VERSION}",
    "rdmaDevices": "${MLNX_DEVICES:-none}",
    "hcaNamingValid": ${HCA_NAMING_VALID},
    "hcaDevices": ${HCA_DEVICES_JSON},
    "ibPkeysConfigured": ${IB_PKEYS_CONFIGURED},
    "ibPkeyCount": ${IB_PKEY_COUNT},
    "ibTenantIsolation": "${IB_TENANT_ISOLATION}",
    "sharpAvailable": ${SHARP_AVAILABLE},
    "roceMode": ${ROCE_MODE},
    "topologyConfigured": $([ -n "$TOPOLOGY_CONF" ] && [ "$TOPOLOGY_CONF" != "(null)" ] && echo "true" || echo "false"),
    "topologyAware": $([ -n "$TOPOLOGY_CONF" ] && [ "$TOPOLOGY_CONF" != "(null)" ] && echo "true" || echo "false"),
    "topologyPlugin": "${TOPOLOGY_CONF:-none}",
    "topologyMechanisms": $([ -n "$TOPOLOGY_CONF" ] && [ "$TOPOLOGY_CONF" != "(null)" ] && printf '["slurm-%s"]' "${TOPOLOGY_CONF}" || echo "[]"),
    "ncclAutoConfig": $([ "$NCCL_CONF_OVERRIDES" = "false" ] && echo "true" || echo "false"),
    "ncclIbGidIndex": "${NCCL_GID_INDEX_VALUE}",
    "nicFabric": {
      "perDevice": ${NIC_FABRIC_JSON},
      "summary": "${NIC_FABRIC_SUMMARY:-none}",
      "computeFabricClass": "${COMPUTE_FABRIC_CLASS}",
      "computeFabricCount": ${COMPUTE_FABRIC_COUNT},
      "computeFabricGbps": ${COMPUTE_FABRIC_GBPS},
      "hasInfiniband": ${NIC_HAS_INFINIBAND},
      "hasRoce": ${NIC_HAS_ROCE},
      "hasEfa": ${NIC_HAS_EFA},
      "hasOther": ${NIC_HAS_OTHER},
      "efaDevices": "${WORKER_EFA_DEVICES:-none}",
      "efaLibfabric": ${WORKER_EFA_LIBFABRIC:-false}
    },
    "utilities": ${NETWORK_UTILITIES_JSON}
  },
  "security": {
    "ibSmKeyConfigured": ${IB_SM_KEY_CONFIGURED},
    "ibPkeyCount": ${IB_PKEY_COUNT},
    "sharpAmKeyConfigured": ${SHARP_AM_KEY_CONFIGURED},
    "ufmSecuredBareMetalCloud": ${UFM_SECURED_PROFILE_JSON},
    "virtualization": {
      "type": "${WORKER_VIRT_TYPE:-unknown}",
      "guest": $(json_bool_or_unknown "${WORKER_VIRT_GUEST:-unknown}"),
      "qemuMachine": "${WORKER_QEMU_MACHINE:-unknown}",
      "virtioSerialExposed": ${WORKER_VIRTIO_SERIAL:-false}
    },
    "guestKernel": {
      "running": "${WORKER_GUEST_KERNEL_RUNNING:-unknown}",
      "newestInstalled": "${WORKER_GUEST_KERNEL_NEWEST_INSTALLED:-unknown}",
      "newerInstalled": ${WORKER_GUEST_KERNEL_NEWER_INSTALLED:-false},
      "rebootRequired": ${WORKER_GUEST_REBOOT_REQUIRED:-false}
    },
${security_advisory_json}
    "nvidiaMay2026": {
      "driverVersion": "${DRIVER_VERSION:-unknown}",
      "patched": "${WORKER_NVIDIA_MAY_2026_PATCHED:-unknown}",
      "nvlinkExposed": $(json_bool_or_unknown "${WORKER_NVLINK_EXPOSED:-unknown}")
    },
    "nvlinkBoundary": {
      "nvlinkExposed": $(json_bool_or_unknown "${WORKER_NVLINK_EXPOSED:-unknown}"),
      "topologyChecked": $(json_bool_or_unknown "${WORKER_NVLINK_TOPOLOGY_CHECKED:-false}"),
      "topologyCoverageComplete": ${nvlink_topology_coverage_complete},
      "nvidiaGpuPresent": $(json_bool_or_unknown "${WORKER_SECURITY_NVIDIA_GPU_PRESENT:-unknown}"),
      "targetIsVm": $(json_bool_or_unknown "${WORKER_VIRT_GUEST:-unknown}"),
      "domainExclusive": $(json_bool_or_unknown "${CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED:-unknown}")
    },
    "pciePassthrough": {
      "guestIommuGroupCount": ${WORKER_IOMMU_GROUPS:-0},
      "hostVerificationRequired": true
    },
    "bmcIpmi": {
      "ipmitoolInstalled": ${IPMITOOL_INSTALLED},
      "ipmitoolPath": "${WORKER_IPMITOOL_PATH:-none}",
      "userAccess": "${IPMI_USER_ACCESS}",
      "sudoAccess": "${IPMI_SUDO_ACCESS}",
      "exposed": ${IPMI_EXPOSED}
    }
  },
  "healthChecks": {
    "programConfigured": ${HEALTH_CHECK_CONFIGURED},
    "program": "${HEALTH_CHECK_PROGRAM:-none}",
    "interval": "${HEALTH_CHECK_INTERVAL:-0}",
    "dcgmInstalled": ${DCGM_INSTALLED},
    "dcgmSlurm": ${DCGM_SLURM},
    "dcgmHealthWatchesEnabled": ${DCGM_HEALTH_WATCHES_ENABLED},
    "dcgmDiagnostics": {
      "diagR1": "${DCGM_DIAG_R1}",
      "diagR2": "${DCGM_DIAG_R2}"
    },
    "nhcInstalled": ${NHC_INSTALLED},
    "nhcPath": "${NHC_PATH:-none}",
    "prologRuntimeSec": "${PROLOG_RUNTIME_SEC}",
    "prologFast": "${PROLOG_FAST}",
    "monitoringStack": {
      "prometheus": ${PROMETHEUS_DETECTED},
      "dcgmExporter": ${DCGM_EXPORTER_DETECTED},
      "nodeExporter": ${NODE_EXPORTER_DETECTED},
      "grafana": ${GRAFANA_DETECTED}
    },
    "autoRemediation": {
      "configured": ${AUTO_REMEDIATION_CONFIGURED},
      "resumeProgram": "${RESUME_PROGRAM:-none}",
      "returnToService": "${RETURN_TO_SERVICE:-0}",
      "unkillableStepProgram": "${UNKILLABLE_STEP:-none}"
    }
  },
  "access": {
    "sudoAvailable": ${SUDO_AVAILABLE},
    "passwordlessSsh": "${PASSWORDLESS_SSH}",
    "sshToComputeNodes": ${SSH_TO_COMPUTE},
    "firstComputeNode": "${FIRST_COMPUTE_NODE}",
    "slurmCommandsOk": ${SLURM_CMDS_OK},
    "essentialTools": ${ESSENTIAL_TOOLS_JSON},
    "userManagement": {
      "useradd": ${USERADD_AVAILABLE},
      "groupadd": ${GROUPADD_AVAILABLE}
    },
    "externalIdp": {
      "detected": ${IDP_DETECTED},
      "type": "${IDP_TYPE}"
    }
  },
  "resourceLimits": {
    "defCpusPerTask": "${DEF_CPUS_PER_TASK:-1}",
    "defMemPerCpu": ${DEF_MEM_PER_CPU:-0},
    "defMemPerGpu": ${DEF_MEM_PER_GPU:-0},
    "defMemPerNode": ${DEF_MEM_PER_NODE:-0},
    "maxMemPerCpu": ${MAX_MEM_PER_CPU:-0},
    "maxMemPerNode": ${MAX_MEM_PER_NODE:-0},
    "taskPlugin": "${TASK_PLUGIN}",
    "proctrackType": "${PROCTRACK_TYPE}",
    "cpuFreqDef": "${CPU_FREQ_DEF:-none}",
    "cpuFreqGovernors": "${CPU_FREQ_GOV:-none}"
  },
  "computeNodeOs": {
    "id": "${WORKER_OS_ID_VAL}",
    "versionId": "${WORKER_OS_VERSION_VAL}",
    "prettyName": "${WORKER_OS_PRETTY_VAL}",
    "kernel": "${WORKER_KERNEL_VAL}",
    "architecture": "${WORKER_ARCH_VAL}"
  },
  "computeNodeCpu": {
    "model": "${WORKER_CPU_MODEL:-unknown}",
    "sockets": "${WORKER_CPU_SOCKETS:-unknown}",
    "coresPerSocket": "${WORKER_CPU_CORES_PER_SOCKET:-unknown}",
    "threads": "${WORKER_CPU_THREADS:-unknown}",
    "threadsPerCore": "${WORKER_CPU_THREADS_PER_CORE:-unknown}",
    "baseMhz": "${WORKER_CPU_BASE_MHZ:-unknown}",
    "maxMhz": "${WORKER_CPU_MAX_MHZ:-unknown}",
    "curMhz": "${WORKER_CPU_CUR_MHZ:-unknown}",
    "governors": "${WORKER_CPU_GOVERNOR:-unknown}",
    "raplPackages": "${WORKER_CPU_RAPL_PACKAGES:-unknown}",
    "packagePowerLimitW": "${WORKER_CPU_PACKAGE_POWER_LIMIT_W:-unknown}",
    "source": "host-check"
  },
  "computeNodeMemory": {
    "populatedDimms": "${WORKER_MEM_DIMMS:-unknown}",
    "dimmSizesGB": "${WORKER_MEM_DIMM_SIZES_GB:-unknown}",
    "types": "${WORKER_MEM_TYPES:-unknown}",
    "ratedSpeedMts": "${WORKER_MEM_RATED_SPEED_MTS:-unknown}",
    "configuredSpeedMts": "${WORKER_MEM_CONFIGURED_SPEED_MTS:-unknown}",
    "effectiveBandwidthPerSocketGBs": "${WORKER_MEM_BW_PER_SOCKET_GBS:-unknown}",
    "effectiveBandwidthPerCoreGBs": "${WORKER_MEM_BW_PER_CORE_GBS:-unknown}",
    "source": "${WORKER_MEM_SOURCE:-unknown}"
  },
  "driveConfig": {
    "headNode": {
      "hostname": "$(hostname)",
      "bootDevice": {
        "device": "${HEAD_BOOT_DEV}",
        "fstype": "${HEAD_BOOT_FSTYPE}",
        "size": "${HEAD_BOOT_SIZE}"
      },
      "blockDevices": ${HEAD_BLKDEV_JSON:-[]},
      "localNvme": {
        "count": ${HEAD_NVME_COUNT:-0},
        "totalCapacityGB": ${HEAD_NVME_TOTAL_GB:-0},
        "devices": ${HEAD_NVME_DEVS_JSON:-[]}
      },
      "sharedMounts": ${HEAD_SHARED_MOUNTS_JSON:-[]}
    },
    "workerNode": {
      "hostname": "${WORKER_HOSTNAME}",
      "checkSucceeded": ${WORKER_CHECK_OK},
      "bootDevice": {
        "device": "${WORKER_BOOT_DEVICE}",
        "fstype": "${WORKER_BOOT_FSTYPE}",
        "size": "${WORKER_BOOT_SIZE}"
      },
      "blockDevices": ${WORKER_BLKDEV_JSON:-[]},
      "localNvme": {
        "count": ${WORKER_NVME_COUNT:-0},
        "totalCapacityGB": ${WORKER_NVME_TOTAL_GB:-0},
        "devices": ${WORKER_NVME_DEVS_JSON:-[]}
      },
      "sharedMounts": ${WORKER_SHARED_MOUNTS_JSON:-[]}
    }
  }
}
EOF
}

# kv_lines_to_json - convert KEY=VALUE lines on stdin into a JSON object.
# Used to fold raw WORKER_* check output into audit_data (e.g. the k8s host check).
kv_lines_to_json() {
    jq -Rn '[inputs | capture("^(?<key>[^=]+)=(?<value>.*)$")?] | from_entries'
}
