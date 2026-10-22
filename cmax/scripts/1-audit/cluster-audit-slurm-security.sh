#!/bin/bash
# Focused host collector for `cmax audit security` on standalone, Slurm, and
# Kubernetes targets.
#
# The complete Slurm collector evaluates the full configuration inventory. This
# collector keeps the shared worker checks that provide security evidence, then
# emits the same raw JSON contract for the standard merge and report path.

set -euo pipefail

WORKLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$WORKLOAD_DIR/audit-common.sh"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

CUSTOM_NAME=""
OUTPUT_DIR=""
JSON_ONLY="false"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name) CUSTOM_NAME="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --json-only) JSON_ONLY="true"; shift ;;
        --help)
            printf 'Usage: %s [--name NAME] [--output-dir DIR] [--json-only]\n' "$0"
            exit 0
            ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    printf 'Error: jq is required but not installed.\n' >&2
    exit 1
fi
SECURITY_HARNESS="${CLUSTERMAX_AUDIT_HARNESS:-slurm}"
if [[ "$SECURITY_HARNESS" != "slurm" \
        && "$SECURITY_HARNESS" != "standalone" \
        && "$SECURITY_HARNESS" != "k8s" ]]; then
    printf 'Error: focused host security collector does not support %s.\n' "$SECURITY_HARNESS" >&2
    exit 1
fi
if [[ "$SECURITY_HARNESS" == "slurm" ]] && ! command -v srun >/dev/null 2>&1; then
    printf 'Error: srun is required for a Slurm security audit.\n' >&2
    exit 1
fi
if [[ "$SECURITY_HARNESS" == "k8s" ]] && ! command -v kubectl >/dev/null 2>&1; then
    printf 'Error: kubectl is required for a Kubernetes security audit.\n' >&2
    exit 1
fi

json_bool() {
    case "${1:-}" in
        true|false) printf '%s' "$1" ;;
        *) printf 'false' ;;
    esac
}

json_int() {
    case "${1:-}" in
        ''|*[!0-9]*) printf '0' ;;
        *) printf '%s' "$1" ;;
    esac
}

AUDIT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_TIMESTAMP_FILE=$(date +"%Y%m%d-%H%M%S")
AUDIT_SRUN_FLAGS=()
if [[ -n "${SLURM_JOB_ID:-}" ]]; then
    AUDIT_SRUN_FLAGS=(--jobid="$SLURM_JOB_ID" --overlap)
fi

K8S_SECURITY_NODE=""
K8S_SECURITY_NODE_COUNT=1
K8S_SECURITY_GPU_NODE_COUNT=1
K8S_SECURITY_GPU_COUNT=0
K8S_SECURITY_GPU_VENDOR="nvidia"
K8S_SECURITY_GPU_MODEL="unknown"
K8S_SECURITY_DRIVER_VERSION="unknown"
K8S_SECURITY_CUDA_VERSION="unknown"
K8S_SECURITY_CHECK_NS="${CLUSTERMAX_AUDIT_K8S_NAMESPACE:-default}"
K8S_SECURITY_CHECK_POD=""
K8S_SECURITY_NODES_JSON='{"items":[]}'
K8S_SECURITY_WORKER_NODES_JSON='[]'
K8S_BMC_IPMI_JSON='{}'
# PwnEscape is a sandbox escape, so the collector reads every worker and
# control-plane host, not only the sampled GPU worker. Each line holds one host
# record for pwnescape.py --fleet.
PWNESCAPE_HOST_RECORDS=""
PWNESCAPE_CONTROL_PLANE_JSON='{"discovered": false, "detail": "The audit did not look for control-plane hosts."}'
# Host-level minimums (driver, runtime, firmware, kernel) on the sampled worker
# say nothing about the other GPU hosts, so the collector reads every GPU host
# and security_fleet.py reports the worst one. Each line holds one host record.
SECURITY_HOST_RECORDS=""
SECURITY_GPU_HOSTS_TOTAL=0
K8S_SECURITY_GPU_NODES=$'\n'
SECURITY_HOST_LIMIT="${CLUSTERMAX_AUDIT_SECURITY_HOST_LIMIT:-32}"
[[ "$SECURITY_HOST_LIMIT" =~ ^[1-9][0-9]*$ ]] || SECURITY_HOST_LIMIT=32

# Append one host record. An empty or partial fact block leaves the host
# unassessed, and the fleet grader then blocks a pass.
add_pwnescape_host_record() {
    local node="$1" role="$2" facts="$3" error="$4" checked=false
    grep -q '^WORKER_GUEST_KERNEL_RUNNING=' <<< "$facts" && checked=true
    PWNESCAPE_HOST_RECORDS+="$(jq -cn --arg node "$node" --arg role "$role" \
        --arg facts "$facts" --arg error "$error" --argjson checked "$checked" '{
          node: $node, role: $role, checked: $checked, facts: $facts,
          error: (if $checked then null else $error end)
        }')"$'\n'
}

# Replace the sampled-worker PwnEscape verdict with the fleet verdict. A
# grader failure must not leave the sampled verdict in place as a pass.
apply_pwnescape_fleet() {
    local fleet
    if fleet=$(printf '%s' "$PWNESCAPE_HOST_RECORDS" \
            | jq -s --argjson control "$PWNESCAPE_CONTROL_PLANE_JSON" \
                '{hosts: ., controlPlane: $control}' \
            | python3 "$WORKLOAD_DIR/pwnescape.py" --fleet 2>/dev/null) \
            && [[ -n "$fleet" ]]; then
        SECURITY_ADVISORY_JSON=$(jq --argjson fleet "$fleet" '.pwnescape = $fleet' \
            <<< "$SECURITY_ADVISORY_JSON")
    else
        SECURITY_ADVISORY_JSON=$(jq '.pwnescape = {
            status: "unknown", scope: "fleet", exploitTested: false,
            reason: "The PwnEscape fleet grader failed. Every host needs CVE-specific patch evidence."
          }' <<< "$SECURITY_ADVISORY_JSON")
    fi
}

# Grade one host's host-check and container-check output. The subshell keeps
# the sampled worker's WORKER_* values intact. Output that lacks the host-check
# marker leaves the host unassessed, and the fleet grader then blocks a pass.
security_host_record() {
    local node="$1" host_out="$2" container_out="$3" error="$4" label_driver="${5:-unknown}"
    if [[ -z "$host_out" ]] || ! grep -q '^WORKER_HOSTNAME=' <<< "$host_out"; then
        jq -cn --arg node "$node" --arg error "$error" \
            '{node: $node, checked: false, error: $error}'
        return 0
    fi
    (
        local key value vendor driver nct=unknown runc=unknown docker=unknown
        local versions advisories janus
        for key in "${!WORKER_@}"; do unset "$key"; done
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^WORKER_[A-Za-z0-9_]+$ ]] || continue
            printf -v "$key" '%s' "$value"
        done < <(grep '^WORKER_' <<< "$host_out")
        if grep -q '^WORKER_CONTAINER_HOSTNAME=' <<< "$container_out"; then
            nct=$(sed -n 's/^WORKER_CONTAINER_SECURITY_NCT_VERSION=//p' <<< "$container_out" | head -1)
            runc=$(sed -n 's/^WORKER_CONTAINER_SECURITY_RUNC_VERSION=//p' <<< "$container_out" | head -1)
            docker=$(sed -n 's/^WORKER_CONTAINER_SECURITY_DOCKER_VERSION=//p' <<< "$container_out" | head -1)
        fi
        vendor=nvidia
        if amd_gpu_check_present "${WORKER_AMD_GPU_COUNT:-0}" "${WORKER_AMD_GPU_MODEL:-}"; then
            vendor=amd
        fi
        driver="${WORKER_DRIVER_VERSION:-unknown}"
        [[ "$driver" == "unknown" || -z "$driver" ]] && driver="$label_driver"
        versions=$(build_security_version_audit "$host_out" "$driver" \
            "${nct:-unknown}" "${runc:-unknown}" "${docker:-unknown}" "$vendor" \
            "${WORKER_NVCC_VERSION:-unknown}" per-host)
        janus=$(json_bool_or_unknown "${WORKER_JANUSCAPE_EXPOSED:-}")
        advisories=$(printf '{%s "_end": null}' \
            "$(build_security_advisory_json \
                --host-facts "$host_out" \
                --bad-epoll-os "${WORKER_OS_ID:-unknown}" \
                --bad-epoll-release "${WORKER_OS_VERSION_ID:-unknown}" \
                --bad-epoll-running "${WORKER_GUEST_KERNEL_RUNNING:-unknown}" \
                --bad-epoll-signature "${WORKER_BAD_EPOLL_SIGNATURE:-unknown}" \
                --bad-epoll-package "${WORKER_BAD_EPOLL_PACKAGE:-unknown}" \
                --bad-epoll-livepatch "${WORKER_BAD_EPOLL_LIVEPATCH:-unknown}" \
                --fragnesia-status "${WORKER_FRAGNESIA_STATUS:-unknown}" \
                --fragnesia-compared-abi "${WORKER_FRAGNESIA_ABI_FLOOR:-unknown}" \
                --ubuntu-kernel-status "${WORKER_UBUNTU_KERNEL_MINIMUM_STATUS:-unknown}" \
                --ubuntu-kernel-abi "${WORKER_UBUNTU_KERNEL_ABI:-unknown}" \
                --ubuntu-kernel-floor "${WORKER_UBUNTU_KERNEL_ABI_FLOOR:-unknown}" \
                --januscape-cpu-exposed "${WORKER_NESTED_CPU_EXPOSED:-false}" \
                --januscape-kvm-exposed "${WORKER_KVM_DEVICE:-false}" \
                --januscape-module "${WORKER_NESTED_MODULE:-none}" \
                --januscape-nested-enabled "${WORKER_NESTED_ENABLED:-unknown}" \
                --januscape-exposed "$janus" \
                --januscape-status "${WORKER_JANUSCAPE_STATUS:-unknown}" \
                --qemu-status "${WORKER_QEMU_CVE_2024_3446_STATUS:-unknown}" \
                --vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")" \
            | jq -c 'del(._end)' 2>/dev/null) || advisories='{}'
        jq -cn --arg node "$node" --argjson versions "${versions:-{\}}" \
            --argjson advisories "${advisories:-{\}}" \
            '{node: $node, checked: true, securityVersions: $versions, security: $advisories}' \
            2>/dev/null \
            || jq -cn --arg node "$node" \
                '{node: $node, checked: false, error: "The host evidence could not be graded."}'
    )
}

add_security_host_record() {
    SECURITY_HOST_RECORDS+="$(security_host_record "$@")"$'\n'
}

# Replace each host-level check with its fleet verdict. A grader failure must
# not leave the sampled verdicts in place as a fleet pass.
apply_security_host_fleet() {
    local merged
    [[ -n "$SECURITY_HOST_RECORDS" ]] || return 0
    if merged=$(printf '%s' "$SECURITY_HOST_RECORDS" \
            | jq -s --argjson versions "$SECURITY_VERSION_AUDIT_JSON" \
                --argjson security "$SECURITY_ADVISORY_JSON" \
                --argjson total "$(json_int "$SECURITY_GPU_HOSTS_TOTAL")" \
                '{sampled: {securityVersions: $versions, security: $security},
                  hostsTotal: $total, hosts: .}' \
            | python3 "$WORKLOAD_DIR/security_fleet.py" 2>/dev/null) \
            && [[ -n "$merged" ]]; then
        SECURITY_VERSION_AUDIT_JSON=$(jq -c '.securityVersions' <<< "$merged")
        SECURITY_ADVISORY_JSON=$(jq -c '.security' <<< "$merged")
    else
        local reason="The fleet grader failed, so this check covers only the sampled worker and is unverified for the other GPU hosts."
        SECURITY_VERSION_AUDIT_JSON=$(jq -c --arg reason "$reason" '
            reduce ("nvidiaDriver","amdDriver","nvidiaContainerToolkit","runc","docker","connectxFirmware","dcgm") as $k
              (.; if (.[$k] | type) == "object" and ((.[$k].status // "") | IN("fail") | not)
                  then .[$k].status = "unknown" | .[$k].detail = $reason else . end)' \
            <<< "$SECURITY_VERSION_AUDIT_JSON")
    fi
    print_info "Host-level security checks: read $(grep -c '"checked":true' <<< "$SECURITY_HOST_RECORDS" || true) of ${SECURITY_GPU_HOSTS_TOTAL} GPU host(s)"
}

cleanup_k8s_security_pod() {
    if [[ -n "$K8S_SECURITY_CHECK_POD" ]]; then
        kubectl delete pod "$K8S_SECURITY_CHECK_POD" \
            -n "$K8S_SECURITY_CHECK_NS" --ignore-not-found=true --wait=false \
            --request-timeout=30s >/dev/null 2>&1 || true
        K8S_SECURITY_CHECK_POD=""
    fi
}
trap cleanup_k8s_security_pod EXIT

prepare_k8s_security_pod() {
    local nodes_json nv_total amd_total resource_key apply_error
    nodes_json=$(kubectl get nodes -o json --request-timeout=60s)
    K8S_SECURITY_NODES_JSON="$nodes_json"
    K8S_SECURITY_WORKER_NODES_JSON=$(jq -c '
        [.items[] | select(
          ((.metadata.labels // {}) | has("node-role.kubernetes.io/control-plane") | not)
          and ((.metadata.labels // {}) | has("node-role.kubernetes.io/master") | not)
        )] as $workers
        | if ($workers | length) > 0 then $workers else .items end' <<< "$nodes_json")
    K8S_SECURITY_NODE_COUNT=$(jq -r 'length' <<< "$K8S_SECURITY_WORKER_NODES_JSON")
    nv_total=$(jq '[.[].status.capacity["nvidia.com/gpu"] // "0" | tonumber] | add // 0' <<< "$K8S_SECURITY_WORKER_NODES_JSON")
    amd_total=$(jq '[.[].status.capacity["amd.com/gpu"] // "0" | tonumber] | add // 0' <<< "$K8S_SECURITY_WORKER_NODES_JSON")
    resource_key="nvidia.com/gpu"
    K8S_SECURITY_GPU_COUNT="$nv_total"
    if [[ "$nv_total" -eq 0 && "$amd_total" -gt 0 ]]; then
        resource_key="amd.com/gpu"
        K8S_SECURITY_GPU_COUNT="$amd_total"
        K8S_SECURITY_GPU_VENDOR="amd"
    fi
    K8S_SECURITY_GPU_NODES=$'\n'"$(jq -r --arg key "$resource_key" \
        '.[] | select((.status.capacity[$key] // "0" | tonumber) > 0) | .metadata.name' \
        <<< "$K8S_SECURITY_WORKER_NODES_JSON")"$'\n'
    K8S_SECURITY_GPU_NODE_COUNT=$(jq -r --arg key "$resource_key" \
        '[.[] | select((.status.capacity[$key] // "0" | tonumber) > 0)] | length' \
        <<< "$K8S_SECURITY_WORKER_NODES_JSON")
    K8S_SECURITY_NODE=$(jq -r --arg key "$resource_key" '
        ([.[] | select((.status.capacity[$key] // "0" | tonumber) > 0) | .metadata.name]
         + [.[].metadata.name]) | first // empty' <<< "$K8S_SECURITY_WORKER_NODES_JSON")
    if [[ -z "$K8S_SECURITY_NODE" ]]; then
        print_error "No Kubernetes node is available for the security host check."
        return 1
    fi
    K8S_SECURITY_GPU_MODEL=$(jq -r --arg node "$K8S_SECURITY_NODE" '
        .items[] | select(.metadata.name == $node)
        | (.metadata.labels["nvidia.com/gpu.product"]
           // .metadata.labels["amd.com/gpu.product-name"] // "unknown")' \
        <<< "$nodes_json")
    K8S_SECURITY_DRIVER_VERSION=$(jq -r --arg node "$K8S_SECURITY_NODE" '
        .items[] | select(.metadata.name == $node) | .metadata.labels as $l
        | ($l["amd.com/gpu.driver-version"]
           // (if ($l["nvidia.com/cuda.driver.major"] // "") != ""
               then (($l["nvidia.com/cuda.driver.major"] // "") + "."
                     + ($l["nvidia.com/cuda.driver.minor"] // "0") + "."
                     + ($l["nvidia.com/cuda.driver.rev"] // "0"))
               else "unknown" end))' <<< "$nodes_json")
    K8S_SECURITY_CUDA_VERSION=$(jq -r --arg node "$K8S_SECURITY_NODE" '
        .items[] | select(.metadata.name == $node) | .metadata.labels as $l
        | if ($l["nvidia.com/cuda.runtime.major"] // "") != ""
          then (($l["nvidia.com/cuda.runtime.major"] // "") + "."
                + ($l["nvidia.com/cuda.runtime.minor"] // "0"))
          else "unknown" end' <<< "$nodes_json")

    create_k8s_security_pod "$K8S_SECURITY_NODE"
}

create_k8s_security_pod() {
    local node="$1" apply_error
    cleanup_k8s_security_pod
    K8S_SECURITY_NODE="$node"
    K8S_SECURITY_CHECK_POD="cmax-audit-security-$$-${RANDOM}"
    apply_error=$(kubectl apply --request-timeout=60s -f - 2>&1 >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${K8S_SECURITY_CHECK_POD}
  namespace: ${K8S_SECURITY_CHECK_NS}
  labels:
    app.kubernetes.io/name: clustermax-audit-security
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 5
  activeDeadlineSeconds: 600
  nodeName: ${node}
  hostPID: true
  hostNetwork: true
  tolerations:
  - operator: Exists
  containers:
  - name: check
    image: ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    imagePullPolicy: IfNotPresent
    command: ["sleep", "480"]
    securityContext:
      privileged: true
      runAsUser: 0
    volumeMounts:
    - name: host-root
      mountPath: /host
    - name: host-proc
      mountPath: /host/proc
  volumes:
  - name: host-root
    hostPath:
      path: /
      type: Directory
  - name: host-proc
    hostPath:
      path: /proc
      type: Directory
EOF
) || {
        print_error "Could not create the Kubernetes security check pod: ${apply_error}"
        return 1
    }
    if ! kubectl wait --for=condition=Ready "pod/${K8S_SECURITY_CHECK_POD}" \
            -n "$K8S_SECURITY_CHECK_NS" --timeout=120s \
            --request-timeout=150s >/dev/null 2>&1; then
        print_error "The Kubernetes security check pod did not become ready."
        return 1
    fi
}

run_k8s_security_script() {
    local fragnesia_abi_minimum ubuntu_kernel_abi_minimum
    fragnesia_abi_minimum=$(minimum_version \
        components.ubuntuNoble.packages.linuxFragnesia.abi)
    ubuntu_kernel_abi_minimum=$(minimum_version \
        components.ubuntuNoble.packages.linux.abi)
    kubectl exec -i -n "$K8S_SECURITY_CHECK_NS" \
        --request-timeout=300s "$K8S_SECURITY_CHECK_POD" -- \
        chroot /host env CLUSTERMAX_AUDIT_SCOPE=security \
        CLUSTERMAX_AUDIT_HARNESS=k8s \
        CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host \
        CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$fragnesia_abi_minimum" \
        CLUSTERMAX_UBUNTU_KERNEL_ABI_MINIMUM="$ubuntu_kernel_abi_minimum" bash -s
}

k8s_bmc_record_for_current_pod() {
    local node="$1" evidence
    evidence=$(run_k8s_security_script <<'EOF' 2>/dev/null || true
device=false
if [ -c /dev/ipmi0 ] || [ -c /dev/ipmi/0 ]; then device=true; fi
path=$(command -v ipmitool 2>/dev/null || true)
installed=false
[ -n "$path" ] && installed=true
mc=not-installed
chassis=not-installed
if [ -n "$path" ]; then
  mc=unknown
  chassis=unknown
  if out=$(timeout 5 "$path" mc info 2>&1); then mc=allowed
  elif [ "$?" -eq 124 ]; then mc=unknown
  elif printf '%s' "$out" | grep -qiE 'permission denied|operation not permitted|access denied'; then mc=blocked
  elif printf '%s' "$out" | grep -qiE 'Get Device ID command failed: 0xff Unspecified error'; then mc=error-response; fi
  if out=$(timeout 5 "$path" chassis status 2>&1); then chassis=allowed
  elif [ "$?" -eq 124 ]; then chassis=unknown
  elif printf '%s' "$out" | grep -qiE 'permission denied|operation not permitted|access denied'; then chassis=blocked
  elif printf '%s' "$out" | grep -qiE '(Get Device ID command failed|Get Chassis Status failed|Unable to get Chassis Status): 0xff Unspecified error'; then chassis=error-response; fi
fi
printf 'DEVICE=%s\nPATH=%s\nINSTALLED=%s\nMC=%s\nCHASSIS=%s\n' \
  "$device" "$path" "$installed" "$mc" "$chassis"
EOF
)
    local device path installed mc chassis
    device=$(grep '^DEVICE=' <<< "$evidence" | cut -d= -f2- || true)
    path=$(grep '^PATH=' <<< "$evidence" | cut -d= -f2- || true)
    installed=$(grep '^INSTALLED=' <<< "$evidence" | cut -d= -f2- || true)
    mc=$(grep '^MC=' <<< "$evidence" | cut -d= -f2- || true)
    chassis=$(grep '^CHASSIS=' <<< "$evidence" | cut -d= -f2- || true)
    if [[ -z "$device" || -z "$installed" || -z "$mc" || -z "$chassis" ]]; then
        jq -n --arg node "$node" '{
          node: $node, checked: false, devicePresent: "unknown",
          ipmitoolInstalled: "unknown", ipmitoolPath: "unknown",
          mcInfoAccess: "unknown", chassisStatusAccess: "unknown",
          exposed: "unknown", error: "BMC and IPMI probe returned no evidence"
        }'
        return 0
    fi
    jq -n --arg node "$node" --arg path "$path" --arg device "$device" \
        --arg installed "$installed" --arg mc "$mc" --arg chassis "$chassis" '{
          node: $node,
          checked: (($device == "false") or ($mc == "allowed") or ($chassis == "allowed")
            or ((($mc == "blocked") or ($mc == "error-response"))
              and (($chassis == "blocked") or ($chassis == "error-response")))),
          assessmentScope: "local-read-commands",
          errorResponseIsAccessDenial: false,
          devicePresent: ($device == "true"),
          ipmitoolInstalled: ($installed == "true"),
          ipmitoolPath: (if $path == "" then "not-installed" else $path end),
          mcInfoAccess: $mc,
          chassisStatusAccess: $chassis,
          exposed: (($mc == "allowed") or ($chassis == "allowed"))
        }'
}

k8s_pwnescape_record_for_current_pod() {
    local node="$1" role="$2" facts
    facts=$(run_k8s_security_script \
        < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null || true)
    add_pwnescape_host_record "$node" "$role" "$facts" \
        "The host-root pod returned no PwnEscape facts."
}

k8s_node_role() {
    jq -r --arg node "$1" '.items[] | select(.metadata.name == $node)
        | (.metadata.labels // {}) as $labels
        | if ($labels | has("node-role.kubernetes.io/control-plane"))
             or ($labels | has("node-role.kubernetes.io/master"))
          then "control-plane" else "worker" end' <<< "$K8S_SECURITY_NODES_JSON"
}

k8s_label_driver() {
    jq -r --arg node "$1" '.items[] | select(.metadata.name == $node) | .metadata.labels as $l
        | ($l["amd.com/gpu.driver-version"]
           // (if ($l["nvidia.com/cuda.driver.major"] // "") != ""
               then (($l["nvidia.com/cuda.driver.major"] // "") + "."
                     + ($l["nvidia.com/cuda.driver.minor"] // "0") + "."
                     + ($l["nvidia.com/cuda.driver.rev"] // "0"))
               else "unknown" end))' <<< "$K8S_SECURITY_NODES_JSON" 2>/dev/null || echo unknown
}

# Read one more GPU host through the current host-root pod: the same host and
# container checks the sampled worker ran.
k8s_security_host_record_for_current_pod() {
    local node="$1" host_out container_out=""
    host_out=$(run_k8s_security_script < "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || true)
    if [[ -f "$WORKLOAD_DIR/container-check.sh" ]]; then
        container_out=$(run_k8s_security_script \
            < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || true)
    fi
    add_security_host_record "$node" "$host_out" "$container_out" \
        "The host-root pod returned no host evidence." "$(k8s_label_driver "$node")"
}

k8s_bmc_unchecked_record() {
    jq -n --arg node "$1" --arg error "$2" '{
      node: $node, checked: false, devicePresent: "unknown",
      ipmitoolInstalled: "unknown", ipmitoolPath: "unknown",
      mcInfoAccess: "unknown", chassisStatusAccess: "unknown",
      exposed: "unknown", error: $error
    }'
}

# Visit every registered node once. Each visit reads PwnEscape facts, because
# a sandbox escape on any worker or control-plane host defeats the tenant
# boundary. A visit to a worker node also runs the BMC probe within its limit.
collect_k8s_host_fleet() {
    local first_node="$K8S_SECURITY_NODE" node role limit records="" checked_count=1
    local bmc_nodes control_count pod_ready is_gpu gpu_read=0
    limit="${CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT:-32}"
    [[ "$limit" =~ ^[1-9][0-9]*$ ]] || limit=32
    bmc_nodes=$'\n'"$(jq -r '.[].metadata.name' <<< "$K8S_SECURITY_WORKER_NODES_JSON")"$'\n'
    control_count=$(jq '[.items[] | (.metadata.labels // {})
        | select(has("node-role.kubernetes.io/control-plane")
                 or has("node-role.kubernetes.io/master"))] | length' \
        <<< "$K8S_SECURITY_NODES_JSON")
    if [[ "$control_count" -gt 0 ]]; then
        PWNESCAPE_CONTROL_PLANE_JSON=$(jq -cn --argjson count "$control_count" '{
          discovered: true,
          detail: ("The cluster registers " + ($count | tostring) + " control-plane node(s).")
        }')
    else
        PWNESCAPE_CONTROL_PLANE_JSON='{"discovered": false, "detail": "No node carries a control-plane role label, so the API server and etcd run on hosts that this audit cannot read, for example a managed control plane."}'
    fi
    print_info "PwnEscape: reading every node; ${control_count} control-plane node(s) are registered"

    records="$(k8s_bmc_record_for_current_pod "$first_node")"
    k8s_pwnescape_record_for_current_pod "$first_node" "$(k8s_node_role "$first_node")"
    SECURITY_GPU_HOSTS_TOTAL=$(grep -c . <<< "$K8S_SECURITY_GPU_NODES" || true)
    if [[ "$K8S_SECURITY_GPU_NODES" == *$'\n'"$first_node"$'\n'* ]]; then
        add_security_host_record "$first_node" "$WORKER_CHECK_OUTPUT" \
            "${CONTAINER_CHECK_OUTPUT:-}" "The sampled worker returned no host evidence." \
            "$K8S_SECURITY_DRIVER_VERSION"
        gpu_read=1
    fi
    while IFS= read -r node; do
        [[ -n "$node" && "$node" != "$first_node" ]] || continue
        role=$(k8s_node_role "$node")
        is_gpu=false
        [[ "$K8S_SECURITY_GPU_NODES" == *$'\n'"$node"$'\n'* ]] && is_gpu=true
        pod_ready=true
        if create_k8s_security_pod "$node"; then
            k8s_pwnescape_record_for_current_pod "$node" "$role"
            if [[ "$is_gpu" == true ]]; then
                if (( gpu_read >= SECURITY_HOST_LIMIT )); then
                    add_security_host_record "$node" "" "" \
                        "Skipped because the GPU host limit is ${SECURITY_HOST_LIMIT} (CLUSTERMAX_AUDIT_SECURITY_HOST_LIMIT)."
                else
                    k8s_security_host_record_for_current_pod "$node"
                    gpu_read=$((gpu_read + 1))
                fi
            fi
        else
            pod_ready=false
            add_pwnescape_host_record "$node" "$role" "" \
                "The privileged host-root pod could not be created."
            [[ "$is_gpu" == true ]] && add_security_host_record "$node" "" "" \
                "The privileged host-root pod could not be created."
        fi
        [[ "$bmc_nodes" == *$'\n'"$node"$'\n'* ]] || continue
        if (( checked_count >= limit )); then
            records+=$'\n'"$(k8s_bmc_unchecked_record "$node" \
                "BMC and IPMI probe skipped because the node limit is ${limit}")"
            continue
        fi
        checked_count=$((checked_count + 1))
        if [[ "$pod_ready" == true ]]; then
            records+=$'\n'"$(k8s_bmc_record_for_current_pod "$node")"
        else
            records+=$'\n'"$(k8s_bmc_unchecked_record "$node" \
                "privileged host-root pod could not be created")"
        fi
    done < <(jq -r '.items[].metadata.name' <<< "$K8S_SECURITY_NODES_JSON")
    K8S_BMC_IPMI_JSON=$(printf '%s\n' "$records" | jq -s '
        map(select(type == "object")) as $hosts
        | [$hosts[] | select(.checked == true)] as $checked
        | [$hosts[] | select(.exposed == true)] as $exposed
        | {
            exposed: (($exposed | length) > 0),
            accessMode: "administrative-privileged-host-root-pod",
            scope: "The Kubernetes identity could create a privileged pod that mounted the worker host root. This check did not test access from an ordinary workload pod.",
            ordinaryPodExposureTested: false,
            nodesTotal: ($hosts | length),
            nodesChecked: ($checked | length),
            nodeCoverageComplete: (($hosts | length) == ($checked | length)),
            exposedNodes: [$exposed[].node],
            unassessedNodes: [$hosts[] | select(.checked != true) | .node],
            hosts: $hosts
          }')
    cleanup_k8s_security_pod
}

# Print the short names of the slurmctld and slurmdbd hosts. `scontrol show
# config` reports `SlurmctldHost[0] = name(addr)` and `AccountingStorageHost =
# name`, and a configless or older daemon may report neither.
slurm_control_hosts() {
    scontrol show config 2>/dev/null | awk -F' = ' '
        $1 ~ /^SlurmctldHost\[[0-9]+\] *$/ || $1 ~ /^ControlMachine *$/ \
            || $1 ~ /^BackupController *$/ || $1 ~ /^AccountingStorageHost *$/ {
            host = $2
            sub(/\(.*/, "", host)
            sub(/\..*/, "", host)
            gsub(/[[:space:]]/, "", host)
            if (host != "" && host != "(null)" && host != "localhost") print host
        }' | sort -u || true
}

# Run the PwnEscape fact script on one Slurm node. A node in the current
# allocation runs as an overlapping step. Any other node gets its own short
# allocation, and --immediate keeps a busy node from blocking the audit.
slurm_pwnescape_facts_on_node() {
    local node="$1" partition="$2"
    if [[ -n "${SLURM_JOB_ID:-}" && "$SLURM_ALLOCATION_NODES" == *$'\n'"$node"$'\n'* ]]; then
        srun "${AUDIT_SRUN_FLAGS[@]}" -N1 --ntasks=1 -w "$node" --time=2:00 \
            bash -s < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null
    else
        env -u SLURM_JOB_ID -u SLURM_JOBID srun -p "$partition" -N1 --ntasks=1 \
            -w "$node" --time=2:00 --immediate=30 \
            bash -s < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null
    fi
}

# Read every compute node, the login host that runs this audit, and every
# slurmctld and slurmdbd host. A control host that is not a compute node is
# read over ssh in batch mode, so the audit never prompts for a credential.
collect_slurm_pwnescape_fleet() {
    local rows node partition host local_host tmp batch="" batch_size=0 concurrency
    local compute_nodes control_hosts facts
    concurrency="${CLUSTERMAX_AUDIT_PWNESCAPE_CONCURRENCY:-16}"
    [[ "$concurrency" =~ ^[1-9][0-9]*$ ]] || concurrency=16
    SLURM_ALLOCATION_NODES=$'\n'
    if [[ -n "${SLURM_JOB_NODELIST:-}" ]]; then
        SLURM_ALLOCATION_NODES+="$(scontrol show hostnames "$SLURM_JOB_NODELIST" 2>/dev/null)"$'\n'
    fi
    # One row per node, in the node's first listed partition.
    rows=$(sinfo -N -h -o '%N|%P' 2>/dev/null | tr -d '*' | awk -F'|' '!seen[$1]++' || true)
    compute_nodes=$'\n'"$(cut -d'|' -f1 <<< "$rows")"$'\n'
    tmp=$(mktemp -d)
    # Launch a bounded batch, wait for it, then launch the next batch. This
    # avoids `wait -n`, which older bash releases on login nodes do not have.
    while IFS='|' read -r node partition; do
        [[ -n "$node" ]] || continue
        slurm_pwnescape_facts_on_node "$node" "$partition" > "$tmp/$node.facts" &
        batch_size=$((batch_size + 1))
        if (( batch_size >= concurrency )); then
            wait
            batch_size=0
        fi
    done <<< "$rows"
    wait
    while IFS='|' read -r node partition; do
        [[ -n "$node" ]] || continue
        add_pwnescape_host_record "$node" worker "$(cat "$tmp/$node.facts" 2>/dev/null)" \
            "srun could not start on this node; it may be busy, down, or outside the tenant's partitions."
    done <<< "$rows"

    local_host=$(hostname -s 2>/dev/null || hostname)
    add_pwnescape_host_record "$local_host" login \
        "$(bash "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null)" \
        "The login host returned no PwnEscape facts."

    control_hosts=$(slurm_control_hosts)
    if [[ -n "$control_hosts" ]]; then
        PWNESCAPE_CONTROL_PLANE_JSON=$(jq -cn --arg hosts "$control_hosts" '{
          discovered: true,
          detail: ("scontrol reports the control hosts " + ($hosts | split("\n") | join(", ")) + ".")
        }')
    else
        PWNESCAPE_CONTROL_PLANE_JSON='{"discovered": false, "detail": "scontrol did not report a slurmctld or slurmdbd host."}'
    fi
    while IFS= read -r host; do
        [[ -n "$host" ]] || continue
        if [[ "$host" == "$local_host" ]]; then
            facts=$(bash "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null)
        elif [[ "$compute_nodes" == *$'\n'"$host"$'\n'* ]]; then
            facts=$(cat "$tmp/$host.facts" 2>/dev/null)
        else
            facts=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" bash -s \
                < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null || true)
        fi
        add_pwnescape_host_record "$host" control-plane "$facts" \
            "The control host was not reachable from the login host by srun or batch-mode ssh."
    done <<< "$control_hosts"
    rm -rf "$tmp"
    print_info "PwnEscape: read $(grep -c '"checked":true' <<< "$PWNESCAPE_HOST_RECORDS" || true) host(s)"
}

# Run one focused check script on one Slurm GPU node, the way the PwnEscape
# fleet reads its nodes: an overlapping step inside the current allocation,
# otherwise a short allocation that --immediate keeps from waiting on a busy
# node.
slurm_security_script_on_node() {
    local node="$1" partition="$2" script="$3" limit="$4"
    if [[ -n "${SLURM_JOB_ID:-}" && "$SLURM_ALLOCATION_NODES" == *$'\n'"$node"$'\n'* ]]; then
        srun "${AUDIT_SRUN_FLAGS[@]}" -N1 --ntasks=1 -w "$node" --gres=gpu:1 \
            --time="$limit" env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
            bash -s < "$WORKLOAD_DIR/$script" 2>/dev/null
    else
        env -u SLURM_JOB_ID -u SLURM_JOBID srun -p "$partition" -N1 --ntasks=1 \
            -w "$node" --gres=gpu:1 --time="$limit" --immediate=30 \
            env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
            bash -s < "$WORKLOAD_DIR/$script" 2>/dev/null
    fi
}

# Read every GPU node with the sampled worker's host and container checks.
collect_slurm_security_host_fleet() {
    local rows node partition tmp batch_size=0 concurrency sampled n_read=0
    concurrency="${CLUSTERMAX_AUDIT_SECURITY_CONCURRENCY:-8}"
    [[ "$concurrency" =~ ^[1-9][0-9]*$ ]] || concurrency=8
    SLURM_ALLOCATION_NODES=$'\n'
    if [[ -n "${SLURM_JOB_NODELIST:-}" ]]; then
        SLURM_ALLOCATION_NODES+="$(scontrol show hostnames "$SLURM_JOB_NODELIST" 2>/dev/null)"$'\n'
    fi
    # One row per GPU node, in the node's first listed GPU partition.
    rows=$(sinfo -N -h -o '%N|%P|%G' 2>/dev/null | tr -d '*' \
        | awk -F'|' 'tolower($3) ~ /gpu/ && !seen[$1]++ {print $1 "|" $2}' || true)
    SECURITY_GPU_HOSTS_TOTAL=$(grep -c . <<< "$rows" || true)
    sampled="${WORKER_HOSTNAME:-}"
    tmp=$(mktemp -d)
    while IFS='|' read -r node partition; do
        [[ -n "$node" && "$node" != "$sampled" ]] || continue
        n_read=$((n_read + 1))
        (( n_read < SECURITY_HOST_LIMIT )) || continue
        {
            slurm_security_script_on_node "$node" "$partition" host-check.sh 5:00 > "$tmp/$node.host" || true
            if [[ -s "$tmp/$node.host" && -f "$WORKLOAD_DIR/container-check.sh" ]]; then
                slurm_security_script_on_node "$node" "$partition" container-check.sh 2:00 \
                    > "$tmp/$node.container" || true
            fi
        } &
        batch_size=$((batch_size + 1))
        if (( batch_size >= concurrency )); then
            wait
            batch_size=0
        fi
    done <<< "$rows"
    wait
    n_read=0
    while IFS='|' read -r node partition; do
        [[ -n "$node" ]] || continue
        if [[ "$node" == "$sampled" ]]; then
            add_security_host_record "$node" "$WORKER_CHECK_OUTPUT" \
                "${CONTAINER_CHECK_OUTPUT:-}" "The sampled worker returned no host evidence."
            continue
        fi
        n_read=$((n_read + 1))
        if (( n_read >= SECURITY_HOST_LIMIT )); then
            add_security_host_record "$node" "" "" \
                "Skipped because the GPU host limit is ${SECURITY_HOST_LIMIT} (CLUSTERMAX_AUDIT_SECURITY_HOST_LIMIT)."
            continue
        fi
        add_security_host_record "$node" "$(cat "$tmp/$node.host" 2>/dev/null)" \
            "$(cat "$tmp/$node.container" 2>/dev/null)" \
            "srun could not start on this node; it may be busy, down, or outside the tenant's partitions."
    done <<< "$rows"
    rm -rf "$tmp"
}

print_header "1. SECURITY WORKER"
print_section "Select GPU worker"
GPU_PARTITION="local"
GPU_SRUN_SCOPE_ARGS=()
if [[ "$SECURITY_HARNESS" == "slurm" ]]; then
    GPU_PARTITION="${CLUSTERMAX_GPU_PARTITION:-${SLURM_JOB_PARTITION:-}}"
    if [[ -z "$GPU_PARTITION" ]] && command -v sinfo >/dev/null 2>&1; then
        SINFO_ROWS=$(sinfo -N -o "%P|%N|%G" --noheader 2>/dev/null || true)
        GPU_PARTITION=$(select_gpu_partition "$SINFO_ROWS")
    fi
    if [[ -z "$GPU_PARTITION" ]]; then
        print_error "No GPU partition was detected."
        print_detail "Set CLUSTERMAX_GPU_PARTITION or run inside a GPU allocation."
        exit 1
    fi
    if [[ -z "${SLURM_JOB_ID:-}" ]]; then
        GPU_SRUN_SCOPE_ARGS=(-p "$GPU_PARTITION")
    fi
elif [[ "$SECURITY_HARNESS" == "k8s" ]]; then
    prepare_k8s_security_pod
    GPU_PARTITION="$K8S_SECURITY_NODE"
fi
print_info "Target: ${GPU_PARTITION}"

print_section "Collect security host evidence"
if [[ "$SECURITY_HARNESS" == "slurm" ]]; then
    WORKER_CHECK_OUTPUT=$(srun "${AUDIT_SRUN_FLAGS[@]}" \
        "${GPU_SRUN_SCOPE_ARGS[@]}" \
        -N1 --ntasks=1 --gres=gpu:"$(slurm_job_gpus_per_node)" --time=5:00 \
        env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
        bash -s < "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || true)
elif [[ "$SECURITY_HARNESS" == "standalone" ]]; then
    WORKER_CHECK_OUTPUT=$(CLUSTERMAX_AUDIT_SCOPE=security \
        CLUSTERMAX_AUDIT_HARNESS=standalone \
        bash "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || true)
else
    WORKER_CHECK_OUTPUT=$(run_k8s_security_script \
        < "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || true)
fi
if [[ -z "$WORKER_CHECK_OUTPUT" ]] \
        || ! grep -q '^WORKER_HOSTNAME=' <<< "$WORKER_CHECK_OUTPUT"; then
    print_error "The security host check did not return worker evidence."
    exit 1
fi

while IFS='=' read -r key value; do
    [[ "$key" =~ ^WORKER_[A-Za-z0-9_]+$ ]] || continue
    printf -v "$key" '%s' "$value"
done < <(grep '^WORKER_' <<< "$WORKER_CHECK_OUTPUT")
print_info "Security host evidence: ${WORKER_HOSTNAME:-unknown}"

print_header "2. SECURITY RUNTIME"
print_section "Collect container runtime versions"
CONTAINER_CHECK_OK="false"
SECURITY_DOCKER_VERSION="unknown"
SECURITY_NCT_VERSION="unknown"
SECURITY_RUNC_VERSION="unknown"
if [[ -f "$WORKLOAD_DIR/container-check.sh" ]]; then
    if [[ "$SECURITY_HARNESS" == "slurm" ]]; then
        CONTAINER_CHECK_OUTPUT=$(srun "${AUDIT_SRUN_FLAGS[@]}" \
            "${GPU_SRUN_SCOPE_ARGS[@]}" \
            -N1 --ntasks=1 --gres=gpu:1 --time=2:00 \
            env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
            bash -s < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || true)
    elif [[ "$SECURITY_HARNESS" == "standalone" ]]; then
        CONTAINER_CHECK_OUTPUT=$(CLUSTERMAX_AUDIT_SCOPE=security \
            CLUSTERMAX_AUDIT_HARNESS=standalone \
            bash "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || true)
    else
        CONTAINER_CHECK_OUTPUT=$(run_k8s_security_script \
            < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || true)
    fi
    if grep -q '^WORKER_CONTAINER_HOSTNAME=' <<< "$CONTAINER_CHECK_OUTPUT"; then
        CONTAINER_CHECK_OK="true"
        while IFS='=' read -r key value; do
            case "$key" in
                WORKER_CONTAINER_SECURITY_DOCKER_VERSION)
                    SECURITY_DOCKER_VERSION="$value"
                    ;;
                WORKER_CONTAINER_SECURITY_NCT_VERSION)
                    SECURITY_NCT_VERSION="$value"
                    ;;
                WORKER_CONTAINER_SECURITY_RUNC_VERSION)
                    SECURITY_RUNC_VERSION="$value"
                    ;;
            esac
        done < <(grep '^WORKER_CONTAINER_' <<< "$CONTAINER_CHECK_OUTPUT")
        print_info "Container runtime versions were collected."
    else
        print_warn "Container runtime versions could not be collected."
    fi
else
    print_warn "The container runtime check is unavailable."
fi

print_header "3. SECURITY EVALUATION"
print_section "Evaluate security versions"
AMD_GPUS_PRESENT="false"
if [[ "${WORKER_AMD_GPU_COUNT:-0}" =~ ^[1-9][0-9]*$ ]] \
        || [[ -n "${WORKER_AMD_GPU_MODEL:-}" \
            && "${WORKER_AMD_GPU_MODEL}" != "unknown" ]] \
        || [[ "$SECURITY_HARNESS" == "k8s" \
            && "$K8S_SECURITY_GPU_VENDOR" == "amd" \
            && "$K8S_SECURITY_GPU_COUNT" -gt 0 ]]; then
    AMD_GPUS_PRESENT="true"
fi

SECURITY_GPU_VENDOR="nvidia"
GPU_MODEL="${WORKER_GPU_MODEL:-unknown}"
DRIVER_VERSION="${WORKER_DRIVER_VERSION:-unknown}"
NVIDIA_DRIVER_VERSION="${WORKER_DRIVER_VERSION:-unknown}"
GPU_COUNT="${WORKER_GPU_COUNT:-0}"
GPU_MEMORY="${WORKER_GPU_MEMORY:-0}"
if [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
    SECURITY_GPU_VENDOR="amd"
    GPU_MODEL="${WORKER_AMD_GPU_MODEL:-unknown}"
    DRIVER_VERSION="${WORKER_AMD_DRIVER_VERSION:-unknown}"
    GPU_COUNT="${WORKER_AMD_GPU_COUNT:-0}"
    GPU_MEMORY="${WORKER_AMD_GPU_MEMORY:-0}"
fi
if [[ "$SECURITY_HARNESS" == "k8s" ]]; then
    if [[ "$GPU_MODEL" == "unknown" ]]; then
        GPU_MODEL="$K8S_SECURITY_GPU_MODEL"
    fi
    if [[ "$DRIVER_VERSION" == "unknown" ]]; then
        DRIVER_VERSION="$K8S_SECURITY_DRIVER_VERSION"
        [[ "$SECURITY_GPU_VENDOR" == "nvidia" ]] \
            && NVIDIA_DRIVER_VERSION="$K8S_SECURITY_DRIVER_VERSION"
    fi
    if [[ "${WORKER_CUDA_VERSION:-unknown}" == "unknown" ]]; then
        WORKER_CUDA_VERSION="$K8S_SECURITY_CUDA_VERSION"
    fi
    if [[ "$GPU_COUNT" == "0" && "$K8S_SECURITY_GPU_COUNT" -gt 0 ]]; then
        GPU_COUNT="$K8S_SECURITY_GPU_COUNT"
    fi
fi

# A standalone target is the whole fleet, so a bounded local process/socket
# scan can prove dcgm-exporter absent. A Slurm worker sample cannot make that
# fleet-wide claim and deliberately leaves the value unknown.
if [[ "$SECURITY_HARNESS" == "standalone" ]]; then
    DCGM_EXPORTER_PRESENT=false
    if pgrep -x dcgm-exporter >/dev/null 2>&1 \
            || systemctl is-active dcgm-exporter >/dev/null 2>&1 \
            || ss -lnt 2>/dev/null | grep -qE ':9400([[:space:]]|$)'; then
        DCGM_EXPORTER_PRESENT=true
    fi
elif [[ "$SECURITY_HARNESS" == "k8s" ]]; then
    if K8S_SECURITY_PODS_JSON=$(kubectl get pods --all-namespaces -o json \
            --request-timeout=60s 2>/dev/null); then
        DCGM_EXPORTER_IMAGE=$(jq -r '
            [.items[]?.spec.containers[]?
             | select(((.name // "") + " " + (.image // ""))
                      | test("dcgm-exporter"; "i"))
             | .image] | first // ""' <<< "$K8S_SECURITY_PODS_JSON")
        if [[ -n "$DCGM_EXPORTER_IMAGE" ]]; then
            DCGM_EXPORTER_PRESENT=true
        else
            DCGM_EXPORTER_PRESENT=false
        fi
    else
        DCGM_EXPORTER_PRESENT=unknown
    fi
fi

SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit \
    "$WORKER_CHECK_OUTPUT" "${NVIDIA_DRIVER_VERSION:-unknown}" \
    "$SECURITY_NCT_VERSION" "$SECURITY_RUNC_VERSION" \
    "$SECURITY_DOCKER_VERSION" "$SECURITY_GPU_VENDOR" \
    "${WORKER_NVCC_VERSION:-unknown}" "$SECURITY_HARNESS")
print_info "Security version policy was evaluated for ${SECURITY_GPU_VENDOR}."

RDMA_TYPE="none"
case ",${WORKER_RDMA_LINK_LAYERS:-}," in
    *,InfiniBand,*|*,infiniband,*) RDMA_TYPE="infiniband" ;;
    *,Ethernet,*|*,ethernet,*) RDMA_TYPE="roce" ;;
    *)
        [[ -n "${WORKER_IB_DEVICES:-}" ]] && RDMA_TYPE="rdma"
        ;;
esac
audit_ufm_secured_profile "$RDMA_TYPE"

IPMI_USER_ACCESS="${WORKER_IPMI_USER_ACCESS:-untested}"
IPMI_SUDO_ACCESS="${WORKER_IPMI_SUDO_ACCESS:-untested}"
IPMI_EXPOSED="false"
if [[ "$IPMI_USER_ACCESS" == "allowed" || "$IPMI_SUDO_ACCESS" == "allowed" ]]; then
    IPMI_EXPOSED="true"
fi
IPMITOOL_INSTALLED="false"
[[ -n "${WORKER_IPMITOOL_PATH:-}" ]] && IPMITOOL_INSTALLED="true"
if [[ "$SECURITY_HARNESS" == "k8s" ]]; then
    collect_k8s_host_fleet
else
    K8S_BMC_IPMI_JSON=$(jq -n \
        --argjson installed "$(json_bool "$IPMITOOL_INSTALLED")" \
        --arg path "${WORKER_IPMITOOL_PATH:-none}" \
        --arg user_access "$IPMI_USER_ACCESS" \
        --arg sudo_access "$IPMI_SUDO_ACCESS" \
        --argjson exposed "$(json_bool "$IPMI_EXPOSED")" '{
          ipmitoolInstalled: $installed,
          ipmitoolPath: $path,
          userAccess: $user_access,
          sudoAccess: $sudo_access,
          exposed: $exposed
        }')
fi
if [[ "$SECURITY_HARNESS" == "slurm" ]]; then
    collect_slurm_pwnescape_fleet
    collect_slurm_security_host_fleet
fi

JANUSCAPE_EXPOSED_JSON=$(json_bool_or_unknown "${WORKER_JANUSCAPE_EXPOSED:-}")
SECURITY_ADVISORY_JSON=$(printf '{%s "_end": null}' \
    "$(build_security_advisory_json \
        --host-facts "${WORKER_CHECK_OUTPUT:-}" \
        --bad-epoll-os "${WORKER_OS_ID:-unknown}" \
        --bad-epoll-release "${WORKER_OS_VERSION_ID:-unknown}" \
        --bad-epoll-running "${WORKER_GUEST_KERNEL_RUNNING:-unknown}" \
        --bad-epoll-signature "${WORKER_BAD_EPOLL_SIGNATURE:-unknown}" \
        --bad-epoll-package "${WORKER_BAD_EPOLL_PACKAGE:-unknown}" \
        --bad-epoll-livepatch "${WORKER_BAD_EPOLL_LIVEPATCH:-unknown}" \
        --fragnesia-status "${WORKER_FRAGNESIA_STATUS:-unknown}" \
        --fragnesia-compared-abi "${WORKER_FRAGNESIA_ABI_FLOOR:-unknown}" \
        --ubuntu-kernel-status "${WORKER_UBUNTU_KERNEL_MINIMUM_STATUS:-unknown}" \
        --ubuntu-kernel-abi "${WORKER_UBUNTU_KERNEL_ABI:-unknown}" \
        --ubuntu-kernel-floor "${WORKER_UBUNTU_KERNEL_ABI_FLOOR:-unknown}" \
        --januscape-cpu-exposed "${WORKER_NESTED_CPU_EXPOSED:-false}" \
        --januscape-kvm-exposed "${WORKER_KVM_DEVICE:-false}" \
        --januscape-module "${WORKER_NESTED_MODULE:-none}" \
        --januscape-nested-enabled "${WORKER_NESTED_ENABLED:-unknown}" \
        --januscape-exposed "$JANUSCAPE_EXPOSED_JSON" \
        --januscape-status "${WORKER_JANUSCAPE_STATUS:-unknown}" \
        --qemu-status "${WORKER_QEMU_CVE_2024_3446_STATUS:-unknown}" \
        --vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")" \
    | jq 'del(._end)')
# A standalone target is one host, so its sampled verdict is already complete.
if [[ "$SECURITY_HARNESS" != "standalone" ]]; then
    apply_security_host_fleet
    apply_pwnescape_fleet
fi

print_section "Write security collector JSON"
AUDIT_CLUSTER_NAME="${CUSTOM_NAME:-cluster}"
NVLINK_TOPOLOGY_COVERAGE_COMPLETE=false
if [[ "$SECURITY_HARNESS" == "standalone" \
        && "${WORKER_NVLINK_TOPOLOGY_CHECKED:-false}" == "true" ]] \
        || [[ "$SECURITY_HARNESS" == "k8s" \
        && "$K8S_SECURITY_GPU_NODE_COUNT" -eq 1 ]]; then
    NVLINK_TOPOLOGY_COVERAGE_COMPLETE=true
fi
JSON_OUTPUT=$(jq -n \
    --arg timestamp "$AUDIT_TIMESTAMP" \
    --arg harness "$SECURITY_HARNESS" \
    --arg cluster_name "$AUDIT_CLUSTER_NAME" \
    --arg worker "${WORKER_HOSTNAME:-unknown}" \
    --arg gpu_model "$GPU_MODEL" \
    --arg driver "$DRIVER_VERSION" \
    --arg cuda "${WORKER_CUDA_VERSION:-unknown}" \
    --arg gpu_memory "$GPU_MEMORY" \
    --argjson gpu_count "$(json_int "$GPU_COUNT")" \
    --argjson node_count "$(json_int "$K8S_SECURITY_NODE_COUNT")" \
    --argjson amd_present "$(json_bool "$AMD_GPUS_PRESENT")" \
    --arg amd_model "${WORKER_AMD_GPU_MODEL:-none}" \
    --arg amd_driver "${WORKER_AMD_DRIVER_VERSION:-unknown}" \
    --arg rdma_type "$RDMA_TYPE" \
    --argjson worker_ok true \
    --argjson container_ok "$(json_bool "$CONTAINER_CHECK_OK")" \
    --argjson security_versions "$SECURITY_VERSION_AUDIT_JSON" \
    --argjson advisories "$SECURITY_ADVISORY_JSON" \
    --argjson ufm "$UFM_SECURED_PROFILE_JSON" \
    --arg virtualization_type "${WORKER_VIRT_TYPE:-unknown}" \
    --argjson virtualization_guest "$(json_bool_or_unknown "${WORKER_VIRT_GUEST:-unknown}")" \
    --argjson nvlink_all_visible "$(json_bool_or_unknown "${WORKER_NVLINK_ALL_HOST_GPUS_VISIBLE:-unknown}")" \
    --arg nvlink_host_gpus "${WORKER_NVLINK_HOST_GPU_COUNT:-unknown}" \
    --arg nvlink_visible_gpus "${WORKER_NVLINK_VISIBLE_GPU_COUNT:-unknown}" \
    --arg qemu_machine "${WORKER_QEMU_MACHINE:-unknown}" \
    --argjson virtio_serial "$(json_bool "${WORKER_VIRTIO_SERIAL:-false}")" \
    --arg running_kernel "${WORKER_GUEST_KERNEL_RUNNING:-unknown}" \
    --arg newest_kernel "${WORKER_GUEST_KERNEL_NEWEST_INSTALLED:-unknown}" \
    --argjson newer_kernel "$(json_bool "${WORKER_GUEST_KERNEL_NEWER_INSTALLED:-false}")" \
    --argjson reboot_required "$(json_bool "${WORKER_GUEST_REBOOT_REQUIRED:-false}")" \
    --arg nvidia_patched "${WORKER_NVIDIA_MAY_2026_PATCHED:-unknown}" \
    --arg nvidia_driver "$NVIDIA_DRIVER_VERSION" \
    --argjson nvlink_exposed "$(json_bool_or_unknown "${WORKER_NVLINK_EXPOSED:-unknown}")" \
    --argjson nvlink_checked "$(json_bool_or_unknown "${WORKER_NVLINK_TOPOLOGY_CHECKED:-false}")" \
    --argjson nvlink_coverage_complete "$NVLINK_TOPOLOGY_COVERAGE_COMPLETE" \
    --argjson nvidia_present "$(json_bool_or_unknown "${WORKER_SECURITY_NVIDIA_GPU_PRESENT:-unknown}")" \
    --argjson nvlink_domain_exclusive "$(json_bool_or_unknown "${CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED:-unknown}")" \
    --argjson iommu_groups "$(json_int "${WORKER_IOMMU_GROUPS:-0}")" \
    --argjson pcie_complete "$(json_bool_or_unknown "${WORKER_PCIE_SCAN_COMPLETE:-unknown}")" \
    --argjson pcie_vfio "$(json_int "${WORKER_PCIE_VFIO_DEVICES:-0}")" \
    --argjson pcie_unsafe "$(json_int "${WORKER_PCIE_UNSAFE_GROUPS:-0}")" \
    --argjson bmc_ipmi "$K8S_BMC_IPMI_JSON" \
    '{
        audit: {
            version: "2.1",
            type: $harness,
            timestamp: $timestamp,
            clusterName: $cluster_name,
            hostname: $worker
        },
        nodes: {total: $node_count, idle: 0, allocated: 1, down: 0, totalCpus: 0, totalMemoryGB: 0},
        gpus: {
            total: $gpu_count,
            nodeCount: 1,
            perNode: $gpu_count,
            model: $gpu_model,
            memoryMB: $gpu_memory,
            driverVersion: $driver,
            cudaVersion: $cuda,
            gpuDirectRdma: false,
            amd: {present: $amd_present, model: $amd_model, driverVersion: $amd_driver}
        },
        software: {workerCheckOk: $worker_ok, workerNode: $worker},
        containers: {workerCheckOk: $container_ok},
        networking: {rdmaType: $rdma_type},
        securityVersions: $security_versions,
        security: ($advisories + {
            ufmSecuredBareMetalCloud: $ufm,
            virtualization: {
                type: $virtualization_type,
                guest: $virtualization_guest,
                qemuMachine: $qemu_machine,
                virtioSerialExposed: $virtio_serial
            },
            guestKernel: {
                running: $running_kernel,
                newestInstalled: $newest_kernel,
                newerInstalled: $newer_kernel,
                rebootRequired: $reboot_required
            },
            nvidiaMay2026: {
                driverVersion: $nvidia_driver,
                patched: $nvidia_patched,
                nvlinkExposed: $nvlink_exposed
            },
            nvlinkBoundary: {
                nvlinkExposed: $nvlink_exposed,
                topologyChecked: $nvlink_checked,
                topologyCoverageComplete: $nvlink_coverage_complete,
                nvidiaGpuPresent: $nvidia_present,
                targetIsVm: $virtualization_guest,
                allHostGpusVisible: $nvlink_all_visible,
                hostGpuCount: $nvlink_host_gpus,
                visibleGpuCount: $nvlink_visible_gpus,
                domainExclusive: $nvlink_domain_exclusive,
                domainExclusivitySource: "operator-attestation"
            },
            pciePassthrough: {
                guestIommuGroupCount: $iommu_groups,
                inventoryComplete: $pcie_complete,
                vfioDevices: $pcie_vfio,
                unsafeGroups: $pcie_unsafe,
                scope: "sampled-worker-host",
                hostVerificationRequired: true
            },
            bmcIpmi: $bmc_ipmi
        })
    }')

if [[ "$SECURITY_HARNESS" == k8s ]]; then
    # K8S_SECURITY_NODE changes during fleet BMC probes. GPU_PARTITION retains
    # the original sampled GPU worker selected at the start of this collector.
    if runtime_enriched=$(printf '%s' "$JSON_OUTPUT" | python3 \
        "${WORKLOAD_DIR}/k8s_runtime_software.py" --node "$GPU_PARTITION"); then
        JSON_OUTPUT="$runtime_enriched"
    else
        JSON_OUTPUT=$(jq '
          .runtimeSoftware.cudaToolkit = {coverageComplete:false,error:"runtime software collector failed"}
          | if .securityVersions.cudaToolkit.status != "fail" then
              .securityVersions.cudaToolkit.status = "unknown"
              | .securityVersions.cudaToolkit.detail = "Runtime software collector failed; patch status is unverified"
            else . end' <<< "$JSON_OUTPUT")
    fi
fi

if [[ "$JSON_ONLY" == "true" ]]; then
    printf '%s\n' "$JSON_OUTPUT"
else
    RESULTS_DIR="${OUTPUT_DIR:-${WORKLOAD_DIR}/audit-results}"
    mkdir -p "$RESULTS_DIR"
    OUTPUT_FILE="${RESULTS_DIR}/${AUDIT_TIMESTAMP_FILE}_${AUDIT_CLUSTER_NAME}.json"
    printf '%s\n' "$JSON_OUTPUT" > "$OUTPUT_FILE"
    print_info "JSON saved: ${OUTPUT_FILE}"
fi
