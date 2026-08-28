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
    local fragnesia_abi_minimum
    fragnesia_abi_minimum=$(minimum_version \
        components.ubuntuNoble.packages.linuxFragnesia.abi)
    kubectl exec -i -n "$K8S_SECURITY_CHECK_NS" \
        --request-timeout=300s "$K8S_SECURITY_CHECK_POD" -- \
        chroot /host env CLUSTERMAX_AUDIT_SCOPE=security \
        CLUSTERMAX_AUDIT_HARNESS=k8s \
        CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host \
        CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$fragnesia_abi_minimum" bash -s
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
  mc=blocked
  chassis=blocked
  timeout 5 "$path" mc info >/dev/null 2>&1 && mc=allowed
  timeout 5 "$path" chassis status >/dev/null 2>&1 && chassis=allowed
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
          checked: true,
          devicePresent: ($device == "true"),
          ipmitoolInstalled: ($installed == "true"),
          ipmitoolPath: (if $path == "" then "not-installed" else $path end),
          mcInfoAccess: $mc,
          chassisStatusAccess: $chassis,
          exposed: (($mc == "allowed") or ($chassis == "allowed"))
        }'
}

collect_k8s_bmc_fleet() {
    local first_node="$K8S_SECURITY_NODE" node limit record records="" checked_count=1
    limit="${CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT:-32}"
    [[ "$limit" =~ ^[1-9][0-9]*$ ]] || limit=32
    records="$(k8s_bmc_record_for_current_pod "$first_node")"
    while IFS= read -r node; do
        [[ -n "$node" && "$node" != "$first_node" ]] || continue
        if (( checked_count >= limit )); then
            record=$(jq -n --arg node "$node" --argjson limit "$limit" '{
              node: $node, checked: false, devicePresent: "unknown",
              ipmitoolInstalled: "unknown", ipmitoolPath: "unknown",
              mcInfoAccess: "unknown", chassisStatusAccess: "unknown",
              exposed: "unknown",
              error: ("BMC and IPMI probe skipped because the node limit is " + ($limit | tostring))
            }')
        elif ! create_k8s_security_pod "$node"; then
            checked_count=$((checked_count + 1))
            record=$(jq -n --arg node "$node" '{
              node: $node, checked: false, devicePresent: "unknown",
              ipmitoolInstalled: "unknown", ipmitoolPath: "unknown",
              mcInfoAccess: "unknown", chassisStatusAccess: "unknown",
              exposed: "unknown", error: "privileged host-root pod could not be created"
            }')
        else
            checked_count=$((checked_count + 1))
            record=$(k8s_bmc_record_for_current_pod "$node")
        fi
        records+=$'\n'"$record"
    done < <(jq -r '.[].metadata.name' <<< "$K8S_SECURITY_WORKER_NODES_JSON")
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
        -N1 --ntasks=1 --gres=gpu:1 --time=5:00 \
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
    "$WORKER_CHECK_OUTPUT" "${WORKER_DRIVER_VERSION:-unknown}" \
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
    collect_k8s_bmc_fleet
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

JANUSCAPE_EXPOSED_JSON=$(json_bool_or_unknown "${WORKER_JANUSCAPE_EXPOSED:-}")
SECURITY_ADVISORY_JSON=$(printf '{%s "_end": null}' \
    "$(build_security_advisory_json \
        --fragnesia-status "${WORKER_FRAGNESIA_STATUS:-unknown}" \
        --fragnesia-compared-abi "${WORKER_FRAGNESIA_ABI_FLOOR:-unknown}" \
        --januscape-cpu-exposed "${WORKER_NESTED_CPU_EXPOSED:-false}" \
        --januscape-kvm-exposed "${WORKER_KVM_DEVICE:-false}" \
        --januscape-module "${WORKER_NESTED_MODULE:-none}" \
        --januscape-nested-enabled "${WORKER_NESTED_ENABLED:-unknown}" \
        --januscape-exposed "$JANUSCAPE_EXPOSED_JSON" \
        --januscape-status "${WORKER_JANUSCAPE_STATUS:-unknown}" \
        --qemu-status "${WORKER_QEMU_CVE_2024_3446_STATUS:-unknown}" \
        --vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")" \
    | jq 'del(._end)')

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
                domainExclusive: $nvlink_domain_exclusive
            },
            pciePassthrough: {
                guestIommuGroupCount: $iommu_groups,
                hostVerificationRequired: true
            },
            bmcIpmi: $bmc_ipmi
        })
    }')

if [[ "$JSON_ONLY" == "true" ]]; then
    printf '%s\n' "$JSON_OUTPUT"
else
    RESULTS_DIR="${OUTPUT_DIR:-${WORKLOAD_DIR}/audit-results}"
    mkdir -p "$RESULTS_DIR"
    OUTPUT_FILE="${RESULTS_DIR}/${AUDIT_TIMESTAMP_FILE}_${AUDIT_CLUSTER_NAME}.json"
    printf '%s\n' "$JSON_OUTPUT" > "$OUTPUT_FILE"
    print_info "JSON saved: ${OUTPUT_FILE}"
fi
