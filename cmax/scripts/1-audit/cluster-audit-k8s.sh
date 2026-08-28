#!/bin/bash
# =============================================================================
# Kubernetes GPU Cluster Audit Script
# =============================================================================
# Run this script first to understand your cluster configuration.
# Checks: Kubernetes version, provider, GPU Operator, Network Operator,
#         RDMA configuration, storage classes, and node/GPU inventory.
#
# Usage:
#   cmax audit                          # Bench harness entrypoint
#   cmax/scripts/1-audit/cluster-audit-k8s.sh --json
#   cmax/scripts/1-audit/cluster-audit-k8s.sh --name "my-cluster"
#   cmax/scripts/1-audit/cluster-audit-k8s.sh --output-dir ./results
#
# Output: Saves JSON to the requested output directory.
# =============================================================================

set -e

# Preserve the collector's original stderr so a caller-level `2>/dev/null`
# cannot hide a persistent JSON collection failure from the operator.
exec {CLUSTERMAX_KUBECTL_ERROR_FD}>&2

# Locate this collector's dir and source the shared audit library. Sourced
# BEFORE this script's own print_* definitions below, so those still win (k8s
# keeps its console formatting); we want kv_lines_to_json and the shared
# host-check.sh for host-level parity with the slurm/standalone collectors.
WORKLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$WORKLOAD_DIR/audit-common.sh"
k8s_audit_source_control_helpers() {
    # k8s-control.sh enables nounset and pipefail for workload launchers. The
    # audit intentionally uses only errexit because many legacy checks accept
    # absent optional variables and empty pipeline matches.
    # shellcheck source=/dev/null
    . "$WORKLOAD_DIR/k8s-control.sh"
    set +u
    set +o pipefail
}
k8s_audit_source_control_helpers

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
JSON_ONLY=false
CUSTOM_NAME=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --json)
            JSON_ONLY=true
            shift
            ;;
        --name)
            CUSTOM_NAME="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --json            Output JSON to stdout only (no file save)"
            echo "  --name NAME       Override cluster name for output file"
            echo "  --output-dir DIR  Custom output directory"
            echo "  -h, --help        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# =============================================================================
# SETUP
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Timestamp
AUDIT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_TIMESTAMP_FILE=$(date -u +"%Y%m%d-%H%M%S")

# Helper functions
print_header() {
    if [[ "$JSON_ONLY" == "false" ]]; then
        echo ""
        echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${BLUE}  $1${NC}"
        echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    fi
}

print_section() {
    # `|| true`: in --json mode the `[[ ]]` is false and the && list returns 1,
    # which would trip `set -e` in the caller. Keep these helpers returning 0.
    [[ "$JSON_ONLY" == "false" ]] && echo "" && echo -e "${CYAN}─── $1 ───${NC}" || true
}

print_info() {
    [[ "$JSON_ONLY" == "false" ]] && echo -e "  ${GREEN}✓${NC} $1" || true
}

print_warn() {
    [[ "$JSON_ONLY" == "false" ]] && echo -e "  ${YELLOW}⚠${NC} $1" || true
}

print_error() {
    [[ "$JSON_ONLY" == "false" ]] && echo -e "  ${RED}✗${NC} $1" || true
}

print_detail() {
    [[ "$JSON_ONLY" == "false" ]] && echo -e "    $1" || true
}

sha256_file() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | awk '{print $1}'
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$file" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
print(digest)
PY
    else
        return 1
    fi
}

ensure_jq() {
    command -v jq >/dev/null 2>&1 && return 0

    local version="1.8.1"
    local asset expected_sha256
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64|Linux/amd64)
            asset="jq-linux-amd64"
            expected_sha256="020468de7539ce70ef1bceaf7cde2e8c4f2ca6c3afb84642aabc5c97d9fc2a0d"
            ;;
        Linux/aarch64|Linux/arm64)
            asset="jq-linux-arm64"
            expected_sha256="6bc62f25981328edd3cfcfe6fe51b073f2d7e7710d7ef7fcdac28d4e384fc3d4"
            ;;
        *)
            echo "Error: jq is not installed and automatic download does not support $(uname -s)/$(uname -m)" >&2
            return 1
            ;;
    esac

    local cache_root="${CLUSTERMAX_CACHE_DIR:-${HOME:-/tmp}/.cache/clustermax}"
    local install_dir="$cache_root/jq/$version/${asset#jq-}"
    local jq_path="$install_dir/jq"
    local actual_sha256=""

    if [[ -x "$jq_path" ]] \
        && actual_sha256="$(sha256_file "$jq_path")" \
        && [[ "$actual_sha256" == "$expected_sha256" ]]; then
        export PATH="$install_dir:$PATH"
        return 0
    fi

    mkdir -p "$install_dir"
    local download_url="https://github.com/jqlang/jq/releases/download/jq-${version}/${asset}"
    local temp_path
    temp_path="$(mktemp "$install_dir/.jq-download.XXXXXX")"
    local downloaded=0

    printf 'jq is not installed; downloading jq %s to %s\n' "$version" "$jq_path" >&2
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --retry 3 --retry-delay 2 \
            --output "$temp_path" "$download_url" && downloaded=1
    fi
    if [[ "$downloaded" -eq 0 ]] && command -v wget >/dev/null 2>&1; then
        wget -q -O "$temp_path" "$download_url" && downloaded=1
    fi
    if [[ "$downloaded" -eq 0 ]] && command -v python3 >/dev/null 2>&1; then
        python3 - "$download_url" "$temp_path" <<'PY' && downloaded=1
import pathlib
import sys
import urllib.request

with urllib.request.urlopen(sys.argv[1]) as response:
    pathlib.Path(sys.argv[2]).write_bytes(response.read())
PY
    fi
    if [[ "$downloaded" -eq 0 ]]; then
        rm -f "$temp_path"
        echo "Error: jq download failed; install jq or provide curl, wget, or python3" >&2
        return 1
    fi

    if ! actual_sha256="$(sha256_file "$temp_path")"; then
        rm -f "$temp_path"
        echo "Error: cannot verify the jq download because no SHA-256 tool is available" >&2
        return 1
    fi
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        rm -f "$temp_path"
        echo "Error: jq download checksum verification failed" >&2
        return 1
    fi

    chmod 0755 "$temp_path"
    mv -f "$temp_path" "$jq_path"
    export PATH="$install_dir:$PATH"
    jq --version >/dev/null 2>&1 || {
        echo "Error: downloaded jq cannot run" >&2
        return 1
    }
}

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl is not installed or not in PATH"
    exit 1
fi

if ! ensure_jq; then
    echo "Error: jq is required for the Kubernetes audit"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null; then
    echo "Error: Cannot connect to Kubernetes cluster. Check your kubeconfig."
    exit 1
fi

# ---------------------------------------------------------------------------
# kubectl JSON hardening
#
# This collector runs under `set -e`, and most checks are bare
# command-substitution assignments of the form
#     VAR=$(kubectl get <resource> -o json | jq '...')
# If kubectl returns anything other than a single clean JSON document on stdout
# (a truncated body or transient partial result over a flaky/remote connection,
# two concatenated documents, or version-skew / auth noise), `jq` exits non-zero
# and `set -e` aborts the ENTIRE audit at that line. That is what killed a
# laptop-driven remote run at section 6 ("Storage Classes"): `kubectl get
# storageclass -o json` returned unparseable stdout, the bare assignment failed,
# and the audit exited before storage, monitoring, or inventory were collected.
#
# Wrap `kubectl get ... -o json` so it emits exactly one parseable JSON
# document. Healthy output is passed through unchanged, and multi-document
# output is reduced to its last complete value. A missing optional resource
# becomes an empty list. Other failures are retried and then fail the audit,
# because an empty list would turn an API or DNS failure into a false claim that
# the cluster has no matching resources. Non-get and non-JSON calls (apply,
# exec, `-o jsonpath`, `--no-headers`, ...) pass straight through, so streaming
# and exit-code semantics are unchanged.
# ---------------------------------------------------------------------------
kubectl() {
    local arg is_get=0 wants_json=0 out status attempt=1
    local error_file error_text="" salvaged=""
    local max_attempts="${CLUSTERMAX_KUBECTL_GET_RETRIES:-3}"
    local retry_delay="${CLUSTERMAX_KUBECTL_RETRY_DELAY:-1}"
    for arg in "$@"; do
        case "$arg" in
            get) is_get=1 ;;
            json|-ojson|-o=json|--output=json) wants_json=1 ;;
        esac
    done

    if [[ $is_get -eq 1 && $wants_json -eq 1 ]]; then
        [[ "$max_attempts" =~ ^[1-9][0-9]*$ ]] || max_attempts=3
        error_file=$(mktemp "${TMPDIR:-/tmp}/cmax-kubectl-json.XXXXXX") \
            || return 1
        while [[ "$attempt" -le "$max_attempts" ]]; do
            if out=$(command kubectl "$@" 2>"$error_file"); then
                status=0
            else
                status=$?
            fi
            error_text=$(<"$error_file")
            if [[ $status -eq 0 ]]; then
                if printf '%s' "$out" | jq -e -s 'length == 1' >/dev/null 2>&1; then
                    command rm -f "$error_file"
                    printf '%s\n' "$out"
                    return 0
                fi
                salvaged=$(printf '%s' "$out" | jq -c -s '.[-1]' 2>/dev/null || true)
                if [[ -n "$salvaged" && "$salvaged" != "null" ]]; then
                    command rm -f "$error_file"
                    printf '%s\n' "$salvaged"
                    return 0
                fi
                error_text="kubectl returned invalid JSON"
            elif [[ "$error_text" == *"the server doesn't have a resource type"* \
                    || "$error_text" == *"no matches for kind"* ]]; then
                command rm -f "$error_file"
                printf '%s\n' '{"items":[]}'
                return 0
            fi
            if [[ "$attempt" -lt "$max_attempts" ]]; then
                sleep "$retry_delay"
            fi
            attempt=$((attempt + 1))
        done
        command rm -f "$error_file"
        printf 'kubectl JSON request failed after %s attempts: %s\n' \
            "$max_attempts" "${error_text:-unknown error}" \
            >&"${CLUSTERMAX_KUBECTL_ERROR_FD:-2}"
        [[ $status -ne 0 ]] && return "$status"
        return 1
    fi

    command kubectl "$@"
}

k8s_toolkit_daemonset_ready() {
    printf '%s\n' "$1" \
        | jq -r '.status.numberReady // 0' 2>/dev/null \
        || printf '%s\n' 0
}

k8s_toolkit_daemonset_image() {
    printf '%s\n' "$1" \
        | jq -r '.spec.template.spec.containers[0].image // ""' 2>/dev/null \
        || true
}

k8s_audit_dra_gpu_counts() {
    local slices_json="$1"
    local driver="$2"
    printf '%s\n' "$slices_json" | jq -c --arg driver "$driver" '
        [ .items[]
          | select(.spec.driver == $driver)
          | { node: (.spec.nodeName // .spec.pool.name // ""),
              count: ((.spec.devices // []) | length) }
          | select(.node != "" and .count > 0) ]
        | group_by(.node)
        | map({key: .[0].node, value: (map(.count) | add)})
        | from_entries'
}

k8s_audit_inject_dra_gpu_capacity() {
    local nodes_json="$1"
    local counts_json="$2"
    printf '%s\n' "$nodes_json" | jq -c --argjson counts "$counts_json" '
        .items |= map(
          .metadata.name as $name
          | (.metadata.labels // {}) as $labels
          | ([.status.conditions[]?
              | select(.type == "Ready" and .status == "True")] | length > 0) as $ready
          | (($labels | has("node-role.kubernetes.io/control-plane"))
             or ($labels | has("node-role.kubernetes.io/master"))) as $control
          | if (($counts[$name] // 0) > 0)
               and $ready and ((.spec.unschedulable // false) | not) and ($control | not)
            then .status.capacity["nvidia.com/gpu"] = ($counts[$name] | tostring)
               | .status.allocatable["nvidia.com/gpu"] = ($counts[$name] | tostring)
            else . end)'
}

k8s_audit_scalar_gpu_alloc_by_node() {
    local pods_json="$1"
    local resource_key="$2"
    printf '%s\n' "$pods_json" | jq -c --arg key "$resource_key" '
        [ .items[]
          | select(.status.phase == "Running" or .status.phase == "Pending")
          | select(.spec.nodeName != null)
          | { node: .spec.nodeName,
              gpu: ([ .spec.containers[]
                      | (.resources.limits // {})[$key] // "0" | tonumber? ]
                    | add // 0) }
          | select(.gpu > 0) ]
        | group_by(.node)
        | map({ key: .[0].node, value: (map(.gpu) | add) })
        | from_entries'
}

k8s_audit_dra_gpu_alloc_by_node() {
    local pods_json="$1"
    local claims_json="$2"
    local driver="$3"
    local pod_nodes
    pod_nodes=$(printf '%s\n' "$pods_json" | jq -c '
        [ .items[]
          | select(.status.phase == "Running" or .status.phase == "Pending")
          | select(.spec.nodeName != null and .metadata.uid != null)
          | {key: .metadata.uid, value: .spec.nodeName} ]
        | from_entries')
    printf '%s\n' "$claims_json" | jq -c \
        --arg driver "$driver" --argjson podNodes "$pod_nodes" '
        [ .items[]
          | ([.status.allocation.devices.results[]?
              | select(.driver == $driver)] | length) as $gpu
          | select($gpu > 0)
          | ([.status.reservedFor[]?
              | .uid as $uid | $podNodes[$uid] // empty] | first // "") as $node
          | select($node != "")
          | {node: $node, gpu: $gpu} ]
        | group_by(.node)
        | map({key: .[0].node, value: (map(.gpu) | add)})
        | from_entries'
}

k8s_audit_merge_gpu_allocations() {
    local scalar_json="$1"
    local dra_json="$2"
    jq -cn --argjson scalar "$scalar_json" --argjson dra "$dra_json" '
        (($scalar | keys) + ($dra | keys) | unique)
        | map(. as $node
              | {key: $node,
                 value: (($scalar[$node] // 0) + ($dra[$node] // 0))})
        | from_entries'
}

# Cache node data (single API call)
NODES_JSON=$(kubectl get nodes -o json 2>/dev/null)
if k8s_gpu_dra_enabled; then
    DRA_GPU_DRIVER="${CLUSTERMAX_K8S_GPU_DRA_DRIVER:-gpu.nvidia.com}"
    DRA_SLICES_JSON=$(kubectl get resourceslices.resource.k8s.io -o json 2>/dev/null)
    DRA_GPU_COUNTS=$(k8s_audit_dra_gpu_counts "$DRA_SLICES_JSON" "$DRA_GPU_DRIVER")
    # Feed the existing audit pipeline a scheduling-equivalent GPU capacity.
    # Only Ready, schedulable workers are promoted, matching the DRA workload
    # topology calculation and excluding stale slices on cordoned nodes.
    NODES_JSON=$(k8s_audit_inject_dra_gpu_capacity "$NODES_JSON" "$DRA_GPU_COUNTS")
fi

# =============================================================================
# SECTION 1: Kubernetes Version & Cluster Identity
# =============================================================================
print_header "1. KUBERNETES VERSION & CLUSTER IDENTITY"

K8S_VERSION_JSON=$(kubectl version -o json 2>/dev/null || echo '{}')
K8S_VERSION=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.gitVersion // "unknown"')
K8S_MAJOR=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.major // "0"')
K8S_MINOR=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.minor // "0"' | tr -d '+')
K8S_PLATFORM=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.platform // "unknown"')
K8S_BUILD_DATE=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.buildDate // "unknown"')
K8S_GIT_COMMIT=$(echo "$K8S_VERSION_JSON" | jq -r '.serverVersion.gitCommit // "unknown"' | cut -c1-12)

print_section "Kubernetes Version"
print_info "Version: ${K8S_VERSION}"
print_info "Platform: ${K8S_PLATFORM}"
print_info "Build: ${K8S_BUILD_DATE} (${K8S_GIT_COMMIT})"

CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
CLUSTER_NAME=$(kubectl config view --minify -o jsonpath='{.clusters[0].name}' 2>/dev/null || echo "unknown")
CLUSTER_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo "unknown")

print_section "Cluster Context"
print_info "Context: ${CURRENT_CONTEXT}"
print_info "Cluster Name: ${CLUSTER_NAME}"
print_info "API Server: ${CLUSTER_SERVER}"

print_section "Client Tooling and RBAC"
HELM_INSTALLED="false"
HELM_VERSION="not-found"
HELM_LIST_ACCESS="not-found"
if command -v helm &>/dev/null; then
    HELM_INSTALLED="true"
    HELM_VERSION=$(helm version --short 2>/dev/null | head -1 || echo "unknown")
    print_info "helm: ${HELM_VERSION}"
    if helm list --all-namespaces --max 1 >/dev/null 2>&1; then
        HELM_LIST_ACCESS="pass"
        print_info "helm list --all-namespaces: PASS"
    else
        HELM_LIST_ACCESS="fail"
        print_warn "helm list --all-namespaces: FAILED"
    fi
else
    print_warn "helm: not found"
fi

KUBECTL_AUTH_JSON_ENTRIES=()
KUBECTL_RBAC_SUMMARY="pass"
add_kubectl_auth_check() {
    local name="$1"
    local verb="$2"
    local resource="$3"
    local scope="${4:-}"
    local result allowed
    if [[ -n "$scope" ]]; then
        result=$(kubectl auth can-i "$verb" "$resource" "$scope" 2>/dev/null || echo "no")
    else
        result=$(kubectl auth can-i "$verb" "$resource" 2>/dev/null || echo "no")
    fi
    allowed="false"
    if [[ "$result" == "yes" ]]; then
        allowed="true"
        print_info "kubectl auth can-i ${verb} ${resource} ${scope}: yes"
    else
        KUBECTL_RBAC_SUMMARY="fail"
        print_warn "kubectl auth can-i ${verb} ${resource} ${scope}: ${result}"
    fi
    KUBECTL_AUTH_JSON_ENTRIES+=("{\"name\":\"${name}\",\"verb\":\"${verb}\",\"resource\":\"${resource}\",\"scope\":\"${scope:-cluster}\",\"allowed\":${allowed},\"result\":\"${result}\"}")
}
add_kubectl_auth_check listNodes list nodes
add_kubectl_auth_check listPods list pods --all-namespaces
add_kubectl_auth_check createPods create pods --all-namespaces
add_kubectl_auth_check createJobs create jobs.batch --all-namespaces
add_kubectl_auth_check createPVCs create persistentvolumeclaims --all-namespaces
add_kubectl_auth_check createServices create services --all-namespaces
KUBECTL_AUTH_JSON="$(printf '%s\n' "${KUBECTL_AUTH_JSON_ENTRIES[@]}" | jq -s .)"

# Server geolocation - determine physical location of cluster nodes
print_section "Server Location"
GEO_REGION=""
GEO_CITY=""
GEO_COUNTRY=""
GEO_IP=""

# Method 1: Extract from node labels (cloud-specific)
NODE_REGION=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels["topology.kubernetes.io/region"] // empty] | first // ""')
NODE_ZONE=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels["topology.kubernetes.io/zone"] // empty] | first // ""')
if [[ -n "$NODE_REGION" ]]; then
    GEO_REGION="$NODE_REGION"
    print_info "Region (node label): ${NODE_REGION}"
    [[ -n "$NODE_ZONE" ]] && print_info "Zone: ${NODE_ZONE}"
fi

# Method 2: in-cluster curl pod, apply + poll + logs (kubectl run --rm -i is
# unreliable on DOKS and Mac clients). The pod egresses through a cluster
# node, so the answer reflects the cluster's location; the operator may be on
# a laptop or VPN nowhere near the data center.
GEO_POD="cmax-audit-geo-$$-${RANDOM}"
GEO_JSON="{}"
apply_geolocation_check_pod() {
    kubectl apply --request-timeout=60s -f - >/dev/null 2>&1 <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${GEO_POD}
  labels:
    app.kubernetes.io/name: clustermax-audit
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 5
  activeDeadlineSeconds: 120
  tolerations:
  - operator: Exists
  containers:
  - name: geo
    image: curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13
    args: ["-sf", "--max-time", "10", "https://ipinfo.io/json"]
EOF
}
if apply_geolocation_check_pod
then
    _geo_deadline=$((SECONDS + 90))
    while [[ "$SECONDS" -lt "$_geo_deadline" ]]; do
        _geo_phase=$(kubectl get pod "$GEO_POD" --request-timeout=30s -o jsonpath='{.status.phase}' 2>/dev/null || true)
        if [[ "$_geo_phase" == "Succeeded" ]]; then
            GEO_JSON=$(kubectl logs "$GEO_POD" --request-timeout=30s 2>/dev/null || echo "{}")
            break
        fi
        if [[ "$_geo_phase" == "Failed" ]]; then
            break
        fi
        sleep 3
    done
fi
kubectl delete pod "$GEO_POD" --ignore-not-found=true --wait=false --request-timeout=30s >/dev/null 2>&1 || true

if echo "$GEO_JSON" | jq -e '.ip' &>/dev/null; then
    GEO_IP=$(echo "$GEO_JSON" | jq -r '.ip // ""')
    GEO_CITY=$(echo "$GEO_JSON" | jq -r '.city // ""')
    GEO_COUNTRY=$(echo "$GEO_JSON" | jq -r '.country // ""')
    GEO_ORG=$(echo "$GEO_JSON" | jq -r '.org // ""')
    GEO_LOC=$(echo "$GEO_JSON" | jq -r '.loc // ""')  # lat,lon
    GEO_REGION=$(echo "$GEO_JSON" | jq -r '.region // ""')
    print_info "External IP (in-cluster): ${GEO_IP}"
    print_info "Location: ${GEO_CITY}, ${GEO_REGION}, ${GEO_COUNTRY}"
    print_info "ISP/Org: ${GEO_ORG}"
    [[ -n "$GEO_LOC" ]] && print_detail "Coordinates: ${GEO_LOC}"
else
    # Method 3: operator-side curl, matching the SLURM collector, where the
    # operator host sits inside the cluster. On a remotely driven k8s audit
    # this reports the operator's vantage point, so it is the last resort.
    GEO_JSON=$(curl -sf --max-time 10 "https://ipinfo.io/json" 2>/dev/null || echo "{}")
    if echo "$GEO_JSON" | jq -e '.ip' &>/dev/null; then
        GEO_IP=$(echo "$GEO_JSON" | jq -r '.ip // ""')
        GEO_CITY=$(echo "$GEO_JSON" | jq -r '.city // ""')
        GEO_COUNTRY=$(echo "$GEO_JSON" | jq -r '.country // ""')
        GEO_ORG=$(echo "$GEO_JSON" | jq -r '.org // ""')
        GEO_LOC=$(echo "$GEO_JSON" | jq -r '.loc // ""')
        [[ -z "$GEO_REGION" ]] && GEO_REGION=$(echo "$GEO_JSON" | jq -r '.region // ""')
        print_info "External IP (operator vantage): ${GEO_IP}"
        print_info "Location: ${GEO_CITY}, ${GEO_REGION}, ${GEO_COUNTRY}"
        print_info "ISP/Org: ${GEO_ORG}"
        [[ -n "$GEO_LOC" ]] && print_detail "Coordinates: ${GEO_LOC}"
    else
        print_warn "Could not determine server location (no egress or API unreachable)"
    fi
fi

# =============================================================================
# SECTION 2: Cluster Provider Detection (Expanded)
# =============================================================================
# Provider detection based on SemiAnalysis ClusterMax 2.0 taxonomy
# https://newsletter.semianalysis.com/p/clustermax-20-the-industry-standard
# =============================================================================
print_header "2. CLUSTER PROVIDER DETECTION"

# Initialize detection variables
PROVIDER="unknown"
PROVIDER_TYPE="unknown"  # managed, self-managed, bare-metal, colocation
PROVIDER_DETAILS=""
DETECTED_SIGNALS=()

# Helper to add detection signal
add_signal() {
    DETECTED_SIGNALS+=("$1")
}

is_aks_nodes_json() {
    local nodes_json="${1:-}"
    [[ -n "$nodes_json" ]] || nodes_json='{"items":[]}'
    jq -e '
        any(.items[];
            ((.metadata.labels // {}) | has("kubernetes.azure.com/cluster"))
        )
    ' <<< "$nodes_json" &>/dev/null
}

is_coreweave_nodes_json() {
    local nodes_json="${1:-}"
    [[ -n "$nodes_json" ]] || nodes_json='{"items":[]}'
    jq -e '
        any(.items[];
            any(((.metadata.labels // {}) | keys[]);
                test("(^|\\.)coreweave\\.(cloud|com)/"; "i")
            )
        )
    ' <<< "$nodes_json" &>/dev/null
}

# --- K8s Distributions ---

# Azure Kubernetes Service. The Azure cloud-provider providerID is also used by
# self-managed Kubernetes, so only the canonical AKS node label is decisive.
if is_aks_nodes_json "$NODES_JSON"; then
    PROVIDER="Azure AKS"
    PROVIDER_TYPE="managed"
    PROVIDER_DETAILS="${PROVIDER_DETAILS} - Microsoft Azure Kubernetes Service"
    add_signal "aks-detected"
fi

# CoreWeave publishes provider-owned node labels on every tenant-visible
# worker. Use the label domain instead of a context name, which users can
# rename and which does not survive kubeconfig composition.
if [[ "$PROVIDER" == "unknown" ]] && is_coreweave_nodes_json "$NODES_JSON"; then
    PROVIDER="CoreWeave"
    PROVIDER_TYPE="managed"
    PROVIDER_DETAILS="CoreWeave Kubernetes Service"
    add_signal "coreweave-node-labels"
fi

# OpenShift
if kubectl api-resources 2>/dev/null | grep -q "routes.route.openshift.io"; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="OpenShift"
    else
        PROVIDER="$PROVIDER (OpenShift)"
    fi
    PROVIDER_TYPE="managed"
    PROVIDER_DETAILS="${PROVIDER_DETAILS} - Red Hat OpenShift"
    add_signal "openshift-detected"
fi

# Rancher
if kubectl get namespace cattle-system &>/dev/null 2>&1; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="Rancher"
    else
        PROVIDER="$PROVIDER + Rancher"
    fi
    add_signal "rancher-detected"
fi

# K3s
if echo "$K8S_VERSION" | grep -qi "k3s"; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="K3s"
        PROVIDER_TYPE="lightweight"
    else
        PROVIDER="$PROVIDER (K3s)"
    fi
    PROVIDER_DETAILS="${PROVIDER_DETAILS} - Lightweight K8s"
    add_signal "k3s-detected"
fi

# K0s
if echo "$K8S_VERSION" | grep -qi "k0s"; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="K0s"
        PROVIDER_TYPE="lightweight"
    else
        PROVIDER="$PROVIDER (K0s)"
    fi
    add_signal "k0s-detected"
fi

# MicroK8s
if echo "$K8S_VERSION" | grep -qi "microk8s" || kubectl get namespace microk8s &>/dev/null 2>&1; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="MicroK8s"
        PROVIDER_TYPE="lightweight"
    else
        PROVIDER="$PROVIDER (MicroK8s)"
    fi
    add_signal "microk8s-detected"
fi

# Talos
if echo "$NODES_JSON" | jq -e '.items[0].status.nodeInfo.osImage | test("Talos")' &>/dev/null; then
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="Talos"
        PROVIDER_TYPE="immutable"
    else
        PROVIDER="$PROVIDER (Talos)"
    fi
    PROVIDER_DETAILS="${PROVIDER_DETAILS} - Talos Linux"
    add_signal "talos-detected"
fi

# --- Management Layers ---

# Rafay
if kubectl get namespace rafay-system &>/dev/null 2>&1; then
    RAFAY_DETECTED="true"
    if [[ "$PROVIDER" != "unknown" ]]; then
        PROVIDER="$PROVIDER + Rafay"
    else
        PROVIDER="Rafay Managed"
    fi
    PROVIDER_DETAILS="${PROVIDER_DETAILS} (Rafay management layer)"
    add_signal "rafay-detected"
else
    RAFAY_DETECTED="false"
fi

# Spectro Cloud / Palette
if kubectl get namespace spectro-system &>/dev/null 2>&1; then
    if [[ "$PROVIDER" != "unknown" ]]; then
        PROVIDER="$PROVIDER + Spectro"
    else
        PROVIDER="Spectro Cloud"
    fi
    add_signal "spectro-detected"
fi

# Kubermatic
if kubectl get namespace kubermatic &>/dev/null 2>&1; then
    if [[ "$PROVIDER" != "unknown" ]]; then
        PROVIDER="$PROVIDER + Kubermatic"
    else
        PROVIDER="Kubermatic"
    fi
    add_signal "kubermatic-detected"
fi

# Cast AI
if kubectl get namespace castai-agent &>/dev/null 2>&1; then
    PROVIDER="$PROVIDER + Cast AI"
    add_signal "castai-detected"
fi

# vCluster (loft.sh) virtual-cluster tenancy
# A vCluster tenant runs a virtual control plane on top of a host cluster, so
# host-level operators (GPU/Network), BIOS/ACS, and apiserver OIDC config are
# not visible from the tenant kubeconfig. Detect it and record those caveats so
# downstream verdicts can be qualified rather than reported as "absent".
VCLUSTER_DETECTED="false"
VCLUSTER_MANAGED_BY=""
VCLUSTER_TENANT_NAME=""
VCLUSTER_SIGNALS=()
VCLUSTER_CAVEATS=()

# Canonical loft.sh marker on synced node objects.
VCLUSTER_MANAGED_BY=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels["vcluster.loft.sh/managed-by"] // empty] | first // ""')
# Any vcluster.loft.sh/* label or annotation key on a node.
VCLUSTER_LOFT_KEYS=$(echo "$NODES_JSON" | jq -r '[.items[] | (.metadata.labels // {}), (.metadata.annotations // {}) | keys[] | select(startswith("vcluster.loft.sh"))] | unique | .[]' 2>/dev/null)
# Vendor tenant-name label, e.g. v2.k8s.vessl.ai/vcluster-tenant-name.
VCLUSTER_TENANT_NAME=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels // {} | to_entries[] | select(.key | endswith("vcluster-tenant-name")) | .value] | first // ""')

if [[ -n "$VCLUSTER_MANAGED_BY" ]]; then
    VCLUSTER_SIGNALS+=("label:vcluster.loft.sh/managed-by=${VCLUSTER_MANAGED_BY}")
fi
if [[ -n "$VCLUSTER_LOFT_KEYS" ]]; then
    while IFS= read -r k; do
        [[ -n "$k" && "$k" != "vcluster.loft.sh/managed-by" ]] && VCLUSTER_SIGNALS+=("key:${k}")
    done <<< "$VCLUSTER_LOFT_KEYS"
fi
if [[ -n "$VCLUSTER_TENANT_NAME" ]]; then
    VCLUSTER_SIGNALS+=("label:*vcluster-tenant-name=${VCLUSTER_TENANT_NAME}")
fi

# Corroborating (not sole-trigger) signal: virtual control plane minor ahead of
# node kubelet minor. Normal upgrade skew is <= 1, so only flag a gap of >= 1
# alongside the label/annotation evidence above.
NODE_KUBELET_MINOR=$(echo "$NODES_JSON" | jq -r '[.items[].status.nodeInfo.kubeletVersion] | first // ""' | sed -E 's/^v?[0-9]+\.([0-9]+).*/\1/')
if [[ "$K8S_MINOR" =~ ^[0-9]+$ && "$NODE_KUBELET_MINOR" =~ ^[0-9]+$ ]] && (( K8S_MINOR > NODE_KUBELET_MINOR )); then
    VCLUSTER_SIGNALS+=("version-skew:server-minor-${K8S_MINOR}-vs-kubelet-minor-${NODE_KUBELET_MINOR}")
fi

# Trigger on loft.sh evidence or a vendor tenant-name label; version skew alone
# is recorded but never the sole trigger.
if [[ -n "$VCLUSTER_MANAGED_BY" || -n "$VCLUSTER_LOFT_KEYS" || -n "$VCLUSTER_TENANT_NAME" ]]; then
    VCLUSTER_DETECTED="true"
    if [[ "$PROVIDER" == "unknown" ]]; then
        PROVIDER="vCluster tenant"
    else
        PROVIDER="$PROVIDER + vCluster"
    fi
    if [[ -n "$VCLUSTER_TENANT_NAME" ]]; then
        PROVIDER_DETAILS="${PROVIDER_DETAILS} (vCluster tenant: ${VCLUSTER_TENANT_NAME})"
    else
        PROVIDER_DETAILS="${PROVIDER_DETAILS} (vCluster tenant)"
    fi
    add_signal "vcluster-detected"
    VCLUSTER_CAVEATS+=("Host-level operators (GPU Operator, Network Operator) run in the host cluster and are not visible from this tenant.")
    VCLUSTER_CAVEATS+=("BIOS / ACS and other host firmware settings are not assessable from the tenant.")
    VCLUSTER_CAVEATS+=("API server authentication (OIDC / SSO) is fronted by vCluster and not visible from the tenant.")
fi

print_section "Provider Detection"
print_info "Provider: ${PROVIDER}"
print_info "Type: ${PROVIDER_TYPE}"
if [[ -n "$PROVIDER_DETAILS" ]]; then
    print_detail "${PROVIDER_DETAILS}"
fi

if [[ ${#DETECTED_SIGNALS[@]} -gt 0 ]]; then
    print_section "Detection Signals"
    for signal in "${DETECTED_SIGNALS[@]}"; do
        print_detail "• ${signal}"
    done
fi

if [[ "$VCLUSTER_DETECTED" == "true" ]]; then
    print_section "vCluster Tenancy"
    print_info "Virtual-cluster tenant detected${VCLUSTER_TENANT_NAME:+ (tenant: ${VCLUSTER_TENANT_NAME})}"
    for sig in "${VCLUSTER_SIGNALS[@]}"; do
        print_detail "• ${sig}"
    done
    for caveat in "${VCLUSTER_CAVEATS[@]}"; do
        print_warn "$caveat"
    done
fi

# =============================================================================
# SECTION 3: Node Inventory
# =============================================================================
print_header "3. NODE INVENTORY"

TOTAL_NODES=$(echo "$NODES_JSON" | jq '.items | length')
READY_NODES=$(echo "$NODES_JSON" | jq '[.items[] | select(.status.conditions[] | select(.type=="Ready" and .status=="True"))] | length')
CONTROL_PLANE=$(echo "$NODES_JSON" | jq '[.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] or .metadata.labels["node-role.kubernetes.io/master"])] | length')
WORKER_NODES=$((TOTAL_NODES - CONTROL_PLANE))

print_section "Node Summary"
print_info "Total Nodes: ${TOTAL_NODES}"
print_info "Ready Nodes: ${READY_NODES}"
print_info "Control Plane: ${CONTROL_PLANE}"
print_info "Workers: ${WORKER_NODES}"

# Node details
print_section "Node Details"
echo "$NODES_JSON" | jq -r '.items[] | "\(.metadata.name)|\(.status.conditions[] | select(.type=="Ready") | .status)|\(.status.nodeInfo.kubeletVersion)|\(.status.nodeInfo.osImage)"' | while IFS='|' read -r name ready version os; do
    if [[ "$ready" == "True" ]]; then
        print_info "${name}: Ready (${version})"
    else
        print_warn "${name}: NotReady (${version})"
    fi
    print_detail "OS: ${os}"
done

# Sample node resources
print_section "Node Resources (Sample)"
SAMPLE_NODE_JSON=$(echo "$NODES_JSON" | jq -e 'first(.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] == null and .metadata.labels["node-role.kubernetes.io/master"] == null))' 2>/dev/null || echo "$NODES_JSON" | jq '.items[0]')
if [[ -n "$SAMPLE_NODE_JSON" ]] && [[ "$SAMPLE_NODE_JSON" != "null" ]]; then
    NODE_CPU=$(echo "$SAMPLE_NODE_JSON" | jq -r '.status.capacity.cpu // "N/A"')
    NODE_MEM=$(echo "$SAMPLE_NODE_JSON" | jq -r '.status.capacity.memory // "N/A"')
    NODE_MEM_DISPLAY=$(format_k8s_memory "$NODE_MEM")
    NODE_INSTANCE=$(echo "$SAMPLE_NODE_JSON" | jq -r '.metadata.labels["node.kubernetes.io/instance-type"] // .metadata.labels["beta.kubernetes.io/instance-type"] // "N/A"')
    print_info "CPU: ${NODE_CPU}"
    print_info "Memory: ${NODE_MEM_DISPLAY}"
    print_info "Instance Type: ${NODE_INSTANCE}"
fi

# =============================================================================
# SECTION 4: GPU Operator & GPU Inventory
# =============================================================================
print_header "4. GPU OPERATOR & GPU INVENTORY"

# Find GPU Operator (NVIDIA GPU Operator or AMD GPU Operator). kube-amd-gpu is
# the AMD GPU Operator's default namespace; amd-gpu-operator is a common helm
# release name. The OPERATOR_POD match below ("gpu-operator") covers both, since
# the AMD controller pod name also contains "gpu-operator".
find_gpu_operator_namespace() {
    local ns
    for ns in gpu-operator gpu-operator-resources nvidia-gpu-operator nvidia kube-amd-gpu amd-gpu-operator gpu; do
        if kubectl get namespace "$ns" &>/dev/null 2>&1; then
            printf '%s\n' "$ns"
            return 0
        fi
    done
    ns=$(kubectl get namespaces -o json 2>/dev/null \
        | jq -r '[.items[].metadata.name | select(test("gpu-operator|nvidia-gpu"; "i"))] | first // empty' 2>/dev/null || true)
    if [[ -n "$ns" ]]; then
        printf '%s\n' "$ns"
        return 0
    fi
    return 1
}

GPU_NS=$(find_gpu_operator_namespace || true)
GPU_OPERATOR_VERSION=""
GPU_OPERATOR_IMAGE=""

if [[ -z "$GPU_NS" ]]; then
    # No operator namespace. A bare device plugin (no operator) still makes GPUs
    # schedulable; detect the AMD device-plugin daemonset (same label used by
    # platform-audit/.../k8s-report-setup.py) so AMD clusters that run only the
    # plugin are still reported as having a working GPU stack.
    AMD_DEVICE_PLUGIN=$(kubectl get daemonset -A -l name=amd-gpu-device-plugin -o name 2>/dev/null | head -1 || true)
    # OKE (and some distros) label the plugin daemonset k8s-app=amd-gpu-device-plugin
    # instead of the upstream name= label, so fall back to that before declaring it absent.
    [[ -z "$AMD_DEVICE_PLUGIN" ]] && AMD_DEVICE_PLUGIN=$(kubectl get daemonset -A -l k8s-app=amd-gpu-device-plugin -o name 2>/dev/null | head -1 || true)
    if [[ -n "$AMD_DEVICE_PLUGIN" ]]; then
        GPU_OPERATOR_INSTALLED="true"
        print_section "GPU Operator"
        print_info "AMD GPU device plugin detected (${AMD_DEVICE_PLUGIN}; no operator namespace)"
    else
        GPU_OPERATOR_INSTALLED="false"
        print_warn "No AMD or NVIDIA GPU Operator detected."
    fi
else
    GPU_OPERATOR_INSTALLED="true"
    print_section "GPU Operator"
    print_info "Namespace: ${GPU_NS}"

    OPERATOR_POD=$(kubectl get pods -n "$GPU_NS" -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name | contains("gpu-operator")) | .metadata.name' | head -1)
    if [[ -n "$OPERATOR_POD" ]]; then
        GPU_OPERATOR_IMAGE=$(kubectl get pod -n "$GPU_NS" "$OPERATOR_POD" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)
        GPU_OPERATOR_VERSION=$(echo "$GPU_OPERATOR_IMAGE" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || echo "$GPU_OPERATOR_IMAGE")
        print_info "Version: ${GPU_OPERATOR_VERSION}"
        print_info "Image: ${GPU_OPERATOR_IMAGE}"
    fi
fi

# GPU Inventory
print_section "GPU Inventory"

# Pick the GPU resource key the cluster's device plugin actually advertises.
# NVIDIA GPU Operator / device plugin -> nvidia.com/gpu; AMD GPU Operator /
# device plugin -> amd.com/gpu. The AMD plugin reports whole GPUs and CPX/SPX
# partitions under the single amd.com/gpu resource, so summing its capacity is
# the scheduling-accurate count. Sum capacity (not allocatable) so detection is
# stable even when every GPU is allocated or a node is cordoned. NVIDIA wins ties
# so existing NVIDIA clusters behave byte-for-byte as before.
NV_GPU_CAPACITY=$(echo "$NODES_JSON" | jq '[.items[].status.capacity["nvidia.com/gpu"] // "0" | tonumber] | add // 0')
AMD_GPU_CAPACITY=$(echo "$NODES_JSON" | jq '[.items[].status.capacity["amd.com/gpu"] // "0" | tonumber] | add // 0')
NVIDIA_GPU_NODE_COUNT=$(echo "$NODES_JSON" | jq \
    '[.items[] | select((.status.capacity["nvidia.com/gpu"] // "0" | tonumber) > 0)] | length')

# AMD GPU stack facts are populated later from the privileged host-check
# (run_host_check_on_node); these defaults also seed the gpus.amd JSON block so
# NVIDIA clusters emit only an inert amd:{present:false} block. present is set
# from the device-plugin resource (not the host-check) so vendor classification
# holds even when the host-check cannot run.
AMD_GPUS_PRESENT="false"
ROCM_SMI_AVAILABLE=false
AMD_SMI_AVAILABLE=false
GPU_RESOURCE_KEY="nvidia.com/gpu"
GPU_VENDOR="nvidia"
if [[ "${NV_GPU_CAPACITY:-0}" -eq 0 && "${AMD_GPU_CAPACITY:-0}" -gt 0 ]]; then
    GPU_RESOURCE_KEY="amd.com/gpu"
    GPU_VENDOR="amd"
    AMD_GPUS_PRESENT="true"
fi

TOTAL_GPUS=$(echo "$NODES_JSON" | jq --arg key "$GPU_RESOURCE_KEY" '[.items[].status.capacity[$key] // "0" | tonumber] | add // 0')
ALLOCATABLE_GPUS=$(echo "$NODES_JSON" | jq --arg key "$GPU_RESOURCE_KEY" '[.items[].status.allocatable[$key] // "0" | tonumber] | add // 0')
if ! GPU_PROFILE_INVENTORY=$(printf '%s\n' "$NODES_JSON" | python3 "$WORKLOAD_DIR/gpu_profiles.py" \
    --resource-key "$GPU_RESOURCE_KEY" --vendor "$GPU_VENDOR"); then
    print_error "GPU profile inventory failed; refusing to promote unscoped GPU metadata"
    exit 1
fi
if [[ "${TOTAL_GPUS:-0}" -gt 0 ]] && ! printf '%s\n' "$GPU_PROFILE_INVENTORY" \
    | jq -e '.primary != null and (.primary.nodeNames | type == "array" and length > 0)' >/dev/null; then
    print_error "GPU resources exist but no valid primary GPU profile was selected"
    exit 1
fi
PRIMARY_GPU_PROFILE_JSON=$(printf '%s\n' "$GPU_PROFILE_INVENTORY" | jq -c '.primary // {}')
GPU_PROFILES_JSON=$(printf '%s\n' "$GPU_PROFILE_INVENTORY" | jq -c '.profiles // []')
PRIMARY_GPU_NODE_NAMES_JSON=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -c '.nodeNames // []')
PRIMARY_GPU_TOTAL=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.totalGpus // 0')
GPU_PROFILE_SUMMARY_SUFFIX=""
if [[ "${TOTAL_GPUS:-0}" -ne "${PRIMARY_GPU_TOTAL:-0}" ]]; then
    GPU_PROFILE_SUMMARY_SUFFIX=" (${TOTAL_GPUS} total across GPU profiles)"
fi

primary_gpu_label() {
    local label_key="$1"
    printf '%s\n' "$NODES_JSON" | jq -r --argjson primary "$PRIMARY_GPU_NODE_NAMES_JSON" \
        --arg label "$label_key" '
        [ .items[]
          | .metadata.name as $name
          | select(($primary | index($name)) != null)
          | .metadata.labels[$label] // empty ]
        | first // ""'
}

# Node-labeller product and memory labels are best-effort for every vendor; the
# primary-scoped host check fills missing values below.
GPU_MODEL=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.model // "unknown"')
GPU_MEMORY=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.memoryMB // "unknown"')
GPU_COUNT_LABEL=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.perNode // "unknown"')

# Fallbacks for clusters that expose nvidia.com/gpu resources but not the
# NVIDIA GPU Operator's nvidia.com/gpu.* descriptive labels (e.g. DOKS, GKE).
# Leave an "NVIDIA" model hint for display when the descriptive labels are
# absent. (Vendor classification downstream comes from gpus.amd.present, not
# this string; AMD is handled in its own branch above + host-check below.)
if [[ "$GPU_MODEL" == "unknown" && "${TOTAL_GPUS:-0}" -gt 0 && "$GPU_VENDOR" == "nvidia" ]]; then
    GPU_MODEL="NVIDIA GPU"
fi
if [[ "$GPU_COUNT_LABEL" == "unknown" && "${TOTAL_GPUS:-0}" -gt 0 ]]; then
    # DOKS exposes a bare nvidia.com/gpu=<n> node label; otherwise fall back to
    # the max per-node GPU capacity across GPU nodes (vendor-aware key).
    GPU_COUNT_LABEL=$(echo "$NODES_JSON" | jq -r --arg key "$GPU_RESOURCE_KEY" \
        --argjson primary "$PRIMARY_GPU_NODE_NAMES_JSON" '
        ( [ .items[] | .metadata.name as $name
            | select(($primary | index($name)) != null)
            | .metadata.labels[$key] // empty | tonumber? ] | max ) //
        ( [ .items[] | .metadata.name as $name
            | select(($primary | index($name)) != null)
            | .status.capacity[$key] // empty | tonumber? ] | max ) //
        "unknown" | tostring')
fi

# Driver info
if [[ "$GPU_VENDOR" == "amd" ]]; then
    # AMD has no CUDA. Driver from the node-labeller label when present; the
    # host-check (rocm-smi/amd-smi) fills it in below when the label is absent.
    DRIVER_VERSION=$(primary_gpu_label "amd.com/gpu.driver-version")
    [[ -z "$DRIVER_VERSION" ]] && DRIVER_VERSION="unknown"
    CUDA_VERSION="n/a"
else
    DRIVER_MAJOR=$(primary_gpu_label "nvidia.com/cuda.driver.major")
    DRIVER_MINOR=$(primary_gpu_label "nvidia.com/cuda.driver.minor")
    DRIVER_REV=$(primary_gpu_label "nvidia.com/cuda.driver.rev")
    CUDA_MAJOR=$(primary_gpu_label "nvidia.com/cuda.runtime.major")
    CUDA_MINOR=$(primary_gpu_label "nvidia.com/cuda.runtime.minor")

    if [[ "$DRIVER_MAJOR" =~ ^[0-9]+$ && "$DRIVER_MINOR" =~ ^[0-9]+$ \
        && "$DRIVER_REV" =~ ^[0-9]+$ ]]; then
        DRIVER_VERSION="${DRIVER_MAJOR}.${DRIVER_MINOR}.${DRIVER_REV}"
    else
        DRIVER_VERSION="unknown"
    fi

    if [[ "$CUDA_MAJOR" =~ ^[0-9]+$ && "$CUDA_MINOR" =~ ^[0-9]+$ ]]; then
        CUDA_VERSION="${CUDA_MAJOR}.${CUDA_MINOR}"
    else
        CUDA_VERSION="unknown"
    fi
fi

# Order GPU nodes by genuinely free GPUs (allocatable minus what running and
# pending pods already request), fullest-free first, so check pods that need a
# GPU land where one can actually be allocated.
AUDIT_PODS_JSON=$(kubectl get pods --all-namespaces -o json --request-timeout=60s 2>/dev/null)
GPU_ALLOC_BY_NODE=$(k8s_audit_scalar_gpu_alloc_by_node "$AUDIT_PODS_JSON" "$GPU_RESOURCE_KEY" 2>/dev/null || true)
[[ -z "$GPU_ALLOC_BY_NODE" ]] && GPU_ALLOC_BY_NODE='{}'
if k8s_gpu_dra_enabled; then
    DRA_CLAIMS_JSON=$(kubectl get resourceclaims.resource.k8s.io --all-namespaces -o json --request-timeout=60s 2>/dev/null || echo '{"items":[]}')
    DRA_GPU_ALLOC_BY_NODE=$(k8s_audit_dra_gpu_alloc_by_node "$AUDIT_PODS_JSON" "$DRA_CLAIMS_JSON" "$DRA_GPU_DRIVER" 2>/dev/null || echo '{}')
    GPU_ALLOC_BY_NODE=$(k8s_audit_merge_gpu_allocations "$GPU_ALLOC_BY_NODE" "$DRA_GPU_ALLOC_BY_NODE")
fi

GPU_NODE_NAMES=$(echo "$NODES_JSON" | jq -r --argjson used "$GPU_ALLOC_BY_NODE" \
    --argjson primary "$PRIMARY_GPU_NODE_NAMES_JSON" --arg key "$GPU_RESOURCE_KEY" '
    [ .items[]
      | select((.status.capacity[$key] // "0" | tonumber?) > 0)
      | .metadata.name as $name
      | select(($primary | index($name)) != null)
      | { name: .metadata.name,
          free: (((.status.allocatable[$key] // "0" | tonumber?) // 0)
                 - ($used[.metadata.name] // 0)) } ]
    | sort_by(-.free) | .[].name')
GPU_FREE_NODE_NAMES=$(echo "$NODES_JSON" | jq -r --argjson used "$GPU_ALLOC_BY_NODE" \
    --argjson primary "$PRIMARY_GPU_NODE_NAMES_JSON" --arg key "$GPU_RESOURCE_KEY" '
    [ .items[]
      | select((.status.capacity[$key] // "0" | tonumber?) > 0)
      | .metadata.name as $name
      | select(($primary | index($name)) != null)
      | { name: .metadata.name,
          free: (((.status.allocatable[$key] // "0" | tonumber?) // 0)
                 - ($used[.metadata.name] // 0)) }
      | select(.free > 0) ]
    | sort_by(-.free) | .[].name')
GPU_NODE_COUNT=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.nodeCount // 0')
GPU_TOTAL_CPUS=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.totalCpus // 0')
GPU_TOTAL_MEMORY_GB=$(printf '%s\n' "$PRIMARY_GPU_PROFILE_JSON" | jq -r '.totalMemoryGB // 0')
FIRST_GPU_NODE=$(head -n 1 <<< "$GPU_NODE_NAMES")
FIRST_FREE_GPU_NODE=$(head -n 1 <<< "$GPU_FREE_NODE_NAMES")
# Check pods have unique names and are removed individually, so concurrent
# collectors can safely share the stable namespace used by later audit checks.
K8S_AUDIT_CHECK_NS="${CLUSTERMAX_AUDIT_K8S_NAMESPACE:-clustermax-audit}"
# nvidia-smi is injected by the NVIDIA container runtime, so the GPU check only
# needs a small CUDA base image, never a multi-GB framework image.
K8S_AUDIT_GPU_CHECK_IMAGE="${CLUSTERMAX_AUDIT_K8S_GPU_IMAGE:-nvcr.io/nvidia/cuda:12.6.0-base-ubuntu22.04}"
K8S_AUDIT_CHECK_NODE_TRIES=3

# Ephemeral check helpers: apply + poll + exec + delete. kubectl run --rm -i
# is unreliable here (create/attach races on DOKS and Mac clients), and
# kubectl wait cannot fail fast on pods the kubelet rejects outright
# (e.g. OutOfnvidia.com/gpu when every GPU is allocated).
check_log() {
    [[ "$JSON_ONLY" == "false" ]] && echo -e "    $1" >&2
    return 0
}

# Bound a command without relying on GNU timeout, which does not exist on
# macOS operator hosts (a bare `timeout` there fails with exit 127 before the
# check ever reaches the cluster). kubectl --request-timeout does not bound a
# running exec stream either. Preserve the function's current stdin explicitly
# in the fallback: several checks pipe a shell script into kubectl exec.
check_deadline() {
    local secs="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
        return $?
    fi
    "$@" <&0 &
    local cmd_pid=$!
    # Do not let the watchdog inherit command-substitution stdout/stderr. If it
    # does, the substitution's pipe remains open until the full deadline even
    # when the checked command has already exited.
    ( sleep "$secs"; kill -TERM "$cmd_pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
    local watchdog_pid=$!
    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?
    kill -TERM "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null || true
    return "$rc"
}

K8S_AUDIT_CHECK_NS_READY=""

ensure_audit_check_namespace() {
    local ns="$K8S_AUDIT_CHECK_NS"
    [[ -n "$K8S_AUDIT_CHECK_NS_READY" ]] && return 0
    if kubectl get namespace "$ns" --request-timeout=30s &>/dev/null; then
        K8S_AUDIT_CHECK_NS_READY=1
        return 0
    fi
    if kubectl create namespace "$ns" --request-timeout=30s &>/dev/null; then
        # PSA labels so privileged host checks are admitted on clusters whose
        # admission defaults enforce restricted. Only a namespace this audit
        # created gets labeled; a pre-existing namespace is never relabeled.
        kubectl label namespace "$ns" \
            pod-security.kubernetes.io/enforce=privileged \
            pod-security.kubernetes.io/audit=privileged \
            pod-security.kubernetes.io/warn=privileged \
            --overwrite --request-timeout=30s &>/dev/null || true
        K8S_AUDIT_CHECK_NS_READY=1
        return 0
    fi
    if [[ "$ns" != "default" ]] && kubectl get namespace default --request-timeout=30s &>/dev/null; then
        check_log "cannot create namespace ${ns}; using default for audit check pods"
        K8S_AUDIT_CHECK_NS="default"
        K8S_AUDIT_CHECK_NS_READY=1
        return 0
    fi
    return 1
}

cleanup_audit_check_namespace() {
    # Every check is removed by cleanup_audit_check_pod. Leave this namespace in
    # place because another concurrent audit or the post-collector checks may
    # still use it. The namespace contains no per-run artifacts after cleanup.
    return 0
}
trap cleanup_audit_check_namespace EXIT

cleanup_audit_check_pod() {
    local ns="$1"
    local pod="$2"
    kubectl delete pod "$pod" -n "$ns" --ignore-not-found=true --wait=false --request-timeout=30s >/dev/null 2>&1 || true
}

audit_check_pod_status() {
    local ns="$1"
    local pod="$2"
    kubectl get pod "$pod" -n "$ns" --request-timeout=30s \
        -o jsonpath='{.status.phase}{" "}{.status.reason}{" "}{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{end}{.status.conditions[?(@.type=="PodScheduled")].message}' 2>/dev/null \
        | tr '\n' ' ' | tr -s ' ' | sed 's/^ //; s/ *$//'
    return 0
}

# Poll until the check container is Ready. Unlike kubectl wait, this returns
# as soon as the pod reaches a terminal phase, so a kubelet rejection
# (OutOfnvidia.com/gpu, admission denial) costs seconds, not the full timeout.
audit_check_wait_ready() {
    local ns="$1"
    local pod="$2"
    local timeout_s="$3"
    local deadline=$((SECONDS + timeout_s))
    local state=""
    while [[ "$SECONDS" -lt "$deadline" ]]; do
        state=$(kubectl get pod "$pod" -n "$ns" --request-timeout=30s \
            -o jsonpath='{.status.phase}/{.status.containerStatuses[0].ready}' 2>/dev/null || true)
        case "$state" in
            Running/true)
                return 0
                ;;
            Failed/*|Succeeded/*)
                check_log "check pod ${pod} terminated before exec: $(audit_check_pod_status "$ns" "$pod")"
                return 1
                ;;
        esac
        sleep 3
    done
    check_log "check pod ${pod} not Ready after ${timeout_s}s: $(audit_check_pod_status "$ns" "$pod")"
    kubectl describe pod "$pod" -n "$ns" --request-timeout=30s 2>/dev/null | tail -15 >&2 || true
    return 1
}

# Pod names use $$/$RANDOM suffixes, never sanitized node names: a slugged
# node name can end in "-", which RFC 1123 rejects, and short DOKS node names
# hit exactly that. The target node is in spec.nodeName and the check logs.
apply_privileged_host_check_pod() {
    local node="$1"
    ensure_audit_check_namespace || { check_log "no usable namespace for check pods"; return 1; }
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod="cmax-audit-host-$$-${RANDOM}"
    local apply_err=""

    apply_err=$(kubectl apply --request-timeout=60s -f - 2>&1 >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
  namespace: ${ns}
  labels:
    app.kubernetes.io/name: clustermax-audit
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  terminationGracePeriodSeconds: 5
  activeDeadlineSeconds: 900
  nodeName: ${node}
  hostPID: true
  hostNetwork: true
  tolerations:
  - operator: Exists
  containers:
  - name: check
    image: ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    imagePullPolicy: IfNotPresent
    command: ["sleep", "600"]
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
        check_log "failed to create host check pod on ${node}: ${apply_err}"
        return 1
    }
    if ! audit_check_wait_ready "$ns" "$pod" 120; then
        cleanup_audit_check_pod "$ns" "$pod"
        return 1
    fi
    echo "$pod"
}

apply_gpu_check_pod() {
    local node="$1"
    local image="$2"
    ensure_audit_check_namespace || { check_log "no usable namespace for check pods"; return 1; }
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod="cmax-audit-gpu-$$-${RANDOM}"
    local apply_err="" node_placement pod_claims_block="" container_resources
    node_placement="  nodeName: ${node}"
    container_resources="      requests:
        ${GPU_RESOURCE_KEY}: \"1\"
      limits:
        ${GPU_RESOURCE_KEY}: \"1\""
    if k8s_gpu_dra_enabled; then
        local claim_template
        claim_template="$(K8S_NAMESPACE="$ns" k8s_ensure_gpu_dra_claim_template 1)" || return $?
        node_placement="  nodeSelector:
    kubernetes.io/hostname: ${node}"
        pod_claims_block="  resourceClaims:
  - name: gpu
    resourceClaimTemplateName: ${claim_template}"
        container_resources="      claims:
      - name: gpu
      requests: {}
      limits: {}"
    fi

    apply_err=$(kubectl apply --request-timeout=60s -f - 2>&1 >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
  namespace: ${ns}
  labels:
    app.kubernetes.io/name: clustermax-audit
spec:
  restartPolicy: Never
  terminationGracePeriodSeconds: 5
  activeDeadlineSeconds: 900
${node_placement}
${pod_claims_block}
  tolerations:
  - operator: Exists
  containers:
  - name: check
    image: ${image}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "600"]
    resources:
${container_resources}
EOF
) || {
        check_log "failed to create GPU check pod on ${node}: ${apply_err}"
        return 1
    }
    if ! audit_check_wait_ready "$ns" "$pod" 420; then
        cleanup_audit_check_pod "$ns" "$pod"
        return 1
    fi
    echo "$pod"
}

# Resolve the check namespace from the top-level shell. The apply_* helpers
# also call ensure_audit_check_namespace, but they run inside command
# substitutions, where the created/fallback flag mutations die with the
# subshell; this call is the one whose flags the EXIT trap and the exec call
# sites actually see.
ensure_audit_check_namespace || check_log "no usable namespace for audit check pods; ephemeral checks may fail"

host_check_driver_known() {
    local out="$1"
    local driver amd_model amd_driver amd_count
    driver=$(printf '%s\n' "$out" | grep '^WORKER_DRIVER_VERSION=' | head -1 | cut -d= -f2- || true)
    if [[ -n "$driver" && "$driver" != "unknown" ]]; then
        return 0
    fi
    # AMD hosts have no NVIDIA driver line, so accept AMD-side facts as "known".
    # Without this the privileged host-check (Strategy 2) is judged a failure on
    # AMD and its rocm-smi/amd-smi facts are discarded, then the NVIDIA-only
    # Strategy 3 GPU-pod fallback is attempted pointlessly.
    if [[ "${GPU_VENDOR:-nvidia}" == "amd" ]]; then
        amd_model=$(printf '%s\n' "$out" | grep '^WORKER_AMD_GPU_MODEL=' | head -1 | cut -d= -f2- || true)
        amd_driver=$(printf '%s\n' "$out" | grep '^WORKER_AMD_DRIVER_VERSION=' | head -1 | cut -d= -f2- || true)
        amd_count=$(printf '%s\n' "$out" | grep '^WORKER_AMD_GPU_COUNT=' | head -1 | cut -d= -f2- || true)
        if [[ -n "$amd_model" && "$amd_model" != "unknown" ]] \
            || [[ -n "$amd_driver" && "$amd_driver" != "unknown" ]] \
            || [[ -n "$amd_count" && "$amd_count" != "0" && "$amd_count" != "unknown" ]]; then
            return 0
        fi
    fi
    return 1
}

if [[ "$TOTAL_GPUS" -gt 0 ]]; then
    print_info "Total GPUs: ${TOTAL_GPUS}"
    print_info "Allocatable: ${ALLOCATABLE_GPUS}"
    print_info "Model: ${GPU_MODEL}"
    [[ "$GPU_MEMORY" != "unknown" ]] && print_info "Memory: ${GPU_MEMORY} MB"
    print_info "Driver: ${DRIVER_VERSION}"
    print_info "CUDA: ${CUDA_VERSION}"

    # Per-node breakdown
    print_section "GPUs Per Node"
    echo "$NODES_JSON" | jq -r --arg key "$GPU_RESOURCE_KEY" '.items[] | select(.status.capacity[$key] != null) | "\(.metadata.name): \(.status.capacity[$key]) GPUs"' | while read -r line; do
        print_detail "$line"
    done
else
    print_warn "No GPUs detected"
fi

# NCU (NVIDIA Nsight Compute) - profiling permissions & hardware counter access
print_section "NCU Profiling & Hardware Counter Access"
NCU_INSTALLED="false"
NCU_VERSION="unknown"
NCU_PROFILING_ENABLED="unknown"
NCU_COUNTER_ACCESS="unknown"

# NCU is NVIDIA Nsight Compute - NVIDIA-only. Skip the whole section (including
# the live counter test, which pulls a CUDA image) on AMD, where it is n/a and
# would only emit misleading "no nvidia-driver pod" / "RESTRICTED" output.
if [[ "${TOTAL_GPUS:-0}" -gt 0 && "${GPU_VENDOR:-nvidia}" == "nvidia" ]]; then
    # 1. Find an nvidia-driver daemonset pod to check profiling config
    DRIVER_DS_POD=""
    DRIVER_DS_NS=""
    if [[ -n "$GPU_NS" ]]; then
        DRIVER_DS_POD=$(kubectl get pods -n "$GPU_NS" -o json 2>/dev/null | \
            jq -r '.items[] | select(.metadata.name | test("nvidia-driver")) | select(.status.phase == "Running") | .metadata.name' | head -1)
        DRIVER_DS_NS="$GPU_NS"
    fi

    if [[ -n "$DRIVER_DS_POD" ]]; then
        # Check NVreg_RestrictProfilingToAdminUsers via driver params
        PROF_PARAM=$(kubectl exec -n "$DRIVER_DS_NS" "$DRIVER_DS_POD" -- \
            cat /proc/driver/nvidia/params 2>/dev/null | grep "RmProfilingAdminOnly" || echo "")
        if echo "$PROF_PARAM" | grep -q "RmProfilingAdminOnly: 0"; then
            NCU_PROFILING_ENABLED="true"
            print_info "NCU profiling config: Unrestricted (RmProfilingAdminOnly=0 in driver pod)"
        elif [[ -n "$PROF_PARAM" ]]; then
            NCU_PROFILING_ENABLED="false"
            print_error "NCU profiling config: RESTRICTED (RmProfilingAdminOnly != 0)"
            print_detail "Users will get: ==ERROR== ERR_NVGPUCTRPERM: Permission denied"
            print_detail "Fix: Set NVreg_RestrictProfilingToAdminUsers=0 in driver module params"
            print_detail "Container pods also need: securityContext.privileged=true or SYS_ADMIN capability"
        else
            print_warn "NCU profiling config: Could not read /proc/driver/nvidia/params"
        fi
    else
        print_warn "NCU profiling config: No nvidia-driver daemonset pod found to check"
    fi

    # 2. Live NCU hardware counter test via ephemeral GPU pod
    #    Compiles a trivial CUDA kernel, profiles it with ncu, checks for ERR_NVGPUCTRPERM
    print_detail "Running live NCU counter test via GPU pod (may take 1-2 min for image pull)..."

    NCU_TEST_SCRIPT='
NCU_P=$(which ncu 2>/dev/null || echo "")
echo "NCU_PATH=$NCU_P"
if [ -n "$NCU_P" ]; then
    NCU_V=$($NCU_P --version 2>/dev/null | grep -oP "version \K[0-9.]+" | head -1 || echo unknown)
    echo "NCU_VERSION=$NCU_V"
    cat > /tmp/ncu_test.cu <<CUDA_EOF
__global__ void ncu_counter_test_kernel() { }
int main() { ncu_counter_test_kernel<<<1,1>>>(); cudaDeviceSynchronize(); return 0; }
CUDA_EOF
    if nvcc -o /tmp/ncu_test /tmp/ncu_test.cu 2>/dev/null; then
        OUT=$($NCU_P --target-processes all --metrics sm__cycles_elapsed.avg /tmp/ncu_test 2>&1 || true)
        if echo "$OUT" | grep -q "ERR_NVGPUCTRPERM"; then
            echo "NCU_COUNTER_ACCESS=denied"
        else
            echo "NCU_COUNTER_ACCESS=granted"
        fi
    else
        echo "NCU_COUNTER_ACCESS=compile-failed"
    fi
else
    echo "NCU_COUNTER_ACCESS=no-ncu"
fi
'

    NCU_POD_OUTPUT="NCU_COUNTER_ACCESS=resource-unavailable"
    if [[ -n "$FIRST_FREE_GPU_NODE" ]]; then
        NCU_POD_OUTPUT="NCU_COUNTER_ACCESS=pod-failed"
        NCU_POD=$(apply_gpu_check_pod "$FIRST_FREE_GPU_NODE" "nvcr.io/nvidia/cuda:12.6.0-devel-ubuntu22.04" || true)
        if [[ -n "$NCU_POD" ]]; then
            NCU_POD_OUTPUT=$(printf '%s\n' "$NCU_TEST_SCRIPT" | check_deadline 300 kubectl exec -n "$K8S_AUDIT_CHECK_NS" "$NCU_POD" -i -- bash 2>&1 || echo "NCU_COUNTER_ACCESS=pod-failed")
            cleanup_audit_check_pod "$K8S_AUDIT_CHECK_NS" "$NCU_POD"
        fi
    fi

    # Parse results from pod output
    POD_NCU_PATH=$(echo "$NCU_POD_OUTPUT" | grep "^NCU_PATH=" | cut -d= -f2-)
    POD_NCU_VERSION=$(echo "$NCU_POD_OUTPUT" | grep "^NCU_VERSION=" | cut -d= -f2-)
    POD_NCU_ACCESS=$(echo "$NCU_POD_OUTPUT" | grep "^NCU_COUNTER_ACCESS=" | cut -d= -f2-)

    if [[ -n "$POD_NCU_PATH" ]]; then
        NCU_INSTALLED="true"
        NCU_VERSION="${POD_NCU_VERSION:-unknown}"
        print_info "ncu: ${POD_NCU_PATH} (version ${NCU_VERSION})"
    fi

    NCU_COUNTER_ACCESS="${POD_NCU_ACCESS:-pod-failed}"
    case "$NCU_COUNTER_ACCESS" in
        granted)
            NCU_PROFILING_ENABLED="true"
            print_info "Hardware counters: ACCESSIBLE (live ncu profiling succeeded)"
            ;;
        denied)
            NCU_PROFILING_ENABLED="false"
            print_error "Hardware counters: DENIED (ERR_NVGPUCTRPERM)"
            print_detail "ncu is installed but cannot access GPU performance counters."
            print_detail "Ensure NVreg_RestrictProfilingToAdminUsers=0 and pods have SYS_ADMIN capability."
            ;;
        compile-failed)
            print_warn "Hardware counters: UNTESTED (nvcc failed to compile test kernel)"
            ;;
        no-ncu)
            print_warn "Hardware counters: UNTESTED (ncu not found in CUDA devel image)"
            ;;
        pod-failed)
            print_warn "Hardware counters: UNTESTED (GPU pod failed to start or timed out)"
            print_detail "Ensure GPU resources are available and the CUDA image is pullable."
            ;;
        resource-unavailable)
            print_warn "Hardware counters: UNTESTED (no unallocated GPU was available)"
            ;;
        *)
            print_warn "Hardware counters: UNKNOWN (${NCU_COUNTER_ACCESS})"
            ;;
    esac
elif [[ "${GPU_VENDOR:-nvidia}" == "amd" ]]; then
    NCU_COUNTER_ACCESS="n/a"
    print_info "NCU checks: n/a (NVIDIA Nsight Compute; this is an AMD cluster - use rocprof / omniperf)"
else
    print_warn "NCU checks: Skipped (no GPUs detected)"
fi

# perf top / perf stat access (Linux performance counters)
# perf is essential for CPU-side profiling - identifying bottlenecks in data
# loading, preprocessing, kernel launch overhead, and host-device sync.
#
# Access issues typically come down to:
#   1. perf_event_paranoid (/proc/sys/kernel/perf_event_paranoid):
#      -1 = no restrictions (allow all)
#       0 = allow raw tracepoint access for non-root
#       1 = allow non-root per-process monitoring (default on many distros)
#       2 = allow non-root per-process only, no kernel profiling
#       3 = no perf event access for non-root at all (Ubuntu default since ~20.04)
#   2. kptr_restrict (/proc/sys/kernel/kptr_restrict):
#      0 = kernel symbol addresses visible to all
#      1 = hidden from non-root (perf top shows [unknown] for kernel functions)
#      2 = always hidden
#   3. Container/VM - host perf subsystem may not be accessible; need
#      securityContext.privileged=true or CAP_SYS_ADMIN / CAP_PERFMON (Linux 5.8+)
#   4. SELinux/AppArmor - can block perf even if paranoid is permissive
#
# Quick fix on host nodes:
#   sudo sysctl -w kernel.perf_event_paranoid=-1
#   sudo sysctl -w kernel.kptr_restrict=0
# Persistent: add to /etc/sysctl.d/99-perf.conf
print_section "perf Access (Linux Performance Counters)"
PERF_INSTALLED="false"
PERF_EVENT_PARANOID="unknown"
PERF_KPTR_RESTRICT="unknown"
PERF_STAT_ACCESS="unknown"
PERF_TOP_ACCESS="unknown"

if [[ "${TOTAL_GPUS:-0}" -gt 0 && -n "$DRIVER_DS_POD" ]]; then
    # Check perf_event_paranoid and kptr_restrict via driver daemonset pod
    # (runs on GPU node with host PID namespace, so /proc/sys reflects host)
    PERF_EVENT_PARANOID=$(kubectl exec -n "$DRIVER_DS_NS" "$DRIVER_DS_POD" -- \
        cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "unknown")
    PERF_KPTR_RESTRICT=$(kubectl exec -n "$DRIVER_DS_NS" "$DRIVER_DS_POD" -- \
        cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "unknown")

    case "$PERF_EVENT_PARANOID" in
        -1) print_info "perf_event_paranoid = -1 (no restrictions - full profiling)" ;;
        0)  print_info "perf_event_paranoid = 0 (allow raw tracepoint access)" ;;
        1)  print_warn "perf_event_paranoid = 1 (user-space per-process only)" ;;
        2)  print_warn "perf_event_paranoid = 2 (restrictive - per-process counters only)" ;;
        3|4) print_error "perf_event_paranoid = ${PERF_EVENT_PARANOID} (perf_event_open denied for non-root)"
            print_detail "Fix on host: sudo sysctl -w kernel.perf_event_paranoid=-1" ;;
        *)  print_warn "perf_event_paranoid = ${PERF_EVENT_PARANOID} (could not parse)" ;;
    esac

    case "$PERF_KPTR_RESTRICT" in
        0) print_info "kptr_restrict = 0 (kernel symbols visible)" ;;
        1) print_warn "kptr_restrict = 1 (kernel symbols hidden - perf top shows [unknown])"
           print_detail "Fix on host: sudo sysctl -w kernel.kptr_restrict=0" ;;
        2) print_error "kptr_restrict = 2 (kernel symbols always hidden)"
           print_detail "Fix on host: sudo sysctl -w kernel.kptr_restrict=0" ;;
    esac

    # Check if perf binary is available in driver pod
    PERF_IN_DRIVER=$(kubectl exec -n "$DRIVER_DS_NS" "$DRIVER_DS_POD" -- \
        which perf 2>/dev/null || echo "")
    if [[ -n "$PERF_IN_DRIVER" ]]; then
        PERF_INSTALLED="true"
        print_info "perf: ${PERF_IN_DRIVER} (in driver daemonset pod)"

        # Live perf stat test
        PERF_STAT_OUT=$(kubectl exec -n "$DRIVER_DS_NS" "$DRIVER_DS_POD" -- \
            perf stat -e cycles,instructions -- sleep 0.1 2>&1 || true)
        if echo "$PERF_STAT_OUT" | grep -qE "cycles|instructions"; then
            if echo "$PERF_STAT_OUT" | grep -q "<not supported>\|<not counted>"; then
                PERF_STAT_ACCESS="partial"
                print_warn "perf stat: PARTIAL (some counters not supported)"
            else
                PERF_STAT_ACCESS="granted"
                print_info "perf stat: PASS"
            fi
        else
            PERF_STAT_ACCESS="denied"
            print_error "perf stat: DENIED"
            print_detail "Pods need securityContext.privileged=true or CAP_SYS_ADMIN / CAP_PERFMON (Linux 5.8+)"
        fi
    else
        print_warn "perf: Not found in driver daemonset pod"
        print_detail "User pods will need to install linux-tools-\$(uname -r) or mount host perf binary"
    fi
elif [[ "${TOTAL_GPUS:-0}" -eq 0 ]]; then
    print_warn "perf checks: Skipped (no GPUs detected)"
else
    print_warn "perf checks: Skipped (no driver daemonset pod found)"
fi

# =============================================================================
# SECTION 5: Network Operator & RDMA
# =============================================================================
print_header "5. NETWORK OPERATOR & RDMA CONFIGURATION"

# Network Operator detection
NETWORK_NS=""
NETWORK_OPERATOR_VERSION=""
for ns in network-operator nvidia-network-operator mellanox; do
    if kubectl get namespace "$ns" &>/dev/null 2>&1; then
        NETWORK_NS="$ns"
        break
    fi
done

if [[ -z "$NETWORK_NS" ]]; then
    if kubectl api-resources 2>/dev/null | grep -q "nicclusterpolicies"; then
        NETWORK_OPERATOR_INSTALLED="partial"
        print_warn "NicClusterPolicy CRD exists but no namespace"
    else
        NETWORK_OPERATOR_INSTALLED="false"
        print_warn "Network Operator not detected"
    fi
else
    NETWORK_OPERATOR_INSTALLED="true"
    print_section "Network Operator"
    print_info "Namespace: ${NETWORK_NS}"

    NET_OPERATOR_POD=$(kubectl get pods -n "$NETWORK_NS" -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name | contains("network-operator")) | .metadata.name' | head -1)
    if [[ -n "$NET_OPERATOR_POD" ]]; then
        NETWORK_OPERATOR_VERSION=$(kubectl get pod -n "$NETWORK_NS" "$NET_OPERATOR_POD" -o jsonpath='{.spec.containers[0].image}' 2>/dev/null)
        print_info "Image: ${NETWORK_OPERATOR_VERSION}"
    fi
fi

# RDMA / EFA detection
print_section "RDMA Configuration"
# The NVIDIA Network Operator advertises RDMA as a vendor-namespaced extended
# resource (nvidia.com/rdma_ib, nvidia.com/rdma_roce) rather than the rdma/*
# prefix used by the rdma-shared-device-plugin. Recognize both spellings so a
# Network Operator cluster (e.g. Together B200) is not misreported as RDMA
# "none". Prefer allocatable+capacity so it matches what pods can request.
RDMA_IB=$(echo "$NODES_JSON" | jq -r '.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | (.["rdma/ib"] // .["nvidia.com/rdma_ib"] // "0")' | sum_k8s_quantities)
RDMA_ROCE=$(echo "$NODES_JSON" | jq -r '.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | (.["rdma/roce"] // .["nvidia.com/rdma_roce"] // "0")' | sum_k8s_quantities)
RDMA_HCA=$(echo "$NODES_JSON" | jq -r '.items[].status.capacity["rdma/hca"] // "0"' | sum_k8s_quantities)

# RDMA shared-device plugins expose one extended resource per node whose name
# varies by deployment: rdma/rdma_shared_device (Moonlite Spectrum-X),
# rdma/rdma_shared_device_a, rdma/hca_shared_devices_a (Vessl), etc. Match any
# rdma/* key containing "shared" so the cascade recognizes the fabric instead of
# reporting "none". Prefer allocatable (what pods can actually request) and fall
# back to capacity. Also capture the matched resource name(s) for reporting.
RDMA_SHARED=$(echo "$NODES_JSON" | jq -r '.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | to_entries[] | select(.key | (startswith("rdma/") and test("shared"))) | .value' | sum_k8s_quantities)
RDMA_SHARED_RES=$(echo "$NODES_JSON" | jq -r '[.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | keys[] | select(startswith("rdma/") and test("shared"))] | unique | join(",")')

# Providers can expose schedulable RDMA devices under deployment-specific
# names that do not contain "shared", such as Neysa's rdma/rdma_nic. Keep a
# generic inventory so an otherwise healthy extended resource is not reported
# as absent merely because its suffix is new to ClusterMAX.
# Match both the rdma/* prefix and vendor-namespaced spellings such as
# nvidia.com/rdma_ib so the inventory captures any RDMA extended resource.
RDMA_GENERIC=$(echo "$NODES_JSON" | jq -r '.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | to_entries[] | select(.key | test("(^|/)rdma[_/]")) | .value' | sum_k8s_quantities)
RDMA_GENERIC_RES=$(echo "$NODES_JSON" | jq -r '[.items[] | (.status.allocatable // {}) + (.status.capacity // {}) | keys[] | select(test("(^|/)rdma[_/]"))] | unique | join(",")')

# DigitalOcean DOKS exposes RoCE fabric via per-NIC extended resources named
# rdma/fabric0 ... rdma/fabric15 (one per fabric NIC, 16 per fabric-connected
# B300 node). Sum all of them so the cascade below recognizes the fabric.
RDMA_FABRIC=$(echo "$NODES_JSON" | jq -r '.items[].status.capacity | to_entries[] | select(.key | startswith("rdma/fabric")) | .value' | sum_k8s_quantities)
RDMA_FABRIC_COUNT_PER_NODE=$(echo "$NODES_JSON" | jq '[.items[] | [.status.capacity | to_entries[] | select(.key | startswith("rdma/fabric"))] | length] | max // 0')

# DRA network drivers advertise devices through ResourceSlices instead of node
# extended resources. Count node-local RDMA-capable devices so managed clusters
# such as Azure GB300 (dra.net / dranet.net) are not misreported as TCP-only.
RDMA_DRA=0
RDMA_DRA_DRIVER=""
if [[ -n "${DRA_SLICES_JSON:-}" ]]; then
    RDMA_DRA=$(echo "$DRA_SLICES_JSON" | jq '[.items[] | select((.spec.driver // "") | test("(^|[.])(?:m?rdma|dra[.]net)"; "i")) | (.spec.devices // [])[] | select(((.attributes // .basic.attributes // {}) | to_entries | any((.key | test("rdma"; "i")) and (.value.bool // true))))] | length')
    RDMA_DRA_DRIVER=$(echo "$DRA_SLICES_JSON" | jq -r '[.items[] | select((.spec.driver // "") | test("(^|[.])(?:m?rdma|dra[.]net)"; "i")) | .spec.driver] | unique | join(",")')
fi

# AWS EFA detection (vpc.amazonaws.com/efa extended resource)
EFA_TOTAL=$(echo "$NODES_JSON" | jq '[.items[].status.capacity["vpc.amazonaws.com/efa"] // "0" | tonumber] | add // 0')
EFA_PER_NODE=$(echo "$NODES_JSON" | jq '[.items[].status.capacity["vpc.amazonaws.com/efa"] // "0" | tonumber] | max // 0')

if [[ "$RDMA_IB" -gt 0 ]]; then
    RDMA_TYPE="infiniband"
    print_info "Type: InfiniBand"
    print_info "rdma/ib: ${RDMA_IB}"
elif [[ "$RDMA_ROCE" -gt 0 ]]; then
    RDMA_TYPE="roce"
    print_info "Type: RoCE"
    print_info "rdma/roce: ${RDMA_ROCE}"
elif [[ "$RDMA_FABRIC" -gt 0 ]]; then
    RDMA_TYPE="roce"
    print_info "Type: RoCE (per-NIC fabric resources)"
    print_info "rdma/fabric* total: ${RDMA_FABRIC}"
    print_detail "Fabric NICs per node: ${RDMA_FABRIC_COUNT_PER_NODE}"
    print_detail "Resource prefix: rdma/fabric0..N (DOKS-style)"
elif [[ "$RDMA_DRA" -gt 0 ]]; then
    RDMA_TYPE="rdma"
    print_info "Type: RDMA (Dynamic Resource Allocation)"
    print_info "DRA RDMA devices: ${RDMA_DRA}"
    [[ -n "$RDMA_DRA_DRIVER" ]] && print_detail "Driver(s): ${RDMA_DRA_DRIVER}"
elif [[ "$EFA_TOTAL" -gt 0 ]]; then
    RDMA_TYPE="efa"
    print_info "Type: AWS EFA (Elastic Fabric Adapter)"
    print_info "Total EFA devices: ${EFA_TOTAL} (${EFA_PER_NODE} per node)"
    print_detail "Resource: vpc.amazonaws.com/efa"
    print_detail "NCCL transport: libfabric (FI_PROVIDER=efa)"
elif [[ "$RDMA_HCA" -gt 0 ]] || [[ "$RDMA_SHARED" -gt 0 ]]; then
    RDMA_TYPE="rdma"
    print_info "Type: RDMA (shared device plugin)"
    [[ "$RDMA_HCA" -gt 0 ]] && print_info "rdma/hca: ${RDMA_HCA}"
    if [[ "$RDMA_SHARED" -gt 0 ]]; then
        print_info "shared RDMA devices: ${RDMA_SHARED}"
        [[ -n "$RDMA_SHARED_RES" ]] && print_detail "Resource(s): ${RDMA_SHARED_RES}"
    fi
elif [[ "$RDMA_GENERIC" -gt 0 ]]; then
    RDMA_TYPE="rdma"
    print_info "Type: RDMA (generic extended resource)"
    print_info "RDMA devices: ${RDMA_GENERIC}"
    [[ -n "$RDMA_GENERIC_RES" ]] && print_detail "Resource(s): ${RDMA_GENERIC_RES}"
else
    RDMA_TYPE="none"
    print_warn "No RDMA resources (using TCP)"
fi

audit_ufm_secured_profile "$RDMA_TYPE"

# MOFED version
MOFED_VERSION=$(primary_gpu_label "network.nvidia.com/operator.mofed.driver-version")
[[ -z "$MOFED_VERSION" ]] && MOFED_VERSION="none"
if [[ "$MOFED_VERSION" != "none" ]]; then
    print_info "MOFED: ${MOFED_VERSION}"
fi

# NIC info from labels
NIC_MODEL=$(primary_gpu_label "nvidia.com/nic-model")
[[ -z "$NIC_MODEL" ]] && NIC_MODEL=$(primary_gpu_label "mellanox.com/nic-model")
[[ -z "$NIC_MODEL" ]] && NIC_MODEL="unknown"
if [[ "$NIC_MODEL" != "unknown" ]]; then
    print_info "NIC Model: ${NIC_MODEL}"
fi

# Multus
print_section "Secondary Networks"
if kubectl api-resources 2>/dev/null | grep -q "network-attachment-definitions"; then
    MULTUS_INSTALLED="true"
    NET_ATTACHMENTS=$(kubectl get network-attachment-definitions --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
    print_info "Multus: Detected (${NET_ATTACHMENTS} attachments)"
else
    MULTUS_INSTALLED="false"
    print_warn "Multus: Not detected"
fi

# =============================================================================
# Topology-Aware Scheduling (K8s equivalent of Slurm topology.conf/topology.yaml)
#
# Slurm encodes network topology in topology.conf/topology.yaml and the scheduler
# uses it for locality-aware placement. Kubernetes has no single built-in
# equivalent; topology-aware GPU/network scheduling is provided by one (or more)
# of the mechanisms below. We detect whichever is present so the audit can report
# that locality-aware placement is available, mirroring the Slurm check.
#
#   1. Kueue Topology-Aware Scheduling (TAS) - upstream-standard Topology CRD
#      (kueue.x-k8s.io). Levels map to node labels (block/rack/host).
#   2. Volcano network-topology-aware scheduling - HyperNode CRD.
#   3. NVIDIA MNNVL / NVLink domains - nvidia.com/gpu.clique labels (GB200 NVL72),
#      the K8s-native key for NVLink-domain-aware placement, set by GPU Feature
#      Discovery / the DRA driver.
#   4. Network/cloud topology node labels usable as scheduling topology keys
#      (topology.kubernetes.io/region|zone, plus finer-grained vendor labels:
#      cloud.google.com/gce-topology-*, topology.k8s.aws/*, network.*).
# =============================================================================
print_section "Topology-Aware Scheduling"
# Three related capabilities a well-configured GPU cluster should expose so the
# scheduler can place tightly-coupled distributed jobs efficiently:
#   (A) Topology awareness  - place pods on network-adjacent nodes (rack/block/NVLink)
#   (B) Gang scheduling     - all-or-nothing placement; avoids partial-allocation
#                             deadlock and the "thundering herd" (pods wait at a
#                             Permit gate until quorum/minMember, then bind atomically)
#   (C) Bin packing         - consolidate jobs onto fewest nodes (least-free-first)
#                             to cut GPU fragmentation and keep whole nodes free for
#                             large gang jobs.
TOPOLOGY_AWARE_SCHEDULING="false"
GANG_SCHEDULING="false"
BIN_PACKING="false"
TOPOLOGY_MECHANISMS=()
GANG_MECHANISMS=()
BINPACK_MECHANISMS=()

# ---------------------------------------------------------------------------
# 1. Kueue Topology-Aware Scheduling (TAS): Topology CRD under kueue.x-k8s.io
# ---------------------------------------------------------------------------
KUEUE_TOPO_CRD=$(kubectl api-resources --api-group=kueue.x-k8s.io 2>/dev/null \
    | awk '$1=="topologies"{print $1}' | head -1 || true)
if [[ -n "$KUEUE_TOPO_CRD" ]]; then
    KUEUE_TOPO_COUNT=$(kubectl get topologies.kueue.x-k8s.io --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${KUEUE_TOPO_COUNT:-0}" -gt 0 ]]; then
        TOPOLOGY_AWARE_SCHEDULING="true"
        TOPOLOGY_MECHANISMS+=("kueue-tas")
        print_info "Kueue Topology-Aware Scheduling: ${KUEUE_TOPO_COUNT} Topology object(s)"
        while IFS= read -r tname; do
            [[ -z "$tname" ]] && continue
            TLEVELS=$(kubectl get topologies.kueue.x-k8s.io "$tname" -o json 2>/dev/null \
                | jq -r '[.spec.levels[].nodeLabel] | join(" > ")' 2>/dev/null)
            [[ -n "$TLEVELS" && "$TLEVELS" != "null" ]] && print_detail "  ${tname}: ${TLEVELS}"
        done <<< "$(kubectl get topologies.kueue.x-k8s.io -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr ' ' '\n')"
        # ResourceFlavors that reference a Topology are the ones that actually grade TAS-enabled.
        KUEUE_TAS_FLAVORS=$(kubectl get resourceflavors.kueue.x-k8s.io -o json 2>/dev/null \
            | jq '[.items[] | select(.spec.topologyName != null)] | length' 2>/dev/null)
        [[ "${KUEUE_TAS_FLAVORS:-0}" -gt 0 ]] && print_detail "  ${KUEUE_TAS_FLAVORS} ResourceFlavor(s) bound to a Topology (TAS-enabled)"
    else
        print_detail "Kueue Topology CRD present but no Topology objects defined"
    fi
fi
# Kueue gang/all-or-nothing admission (workload admitted as a unit).
if kubectl api-resources --api-group=kueue.x-k8s.io 2>/dev/null | grep -q "workloads"; then
    GANG_SCHEDULING="true"
    GANG_MECHANISMS+=("kueue")
fi

# ---------------------------------------------------------------------------
# 2. Volcano: HyperNode (topology), gang plugin, binpack plugin
# ---------------------------------------------------------------------------
if kubectl api-resources 2>/dev/null | grep -qi "hypernodes"; then
    HYPERNODE_COUNT=$(kubectl get hypernodes --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${HYPERNODE_COUNT:-0}" -gt 0 ]]; then
        TOPOLOGY_AWARE_SCHEDULING="true"
        TOPOLOGY_MECHANISMS+=("volcano-hypernode")
        print_info "Volcano Network-Topology-Aware Scheduling: ${HYPERNODE_COUNT} HyperNode(s)"
    else
        print_detail "Volcano HyperNode CRD present but no HyperNode objects defined"
    fi
fi
# Nodes labelled volcano.sh/hypernode also signal Volcano topology domains.
VOLCANO_HN_LABEL_NODES=$(echo "$NODES_JSON" | jq '[.items[] | select(.metadata.labels["volcano.sh/hypernode"] // "" != "")] | length' 2>/dev/null)
if [[ "${VOLCANO_HN_LABEL_NODES:-0}" -gt 0 ]]; then
    TOPOLOGY_AWARE_SCHEDULING="true"
    [[ " ${TOPOLOGY_MECHANISMS[*]} " == *" volcano-hypernode "* ]] || TOPOLOGY_MECHANISMS+=("volcano-hypernode")
    print_detail "volcano.sh/hypernode label on ${VOLCANO_HN_LABEL_NODES} node(s)"
fi
# Volcano scheduler ConfigMap: inspect enabled plugins (gang / binpack).
# The Volcano namespace/configmap is optional. This collector runs with
# `set -e`, so a plain assignment would abort the entire audit on clusters
# without Volcano instead of recording gang/bin-pack as absent.
VOLCANO_CONF=$(kubectl get configmap volcano-scheduler-configmap -n volcano-system -o jsonpath='{.data.volcano-scheduler\.conf}' 2>/dev/null || true)
if [[ -z "$VOLCANO_CONF" ]]; then
    # Fall back to any volcano-* scheduler configmap in any namespace.
    VC_CM=$(kubectl get configmap -A -o json 2>/dev/null \
        | jq -r '.items[] | select(.metadata.name | test("volcano.*scheduler"; "i")) | .metadata.namespace + "/" + .metadata.name' | head -1)
    if [[ -n "$VC_CM" ]]; then
        VOLCANO_CONF=$(kubectl get configmap "${VC_CM#*/}" -n "${VC_CM%/*}" -o jsonpath='{.data.volcano-scheduler\.conf}' 2>/dev/null || true)
    fi
fi
if [[ -n "$VOLCANO_CONF" ]]; then
    if printf '%s\n' "$VOLCANO_CONF" | grep -Eq '^\s*-?\s*name:\s*gang\b'; then
        GANG_SCHEDULING="true"; GANG_MECHANISMS+=("volcano")
        print_info "Volcano gang plugin enabled (all-or-nothing scheduling)"
    fi
    if printf '%s\n' "$VOLCANO_CONF" | grep -Eq '^\s*-?\s*name:\s*binpack\b'; then
        BIN_PACKING="true"; BINPACK_MECHANISMS+=("volcano-binpack")
        print_info "Volcano binpack plugin enabled (consolidates jobs, reduces GPU fragmentation)"
    fi
fi

# ---------------------------------------------------------------------------
# 3. Kubeflow Trainer / Training Operator (delegates to Volcano or KAI)
# ---------------------------------------------------------------------------
if kubectl api-resources 2>/dev/null | grep -Eqi "trainjobs|pytorchjobs|trainingruntimes"; then
    print_detail "Kubeflow Trainer/Training-Operator present (delegates gang+topology to Volcano/KAI via podGroupPolicy)"
fi

# ---------------------------------------------------------------------------
# 4. NVIDIA KAI Scheduler (gang via PodGrouper)
# ---------------------------------------------------------------------------
if kubectl get pods -A -o json 2>/dev/null | jq -e '[.items[] | select(.metadata.name | test("kai-scheduler"; "i"))] | length > 0' >/dev/null 2>&1; then
    GANG_SCHEDULING="true"; GANG_MECHANISMS+=("kai-scheduler")
    print_info "NVIDIA KAI Scheduler detected (gang scheduling for distributed training)"
fi

# ---------------------------------------------------------------------------
# 5. JobSet: exclusive 1:1 job-to-topology placement
# ---------------------------------------------------------------------------
if kubectl api-resources 2>/dev/null | grep -qi "jobsets"; then
    TOPOLOGY_MECHANISMS+=("jobset")
    JOBSET_EXCL=$(kubectl get jobsets.jobset.x-k8s.io -A -o json 2>/dev/null \
        | jq '[.items[] | select((.metadata.annotations // {})["alpha.jobset.sigs.k8s.io/exclusive-topology"] != null)] | length' 2>/dev/null)
    if [[ "${JOBSET_EXCL:-0}" -gt 0 ]]; then
        TOPOLOGY_AWARE_SCHEDULING="true"
        print_info "JobSet exclusive-topology placement in use (${JOBSET_EXCL} JobSet(s))"
    else
        print_detail "JobSet CRD present (supports alpha.jobset.sigs.k8s.io/exclusive-topology for rack/block-exclusive jobs)"
    fi
fi

# ---------------------------------------------------------------------------
# 6. Native Kubernetes gang scheduling (v1.35 alpha, Workload object)
# ---------------------------------------------------------------------------
if kubectl api-resources 2>/dev/null | grep -Eqi "^workloads\b.*scheduling.k8s.io"; then
    GANG_SCHEDULING="true"; GANG_MECHANISMS+=("k8s-native")
    print_detail "Native Kubernetes Workload/gang scheduling API present (scheduling.k8s.io)"
fi

# ---------------------------------------------------------------------------
# 7. NVIDIA MNNVL / NVLink domains: nvidia.com/gpu.clique labels (GB200 NVL72)
# ---------------------------------------------------------------------------
GPU_CLIQUE_NODES=$(echo "$NODES_JSON" | jq '[.items[] | select(.metadata.labels["nvidia.com/gpu.clique"] // "" != "")] | length' 2>/dev/null)
if [[ "${GPU_CLIQUE_NODES:-0}" -gt 0 ]]; then
    TOPOLOGY_AWARE_SCHEDULING="true"
    TOPOLOGY_MECHANISMS+=("nvidia-gpu-clique")
    GPU_CLIQUE_DISTINCT=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels["nvidia.com/gpu.clique"] // empty] | unique | length' 2>/dev/null)
    print_info "NVIDIA NVLink cliques: ${GPU_CLIQUE_NODES} node(s) across ${GPU_CLIQUE_DISTINCT} clique(s) (nvidia.com/gpu.clique)"
    print_detail "MNNVL/NVL72 NVLink-domain-aware placement available via gpu.clique topology key"
fi

# ---------------------------------------------------------------------------
# 8. Network/cloud topology node labels usable as scheduling topology keys
# ---------------------------------------------------------------------------
TOPO_REGION_NODES=$(echo "$NODES_JSON" | jq '[.items[] | select(.metadata.labels["topology.kubernetes.io/region"] // "" != "")] | length' 2>/dev/null)
TOPO_ZONE_NODES=$(echo "$NODES_JSON" | jq '[.items[] | select(.metadata.labels["topology.kubernetes.io/zone"] // "" != "")] | length' 2>/dev/null)
TOPO_FINE_KEYS=$(echo "$NODES_JSON" | jq -r '[.items[].metadata.labels // {} | keys[]] | unique | map(select(
        startswith("cloud.google.com/gce-topology")
     or startswith("topology.k8s.aws/")
     or startswith("networking.gke.io/")
     or test("network.*topology"; "i")
     or test("topology.*block|topology.*rack|topology.*switch"; "i")
    )) | unique | join(", ")' 2>/dev/null)
if [[ -n "$TOPO_FINE_KEYS" && "$TOPO_FINE_KEYS" != "null" ]]; then
    TOPOLOGY_AWARE_SCHEDULING="true"
    TOPOLOGY_MECHANISMS+=("network-topology-labels")
    print_info "Network topology node labels: ${TOPO_FINE_KEYS}"
    print_detail "Usable as topology keys for rack/block-aware placement (e.g. Kueue TAS levels)"
fi
if [[ "${TOPO_REGION_NODES:-0}" -gt 0 || "${TOPO_ZONE_NODES:-0}" -gt 0 ]]; then
    print_detail "Standard topology labels present: region on ${TOPO_REGION_NODES:-0} node(s), zone on ${TOPO_ZONE_NODES:-0} node(s)"
fi

# ---------------------------------------------------------------------------
# Summary + remediation
# ---------------------------------------------------------------------------
# De-duplicate mechanism lists.
[[ ${#TOPOLOGY_MECHANISMS[@]} -gt 0 ]] && IFS=$'\n' read -r -d '' -a TOPOLOGY_MECHANISMS < <(printf '%s\n' "${TOPOLOGY_MECHANISMS[@]}" | awk '!seen[$0]++' && printf '\0')
[[ ${#GANG_MECHANISMS[@]} -gt 0 ]] && IFS=$'\n' read -r -d '' -a GANG_MECHANISMS < <(printf '%s\n' "${GANG_MECHANISMS[@]}" | awk '!seen[$0]++' && printf '\0')
[[ ${#BINPACK_MECHANISMS[@]} -gt 0 ]] && IFS=$'\n' read -r -d '' -a BINPACK_MECHANISMS < <(printf '%s\n' "${BINPACK_MECHANISMS[@]}" | awk '!seen[$0]++' && printf '\0')

if [[ "$TOPOLOGY_AWARE_SCHEDULING" == "true" ]]; then
    print_info "Topology-aware scheduling available via: ${TOPOLOGY_MECHANISMS[*]}"
else
    print_warn "Topology-aware scheduling not detected (no Kueue TAS, Volcano HyperNode, JobSet exclusive-topology, NVLink cliques, or fine-grained network topology labels)"
    print_detail "GPU clusters should expose topology so the scheduler can place tightly-coupled jobs on network-adjacent nodes"
    print_detail "Options: Kueue Topology-Aware Scheduling, Volcano HyperNode, JobSet exclusive-topology, NVIDIA gpu.clique (MNNVL), or block/rack topology node labels"
fi
if [[ "$GANG_SCHEDULING" == "true" ]]; then
    print_info "Gang scheduling available via: ${GANG_MECHANISMS[*]} (all-or-nothing; avoids partial-allocation deadlock / thundering herd)"
else
    print_warn "Gang scheduling not detected - distributed jobs can partially schedule and deadlock GPUs"
    print_detail "Install Volcano (gang plugin), Kueue, NVIDIA KAI, or enable native k8s GangScheduling"
fi
if [[ "$BIN_PACKING" == "true" ]]; then
    print_info "Bin packing configured via: ${BINPACK_MECHANISMS[*]} (consolidates jobs, reduces GPU fragmentation)"
else
    print_detail "Bin packing not explicitly configured (Volcano binpack plugin recommended to reduce GPU fragmentation)"
fi

# Build JSON arrays of detected mechanisms for the structured output below.
if [[ ${#TOPOLOGY_MECHANISMS[@]} -gt 0 ]]; then
    TOPOLOGY_MECHANISMS_JSON=$(printf '%s\n' "${TOPOLOGY_MECHANISMS[@]}" | jq -R . | jq -s -c .)
else
    TOPOLOGY_MECHANISMS_JSON="[]"
fi
if [[ ${#GANG_MECHANISMS[@]} -gt 0 ]]; then
    GANG_MECHANISMS_JSON=$(printf '%s\n' "${GANG_MECHANISMS[@]}" | jq -R . | jq -s -c .)
else
    GANG_MECHANISMS_JSON="[]"
fi
if [[ ${#BINPACK_MECHANISMS[@]} -gt 0 ]]; then
    BINPACK_MECHANISMS_JSON=$(printf '%s\n' "${BINPACK_MECHANISMS[@]}" | jq -R . | jq -s -c .)
else
    BINPACK_MECHANISMS_JSON="[]"
fi

# Load Balancer detection
print_section "Load Balancer"
LOADBALANCER_TYPE="none"
METALLB_INSTALLED="false"

# Check for MetalLB
if kubectl get namespace metallb-system &>/dev/null 2>&1; then
    METALLB_PODS=$(kubectl get pods -n metallb-system --no-headers 2>/dev/null | grep -c Running || echo "0")
    if [[ "$METALLB_PODS" -gt 0 ]]; then
        METALLB_INSTALLED="true"
        LOADBALANCER_TYPE="metallb"
        # Check for IP address pools
        METALLB_POOLS=$(kubectl get ipaddresspools.metallb.io -A --no-headers 2>/dev/null | wc -l | tr -d ' ' || echo "0")
        print_info "MetalLB: Installed (${METALLB_POOLS} IP pools)"
    else
        print_warn "MetalLB: Namespace exists but not running"
    fi
fi

# Check for cloud load balancer capability (via existing LoadBalancer services)
LB_SERVICES=$(kubectl get svc --all-namespaces -o json 2>/dev/null | jq '[.items[] | select(.spec.type=="LoadBalancer")] | length')
LB_WITH_IP=$(kubectl get svc --all-namespaces -o json 2>/dev/null | jq '[.items[] | select(.spec.type=="LoadBalancer" and .status.loadBalancer.ingress != null and (.status.loadBalancer.ingress | length > 0))] | length')

if [[ "$LB_SERVICES" -gt 0 ]]; then
    if [[ "$LOADBALANCER_TYPE" == "none" ]]; then
        if [[ "$LB_WITH_IP" -gt 0 ]]; then
            LOADBALANCER_TYPE="cloud"
            print_info "Cloud LB: Working (${LB_WITH_IP}/${LB_SERVICES} services have IPs)"
        else
            LOADBALANCER_TYPE="pending"
            print_warn "LoadBalancer services exist but no IPs assigned (${LB_SERVICES} pending)"
        fi
    else
        print_info "LoadBalancer services: ${LB_WITH_IP}/${LB_SERVICES} with IPs"
    fi
else
    if [[ "$LOADBALANCER_TYPE" == "none" ]]; then
        print_warn "No LoadBalancer: MetalLB not installed, no cloud LB detected"
    fi
fi

# Ingress Controller detection
print_section "Ingress Controller"
INGRESS_CONTROLLER="none"
INGRESS_CLASS=""

# Check for ingress classes
INGRESS_CLASSES_JSON=$(kubectl get ingressclass -o json 2>/dev/null || echo '{"items":[]}')
INGRESS_CLASS_COUNT=$(echo "$INGRESS_CLASSES_JSON" | jq '.items | length')

if [[ "$INGRESS_CLASS_COUNT" -gt 0 ]]; then
    # Get default ingress class
    INGRESS_CLASS=$(echo "$INGRESS_CLASSES_JSON" | jq -r '.items[] | select(.metadata.annotations["ingressclass.kubernetes.io/is-default-class"]=="true") | .metadata.name' | head -1)
    INGRESS_CLASS=${INGRESS_CLASS:-$(echo "$INGRESS_CLASSES_JSON" | jq -r '.items[0].metadata.name')}

    # Detect controller type from class
    CONTROLLER_NAME=$(echo "$INGRESS_CLASSES_JSON" | jq -r ".items[] | select(.metadata.name==\"$INGRESS_CLASS\") | .spec.controller")

    case "$CONTROLLER_NAME" in
        *"nginx"*|*"ingress-nginx"*)
            INGRESS_CONTROLLER="nginx"
            ;;
        *"traefik"*)
            INGRESS_CONTROLLER="traefik"
            ;;
        *"haproxy"*)
            INGRESS_CONTROLLER="haproxy"
            ;;
        *"contour"*)
            INGRESS_CONTROLLER="contour"
            ;;
        *"istio"*)
            INGRESS_CONTROLLER="istio"
            ;;
        *"kong"*)
            INGRESS_CONTROLLER="kong"
            ;;
        *"gce"*|*"gcp"*)
            INGRESS_CONTROLLER="gce"
            ;;
        *"alb"*|*"aws"*)
            INGRESS_CONTROLLER="aws-alb"
            ;;
        *)
            INGRESS_CONTROLLER="other"
            ;;
    esac
    print_info "Controller: ${INGRESS_CONTROLLER}"
    print_info "Default Class: ${INGRESS_CLASS}"
    print_detail "Controller: ${CONTROLLER_NAME}"
else
    # Check for common ingress namespaces
    if kubectl get namespace ingress-nginx &>/dev/null 2>&1; then
        INGRESS_CONTROLLER="nginx"
        print_info "NGINX Ingress: Detected (namespace exists)"
    elif kubectl get namespace traefik &>/dev/null 2>&1; then
        INGRESS_CONTROLLER="traefik"
        print_info "Traefik: Detected (namespace exists)"
    else
        print_warn "No Ingress Controller detected"
    fi
fi

# Count ingress resources
INGRESS_COUNT=$(kubectl get ingress --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [[ "$INGRESS_COUNT" -gt 0 ]]; then
    print_info "Ingress Resources: ${INGRESS_COUNT}"
fi

# =============================================================================
# SECTION 6: Storage Configuration
# =============================================================================
print_header "6. STORAGE CONFIGURATION"

print_section "Storage Classes"
SC_JSON=$(kubectl get storageclass -o json 2>/dev/null)
DEFAULT_SC=$(echo "$SC_JSON" | jq -r '.items[] | select(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true") | .metadata.name' | head -1)
DEFAULT_SC=${DEFAULT_SC:-"none"}

# Build storage class list for JSON
STORAGE_CLASSES_JSON=$(echo "$SC_JSON" | jq '[.items[] | {name: .metadata.name, provisioner: .provisioner, default: (.metadata.annotations["storageclass.kubernetes.io/is-default-class"] == "true"), reclaimPolicy: .reclaimPolicy, volumeBindingMode: .volumeBindingMode}]')

echo "$SC_JSON" | jq -r '.items[] | "\(.metadata.name)|\(.provisioner)|\(.metadata.annotations["storageclass.kubernetes.io/is-default-class"] // "false")"' | while IFS='|' read -r name prov default; do
    if [[ "$default" == "true" ]]; then
        print_info "${name} (DEFAULT)"
    else
        print_info "${name}"
    fi
    print_detail "Provisioner: ${prov}"
done

# RWX detection
print_section "ReadWriteMany Capability"
RWX_CAPABLE=false
RWX_CLASSES=()
for SC in $(echo "$SC_JSON" | jq -r '.items[].metadata.name'); do
    PROVISIONER=$(echo "$SC_JSON" | jq -r ".items[] | select(.metadata.name==\"$SC\") | .provisioner")
    if [[ "$PROVISIONER" == *"nfs"* ]] || [[ "$PROVISIONER" == *"cephfs"* ]] || \
       [[ "$PROVISIONER" == *"gluster"* ]] || [[ "$PROVISIONER" == *"efs"* ]] || \
       [[ "$PROVISIONER" == *"azurefile"* ]] || [[ "$PROVISIONER" == "file.csi.azure.com" ]] || \
       [[ "$PROVISIONER" == *"filestore"* ]] || \
       [[ "$PROVISIONER" == *"weka"* ]] || [[ "$PROVISIONER" == *"lustre"* ]] || \
       [[ "$PROVISIONER" == *"gpfs"* ]] || [[ "$PROVISIONER" == *"vastdata"* ]]; then
        RWX_CAPABLE=true
        RWX_CLASSES+=("$SC")
        print_info "RWX: ${SC} (${PROVISIONER})"
    fi
done

if [[ "$RWX_CAPABLE" == "false" ]]; then
    # Some clusters (e.g. DOKS) ship without an RWX-capable StorageClass but
    # users provision a static NFS PV by hand. If any RWX PVC is already
    # Bound, count that as RWX-capable rather than reporting "no RWX".
    RWX_PVC_COUNT=$(kubectl get pvc --all-namespaces -o json 2>/dev/null \
        | jq '[.items[] | select(.status.phase=="Bound") | select(.spec.accessModes // [] | any(. == "ReadWriteMany"))] | length' 2>/dev/null || echo 0)
    if [[ "$RWX_PVC_COUNT" -gt 0 ]]; then
        RWX_CAPABLE=true
        print_info "RWX: bound PVCs detected (${RWX_PVC_COUNT})"
        print_detail "Source: manually provisioned NFS / static PV"
    else
        print_warn "No RWX-capable storage detected"
    fi
fi

# Storage providers
print_section "Storage Providers"
STORAGE_PROVIDERS=()
[[ $(kubectl get pods -n openebs --no-headers 2>/dev/null | grep -c Running) -gt 0 ]] && STORAGE_PROVIDERS+=("OpenEBS") && print_info "OpenEBS"
[[ $(kubectl get pods -n longhorn-system --no-headers 2>/dev/null | grep -c Running) -gt 0 ]] && STORAGE_PROVIDERS+=("Longhorn") && print_info "Longhorn"
[[ $(kubectl get pods -n rook-ceph --no-headers 2>/dev/null | grep -c Running) -gt 0 ]] && STORAGE_PROVIDERS+=("Rook-Ceph") && print_info "Rook-Ceph"
[[ $(kubectl get pods -n portworx --no-headers 2>/dev/null | grep -c Running) -gt 0 ]] && STORAGE_PROVIDERS+=("Portworx") && print_info "Portworx"

if [[ ${#STORAGE_PROVIDERS[@]} -eq 0 ]]; then
    print_detail "No dedicated storage provider detected"
fi

# Host path storage detection (for model caching)
print_section "Host Path Storage"
HOSTPATH_AVAILABLE="false"
HOSTPATH_CLASSES=()

for SC in $(echo "$SC_JSON" | jq -r '.items[].metadata.name'); do
    PROVISIONER=$(echo "$SC_JSON" | jq -r ".items[] | select(.metadata.name==\"$SC\") | .provisioner")
    if [[ "$PROVISIONER" == *"hostpath"* ]] || [[ "$PROVISIONER" == *"local"* ]] || \
       [[ "$PROVISIONER" == *"openebs.io/local"* ]] || [[ "$PROVISIONER" == *"rancher.io/local-path"* ]] || \
       [[ "$PROVISIONER" == *"microk8s.io/hostpath"* ]]; then
        HOSTPATH_AVAILABLE="true"
        HOSTPATH_CLASSES+=("$SC")
        print_info "Host Path: ${SC} (${PROVISIONER})"
    fi
done

if [[ "$HOSTPATH_AVAILABLE" == "false" ]]; then
    # Check if nodes have local-storage labels or local PVs
    LOCAL_PVS=$(kubectl get pv -o json 2>/dev/null | jq '[.items[] | select(.spec.local != null or .spec.hostPath != null)] | length')
    if [[ "$LOCAL_PVS" -gt 0 ]]; then
        HOSTPATH_AVAILABLE="true"
        print_info "Local PVs: ${LOCAL_PVS} available"
    else
        print_warn "No host path storage for model caching"
        print_detail "Consider: OpenEBS local-path, Rancher local-path, or static local PVs"
    fi
fi

# PVC Provisioning Test (quick functional check)
print_section "Storage Provisioning Test"
PVC_TEST_RESULT="skipped"
PVC_TEST_MESSAGE=""

if [[ "$DEFAULT_SC" != "none" ]]; then
    # Create a test namespace if needed
    TEST_NS="storage-audit-test"
    TEST_PVC="audit-test-pvc-$(date +%s)"

    # Try to create a small test PVC
    if kubectl create namespace "$TEST_NS" &>/dev/null 2>&1 || kubectl get namespace "$TEST_NS" &>/dev/null 2>&1; then
        # Create test PVC
        cat <<TESTPVC | kubectl apply -f - &>/dev/null 2>&1
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${TEST_PVC}
  namespace: ${TEST_NS}
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
  storageClassName: ${DEFAULT_SC}
TESTPVC

        # Wait briefly for provisioning (max 10 seconds)
        for i in {1..10}; do
            PVC_STATUS=$(kubectl get pvc -n "$TEST_NS" "$TEST_PVC" -o jsonpath='{.status.phase}' 2>/dev/null)
            if [[ "$PVC_STATUS" == "Bound" ]]; then
                PVC_TEST_RESULT="passed"
                PVC_TEST_MESSAGE="PVC bound in ${i}s"
                print_info "Provisioning: ✓ PVC bound in ${i}s"
                break
            elif [[ "$PVC_STATUS" == "Pending" ]]; then
                # Check for events/errors
                PVC_EVENTS=$(kubectl get events -n "$TEST_NS" --field-selector involvedObject.name="$TEST_PVC" -o json 2>/dev/null | jq -r '.items[-1].message // ""')
                if [[ "$i" == "10" ]]; then
                    # Check if it's WaitForFirstConsumer (which is expected behavior)
                    BINDING_MODE=$(echo "$SC_JSON" | jq -r ".items[] | select(.metadata.name==\"$DEFAULT_SC\") | .volumeBindingMode")
                    if [[ "$BINDING_MODE" == "WaitForFirstConsumer" ]]; then
                        PVC_TEST_RESULT="passed"
                        PVC_TEST_MESSAGE="WaitForFirstConsumer mode (normal)"
                        print_info "Provisioning: ✓ Pending (WaitForFirstConsumer - normal)"
                    else
                        PVC_TEST_RESULT="warning"
                        PVC_TEST_MESSAGE="PVC pending after 10s: ${PVC_EVENTS}"
                        print_warn "Provisioning: PVC pending after 10s"
                        [[ -n "$PVC_EVENTS" ]] && print_detail "${PVC_EVENTS}"
                    fi
                fi
            fi
            sleep 1
        done

        # Cleanup
        kubectl delete pvc -n "$TEST_NS" "$TEST_PVC" &>/dev/null 2>&1
        kubectl delete namespace "$TEST_NS" &>/dev/null 2>&1 &
    else
        PVC_TEST_RESULT="skipped"
        PVC_TEST_MESSAGE="Could not create test namespace"
        print_warn "Provisioning: Skipped (could not create test namespace)"
    fi
else
    PVC_TEST_RESULT="skipped"
    PVC_TEST_MESSAGE="No default storage class"
    print_warn "Provisioning: Skipped (no default storage class)"
fi

# Default storage class functional summary
print_section "Storage Readiness"
STORAGE_READY="false"
STORAGE_ISSUES=()

if [[ "$DEFAULT_SC" == "none" ]]; then
    STORAGE_ISSUES+=("No default storage class configured")
    print_warn "✗ No default storage class"
else
    print_info "✓ Default storage class: ${DEFAULT_SC}"
fi

if [[ "$PVC_TEST_RESULT" == "passed" ]]; then
    print_info "✓ PVC provisioning working"
    STORAGE_READY="true"
elif [[ "$PVC_TEST_RESULT" == "warning" ]]; then
    STORAGE_ISSUES+=("PVC provisioning may be slow or have issues")
    print_warn "⚠ PVC provisioning issues detected"
fi

if [[ "$HOSTPATH_AVAILABLE" == "true" ]]; then
    print_info "✓ Host path storage available for caching"
else
    STORAGE_ISSUES+=("No host path storage for model caching")
fi

if [[ "$RWX_CAPABLE" == "true" ]]; then
    print_info "✓ RWX storage available for shared data"
else
    STORAGE_ISSUES+=("No RWX storage for shared volumes")
fi

if [[ ${#STORAGE_ISSUES[@]} -eq 0 ]]; then
    STORAGE_READY="true"
fi

# --- Per-Node Storage (drive config from worker nodes) ---
print_section "Per-Node Storage (drive config)"
NODE_STORAGE_JSON="["
NODE_STORAGE_FIRST="true"

# Sample up to 3 GPU worker nodes. The storage layout that matters for GPU
# workloads is the GPU nodes' (local NVMe scratch is provisioned there); the
# rest of this collector also iterates GPU_NODE_NAMES. On a mixed cluster the
# old "any non-control-plane node" selection could sample a CPU-only service
# node and report its (different) storage. Fall back to any non-control-plane
# node only if no GPU node is visible.
WORKER_NODE_NAMES=$(echo "$GPU_NODE_NAMES" | tr ' ' '\n' | sed '/^$/d' | head -3)
if [[ -z "$WORKER_NODE_NAMES" ]]; then
    WORKER_NODE_NAMES=$(echo "$NODES_JSON" | jq -r '
        [.items[] |
         select(
           (.metadata.labels["node-role.kubernetes.io/control-plane"] == null) and
           (.metadata.labels["node-role.kubernetes.io/master"] == null)
         ) | .metadata.name
        ] | .[0:3] | .[]')
fi

if [[ -z "$WORKER_NODE_NAMES" ]]; then
    print_warn "No GPU/worker nodes found for storage check"
else
    # Storage check script (runs inside a pod on the target node)
    STORAGE_CHECK_SCRIPT='
BOOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || df / 2>/dev/null | tail -1 | awk "{print \$1}")
BOOT_FS=$(findmnt -n -o FSTYPE / 2>/dev/null || df -T / 2>/dev/null | tail -1 | awk "{print \$2}")
BOOT_SIZE=$(df -h / 2>/dev/null | tail -1 | awk "{print \$2}")
echo "BOOT_DEVICE=${BOOT_DEV:-unknown}"
echo "BOOT_FSTYPE=${BOOT_FS:-unknown}"
echo "BOOT_SIZE=${BOOT_SIZE:-unknown}"

if command -v lsblk >/dev/null 2>&1; then
    lsblk -d -b -o NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,TRAN -P -n 2>/dev/null | while IFS= read -r line; do
        eval "$line" 2>/dev/null || continue
        echo "BLKDEV_${NAME}=${TYPE}|${SIZE}|${MOUNTPOINT}|${FSTYPE}|${TRAN}"
    done
fi

if command -v lsblk >/dev/null 2>&1; then
    NVME_C=$(lsblk -d -o NAME -n 2>/dev/null | grep -c "^nvme" || echo 0)
    NVME_GB=$(lsblk -d -b -o NAME,SIZE -n 2>/dev/null | awk "\$1~/^nvme/{s+=\$2}END{printf \"%.0f\n\",s/1073741824}")
    NVME_LIST=$(lsblk -d -o NAME -n 2>/dev/null | grep "^nvme" | tr "\n" "," | sed "s/,$//" || echo "")
else
    NVME_C=0; NVME_GB=0; NVME_LIST=""
fi
echo "NVME_COUNT=${NVME_C}"
echo "NVME_TOTAL_GB=${NVME_GB}"
echo "NVME_DEVICES=${NVME_LIST}"

if command -v findmnt >/dev/null 2>&1; then
    findmnt -t nfs,nfs4,lustre,gpfs,ceph,glusterfs,fuse.weka,fuse.lustre,fuse.ceph,fuse.beegfs,beegfs,wekafs,panfs \
        -n -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | while read -r tgt src fst opts; do
        [ -z "$tgt" ] && continue
        SAFE=$(echo "$tgt" | tr "/" "_" | sed "s/^_//")
        DF_LINE=$(df -h "$tgt" 2>/dev/null | tail -1)
        DF_SZ=$(echo "$DF_LINE" | awk "{print \$2}")
        DF_US=$(echo "$DF_LINE" | awk "{print \$3}")
        DF_AV=$(echo "$DF_LINE" | awk "{print \$4}")
        echo "SHARED_${SAFE}=${src}|${fst}|${DF_SZ}|${DF_US}|${DF_AV}|${opts}"
    done
fi
'

    for NODE in $WORKER_NODE_NAMES; do
        print_detail "Checking node: ${NODE}"
        CHECK_OUTPUT=""

        # Strategy 1: exec into nvidia-driver daemonset pod on that node
        if [[ -n "$GPU_NS" ]]; then
            NODE_DS_POD=$(kubectl get pods -n "$GPU_NS" --field-selector "spec.nodeName=${NODE}" -o json 2>/dev/null | \
                jq -r '.items[] | select(.metadata.name | test("nvidia-driver")) | select(.status.phase == "Running") | .metadata.name' | head -1)
            if [[ -n "$NODE_DS_POD" ]]; then
                CHECK_OUTPUT=$(echo "$STORAGE_CHECK_SCRIPT" | kubectl exec -n "$GPU_NS" "$NODE_DS_POD" -i -- bash 2>/dev/null || echo "")
            fi
        fi

        # Strategy 2: privileged host pod with chroot (if no driver daemonset found)
        if [[ -z "$CHECK_OUTPUT" || ! "$CHECK_OUTPUT" =~ BOOT_DEVICE ]]; then
            STORAGE_POD=$(apply_privileged_host_check_pod "$NODE" || true)
            if [[ -n "$STORAGE_POD" ]]; then
                CHECK_OUTPUT=$(printf '%s\n' "$STORAGE_CHECK_SCRIPT" | check_deadline 120 kubectl exec -n "$K8S_AUDIT_CHECK_NS" "$STORAGE_POD" -i -- chroot /host bash -s 2>/dev/null || echo "")
                cleanup_audit_check_pod "$K8S_AUDIT_CHECK_NS" "$STORAGE_POD"
            fi
        fi

        if [[ -z "$CHECK_OUTPUT" || ! "$CHECK_OUTPUT" =~ BOOT_DEVICE ]]; then
            print_warn "  Storage check failed for ${NODE}"
            continue
        fi

        # Parse check output
        N_BOOT_DEV=$(echo "$CHECK_OUTPUT" | grep '^BOOT_DEVICE=' | cut -d= -f2-)
        N_BOOT_FS=$(echo "$CHECK_OUTPUT" | grep '^BOOT_FSTYPE=' | cut -d= -f2-)
        N_BOOT_SIZE=$(echo "$CHECK_OUTPUT" | grep '^BOOT_SIZE=' | cut -d= -f2-)
        N_NVME_COUNT=$(echo "$CHECK_OUTPUT" | grep '^NVME_COUNT=' | cut -d= -f2-)
        N_NVME_GB=$(echo "$CHECK_OUTPUT" | grep '^NVME_TOTAL_GB=' | cut -d= -f2-)
        N_NVME_DEVS=$(echo "$CHECK_OUTPUT" | grep '^NVME_DEVICES=' | cut -d= -f2-)

        # Build block devices JSON array for this node
        N_BLKDEV_JSON="["
        N_BLKDEV_FIRST="true"
        while IFS='=' read -r key val; do
            [[ "$key" =~ ^BLKDEV_ ]] || continue
            devname="${key#BLKDEV_}"
            IFS='|' read -r btype bsize bmp bfs btran <<< "$val"
            transport="${btran}"
            [[ -z "$transport" ]] && case "$devname" in nvme*) transport="nvme";; sd*) transport="sata";; vd*) transport="virtio";; *) transport="unknown";; esac
            classification="other"
            case "$devname" in nvme*) classification="local-nvme";; sd*) classification="local-sata";; vd*|xvd*) classification="virtual-disk";; esac
            [[ "$bmp" == "/" || "$bmp" == "/boot" || "$bmp" == "/boot/efi" ]] && classification="boot"
            size_human="${bsize}"
            if command -v numfmt &>/dev/null && [[ -n "$bsize" && "$bsize" != "0" ]]; then
                size_human=$(numfmt --to=iec --suffix=B "$bsize" 2>/dev/null || echo "$bsize")
            fi
            [[ "$N_BLKDEV_FIRST" == "true" ]] && N_BLKDEV_FIRST="false" || N_BLKDEV_JSON+=","
            N_BLKDEV_JSON+="{\"name\":\"${devname}\",\"type\":\"${btype}\",\"size\":\"${size_human}\",\"sizeBytes\":${bsize:-0},\"transport\":\"${transport}\",\"mountpoint\":\"${bmp}\",\"fstype\":\"${bfs}\",\"classification\":\"${classification}\"}"
        done < <(echo "$CHECK_OUTPUT" | grep '^BLKDEV_')
        N_BLKDEV_JSON+="]"

        # Build shared mounts JSON array for this node
        N_SHARED_JSON="["
        N_SHARED_FIRST="true"
        while IFS='=' read -r key val; do
            [[ "$key" =~ ^SHARED_ ]] || continue
            safe_target="${key#SHARED_}"
            target=$(echo "$safe_target" | sed 's/^_*/\//;s/_/\//g')
            IFS='|' read -r src fstype df_sz df_us df_av opts <<< "$val"
            [[ "$N_SHARED_FIRST" == "true" ]] && N_SHARED_FIRST="false" || N_SHARED_JSON+=","
            N_SHARED_JSON+="{\"mountpoint\":\"${target}\",\"fstype\":\"${fstype}\",\"source\":\"${src}\",\"size\":\"${df_sz}\",\"used\":\"${df_us}\",\"available\":\"${df_av}\",\"options\":\"${opts}\"}"
        done < <(echo "$CHECK_OUTPUT" | grep '^SHARED_')
        N_SHARED_JSON+="]"

        # Build NVMe devices JSON array
        N_NVME_DEVS_JSON="["
        if [[ -n "$N_NVME_DEVS" ]]; then
            N_NVME_FIRST="true"
            IFS=',' read -ra NVME_ARR <<< "$N_NVME_DEVS"
            for d in "${NVME_ARR[@]}"; do
                [[ -z "$d" ]] && continue
                [[ "$N_NVME_FIRST" == "true" ]] && N_NVME_FIRST="false" || N_NVME_DEVS_JSON+=","
                N_NVME_DEVS_JSON+="\"${d}\""
            done
        fi
        N_NVME_DEVS_JSON+="]"

        print_info "${NODE}: ${N_NVME_COUNT:-0} NVMe (${N_NVME_GB:-0} GB), boot=${N_BOOT_DEV} (${N_BOOT_FS})"

        # Append to node storage JSON array
        [[ "$NODE_STORAGE_FIRST" == "true" ]] && NODE_STORAGE_FIRST="false" || NODE_STORAGE_JSON+=","
        NODE_STORAGE_JSON+="{\"nodeName\":\"${NODE}\",\"bootDevice\":{\"device\":\"${N_BOOT_DEV}\",\"fstype\":\"${N_BOOT_FS}\",\"size\":\"${N_BOOT_SIZE}\"},\"blockDevices\":${N_BLKDEV_JSON},\"localNvme\":{\"count\":${N_NVME_COUNT:-0},\"totalCapacityGB\":${N_NVME_GB:-0},\"devices\":${N_NVME_DEVS_JSON}},\"sharedMounts\":${N_SHARED_JSON}}"
    done
fi
NODE_STORAGE_JSON+="]"

# =============================================================================
# SECTION 7: Additional Components
# =============================================================================
print_header "7. ADDITIONAL COMPONENTS"

print_section "Workload Orchestration"
MPI_OPERATOR=$(kubectl get crd mpijobs.kubeflow.org &>/dev/null 2>&1 && echo "true" || echo "false")
KUEUE=$(kubectl get crd workloads.kueue.x-k8s.io &>/dev/null 2>&1 && echo "true" || echo "false")
VOLCANO=$(kubectl get crd jobs.batch.volcano.sh &>/dev/null 2>&1 && echo "true" || echo "false")
TRAINING_OPERATOR=$(kubectl get crd pytorchjobs.kubeflow.org &>/dev/null 2>&1 && echo "true" || echo "false")

[[ "$MPI_OPERATOR" == "true" ]] && print_info "MPI Operator: Installed" || print_warn "MPI Operator: Not installed"
[[ "$KUEUE" == "true" ]] && print_info "Kueue: Installed" || print_warn "Kueue: Not installed"
[[ "$VOLCANO" == "true" ]] && print_info "Volcano: Installed" || print_warn "Volcano: Not installed"
[[ "$TRAINING_OPERATOR" == "true" ]] && print_info "Training Operator: Installed" || print_warn "Training Operator: Not installed"

# =============================================================================
# SECTION 8: Summary
# =============================================================================
print_header "8. SUMMARY (provisional)"

print_section "Cluster Overview"
echo ""
echo "  Provider:           ${PROVIDER}"
echo "  Kubernetes:         ${K8S_VERSION}"
echo "  Nodes:              ${TOTAL_NODES} total (${WORKER_NODES} workers)"
echo "  GPUs:               ${PRIMARY_GPU_TOTAL} × ${GPU_MODEL}${GPU_PROFILE_SUMMARY_SUFFIX}"
echo "  NCU Available:      ${NCU_INSTALLED} (${NCU_VERSION})"
echo "  NCU HW Counters:    ${NCU_COUNTER_ACCESS}"
echo "  perf Installed:     ${PERF_INSTALLED} (paranoid=${PERF_EVENT_PARANOID}, kptr=${PERF_KPTR_RESTRICT})"
echo "  perf stat:          ${PERF_STAT_ACCESS}"
echo "  RDMA:               ${RDMA_TYPE}"
echo "  Load Balancer:      ${LOADBALANCER_TYPE}"
echo "  Ingress:            ${INGRESS_CONTROLLER}"
echo "  Default Storage:    ${DEFAULT_SC}"
echo "  RWX Storage:        ${RWX_CAPABLE}"
echo "  Host Path Storage:  ${HOSTPATH_AVAILABLE}"
echo "  Storage Ready:      ${STORAGE_READY}"
echo ""
echo "  NOTE: GPU model / memory / driver / ROCm shown above are PROVISIONAL"
echo "        (from node labels, which managed clusters often omit). The"
echo "        host-check below resolves them - see the RESOLVED SUMMARY."
echo ""

# =============================================================================
# GENERATE JSON OUTPUT
# =============================================================================

# Determine cluster name for file
if [[ -n "$CUSTOM_NAME" ]]; then
    AUDIT_CLUSTER_NAME="$CUSTOM_NAME"
else
    # Clean the cluster name for filesystem
    AUDIT_CLUSTER_NAME=$(echo "$CLUSTER_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-64)
fi

# =============================================================================
# HOST-LEVEL CHECK (shared host-check.sh via the nvidia-driver daemonset pod)
# =============================================================================
# Bring k8s to parity with the slurm/standalone host checks (driver, NCCL,
# GDRCopy, IB sysfs, perf, dmesg Xids, BMC). The same host-check.sh the other
# collectors run is exec'd inside a privileged nvidia-driver daemonset pod; its
# WORKER_* facts are folded, additively, into audit_data.hostCheck. Degrades to
# {} when there is no driver pod or the pod lacks host access.
print_section "Host-Level Check (shared host-check.sh)"
HOST_CHECK_JSON="{}"
HOST_CHECK_OUT=""
HOST_CHECK_OK=false
NCCL_VERSION="unknown"
GPU_DIRECT_RDMA=false
# PCIe ACS (Access Control Services). ACS ON for a switch on the GPU<->backend-NIC
# path reroutes P2P traffic through the CPU root complex and breaks GPUDirect
# RDMA, slowing NCCL/RCCL collectives. We only flag the switches attached to the
# backend NICs and GPUs (not every bridge). Populated from the shared
# host-check.sh run via the privileged pod, which resolves the topology from the
# host's sysfs and reports path-scoped counts.
ACS_SCOPED=false
ACS_SUPPORTED=false
ACS_BRIDGES=0
ACS_ENABLED_COUNT=0
ACS_TOTAL_BRIDGES=0
ACS_ENABLED="unknown"
# How ACS_ENABLED was determined: "config" (static lspci ACSCtl) or
# "functional" (the no-root GDR self-test in host-check.sh, which catches the
# footgun when lspci is unreadable - the unprivileged tenant case).
ACS_METHOD="config"
ACS_FUNCTIONAL_PAIR="none"
ACS_FUNCTIONAL_SYNDROME=""

host_check_kv() {
    printf '%s\n' "$HOST_CHECK_OUT" | grep "^${1}=" | head -1 | cut -d= -f2- || true
}

# host_check_stdin - the host check as this collector delivers it.
#
# The check is piped into a container (or a chroot of the host root) that cannot
# see this checkout, so it cannot resolve the minimum version table itself.
# Prepend the Fragnesia kernel ABI minimum the collector already read from the
# table. minimum_version() yields "unknown" when the reader or the table is
# unavailable, and the check then reports an unknown Fragnesia state rather than
# grading the worker against a guessed minimum.
host_check_stdin() {
    printf 'CLUSTERMAX_FRAGNESIA_ABI_MINIMUM=%s\n' \
        "$(minimum_version components.ubuntuNoble.packages.linuxFragnesia.abi)"
    cat "$WORKLOAD_DIR/host-check.sh"
}

# Run the full shared host-check.sh against the host root of one node via a
# privileged pod and chroot /host. Needs no nvidia.com/gpu resource, so it
# works even when every GPU on the cluster is allocated to workloads.
run_host_check_on_node() {
    local node="$1"
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod=""
    local outcome=""

    pod=$(apply_privileged_host_check_pod "$node" || true)
    [[ -z "$pod" ]] && return 0

    outcome=$(check_deadline 180 kubectl exec -n "$ns" "$pod" -i -- \
        chroot /host bash -s < <(host_check_stdin) 2>/dev/null | grep '^WORKER_' || true)
    cleanup_audit_check_pod "$ns" "$pod"
    printf '%s\n' "$outcome"
}

run_gpu_error_check_on_node() {
    local node="$1" pod="" outcome=""
    pod=$(apply_privileged_host_check_pod "$node" || true)
    [[ -z "$pod" ]] && return 0
    outcome=$(check_deadline 60 kubectl exec -n "$K8S_AUDIT_CHECK_NS" "$pod" -- \
        chroot /host bash -c "$(gpu_error_scan_script)" 2>/dev/null || true)
    cleanup_audit_check_pod "$K8S_AUDIT_CHECK_NS" "$pod"
    printf '%s\n' "$outcome"
}

DMESG_XIDS_COUNT=unavailable
DMESG_XID_LAST=unavailable
DMESG_AMDGPU_ERRORS_COUNT=unavailable
GPU_ERROR_NODES_TOTAL=${GPU_NODE_COUNT:-0}
GPU_ERROR_NODES_CHECKED=0
GPU_ERROR_OUTPUT=""
for node in $GPU_NODE_NAMES; do
    GPU_ERROR_OUTPUT+="$(run_gpu_error_check_on_node "$node")"$'\n'
done
aggregate_gpu_error_history "$GPU_ERROR_OUTPUT" || true

run_gpu_smi_check() {
    local node="$1"
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod=""
    local outcome=""
    local script='
echo "WORKER_CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
echo "WORKER_NVIDIA_VISIBLE_DEVICES=${NVIDIA_VISIBLE_DEVICES:-unset}"
if command -v nvidia-smi >/dev/null 2>&1; then
    driver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo unknown)
    echo "WORKER_DRIVER_VERSION=$driver"
    echo "WORKER_CUDA_VERSION=$(nvidia-smi 2>/dev/null | grep -oP "CUDA Version: \K[0-9.]+" || echo unknown)"
    echo "WORKER_GPU_MODEL=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | tr " " "-" || echo unknown)"
    echo "WORKER_GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo 0)"
    minimum=""
    case "$driver" in
        595.*) minimum=595.71.05 ;;
        580.*) minimum=580.159.03 ;;
        535.*) minimum=535.309.01 ;;
    esac
    patched=unknown
    if [[ -n "$minimum" ]]; then
        if [[ "$(printf "%s\n%s\n" "$minimum" "$driver" | sort -V | head -1)" == "$minimum" ]]; then
            patched=true
        else
            patched=false
        fi
    else
        branch=${driver%%.*}
        if [[ "$branch" =~ ^[0-9]+$ ]] && [ "$branch" -gt 595 ]; then
            patched=true   # branch newer than the newest in the May 2026 bulletin
        fi
    fi
    echo "WORKER_NVIDIA_MAY_2026_PATCHED=$patched"
else
    echo "WORKER_DRIVER_VERSION=unknown"
    echo "WORKER_CUDA_VERSION=unknown"
    echo "WORKER_NVIDIA_MAY_2026_PATCHED=unknown"
fi
'

    pod=$(apply_gpu_check_pod "$node" "$K8S_AUDIT_GPU_CHECK_IMAGE" || true)
    [[ -z "$pod" ]] && return 0

    outcome=$(check_deadline 120 kubectl exec -n "$ns" "$pod" -- bash -c "$script" 2>/dev/null | grep '^WORKER_' || true)
    cleanup_audit_check_pod "$ns" "$pod"
    printf '%s\n' "$outcome"
}

# Container runtimes live on Kubernetes worker hosts, not on the machine
# running kubectl.  Use the same privileged host-pod path as the hardware
# check, then chroot into the selected GPU worker before running the shared
# container inventory.
run_container_check_on_node() {
    local node="$1"
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod=""
    local outcome=""

    pod=$(apply_privileged_host_check_pod "$node" || true)
    [[ -z "$pod" ]] && return 0

    outcome=$(check_deadline 180 kubectl exec -n "$ns" "$pod" -i -- \
        chroot /host env CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host bash -s \
        < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null | grep '^WORKER_CONTAINER_' || true)
    cleanup_audit_check_pod "$ns" "$pod"
    printf '%s\n' "$outcome"
}

# Probe local BMC access through the same administrative host-root path that
# the Kubernetes collector uses for worker facts. The result does not claim
# that a regular workload pod can reach IPMI. It records the exact node and
# access path so the final report can distinguish cluster administrator access
# from ordinary tenant access.
run_bmc_ipmi_check_on_node() {
    local node="$1"
    local ns="$K8S_AUDIT_CHECK_NS"
    local pod=""
    local outcome=""

    pod=$(apply_privileged_host_check_pod "$node" || true)
    if [[ -z "$pod" ]]; then
        jq -cn --arg node "$node" '{
          node: $node,
          checked: false,
          devicePresent: "unknown",
          ipmitoolInstalled: "unknown",
          ipmitoolPath: "unknown",
          mcInfoAccess: "unknown",
          chassisStatusAccess: "unknown",
          exposed: "unknown",
          error: "privileged host-root pod could not be created"
        }'
        return 0
    fi

    outcome=$(check_deadline 30 kubectl exec -n "$ns" "$pod" -- chroot /host bash -c '
device=false
for candidate in /dev/ipmi0 /dev/ipmi/0 /dev/ipmidev/0; do
    if [[ -e "$candidate" ]]; then
        device=true
        break
    fi
done
path=$(command -v ipmitool 2>/dev/null || true)
installed=false
mc=not-installed
chassis=not-installed
if [[ -n "$path" ]]; then
    installed=true
    if timeout 5 "$path" mc info >/dev/null 2>&1; then
        mc=allowed
    else
        mc=blocked
    fi
    if timeout 5 "$path" chassis status >/dev/null 2>&1; then
        chassis=allowed
    else
        chassis=blocked
    fi
fi
printf "DEVICE=%s\nPATH=%s\nINSTALLED=%s\nMC=%s\nCHASSIS=%s\n" \
    "$device" "$path" "$installed" "$mc" "$chassis"
' 2>/dev/null || true)
    cleanup_audit_check_pod "$ns" "$pod"

    local device path installed mc chassis exposed checked error
    device=$(printf '%s\n' "$outcome" | sed -n 's/^DEVICE=//p' | head -1)
    path=$(printf '%s\n' "$outcome" | sed -n 's/^PATH=//p' | head -1)
    installed=$(printf '%s\n' "$outcome" | sed -n 's/^INSTALLED=//p' | head -1)
    mc=$(printf '%s\n' "$outcome" | sed -n 's/^MC=//p' | head -1)
    chassis=$(printf '%s\n' "$outcome" | sed -n 's/^CHASSIS=//p' | head -1)
    checked=true
    error=""
    if [[ -z "$device" || -z "$installed" || -z "$mc" || -z "$chassis" ]]; then
        checked=false
        device=unknown
        installed=unknown
        path=unknown
        mc=unknown
        chassis=unknown
        error="the host-root IPMI probe did not return complete evidence"
    fi
    exposed=false
    if [[ "$mc" == "allowed" || "$chassis" == "allowed" ]]; then
        exposed=true
    elif [[ "$checked" != "true" ]]; then
        exposed=unknown
    fi

    jq -cn \
        --arg node "$node" \
        --arg checked "$checked" \
        --arg device "$device" \
        --arg installed "$installed" \
        --arg path "${path:-none}" \
        --arg mc "$mc" \
        --arg chassis "$chassis" \
        --arg exposed "$exposed" \
        --arg error "$error" \
        '{
          node: $node,
          checked: ($checked == "true"),
          devicePresent: (if $device == "unknown" then "unknown" else ($device == "true") end),
          ipmitoolInstalled: (if $installed == "unknown" then "unknown" else ($installed == "true") end),
          ipmitoolPath: $path,
          mcInfoAccess: $mc,
          chassisStatusAccess: $chassis,
          exposed: (if $exposed == "unknown" then "unknown" else ($exposed == "true") end)
        } + (if $error == "" then {} else {error: $error} end)'
}

summarize_bmc_ipmi_nodes() {
    jq -cs '
      . as $hosts
      | ($hosts | map(select(.checked == true))) as $checked
      | ($checked | map(select(.exposed == true) | .node)) as $exposed
      | ($hosts | map(select(.checked != true) | .node)) as $unassessed
      | {
          exposed: ($exposed | length > 0),
          accessMode: "administrative-privileged-host-root-pod",
          scope: "The Kubernetes identity could create a privileged pod that mounted the worker host root. This check did not test access from an ordinary workload pod.",
          ordinaryPodExposureTested: false,
          nodesTotal: ($hosts | length),
          nodesChecked: ($checked | length),
          nodeCoverageComplete: (($hosts | length) > 0 and (($checked | length) == ($hosts | length))),
          exposedNodes: $exposed,
          unassessedNodes: $unassessed,
          hosts: $hosts
        }'
}

# The worker-host inventory tells us what is installed.  A separate CUDA pod
# below proves the cluster's configured runtime actually injects the GPU into a
# normal workload container.
print_section "Container Runtime on GPU Worker"
K8S_CONTAINER_WORKER_CHECK_OK=false
K8S_CONTAINER_WORKER_NODE="unknown"
K8S_DOCKER_INSTALLED=false
K8S_DOCKER_ON_WORKERS=false
K8S_DOCKER_VERSION="unknown"
K8S_NVIDIA_CONTAINER_TOOLKIT=false
K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION="unknown"
K8S_RUNC_INSTALLED=false
K8S_RUNC_VERSION="unknown"
K8S_SECURITY_DOCKER_VERSION="unknown"
K8S_SECURITY_NCT_VERSION="unknown"
K8S_SECURITY_RUNC_VERSION="unknown"
K8S_SECURITY_DRIVER_VERSION="unknown"
K8S_DOCKER_NVIDIA_RUNTIME_CONFIGURED=false
K8S_ENROOT_INSTALLED=false
K8S_ENROOT_VERSION="unknown"
K8S_ENROOT_IMPORT_WORKS=false
K8S_SINGULARITY_INSTALLED=false
K8S_SINGULARITY_VERSION="unknown"
K8S_GPU_CONTAINER_RUNTIME_WORKS=false
K8S_GPU_CONTAINER_RUNTIME_NODE="unknown"
K8S_CUDA_VISIBLE_DEVICES="unknown"
K8S_NVIDIA_VISIBLE_DEVICES="unknown"

if [[ -f "$WORKLOAD_DIR/container-check.sh" && -n "$GPU_NODE_NAMES" ]]; then
    _container_tries=0
    for node in $GPU_NODE_NAMES; do
        if [[ "$_container_tries" -ge "$K8S_AUDIT_CHECK_NODE_TRIES" ]]; then break; fi
        _container_tries=$((_container_tries + 1))
        print_detail "Container host check: privileged pod on ${node} (ns=${K8S_AUDIT_CHECK_NS})"
        _container_out=$(run_container_check_on_node "$node")
        if grep -q '^WORKER_CONTAINER_HOSTNAME=' <<< "$_container_out"; then
            while IFS='=' read -r key val; do
                case "$key" in
                    WORKER_CONTAINER_HOSTNAME|WORKER_CONTAINER_RUNTIME_SCOPE|WORKER_CONTAINER_DOCKER_INSTALLED|WORKER_CONTAINER_DOCKER_ACCESSIBLE|WORKER_CONTAINER_DOCKER_VERSION|WORKER_CONTAINER_DOCKER_SERVER_VERSION|WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED|WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION|WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED|WORKER_CONTAINER_RUNC_INSTALLED|WORKER_CONTAINER_RUNC_VERSION|WORKER_CONTAINER_SECURITY_DOCKER_VERSION|WORKER_CONTAINER_SECURITY_NCT_VERSION|WORKER_CONTAINER_SECURITY_RUNC_VERSION|WORKER_CONTAINER_ENROOT_INSTALLED|WORKER_CONTAINER_ENROOT_VERSION|WORKER_CONTAINER_ENROOT_IMPORT|WORKER_CONTAINER_SINGULARITY_INSTALLED|WORKER_CONTAINER_SINGULARITY_VERSION)
                        printf -v "$key" '%s' "$val"
                        ;;
                esac
            done < <(grep '^WORKER_CONTAINER_' <<< "$_container_out")
            K8S_CONTAINER_WORKER_CHECK_OK=true
            K8S_CONTAINER_WORKER_NODE="${WORKER_CONTAINER_HOSTNAME}"
            K8S_DOCKER_INSTALLED="${WORKER_CONTAINER_DOCKER_INSTALLED:-false}"
            K8S_DOCKER_ON_WORKERS="${WORKER_CONTAINER_DOCKER_ACCESSIBLE:-false}"
            K8S_DOCKER_VERSION="${WORKER_CONTAINER_DOCKER_VERSION:-unknown}"
            K8S_NVIDIA_CONTAINER_TOOLKIT="${WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED:-false}"
            K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION="${WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION:-unknown}"
            K8S_DOCKER_NVIDIA_RUNTIME_CONFIGURED="${WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED:-false}"
            K8S_RUNC_INSTALLED="${WORKER_CONTAINER_RUNC_INSTALLED:-false}"
            K8S_RUNC_VERSION="${WORKER_CONTAINER_RUNC_VERSION:-unknown}"
            K8S_SECURITY_DOCKER_VERSION="${WORKER_CONTAINER_SECURITY_DOCKER_VERSION:-unknown}"
            K8S_SECURITY_NCT_VERSION="${WORKER_CONTAINER_SECURITY_NCT_VERSION:-unknown}"
            K8S_SECURITY_RUNC_VERSION="${WORKER_CONTAINER_SECURITY_RUNC_VERSION:-unknown}"
            K8S_ENROOT_INSTALLED="${WORKER_CONTAINER_ENROOT_INSTALLED:-false}"
            K8S_ENROOT_VERSION="${WORKER_CONTAINER_ENROOT_VERSION:-unknown}"
            [[ "${WORKER_CONTAINER_ENROOT_IMPORT:-}" == "pass" ]] && K8S_ENROOT_IMPORT_WORKS=true
            K8S_SINGULARITY_INSTALLED="${WORKER_CONTAINER_SINGULARITY_INSTALLED:-false}"
            K8S_SINGULARITY_VERSION="${WORKER_CONTAINER_SINGULARITY_VERSION:-unknown}"
            print_info "Worker host container check: ${K8S_CONTAINER_WORKER_NODE}; NVIDIA Container Toolkit=${K8S_NVIDIA_CONTAINER_TOOLKIT} (${K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION})"
            break
        fi
    done
    if [[ "$K8S_CONTAINER_WORKER_CHECK_OK" != "true" ]]; then
        print_warn "Container host check failed on GPU workers (privileged pod unavailable or inaccessible)"
    fi
elif [[ -z "$GPU_NODE_NAMES" ]]; then
    print_warn "Container host check skipped: no GPU worker node detected"
else
    print_warn "Container host check skipped: container-check.sh is unavailable"
fi

# GPU Operator may install the toolkit from its daemonset into a host path that
# is not visible on the host check's default PATH. A Ready toolkit daemonset is
# authoritative for Kubernetes even when the chroot inventory cannot find the
# binary directly.
if [[ "$K8S_NVIDIA_CONTAINER_TOOLKIT" != "true" && -n "${GPU_NS:-}" ]]; then
    _toolkit_ds=$(kubectl get daemonset nvidia-container-toolkit-daemonset -n "$GPU_NS" -o json 2>/dev/null || true)
    _toolkit_ready=$(k8s_toolkit_daemonset_ready "$_toolkit_ds")
    if [[ "${_toolkit_ready:-0}" -gt 0 ]]; then
        K8S_NVIDIA_CONTAINER_TOOLKIT=true
        _toolkit_image=$(k8s_toolkit_daemonset_image "$_toolkit_ds")
        # Remove an optional digest before extracting the tag. Otherwise a
        # digest-pinned image can be mistaken for a numeric Toolkit version.
        _toolkit_image_without_digest="${_toolkit_image%@*}"
        _toolkit_tag="${_toolkit_image_without_digest##*:}"
        if [[ -n "$_toolkit_tag" && "$_toolkit_tag" != "$_toolkit_image_without_digest" ]]; then
            K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION="${_toolkit_tag#v}"
        fi
        K8S_SECURITY_NCT_VERSION="$K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION"
        print_info "NVIDIA Container Toolkit: GPU Operator daemonset Ready (${_toolkit_ready} node(s), ${K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION})"
    fi
fi

if [[ "${TOTAL_GPUS:-0}" -gt 0 && -n "$GPU_FREE_NODE_NAMES" && "$GPU_VENDOR" == "nvidia" ]]; then
    _runtime_tries=0
    for node in $GPU_FREE_NODE_NAMES; do
        if [[ "$_runtime_tries" -ge "$K8S_AUDIT_CHECK_NODE_TRIES" ]]; then break; fi
        _runtime_tries=$((_runtime_tries + 1))
        print_detail "GPU container runtime test: CUDA pod on ${node} (image=${K8S_AUDIT_GPU_CHECK_IMAGE})"
        _runtime_out=$(run_gpu_smi_check "$node")
        _runtime_driver=$(printf '%s\n' "$_runtime_out" | grep '^WORKER_DRIVER_VERSION=' | head -1 | cut -d= -f2- || true)
        if [[ -n "$_runtime_driver" && "$_runtime_driver" != "unknown" ]]; then
            K8S_GPU_CONTAINER_RUNTIME_WORKS=true
            K8S_GPU_CONTAINER_RUNTIME_NODE="$node"
            K8S_CUDA_VISIBLE_DEVICES=$(printf '%s\n' "$_runtime_out" | grep '^WORKER_CUDA_VISIBLE_DEVICES=' | head -1 | cut -d= -f2- || echo "unset")
            K8S_NVIDIA_VISIBLE_DEVICES=$(printf '%s\n' "$_runtime_out" | grep '^WORKER_NVIDIA_VISIBLE_DEVICES=' | head -1 | cut -d= -f2- || echo "unset")
            print_info "GPU container runtime: PASS on ${node} (driver ${_runtime_driver})"
            break
        fi
    done
    if [[ "$K8S_GPU_CONTAINER_RUNTIME_WORKS" != "true" ]]; then
        print_warn "GPU container runtime: no CUDA check pod could access nvidia-smi on a worker"
    fi
elif [[ "${TOTAL_GPUS:-0}" -gt 0 && -z "$GPU_FREE_NODE_NAMES" && "$GPU_VENDOR" == "nvidia" ]]; then
    print_warn "GPU container runtime: untested because no unallocated GPU was available"
elif [[ "${TOTAL_GPUS:-0}" -gt 0 && -n "$GPU_NODE_NAMES" && "$GPU_VENDOR" == "amd" ]]; then
    # No CUDA/nvidia-smi pod on AMD. The privileged host-check below verifies the
    # AMD GPU stack (rocm-smi/amd-smi) without pulling a multi-GB ROCm image.
    print_detail "GPU container runtime: AMD detected; runtime facts collected via the privileged host-check (rocm-smi/amd-smi)"
fi

if [[ -f "$WORKLOAD_DIR/host-check.sh" ]]; then
    # Strategy 1: exec into an nvidia-driver daemonset pod (GPU Operator clusters).
    HOST_CHECK_POD=$(kubectl get pods -n "${GPU_NS:-}" -o json 2>/dev/null \
        | jq -r --argjson primary "$PRIMARY_GPU_NODE_NAMES_JSON" '
            .items[]
            | .spec.nodeName as $node
            | select(($primary | index($node)) != null)
            | select(.metadata.name | test("nvidia-driver"))
            | select(.status.phase == "Running")
            | .metadata.name' 2>/dev/null \
        | head -1 || true)
    if [[ -n "$HOST_CHECK_POD" && -n "$GPU_NS" ]]; then
        # 300s: the host-check's no-root functional ACS fallback can run two
        # `timeout 60` ib_write_bw loops plus sleeps after a full lspci -vvv
        # (slurm's srun window was raised to 5:00 for the same reason).
        HOST_CHECK_OUT=$(check_deadline 300 kubectl exec -n "$GPU_NS" "$HOST_CHECK_POD" -i -- bash \
            < <(host_check_stdin) 2>/dev/null | grep '^WORKER_' || true)
        if [[ -n "$HOST_CHECK_OUT" ]]; then
            print_info "Host check via ${HOST_CHECK_POD}: $(printf '%s\n' "$HOST_CHECK_OUT" | grep -c '^WORKER_') facts"
        else
            print_warn "Host check: no WORKER_ facts returned from driver daemonset pod"
        fi
    fi

    # Strategy 2: privileged host pod, chroot into the host root. Preferred
    # fallback because it needs no free GPU and returns the full WORKER_*
    # host fact set.
    if ! host_check_driver_known "$HOST_CHECK_OUT" && [[ -n "$GPU_NODE_NAMES" ]]; then
        _hp_tries=0
        for node in $GPU_NODE_NAMES; do
            if [[ "$_hp_tries" -ge "$K8S_AUDIT_CHECK_NODE_TRIES" ]]; then break; fi
            _hp_tries=$((_hp_tries + 1))
            print_detail "Host check fallback: privileged host pod on ${node} (ns=${K8S_AUDIT_CHECK_NS})"
            _hp_out=$(run_host_check_on_node "$node")
            if host_check_driver_known "$_hp_out"; then
                HOST_CHECK_OUT="$_hp_out"
                print_info "Host check via privileged pod on ${node}: $(printf '%s\n' "$HOST_CHECK_OUT" | grep -c '^WORKER_') facts"
                break
            fi
        done
        if ! host_check_driver_known "$HOST_CHECK_OUT"; then
            print_warn "Host check: privileged pod fallback returned no driver facts"
        fi
    fi

    # Strategy 3: plain GPU pod running nvidia-smi, for clusters that forbid
    # privileged pods. Needs a schedulable nvidia.com/gpu, so NVIDIA-only.
    if ! host_check_driver_known "$HOST_CHECK_OUT" && [[ -n "$GPU_NODE_NAMES" && "${TOTAL_GPUS:-0}" -gt 0 && "$GPU_VENDOR" == "nvidia" ]]; then
        _hp_tries=0
        for node in $GPU_NODE_NAMES; do
            if [[ "$_hp_tries" -ge "$K8S_AUDIT_CHECK_NODE_TRIES" ]]; then break; fi
            _hp_tries=$((_hp_tries + 1))
            print_detail "Host check fallback: GPU pod on ${node} (ns=${K8S_AUDIT_CHECK_NS}, image=${K8S_AUDIT_GPU_CHECK_IMAGE})"
            _hp_out=$(run_gpu_smi_check "$node")
            if host_check_driver_known "$_hp_out"; then
                HOST_CHECK_OUT="$_hp_out"
                print_info "GPU pod check on ${node}: driver/CUDA facts collected"
                break
            fi
        done
        if ! host_check_driver_known "$HOST_CHECK_OUT"; then
            print_warn "Host check: GPU pod fallback returned no driver facts"
        fi
    fi

    if [[ -n "$HOST_CHECK_OUT" ]]; then
        HOST_CHECK_JSON=$(printf '%s\n' "$HOST_CHECK_OUT" | kv_lines_to_json 2>/dev/null || echo "{}")
        HOST_CHECK_OK=true
    elif [[ -z "$GPU_NODE_NAMES" ]]; then
        print_warn "Host check: skipped (no GPU node available for fallback checks)"
    fi
else
    print_warn "Host check: skipped (host-check.sh not found)"
fi

if (( GPU_ERROR_NODES_CHECKED == 0 )) && [[ -n "$HOST_CHECK_OUT" ]]; then
    DMESG_XIDS_COUNT=$(host_check_kv "WORKER_DMESG_XIDS_COUNT")
    DMESG_XID_LAST=$(host_check_kv "WORKER_DMESG_XID_LAST")
    DMESG_AMDGPU_ERRORS_COUNT=$(host_check_kv "WORKER_DMESG_AMDGPU_ERRORS_COUNT")
    [[ "$DMESG_XIDS_COUNT" =~ ^[0-9]+$ ]] && GPU_ERROR_NODES_CHECKED=1
fi

if [[ -n "$HOST_CHECK_OUT" ]]; then
    HP_DRIVER=$(host_check_kv "WORKER_DRIVER_VERSION")
    HP_CUDA=$(host_check_kv "WORKER_CUDA_VERSION")
    HP_NCCL=$(host_check_kv "WORKER_NCCL_VERSION")
    HP_GPU_MODEL=$(host_check_kv "WORKER_GPU_MODEL")
    HP_GPU_MEMORY=$(host_check_kv "WORKER_GPU_MEMORY")
    HP_PEERMEM=$(host_check_kv "WORKER_PEERMEM")
    HP_RDMA_DEVICES=$(host_check_kv "WORKER_RDMA_DEVICES")
    HP_RDMA_ACTIVE=$(host_check_kv "WORKER_RDMA_ACTIVE_PORTS")
    HP_RDMA_DRIVERS=$(host_check_kv "WORKER_RDMA_DRIVERS")
    HP_RDMA_LAYERS=$(host_check_kv "WORKER_RDMA_LINK_LAYERS")
    HP_RDMA_MAX_RATE=$(host_check_kv "WORKER_RDMA_MAX_RATE_GBPS")
    HP_CPU_MODEL=$(host_check_kv "WORKER_CPU_MODEL")

    # The early perf check can lack a driver daemonset pod. The later
    # privileged host check is authoritative for the worker host and must
    # replace a provisional skip with its measured result.
    HP_PERF_PATH=$(host_check_kv "WORKER_PERF_PATH")
    HP_PERF_EVENT_PARANOID=$(host_check_kv "WORKER_PERF_EVENT_PARANOID")
    HP_PERF_KPTR_RESTRICT=$(host_check_kv "WORKER_KPTR_RESTRICT")
    HP_PERF_STAT_ACCESS=$(host_check_kv "WORKER_PERF_STAT_ACCESS")
    HP_PERF_TOP_ACCESS=$(host_check_kv "WORKER_PERF_TOP_ACCESS")
    if [[ -n "$HP_PERF_PATH" ]]; then
        PERF_INSTALLED="true"
    elif [[ -n "$HP_PERF_STAT_ACCESS" ]]; then
        PERF_INSTALLED="false"
    fi
    [[ -n "$HP_PERF_EVENT_PARANOID" ]] && PERF_EVENT_PARANOID="$HP_PERF_EVENT_PARANOID"
    [[ -n "$HP_PERF_KPTR_RESTRICT" ]] && PERF_KPTR_RESTRICT="$HP_PERF_KPTR_RESTRICT"
    [[ -n "$HP_PERF_STAT_ACCESS" ]] && PERF_STAT_ACCESS="$HP_PERF_STAT_ACCESS"
    [[ -n "$HP_PERF_TOP_ACCESS" ]] && PERF_TOP_ACCESS="$HP_PERF_TOP_ACCESS"

    # CPU inventory lands in audit_data.hostCheck with every other WORKER_*
    # fact; merge_audit.py folds it onto the canonical computeNodeCpu block.
    # Only the resolved summary is printed here.
    if [[ -n "$HP_CPU_MODEL" && "$HP_CPU_MODEL" != "unknown" ]]; then
        print_info "Compute node CPU: ${HP_CPU_MODEL} (sockets: $(host_check_kv "WORKER_CPU_SOCKETS"), package power limit W: $(host_check_kv "WORKER_CPU_PACKAGE_POWER_LIMIT_W"))"
    fi

    # Memory inventory follows the same path: merge_audit.py folds the
    # WORKER_MEM_* facts onto the canonical computeNodeMemory block.
    HP_MEM_DIMMS=$(host_check_kv "WORKER_MEM_DIMMS")
    if [[ -n "$HP_MEM_DIMMS" && "$HP_MEM_DIMMS" != "unknown" ]]; then
        print_info "Compute node memory: ${HP_MEM_DIMMS} DIMMs x $(host_check_kv "WORKER_MEM_DIMM_SIZES_GB")GB $(host_check_kv "WORKER_MEM_TYPES"), configured MT/s: $(host_check_kv "WORKER_MEM_CONFIGURED_SPEED_MTS"), BW GB/s per socket: $(host_check_kv "WORKER_MEM_BW_PER_SOCKET_GBS"), per logical core: $(host_check_kv "WORKER_MEM_BW_PER_CORE_GBS")"
    fi

    if [[ -n "$HP_DRIVER" && "$HP_DRIVER" != "unknown" ]]; then
        K8S_SECURITY_DRIVER_VERSION="$HP_DRIVER"
    fi

    # Host RDMA fabric: NICs present in /sys/class/infiniband even when no k8s
    # rdma/* resource is exposed (the bare-NIC + hostNetwork case, e.g. AMD
    # Pensando `ionic` RoCE). Reported separately from rdmaType so a healthy
    # fabric is not misread as absent just because it is not schedulable.
    if [[ "${HP_RDMA_ACTIVE:-0}" =~ ^[0-9]+$ && "${HP_RDMA_ACTIVE:-0}" -gt 0 ]]; then
        if [[ "$RDMA_TYPE" == "none" ]]; then
            print_warn "Host RDMA fabric present (${HP_RDMA_ACTIVE} active port(s); drivers: ${HP_RDMA_DRIVERS:-unknown}; up to ${HP_RDMA_MAX_RATE:-?} Gb/s) but NOT exposed as a k8s rdma/* resource - pods reach it only via hostNetwork"
        else
            print_detail "Host RDMA devices: ${HP_RDMA_DEVICES} (${HP_RDMA_ACTIVE} active; drivers: ${HP_RDMA_DRIVERS:-unknown})"
        fi
    fi

    if [[ "$DRIVER_VERSION" == "unknown" && -n "$HP_DRIVER" && "$HP_DRIVER" != "unknown" ]]; then
        DRIVER_VERSION="$HP_DRIVER"
    fi
    if [[ "$CUDA_VERSION" == "unknown" && -n "$HP_CUDA" && "$HP_CUDA" != "unknown" ]]; then
        CUDA_VERSION="$HP_CUDA"
    fi
    if [[ -n "$HP_NCCL" && "$HP_NCCL" != "not-found" && "$HP_NCCL" != "unknown" ]]; then
        NCCL_VERSION="$HP_NCCL"
    fi
    if [[ "$GPU_MODEL" == "unknown" || "$GPU_MODEL" == "NVIDIA GPU" ]]; then
        if [[ -n "$HP_GPU_MODEL" && "$HP_GPU_MODEL" != "unknown" && "$HP_GPU_MODEL" != "no-nvidia-smi" ]]; then
            GPU_MODEL="$HP_GPU_MODEL"
        fi
    fi
    if [[ "$GPU_MEMORY" == "unknown" && -n "$HP_GPU_MEMORY" && "$HP_GPU_MEMORY" != "0" ]]; then
        GPU_MEMORY="$HP_GPU_MEMORY"
    fi
    GPU_PROFILE_INVENTORY=$(printf '%s\n' "$GPU_PROFILE_INVENTORY" \
        | python3 "$WORKLOAD_DIR/gpu_profiles.py" \
            --resolved-model "$GPU_MODEL" --resolved-memory-mb "$GPU_MEMORY")
    PRIMARY_GPU_PROFILE_JSON=$(printf '%s\n' "$GPU_PROFILE_INVENTORY" | jq -c '.primary // {}')
    GPU_PROFILES_JSON=$(printf '%s\n' "$GPU_PROFILE_INVENTORY" | jq -c '.profiles // []')
    if [[ "$HP_PEERMEM" == "true" ]]; then
        GPU_DIRECT_RDMA=true
    fi

    # PCIe ACS - read from the same host-check.sh output. Counts are scoped to
    # the GPU<->backend-NIC PCIe switches (host-check.sh resolves the topology
    # from the host's sysfs). ACS_ENABLED is a 3-state string
    # ("true"/"false"/"unknown"). When the topology could not be resolved
    # (ACS_SCOPED=false) we only warn, never fail, since we cannot tell which
    # bridges are on the path. See https://www.clustermax.ai/k8s and
    # https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/troubleshooting.html
    HP_ACS_CHECK_OK=$(host_check_kv "WORKER_ACS_CHECK_OK")
    HP_ACS_METHOD=$(host_check_kv "WORKER_ACS_METHOD")
    HP_ACS_FN_PAIR=$(host_check_kv "WORKER_ACS_FUNCTIONAL_PAIR")
    HP_ACS_FN_SYN=$(host_check_kv "WORKER_ACS_FUNCTIONAL_SYNDROME")
    [[ -n "$HP_ACS_METHOD" ]] && ACS_METHOD="$HP_ACS_METHOD"
    [[ -n "$HP_ACS_FN_PAIR" ]] && ACS_FUNCTIONAL_PAIR="$HP_ACS_FN_PAIR"
    [[ -n "$HP_ACS_FN_SYN" ]] && ACS_FUNCTIONAL_SYNDROME="$HP_ACS_FN_SYN"
    if [[ "$HP_ACS_METHOD" == "functional" ]]; then
        # The no-root functional GDR self-test decided this. It targets the PIX
        # pair directly, so it is authoritative regardless of whether lspci was
        # readable (this is the unprivileged-tenant path the static read misses).
        HP_ACS_ENABLED=$(host_check_kv "WORKER_ACS_ENABLED")
        [[ -n "$HP_ACS_ENABLED" ]] && ACS_ENABLED="$HP_ACS_ENABLED"
        ACS_SCOPED=true
        ACS_SUPPORTED=true
        # Three-way verdict (match slurm/standalone): a non-"true" value is NOT
        # automatically a pass - only an explicit "false" passes; anything else
        # (self-test ran but inconclusive) stays unknown/warn so an enabled=
        # "unknown" JSON value can never be logged as success.
        if [[ "$ACS_ENABLED" == "true" ]]; then
            print_error "PCIe ACS: ENABLED (functional) - GPUDirect RDMA self-test on PIX pair ${ACS_FUNCTIONAL_PAIR} faulted (syndrome ${ACS_FUNCTIONAL_SYNDROME:-?}) while host-memory RDMA on the same NIC passed. Same-switch GPUDirect RDMA is blocked; disable ACS on the GPU<->NIC PCIe switches (see https://www.clustermax.ai/k8s)"
        elif [[ "$ACS_ENABLED" == "false" ]]; then
            print_info "PCIe ACS: functional GPUDirect RDMA self-test on PIX pair ${ACS_FUNCTIONAL_PAIR} passed (good - GPUDirect RDMA unobstructed)"
        else
            ACS_ENABLED="unknown"
            print_warn "PCIe ACS: functional GDR self-test inconclusive on PIX pair ${ACS_FUNCTIONAL_PAIR:-?} (neither a clean pass nor the 0x51 fault); treat as untested"
        fi
    elif [[ "$HP_ACS_CHECK_OK" == "true" ]]; then
        HP_ACS_SCOPED=$(host_check_kv "WORKER_ACS_SCOPED")
        HP_ACS_SUPPORTED=$(host_check_kv "WORKER_ACS_SUPPORTED")
        HP_ACS_BRIDGES=$(host_check_kv "WORKER_ACS_BRIDGES")
        HP_ACS_ENABLED_COUNT=$(host_check_kv "WORKER_ACS_ENABLED_COUNT")
        HP_ACS_TOTAL_BRIDGES=$(host_check_kv "WORKER_ACS_TOTAL_BRIDGES")
        HP_ACS_ENABLED=$(host_check_kv "WORKER_ACS_ENABLED")
        [[ -n "$HP_ACS_SCOPED" ]] && ACS_SCOPED="$HP_ACS_SCOPED"
        [[ -n "$HP_ACS_SUPPORTED" ]] && ACS_SUPPORTED="$HP_ACS_SUPPORTED"
        [[ -n "$HP_ACS_BRIDGES" ]] && ACS_BRIDGES="$HP_ACS_BRIDGES"
        [[ -n "$HP_ACS_ENABLED_COUNT" ]] && ACS_ENABLED_COUNT="$HP_ACS_ENABLED_COUNT"
        [[ -n "$HP_ACS_TOTAL_BRIDGES" ]] && ACS_TOTAL_BRIDGES="$HP_ACS_TOTAL_BRIDGES"
        if [[ "$HP_ACS_SCOPED" != "true" ]]; then
            # Topology not resolved - report unknown, warn only.
            ACS_ENABLED="unknown"
        elif [[ "$HP_ACS_SUPPORTED" != "true" ]]; then
            # supported=false is a pass only when the path switches were read and
            # none were ACS-capable; enabled=unknown means they were unread ->
            # inconclusive, not a false "no ACS".
            if [[ "$HP_ACS_ENABLED" == "unknown" ]]; then
                ACS_ENABLED="unknown"
            else
                ACS_ENABLED="false"
            fi
        elif [[ -n "$HP_ACS_ENABLED" ]]; then
            ACS_ENABLED="$HP_ACS_ENABLED"
        fi
        if [[ "$ACS_SCOPED" != "true" ]]; then
            print_warn "PCIe ACS: topology not resolved on host (${ACS_TOTAL_BRIDGES} ACS-capable bridge(s) host-wide). Only GPU<->NIC path switches matter; check manually: sudo lspci -vvv | grep ACSCtl"
        elif [[ "$ACS_ENABLED" == "true" ]]; then
            print_error "PCIe ACS: ENABLED on ${ACS_ENABLED_COUNT}/${ACS_BRIDGES} GPU<->NIC path switch(es) on host - GPUDirect RDMA degraded (disable ACS on those switches; see https://www.clustermax.ai/k8s)"
        elif [[ "$ACS_ENABLED" == "false" ]]; then
            print_info "PCIe ACS: disabled on all GPU<->NIC path switches on host (good - GPUDirect RDMA unobstructed)"
        else
            print_warn "PCIe ACS: UNKNOWN on host (lspci -vvv not readable on path switches)"
        fi
    else
        print_warn "PCIe ACS: UNTESTED (no root lspci -vvv and no GDR self-test tooling). Check manually: sudo lspci -vvv | grep ACSCtl"
    fi

    # AMD reconciliation. On AMD hosts the NVIDIA WORKER_* fields above are empty
    # or "no-nvidia-smi"; the GPU model/driver come from the shared host-check's
    # rocm-smi/amd-smi fields instead. These HP_AMD_* vars also feed the gpus.amd
    # JSON block below.
    if [[ "$GPU_VENDOR" == "amd" ]]; then
        HP_AMD_MODEL=$(host_check_kv "WORKER_AMD_GPU_MODEL")
        HP_AMD_DRIVER=$(host_check_kv "WORKER_AMD_DRIVER_VERSION")
        HP_AMD_COUNT=$(host_check_kv "WORKER_AMD_GPU_COUNT")
        HP_ROCM_VERSION=$(host_check_kv "WORKER_ROCM_VERSION")
        HP_ROCM_SMI=$(host_check_kv "WORKER_ROCM_SMI_PATH")
        HP_AMD_SMI=$(host_check_kv "WORKER_AMD_SMI_PATH")
        HP_AMD_PEERMEM=$(host_check_kv "WORKER_AMD_PEERMEM")
        HP_AMD_MEMORY=$(host_check_kv "WORKER_AMD_GPU_MEMORY")
        HP_ROCM_CT=$(host_check_kv "WORKER_ROCM_CT_PATH")

        [[ -n "$HP_ROCM_SMI" ]] && ROCM_SMI_AVAILABLE=true
        [[ -n "$HP_AMD_SMI" ]] && AMD_SMI_AVAILABLE=true
        # ROCm container toolkit (amd-container-toolkit) is the AMD analog of the
        # NVIDIA Container Toolkit. The containers.* block only reports NVIDIA, so
        # surface the AMD side here. Absent on cri-o + device-plugin clusters that
        # use no container-runtime hook (fine) - report it rather than leave blank.
        if [[ -n "$HP_ROCM_CT" ]]; then
            print_info "ROCm container toolkit: present (${HP_ROCM_CT})"
        else
            print_detail "ROCm container toolkit: not detected (cri-o + device-plugin clusters may not use one)"
        fi

        # Model: prefer the host-check product name. Tag it with an AMD/Instinct
        # token when missing so normalize_chip_name yields the bare chip (e.g.
        # MI355X) and the dashboard shows it correctly. Vendor classification
        # downstream comes from gpus.amd.present, not this string.
        if [[ "$GPU_MODEL" == "unknown" || -z "$GPU_MODEL" ]]; then
            if [[ -n "$HP_AMD_MODEL" && "$HP_AMD_MODEL" != "unknown" ]]; then
                if printf '%s' "$HP_AMD_MODEL" | grep -qiE 'amd|instinct'; then
                    GPU_MODEL="$HP_AMD_MODEL"
                else
                    GPU_MODEL="AMD-Instinct-${HP_AMD_MODEL}"
                fi
            else
                GPU_MODEL="AMD-Instinct-GPU"
            fi
        fi
        if [[ "$DRIVER_VERSION" == "unknown" && -n "$HP_AMD_DRIVER" && "$HP_AMD_DRIVER" != "unknown" ]]; then
            DRIVER_VERSION="$HP_AMD_DRIVER"
        fi
        # HBM per GPU (MiB) from the host-check when the AMD node-labeller did not
        # publish amd.com/gpu.vram (the common OKE / bare-plugin case).
        if [[ ( "$GPU_MEMORY" == "unknown" || -z "$GPU_MEMORY" ) && -n "$HP_AMD_MEMORY" && "$HP_AMD_MEMORY" != "unknown" ]]; then
            GPU_MEMORY="$HP_AMD_MEMORY"
        fi
        if [[ "$HP_AMD_PEERMEM" == "true" ]]; then
            GPU_DIRECT_RDMA=true
        fi
        # GPUDirect RDMA verdict + AMD evidence. The blessed path is the amdgpu
        # dma_buf export (legacy amd_peermem is deprecated). The verdict was
        # computed but never printed; report it explicitly with the underlying
        # signals and how to verify - a disabled GDR path is a ClusterMAX footgun
        # for multinode RCCL, so a plain false deserves an actionable explanation.
        HP_AMD_DMABUF=$(host_check_kv "WORKER_AMD_DMABUF")
        HP_AMD_PEERMEM_LEGACY=$(host_check_kv "WORKER_AMD_PEERMEM_LEGACY")
        if [[ "$GPU_DIRECT_RDMA" == "true" ]]; then
            print_info "GPUDirect RDMA: enabled (amdgpu dma_buf=${HP_AMD_DMABUF:-?}, amd_peermem=${HP_AMD_PEERMEM_LEGACY:-?})"
        else
            print_warn "GPUDirect RDMA: not enabled - amdgpu dma_buf export absent and amd_peermem not loaded (needed for fast multinode RCCL)"
            print_detail "Verify on a GPU node: find /sys/module/amdgpu -maxdepth 4 -name 'dma_buf*'; dmesg -T | grep -i p2p; rocm-bandwidth-test"
        fi
    fi
fi

# BMC and IPMI exposure varies by worker model and generation. A single host
# sample cannot support a cluster-wide claim. Check each worker through an
# explicit privileged host-root pod, up to a configurable safety limit, and
# retain an unassessed record for every node beyond that limit.
print_section "BMC and IPMI Fleet Check"
BMC_IPMI_JSON='{
  "exposed": false,
  "accessMode": "administrative-privileged-host-root-pod",
  "scope": "The Kubernetes identity could not complete a worker-node IPMI check.",
  "ordinaryPodExposureTested": false,
  "nodesTotal": 0,
  "nodesChecked": 0,
  "nodeCoverageComplete": false,
  "exposedNodes": [],
  "unassessedNodes": [],
  "hosts": []
}'
BMC_NODE_LIMIT="${CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT:-32}"
if ! [[ "$BMC_NODE_LIMIT" =~ ^[1-9][0-9]*$ ]]; then
    BMC_NODE_LIMIT=32
fi
BMC_NODE_NAMES=()
while IFS= read -r node; do
    [[ -n "$node" ]] && BMC_NODE_NAMES+=("$node")
done < <(printf '%s' "$NODES_JSON" | jq -r '
    .items[]
    | select(.metadata.labels["node-role.kubernetes.io/control-plane"] == null)
    | select(.metadata.labels["node-role.kubernetes.io/master"] == null)
    | .metadata.name' | sort)
if [[ "${#BMC_NODE_NAMES[@]}" -eq 0 ]]; then
    print_warn "BMC and IPMI fleet check skipped because no worker nodes were found"
else
    BMC_HOSTS_JSONL=""
    BMC_NODE_INDEX=0
    for node in "${BMC_NODE_NAMES[@]}"; do
        BMC_NODE_INDEX=$((BMC_NODE_INDEX + 1))
        if [[ "$BMC_NODE_INDEX" -le "$BMC_NODE_LIMIT" ]]; then
            print_detail "BMC and IPMI check: privileged host-root pod on ${node}"
            BMC_HOST_JSON=$(run_bmc_ipmi_check_on_node "$node")
        else
            BMC_HOST_JSON=$(jq -cn --arg node "$node" '{
              node: $node,
              checked: false,
              devicePresent: "unknown",
              ipmitoolInstalled: "unknown",
              ipmitoolPath: "unknown",
              mcInfoAccess: "unknown",
              chassisStatusAccess: "unknown",
              exposed: "unknown",
              error: "the configured fleet check node limit was reached"
            }')
        fi
        BMC_HOSTS_JSONL+="${BMC_HOST_JSON}"$'\n'
    done
    BMC_IPMI_JSON=$(printf '%s' "$BMC_HOSTS_JSONL" | summarize_bmc_ipmi_nodes)
    BMC_EXPOSED_COUNT=$(printf '%s' "$BMC_IPMI_JSON" | jq -r '.exposedNodes | length')
    BMC_CHECKED_COUNT=$(printf '%s' "$BMC_IPMI_JSON" | jq -r '.nodesChecked')
    if [[ "$BMC_EXPOSED_COUNT" -gt 0 ]]; then
        print_error "BMC and IPMI: local management access succeeded on ${BMC_EXPOSED_COUNT}/${#BMC_NODE_NAMES[@]} worker nodes through administrative privileged host-root pods"
    elif [[ "$BMC_CHECKED_COUNT" -eq "${#BMC_NODE_NAMES[@]}" ]]; then
        print_info "BMC and IPMI: local management access was blocked on all ${BMC_CHECKED_COUNT} worker nodes"
    else
        print_warn "BMC and IPMI: ${BMC_CHECKED_COUNT}/${#BMC_NODE_NAMES[@]} worker nodes were checked, and no checked node exposed local management access"
    fi
fi

# =============================================================================
# RESOLVED SUMMARY (post host-check)
# =============================================================================
# Security-bulletin evidence from the shared host check. These are deliberately
# guest/worker-visible exposure checks; host patch state remains explicit.
HP_VIRT_TYPE=$(host_check_kv "WORKER_VIRT_TYPE")
HP_VIRT_GUEST=$(host_check_kv "WORKER_VIRT_GUEST")
HP_QEMU_MACHINE=$(host_check_kv "WORKER_QEMU_MACHINE")
HP_VIRTIO_SERIAL=$(host_check_kv "WORKER_VIRTIO_SERIAL")
HP_NESTED_CPU=$(host_check_kv "WORKER_NESTED_CPU_EXPOSED")
HP_KVM_DEVICE=$(host_check_kv "WORKER_KVM_DEVICE")
HP_NESTED_MODULE=$(host_check_kv "WORKER_NESTED_MODULE")
HP_NESTED_ENABLED=$(host_check_kv "WORKER_NESTED_ENABLED")
HP_JANUSCAPE_EXPOSED=$(host_check_kv "WORKER_JANUSCAPE_EXPOSED")
HP_JANUSCAPE_EXPOSED_JSON=$(json_bool_or_unknown "$HP_JANUSCAPE_EXPOSED")
HP_JANUSCAPE_STATUS=$(host_check_kv "WORKER_JANUSCAPE_STATUS")
HP_QEMU_3446_STATUS=$(host_check_kv "WORKER_QEMU_CVE_2024_3446_STATUS")
HP_VMSCAPE_STATUS=$(host_check_kv "WORKER_VMSCAPE_STATUS")
HP_NVIDIA_MAY_2026=$(host_check_kv "WORKER_NVIDIA_MAY_2026_PATCHED")
HP_NVLINK_EXPOSED=$(host_check_kv "WORKER_NVLINK_EXPOSED")
HP_NVLINK_TOPOLOGY_CHECKED=$(host_check_kv "WORKER_NVLINK_TOPOLOGY_CHECKED")
HP_SECURITY_NVIDIA_GPU_PRESENT=$(host_check_kv "WORKER_SECURITY_NVIDIA_GPU_PRESENT")
HP_NVLINK_TOPOLOGY_COVERAGE_COMPLETE=false
if [[ "$NVIDIA_GPU_NODE_COUNT" -eq 1 ]]; then
    HP_NVLINK_TOPOLOGY_COVERAGE_COMPLETE=true
fi
HP_IOMMU_GROUPS=$(host_check_kv "WORKER_IOMMU_GROUPS")
HP_GUEST_KERNEL_RUNNING=$(host_check_kv "WORKER_GUEST_KERNEL_RUNNING")
HP_GUEST_KERNEL_NEWEST=$(host_check_kv "WORKER_GUEST_KERNEL_NEWEST_INSTALLED")
HP_GUEST_KERNEL_NEWER=$(host_check_kv "WORKER_GUEST_KERNEL_NEWER_INSTALLED")
HP_GUEST_REBOOT_REQUIRED=$(host_check_kv "WORKER_GUEST_REBOOT_REQUIRED")
HP_FRAGNESIA_STATUS=$(host_check_kv "WORKER_FRAGNESIA_STATUS")
HP_FRAGNESIA_ABI_MINIMUM=$(host_check_kv "WORKER_FRAGNESIA_ABI_FLOOR")

# The provisional section 8 prints GPU facts from node labels, which managed
# clusters (OKE/GKE/EKS) frequently omit - so it can read "unknown" there. The
# host-check (above) resolves them from rocm-smi/nvidia-smi after that section
# already printed. Re-print the resolved values so a human reading the log sees
# the truth; the structured JSON below already carries them.
print_header "8b. RESOLVED SUMMARY (post host-check)"
print_section "Resolved GPU Facts"
echo ""
echo "  GPUs:               ${PRIMARY_GPU_TOTAL} × ${GPU_MODEL}${GPU_PROFILE_SUMMARY_SUFFIX}"
echo "  GPU memory (MB):    ${GPU_MEMORY}"
echo "  GPU driver:         ${DRIVER_VERSION}"
if [[ "${GPU_VENDOR:-}" == "amd" ]]; then
    echo "  ROCm:               ${HP_ROCM_VERSION:-unknown}"
fi
echo "  GPUDirect RDMA:     ${GPU_DIRECT_RDMA}"
echo ""

# =============================================================================
# MONITORING STACK (folded in from the former platform-audit add-on)
# =============================================================================
# monitoring-k8s.sh (was platform-audit/workload/monitoring-audit.sh) detects the
# Prometheus/Grafana/DCGM-exporter/Alertmanager/KSM/node-exporter/GFD/log stack
# and a 0-10 readiness score - the one capability the core k8s collector lacked.
# Run it and fold its JSON into audit_data.monitoring (additive; degrades to {}).
print_section "Monitoring Stack (shared monitoring-k8s.sh)"
MONITORING_JSON="{}"
if [[ -f "$WORKLOAD_DIR/monitoring-k8s.sh" ]]; then
    _mon_tmp=$(mktemp -d)
    if check_deadline 120 bash "$WORKLOAD_DIR/monitoring-k8s.sh" --name "$AUDIT_CLUSTER_NAME" --output-dir "$_mon_tmp" >/dev/null 2>&1; then
        MONITORING_JSON=$(cat "$_mon_tmp"/*.json 2>/dev/null || echo "{}")
    fi
    rm -rf "$_mon_tmp"
    [[ -z "$MONITORING_JSON" ]] && MONITORING_JSON="{}"
    print_info "Monitoring stack audit captured"
fi

# dcgm-exporter is a Kubernetes deployment, so its container image tag is the
# only place this audit can read the DCGM and dcgm-exporter versions together
# (NVIDIA a_id 5857). monitoring-k8s.sh already captured the tag; read it from
# that JSON instead of querying the cluster a second time. An unreadable or
# absent monitoring block leaves both empty, which grades unknown.
# security.nvidiaMay2026 is an NVIDIA-named key, so it must never carry a
# non-NVIDIA driver version. gpus.driverVersion is vendor-neutral, and the AMD
# reconciliation block above promotes the amdgpu version into DRIVER_VERSION;
# interpolating that here stamps an amdgpu version (42 committed records carry
# 6.16.13 this way) under an NVIDIA bulletin key. The bulletin verdict itself
# already reports not_applicable on AMD, so this only stops the evidence field
# from contradicting it.
NVIDIA_MAY_2026_DRIVER_VERSION="unknown"
if [[ "${GPU_VENDOR:-nvidia}" == "nvidia" ]]; then
    NVIDIA_MAY_2026_DRIVER_VERSION="${DRIVER_VERSION:-unknown}"
fi
[[ -n "$NVIDIA_MAY_2026_DRIVER_VERSION" ]] || NVIDIA_MAY_2026_DRIVER_VERSION="unknown"

DCGM_EXPORTER_IMAGE=""
DCGM_EXPORTER_PRESENT="unknown"
if command -v jq >/dev/null 2>&1; then
    DCGM_EXPORTER_IMAGE=$(printf '%s' "$MONITORING_JSON" \
        | jq -r 'if (.dcgm.version // "unknown") == "unknown" then "" else .dcgm.version end' 2>/dev/null || true)
    DCGM_EXPORTER_PRESENT=$(printf '%s' "$MONITORING_JSON" \
        | jq -r 'if .dcgm.installed == true then "true" elif .dcgm.installed == false then "false" else "unknown" end' 2>/dev/null || echo "unknown")
fi
[[ -n "$DCGM_EXPORTER_PRESENT" ]] || DCGM_EXPORTER_PRESENT="unknown"

# Build JSON
SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit \
    "$HOST_CHECK_OUT" "$K8S_SECURITY_DRIVER_VERSION" \
    "$K8S_SECURITY_NCT_VERSION" "$K8S_SECURITY_RUNC_VERSION" \
    "$K8S_SECURITY_DOCKER_VERSION" "$GPU_VENDOR")

# The Ubuntu Noble advisory members come from the same shared builder the
# slurm/standalone collector uses, so the two JSON shapes read one minimum table
# instead of two hand-maintained copies.
SECURITY_ADVISORY_JSON=$(build_security_advisory_json \
    --fragnesia-status "${HP_FRAGNESIA_STATUS:-unknown}" \
    --fragnesia-compared-abi "${HP_FRAGNESIA_ABI_MINIMUM:-unknown}" \
    --januscape-cpu-exposed "${HP_NESTED_CPU:-false}" \
    --januscape-kvm-exposed "${HP_KVM_DEVICE:-false}" \
    --januscape-module "${HP_NESTED_MODULE:-none}" \
    --januscape-nested-enabled "${HP_NESTED_ENABLED:-unknown}" \
    --januscape-exposed "$HP_JANUSCAPE_EXPOSED_JSON" \
    --januscape-status "${HP_JANUSCAPE_STATUS:-unknown}" \
    --qemu-status "${HP_QEMU_3446_STATUS:-unknown}" \
    --vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")

JSON_OUTPUT=$(cat <<EOF
{
  "audit": {
    "version": "1.0",
    "timestamp": "${AUDIT_TIMESTAMP}",
    "clusterName": "${AUDIT_CLUSTER_NAME}",
    "contextName": "${CURRENT_CONTEXT}"
  },
  "kubernetes": {
    "version": "${K8S_VERSION}",
    "major": ${K8S_MAJOR},
    "minor": ${K8S_MINOR},
    "platform": "${K8S_PLATFORM}",
    "buildDate": "${K8S_BUILD_DATE}",
    "gitCommit": "${K8S_GIT_COMMIT}"
  },
  "provider": {
    "name": "${PROVIDER}",
    "type": "${PROVIDER_TYPE}",
    "tier": "unknown",
    "details": "${PROVIDER_DETAILS}",
    "signals": $( [[ ${#DETECTED_SIGNALS[@]} -gt 0 ]] && printf '%s\n' "${DETECTED_SIGNALS[@]}" | jq -R . | jq -s . || echo '[]' ),
    "rafayManaged": ${RAFAY_DETECTED:-false},
    "vclusterTenancy": {
      "detected": ${VCLUSTER_DETECTED:-false},
      "tenantName": "${VCLUSTER_TENANT_NAME}",
      "managedBy": "${VCLUSTER_MANAGED_BY}",
      "signals": $( [[ ${#VCLUSTER_SIGNALS[@]} -gt 0 ]] && printf '%s\n' "${VCLUSTER_SIGNALS[@]}" | jq -R . | jq -s . || echo '[]' ),
      "caveats": $( [[ ${#VCLUSTER_CAVEATS[@]} -gt 0 ]] && printf '%s\n' "${VCLUSTER_CAVEATS[@]}" | jq -R . | jq -s . || echo '[]' )
    }
  },
  "location": {
    "region": "${GEO_REGION}",
    "cloudRegion": "${NODE_REGION}",
    "zone": "${NODE_ZONE}",
    "city": "${GEO_CITY}",
    "country": "${GEO_COUNTRY}",
    "externalIp": "${GEO_IP}",
    "org": "${GEO_ORG:-}",
    "coordinates": "${GEO_LOC:-}"
  },
  "access": {
    "helm": {
      "installed": ${HELM_INSTALLED},
      "version": "${HELM_VERSION}",
      "listAllNamespaces": "${HELM_LIST_ACCESS}"
    },
    "rbac": {
      "summary": "${KUBECTL_RBAC_SUMMARY}",
      "checks": ${KUBECTL_AUTH_JSON}
    }
  },
  "nodes": {
    "total": ${TOTAL_NODES},
    "ready": ${READY_NODES},
    "controlPlane": ${CONTROL_PLANE},
    "workers": ${WORKER_NODES},
    "sampleCpu": "${NODE_CPU:-unknown}",
    "sampleMemory": "${NODE_MEM:-unknown}",
    "instanceType": "${NODE_INSTANCE:-unknown}"
  },
  "gpus": {
    "vendor": "${GPU_VENDOR}",
    "total": ${TOTAL_GPUS:-0},
    "allocatable": ${ALLOCATABLE_GPUS:-0},
    "model": "${GPU_MODEL}",
    "memoryMB": "${GPU_MEMORY}",
    "perNode": "${GPU_COUNT_LABEL}",
    "nodeCount": ${GPU_NODE_COUNT:-0},
    "primaryProfile": ${PRIMARY_GPU_PROFILE_JSON},
    "profiles": ${GPU_PROFILES_JSON:-[]},
    "totalCpus": ${GPU_TOTAL_CPUS:-0},
    "totalMemoryGB": ${GPU_TOTAL_MEMORY_GB:-0},
    "driverVersion": "${DRIVER_VERSION}",
    "cudaVersion": "${CUDA_VERSION}",
    "gpuDirectRdma": ${GPU_DIRECT_RDMA},
    "gpuDirectRdmaPath": {
      "amdDmaBuf": ${HP_AMD_DMABUF:-false},
      "amdPeermemLegacy": ${HP_AMD_PEERMEM_LEGACY:-false}
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
    "amd": {
      "present": ${AMD_GPUS_PRESENT},
      "model": "${HP_AMD_MODEL:-none}",
      "driverVersion": "${HP_AMD_DRIVER:-unknown}",
      "rocmVersion": "${HP_ROCM_VERSION:-unknown}",
      "rocmSmi": ${ROCM_SMI_AVAILABLE},
      "amdSmi": ${AMD_SMI_AVAILABLE},
      "count": "${HP_AMD_COUNT:-unknown}",
      "rocmContainerToolkit": $([ -n "${HP_ROCM_CT:-}" ] && echo true || echo false)
    },
    "dmesgErrors": {
      "xidsCount": "${DMESG_XIDS_COUNT:-unavailable}",
      "lastXid": "${DMESG_XID_LAST:-unavailable}",
      "amdgpuErrorsCount": "${DMESG_AMDGPU_ERRORS_COUNT:-unavailable}",
      "nodesChecked": ${GPU_ERROR_NODES_CHECKED:-0},
      "nodesTotal": ${GPU_ERROR_NODES_TOTAL:-0}
    }
  },
  "containers": {
    "runtimeScope": "${WORKER_CONTAINER_RUNTIME_SCOPE:-unknown}",
    "workerCheckOk": ${K8S_CONTAINER_WORKER_CHECK_OK},
    "workerNode": "${K8S_CONTAINER_WORKER_NODE}",
    "docker": ${K8S_DOCKER_INSTALLED},
    "dockerOnWorkers": ${K8S_DOCKER_ON_WORKERS},
    "dockerVersion": "${K8S_DOCKER_VERSION}",
    "nvidiaContainerToolkit": ${K8S_NVIDIA_CONTAINER_TOOLKIT},
    "nvidiaContainerToolkitVersion": "${K8S_NVIDIA_CONTAINER_TOOLKIT_VERSION}",
    "dockerNvidiaRuntimeConfigured": ${K8S_DOCKER_NVIDIA_RUNTIME_CONFIGURED},
    "runc": ${K8S_RUNC_INSTALLED},
    "runcVersion": "${K8S_RUNC_VERSION}",
    "enroot": ${K8S_ENROOT_INSTALLED},
    "enrootVersion": "${K8S_ENROOT_VERSION}",
    "enrootImportWorks": ${K8S_ENROOT_IMPORT_WORKS},
    "singularity": ${K8S_SINGULARITY_INSTALLED},
    "singularityVersion": "${K8S_SINGULARITY_VERSION}",
    "gpuRuntimeWorks": ${K8S_GPU_CONTAINER_RUNTIME_WORKS},
    "gpuRuntimeNode": "${K8S_GPU_CONTAINER_RUNTIME_NODE}"
  },
  "securityVersions": ${SECURITY_VERSION_AUDIT_JSON},
  "software": {
    "workerCheckOk": ${HOST_CHECK_OK},
    "ncclVersion": "${NCCL_VERSION}",
    "ncu": {
      "installed": ${NCU_INSTALLED},
      "version": "${NCU_VERSION}",
      "profilingEnabled": $(json_bool_or_unknown "${NCU_PROFILING_ENABLED:-}"),
      "hardwareCounterAccess": "${NCU_COUNTER_ACCESS}"
    },
    "cudaVisibleDevices": "${K8S_CUDA_VISIBLE_DEVICES}",
    "nvidiaVisibleDevices": "${K8S_NVIDIA_VISIBLE_DEVICES}",
    "perf": {
      "installed": ${PERF_INSTALLED},
      "perfEventParanoid": "${PERF_EVENT_PARANOID}",
      "kptrRestrict": "${PERF_KPTR_RESTRICT}",
      "statAccess": "${PERF_STAT_ACCESS}",
      "topAccess": "${PERF_TOP_ACCESS}"
    }
  },
  "hostCheck": ${HOST_CHECK_JSON},
  "monitoring": ${MONITORING_JSON},
  "operators": {
    "gpuOperator": {
      "installed": ${GPU_OPERATOR_INSTALLED},
      "namespace": "${GPU_NS:-none}",
      "version": "${GPU_OPERATOR_VERSION:-unknown}",
      "image": "${GPU_OPERATOR_IMAGE:-none}"
    },
    "networkOperator": {
      "installed": $([ "$NETWORK_OPERATOR_INSTALLED" == "true" ] && echo "true" || echo "false"),
      "namespace": "${NETWORK_NS:-none}",
      "version": "${NETWORK_OPERATOR_VERSION:-unknown}"
    },
    "mpiOperator": ${MPI_OPERATOR},
    "kueue": ${KUEUE},
    "volcano": ${VOLCANO},
    "trainingOperator": ${TRAINING_OPERATOR}
  },
  "networking": {
    "rdmaType": "${RDMA_TYPE}",
    "rdmaResources": {
      "ib": ${RDMA_IB:-0},
      "roce": ${RDMA_ROCE:-0},
      "hca": ${RDMA_HCA:-0},
      "shared": ${RDMA_SHARED:-0},
      "sharedResources": "${RDMA_SHARED_RES}",
      "generic": ${RDMA_GENERIC:-0},
      "genericResources": "${RDMA_GENERIC_RES}",
      "fabric": ${RDMA_FABRIC:-0},
      "fabricPerNode": ${RDMA_FABRIC_COUNT_PER_NODE:-0}
    },
    "hostRdma": {
      "devices": ${HP_RDMA_DEVICES:-0},
      "activePorts": ${HP_RDMA_ACTIVE:-0},
      "drivers": "${HP_RDMA_DRIVERS}",
      "linkLayers": "${HP_RDMA_LAYERS}",
      "maxRateGbps": ${HP_RDMA_MAX_RATE:-0}
    },
    "efa": {
      "available": $([ "${EFA_TOTAL:-0}" -gt 0 ] && echo "true" || echo "false"),
      "totalDevices": ${EFA_TOTAL:-0},
      "perNode": ${EFA_PER_NODE:-0}
    },
    "mofedVersion": "${MOFED_VERSION}",
    "nicModel": "${NIC_MODEL}",
    "multusInstalled": ${MULTUS_INSTALLED},
    "loadBalancer": {
      "type": "${LOADBALANCER_TYPE}",
      "metallbInstalled": ${METALLB_INSTALLED},
      "servicesWithIP": ${LB_WITH_IP:-0},
      "totalLBServices": ${LB_SERVICES:-0}
    },
    "ingress": {
      "controller": "${INGRESS_CONTROLLER}",
      "defaultClass": "${INGRESS_CLASS:-none}",
      "resourceCount": ${INGRESS_COUNT:-0}
    },
    "topologyAware": ${TOPOLOGY_AWARE_SCHEDULING:-false},
    "topologyConfigured": ${TOPOLOGY_AWARE_SCHEDULING:-false},
    "topologyMechanisms": ${TOPOLOGY_MECHANISMS_JSON:-[]},
    "gangScheduling": ${GANG_SCHEDULING:-false},
    "gangMechanisms": ${GANG_MECHANISMS_JSON:-[]},
    "binPacking": ${BIN_PACKING:-false},
    "binPackMechanisms": ${BINPACK_MECHANISMS_JSON:-[]}
  },
  "security": {
    "bmcIpmi": ${BMC_IPMI_JSON},
    "ufmSecuredBareMetalCloud": ${UFM_SECURED_PROFILE_JSON},
    "virtualization": {
      "type": "${HP_VIRT_TYPE:-unknown}",
      "guest": $(json_bool_or_unknown "${HP_VIRT_GUEST:-unknown}"),
      "qemuMachine": "${HP_QEMU_MACHINE:-unknown}",
      "virtioSerialExposed": ${HP_VIRTIO_SERIAL:-false}
    },
    "guestKernel": {
      "running": "${HP_GUEST_KERNEL_RUNNING:-unknown}",
      "newestInstalled": "${HP_GUEST_KERNEL_NEWEST:-unknown}",
      "newerInstalled": ${HP_GUEST_KERNEL_NEWER:-false},
      "rebootRequired": ${HP_GUEST_REBOOT_REQUIRED:-false}
    },
${SECURITY_ADVISORY_JSON}
    "nvidiaMay2026": {
      "driverVersion": "${NVIDIA_MAY_2026_DRIVER_VERSION:-unknown}",
      "patched": "${HP_NVIDIA_MAY_2026:-unknown}",
      "nvlinkExposed": $(json_bool_or_unknown "${HP_NVLINK_EXPOSED:-unknown}")
    },
    "nvlinkBoundary": {
      "nvlinkExposed": $(json_bool_or_unknown "${HP_NVLINK_EXPOSED:-unknown}"),
      "topologyChecked": $(json_bool_or_unknown "${HP_NVLINK_TOPOLOGY_CHECKED:-false}"),
      "topologyCoverageComplete": ${HP_NVLINK_TOPOLOGY_COVERAGE_COMPLETE},
      "nvidiaGpuPresent": $(json_bool_or_unknown "${HP_SECURITY_NVIDIA_GPU_PRESENT:-unknown}"),
      "targetIsVm": $(json_bool_or_unknown "${HP_VIRT_GUEST:-unknown}"),
      "domainExclusive": $(json_bool_or_unknown "${CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED:-unknown}")
    },
    "pciePassthrough": {
      "guestIommuGroupCount": ${HP_IOMMU_GROUPS:-0},
      "hostVerificationRequired": true
    }
  },
  "storage": {
    "defaultClass": "${DEFAULT_SC}",
    "rwxCapable": ${RWX_CAPABLE},
    "hostPathAvailable": ${HOSTPATH_AVAILABLE},
    "storageReady": ${STORAGE_READY},
    "pvcTest": {
      "result": "${PVC_TEST_RESULT}",
      "message": "${PVC_TEST_MESSAGE}"
    },
    "providers": $( [[ ${#STORAGE_PROVIDERS[@]} -gt 0 ]] && printf '%s\n' "${STORAGE_PROVIDERS[@]}" | jq -R . | jq -s . || echo '[]' ),
    "classes": ${STORAGE_CLASSES_JSON},
    "nodeStorage": ${NODE_STORAGE_JSON:-[]}
  }
}
EOF
)

# Output JSON
if [[ "$JSON_ONLY" == "true" ]]; then
    echo "$JSON_OUTPUT" | jq .
else
    # Save to file
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -n "$OUTPUT_DIR" ]]; then
        RESULTS_DIR="$OUTPUT_DIR"
    else
        RESULTS_DIR="${SCRIPT_DIR}/audit-results"
    fi

    mkdir -p "$RESULTS_DIR"
    OUTPUT_FILE="${RESULTS_DIR}/${AUDIT_TIMESTAMP_FILE}_${AUDIT_CLUSTER_NAME}.json"

    if ! printf '%s\n' "$JSON_OUTPUT" | jq . > "$OUTPUT_FILE"; then
        INVALID_OUTPUT="${TMPDIR:-/tmp}/clustermax-audit-invalid-${AUDIT_TIMESTAMP_FILE}.json"
        printf '%s\n' "$JSON_OUTPUT" > "$INVALID_OUTPUT"
        print_error "Collector produced invalid JSON; raw output saved to ${INVALID_OUTPUT}"
        exit 5
    fi

    print_section "Output"
    print_info "JSON saved: ${OUTPUT_FILE}"
    echo ""
fi
