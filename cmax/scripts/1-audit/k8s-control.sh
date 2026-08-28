#!/bin/bash
# These shared helpers support the audit's Kubernetes collector.
# They run on the operator side with kubectl access. They write
# RESULT_DIR/<runner>.values.json on success and stream other output to stdout/stderr.

set -euo pipefail

k8s_control_init() {
    RUNNER_NAME="${1:?runner name required}"
    : "${RESULT_DIR:?RESULT_DIR must be set by bench}"
    K8S_NAMESPACE="${K8S_NAMESPACE:-default}"
    CLUSTER_NAME="${CLUSTER_NAME:-${CLUSTER_SLUG:-${CLUSTERMAX_CLUSTER:-unknown}}}"
    K8S_CASE="${K8S_CASE:-default}"
    K8S_TIMEOUT_S="${K8S_TIMEOUT_S:-${TIMEOUT_S:-3600}}"
    CLUSTERMAX_LOG_DIR="${CLUSTERMAX_LOG_DIR:-${RESULT_DIR}/logs}"
    mkdir -p "$RESULT_DIR" "$CLUSTERMAX_LOG_DIR"
}

k8s_require_tools() {
    command -v kubectl >/dev/null 2>&1 || {
        echo "ERROR: kubectl is required for k8s_control workloads" >&2
        return 127
    }
}

k8s_gpu_dra_enabled() {
    case "${CLUSTERMAX_K8S_GPU_DRA:-0}" in
        1) return 0 ;;
        0|"") return 1 ;;
        *) echo "ERROR: CLUSTERMAX_K8S_GPU_DRA must be 1 or 0" >&2; exit 2 ;;
    esac
}

# Indexed Pods use <job>-<index>.<service>.<namespace>.svc.cluster.local as
# their FQDN. Keep both repeated labels short enough for the kernel hostname
# limit while retaining a stable runner prefix and collision-resistant suffix.
k8s_distributed_name() {
    local runner="${1:?runner required}" raw="cmax-${1}" digest compact
    if (( ${#raw} <= 16 )); then
        printf '%s\n' "$raw"
        return 0
    fi
    digest="$(printf '%s' "$runner" | sha256sum | cut -c1-6)"
    compact="${runner//-/}"
    printf 'cmax-%s-%s\n' "${compact:0:4}" "$digest"
}

k8s_ensure_gpu_dra_claim_template() {
    local count="${1:?GPU count required}"
    local ns="${K8S_NAMESPACE:-default}"
    local explicit="${CLUSTERMAX_K8S_GPU_DRA_CLAIM_TEMPLATE:-}"
    local device_class="${CLUSTERMAX_K8S_GPU_DRA_DEVICE_CLASS:-gpu.nvidia.com}"
    local name apply_rc=0
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || {
        echo "ERROR: DRA GPU count must be a positive integer; got ${count}" >&2
        return 2
    }
    if [[ -n "$explicit" ]]; then
        kubectl -n "$ns" get resourceclaimtemplate "$explicit" >/dev/null 2>&1 || {
            echo "ERROR: GPU DRA ResourceClaimTemplate not found: ${ns}/${explicit}" >&2
            return 2
        }
        printf '%s\n' "$explicit"
        return 0
    fi
    name="cmax-gpu-dra-${count}"
    kubectl -n "$ns" apply -f - >/dev/null <<EOF || apply_rc=$?
apiVersion: resource.k8s.io/v1
kind: ResourceClaimTemplate
metadata:
  name: ${name}
  namespace: ${ns}
  labels:
    app.kubernetes.io/name: clustermax-bench
spec:
  spec:
    devices:
      requests:
      - name: gpu
        exactly:
          deviceClassName: ${device_class}
          allocationMode: ExactCount
          count: ${count}
EOF
    if (( apply_rc != 0 )); then
        echo "ERROR: failed to create GPU DRA ResourceClaimTemplate: ${ns}/${name}" >&2
        return "$apply_rc"
    fi
    printf '%s\n' "$name"
}

k8s_gpu_dra_pod_claim_entry_yaml() {
    local count="${1:?GPU count required}" indent="${2:-      }" template
    k8s_gpu_dra_enabled || return 0
    template="$(k8s_ensure_gpu_dra_claim_template "$count")" || return $?
    printf '%s- name: gpu\n%s  resourceClaimTemplateName: %s\n' \
        "$indent" "$indent" "$template"
}

k8s_gpu_dra_container_claim_entry_yaml() {
    local indent="${1:-          }"
    k8s_gpu_dra_enabled || return 0
    printf '%s- name: gpu\n' "$indent"
}

# Print "<node> <count>" for every node-local GPU DRA allocation pool. Unlike
# k8s_gpu_topology this deliberately includes cordoned/NotReady nodes so
# lifecycle tests can observe GPU registration disappearing and returning.
k8s_dra_gpu_node_counts() {
    local driver="${CLUSTERMAX_K8S_GPU_DRA_DRIVER:-gpu.nvidia.com}"
    kubectl get resourceslices.resource.k8s.io -o json 2>/dev/null | \
        CLUSTERMAX_K8S_GPU_DRA_DRIVER="$driver" python3 -c '
import json, os, sys
driver = os.environ.get("CLUSTERMAX_K8S_GPU_DRA_DRIVER", "gpu.nvidia.com")
counts = {}
for item in json.load(sys.stdin).get("items", []):
    spec = item.get("spec", {})
    if spec.get("driver") != driver:
        continue
    node = spec.get("nodeName") or spec.get("pool", {}).get("name")
    if node:
        counts[node] = counts.get(node, 0) + len(spec.get("devices", []))
for node in sorted(counts):
    if counts[node] > 0:
        print(node, counts[node])
'
}

k8s_gpu_capacity_for_node() {
    local node="${1:?node required}"
    if k8s_gpu_dra_enabled; then
        k8s_dra_gpu_node_counts | awk -v node="$node" '$1 == node { print $2; found=1 } END { if (!found) print 0 }'
    else
        kubectl get node "$node" -o jsonpath='{.status.capacity.nvidia\.com/gpu}' 2>/dev/null || printf '0\n'
    fi
}

k8s_gpu_allocatable_for_node() {
    local node="${1:?node required}"
    if k8s_gpu_dra_enabled; then
        # DRA exposes the node-local device pool through ResourceSlices rather
        # than separate Node capacity and allocatable scalar fields.
        k8s_dra_gpu_node_counts | awk -v node="$node" '$1 == node { print $2; found=1 } END { if (!found) print 0 }'
    else
        kubectl get node "$node" -o jsonpath='{.status.allocatable.nvidia\.com/gpu}' 2>/dev/null || printf '0\n'
    fi
}

# Most scheduling callers need allocatable GPUs. Lifecycle callers that must
# compare registration milestones use the explicit capacity/allocatable helpers.
k8s_gpu_count_for_node() {
    k8s_gpu_allocatable_for_node "$1"
}

# Ready, schedulable, non-control-plane workers with GPU capacity, one per line.
k8s_gpu_worker_nodes() {
    local counts='{}'
    if k8s_gpu_dra_enabled; then
        counts="$(k8s_dra_gpu_node_counts | python3 -c '
import json, sys
print(json.dumps({line.split()[0]: int(line.split()[1]) for line in sys.stdin if line.split()}))
')"
    fi
    kubectl get nodes -o json 2>/dev/null | \
        CMAX_DRA_GPU_COUNTS="$counts" CLUSTERMAX_K8S_GPU_DRA="${CLUSTERMAX_K8S_GPU_DRA:-0}" python3 -c '
import json, os, sys
counts = json.loads(os.environ.get("CMAX_DRA_GPU_COUNTS", "{}"))
dra = os.environ.get("CLUSTERMAX_K8S_GPU_DRA", "0") == "1"
for node in json.load(sys.stdin).get("items", []):
    md = node.get("metadata", {}); labels = md.get("labels", {})
    spec = node.get("spec", {}); status = node.get("status", {})
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", []))
    control = "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels
    scalar = int(status.get("allocatable", {}).get("nvidia.com/gpu", 0) or 0)
    has_gpu = counts.get(md.get("name", ""), 0) > 0 if dra else scalar > 0
    if ready and not spec.get("unschedulable") and not control and has_gpu:
        print(md.get("name", ""))
'
}

k8s_runtime_class_yaml() {
    local indent="${1:-  }"
    local runtime_class="${CLUSTERMAX_K8S_RUNTIME_CLASS:-}"
    [[ -n "$runtime_class" ]] && printf '%sruntimeClassName: %s\n' "$indent" "$runtime_class"
    return 0
}

k8s_arch_node_selector_yaml() {
    local indent="${1:-  }"
    local arch="${CLUSTERMAX_NODE_ARCH:-${CLUSTERMAX_ARCH:-}}"
    arch="$(printf '%s' "$arch" | tr '[:upper:]' '[:lower:]')"
    case "$arch" in
        aarch64|arm64|linux/arm64|linux/aarch64) arch="arm64" ;;
        amd64|x86_64|linux/amd64|linux/x86_64) arch="amd64" ;;
        ""|unknown|n/a|none|null) return 0 ;;
    esac
    printf '%snodeSelector:\n%s  kubernetes.io/arch: %s\n' "$indent" "$indent" "$arch"
}

# Keep GPU benchmark workers off control-plane nodes. An optional audited GPU
# product label further prevents mixed-pool clusters from scheduling a rung on
# the wrong accelerator family.
k8s_worker_affinity_yaml() {
    local indent="${1:-  }"
    local product="${CLUSTERMAX_K8S_GPU_PRODUCT:-}" product_expression=""
    if [[ -n "$product" ]]; then
        product_expression="${indent}        - key: nvidia.com/gpu.product
${indent}          operator: In
${indent}          values: [${product}]
"
    fi
    cat <<EOF
${indent}affinity:
${indent}  nodeAffinity:
${indent}    requiredDuringSchedulingIgnoredDuringExecution:
${indent}      nodeSelectorTerms:
${indent}      - matchExpressions:
${indent}        - key: node-role.kubernetes.io/control-plane
${indent}          operator: DoesNotExist
${indent}        - key: node-role.kubernetes.io/master
${indent}          operator: DoesNotExist
${product_expression}
EOF
}

k8s_gpu_product_affinity_yaml() {
    local indent="${1:-  }"
    local product="${CLUSTERMAX_K8S_GPU_PRODUCT:-}"
    [[ -n "$product" ]] || return 0
    cat <<EOF
${indent}affinity:
${indent}  nodeAffinity:
${indent}    requiredDuringSchedulingIgnoredDuringExecution:
${indent}      nodeSelectorTerms:
${indent}      - matchExpressions:
${indent}        - key: nvidia.com/gpu.product
${indent}          operator: In
${indent}          values: [${product}]
EOF
}

k8s_forward_env_yaml() {
    local indent="${1:-    }"
    python3 - "$indent" <<'PY'
import json
import os
import re
import sys

indent = sys.argv[1]
prefixes = (
    "CLUSTERMAX_CONTAINER_",
    "CKPT_",
    "DATAGEN_",
    "DCP_",
    "ELBENCHO_",
    "FIO_",
    "GEMM_",
    "GEMV_",
    "GROUPED_GEMM_",
    "GPTOSS_",
    "IOR_",
    "LIFECYCLE_",
    "LLAMA_",
    "MAMF_",
    "NVBANDWIDTH_",
    "NVBW_",
    "S3_ENDURANCE_",
    "VLLM_",
)
exact = {
    "ALL_DTYPES",
    "BS_RAND",
    "BS_RAND_DIRECT",
    "BS_SEQ",
    "CLUSTERMAX_GPU_CACHE_FLUSH_MB",
    "CLUSTERMAX_K8S_GPU_DRA",
    "CLUSTERMAX_K8S_GPU_DRA_CLAIM_TEMPLATE",
    "CLUSTERMAX_K8S_GPU_DRA_DEVICE_CLASS",
    "CLUSTERMAX_K8S_GPU_DRA_DRIVER",
    "CLUSTERMAX_S3_PREFIX",
    "CLUSTERMAX_STORAGE_LABEL",
    "CLUSTERMAX_TRAINING_PROGRESS_TIMEOUT_S",
    "CONTAINER_REGISTRY",
    "CLUSTER_DATACENTER",
    "CLUSTER_REGION",
    "CLUSTER_SLUG",
    "DTYPE",
    "DURATION_S",
    "DIRECT_IO_MODES",
    "FILE_SIZE",
    "FIO_PATTERNS",
    "GLOO_SOCKET_IFNAME",
    "HF_UPLOAD_REPO",
    "ITERATIONS",
    "LOCAL_BATCH_SIZE",
    "LOG_FREQ",
    "MODE",
    "MODEL_ID",
    "MODEL_LOAD_IMAGE",
    "NGC_IMAGE",
    "NUMJOBS",
    "PIP_INSTALL_PKGS",
    "QUICK",
    "RESERVE_SMS",
    "RUNTIME",
    "SEQ_LEN",
    "SKIP",
    "SPEEDTEST_BYTES",
    "SPEEDTEST_ROUNDS",
    "SPEEDTEST_URL",
    "S3_RUNG_CLIENTS",
    "S3_RUNG_JOB",
    "S3_RUNG_LARGE",
    "S3_RUNG_RUNNER",
    "S3_RUNG_SMALL",
    "STORAGE_LABEL",
    "STEPS",
}

for name in sorted(os.environ):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        continue
    if name not in exact and not name.startswith(prefixes):
        continue
    print(f"{indent}- name: {name}")
    print(f"{indent}  value: {json.dumps(os.environ[name])}")
PY
}

# Store normalized S3 credentials in a short-lived Secret for distributed
# storage jobs. Secret values travel over stdin and never appear in argv or the
# rendered workload logs. Echo the Secret name, or nothing when S3 is unused.
k8s_apply_s3_env_secret() {
    local name="${1:?secret name required}" ns="${2:?namespace required}"
    [[ "${CLUSTERMAX_DISTRIBUTED_S3_SECRET:-0}" == "1" ]] || return 0
    [[ -n "${CLUSTERMAX_S3_BUCKET:-}" && -n "${CLUSTERMAX_S3_ACCESS_KEY_ID:-}" && -n "${CLUSTERMAX_S3_SECRET_ACCESS_KEY:-}" ]] || return 0
    S3_SECRET_NAME="$name" S3_SECRET_NAMESPACE="$ns" python3 - <<'PY' |
import json
import os

keys = (
    "CLUSTERMAX_S3_BUCKET",
    "CLUSTERMAX_S3_ACCESS_KEY_ID",
    "CLUSTERMAX_S3_SECRET_ACCESS_KEY",
    "CLUSTERMAX_S3_ENDPOINT_URL",
    "CLUSTERMAX_S3_REGION",
    "CLUSTERMAX_S3_ADDRESSING",
    "CLUSTERMAX_S3_VERIFY",
    "CLUSTERMAX_S3_SESSION_TOKEN",
)
print(json.dumps({
    "apiVersion": "v1",
    "kind": "Secret",
    "metadata": {"name": os.environ["S3_SECRET_NAME"], "namespace": os.environ["S3_SECRET_NAMESPACE"]},
    "type": "Opaque",
    "stringData": {key: os.environ[key] for key in keys if os.environ.get(key)},
}))
PY
        kubectl apply -f - >/dev/null || return 1
    printf '%s\n' "$name"
}

# Apply a manifest file. On locked-down vCluster tenants the host admission webhooks reject
# the stock reliability manifests (privileged / IPC_LOCK / root / no GPU-type
# affinity / no runtimeClass), so transform each Pod/Job pod-template to a
# compliant form before applying. MPIJob and other host-privileged manifests
# (node-health, dcgm, hbm-spill, alltoall) cannot be made compliant - they need
# capabilities this tenant does not grant - and are left unchanged (they will be
# rejected, which is the correct signal that the case is infeasible here).
k8s_apply_file() {
    local file="${1:?manifest path required}"
    echo ""
    if [[ "${CLUSTERMAX_K8S_MODE:-}" =~ ^(vcluster|cloudeka)$ ]]; then
        echo ">>> kubectl apply -f ${file} (vcluster-transformed)"
        CMAX_UID="${CLUSTERMAX_K8S_RUN_AS_USER:-1000}" \
        CMAX_PRODUCT="${CLUSTERMAX_K8S_GPU_PRODUCT:-}" \
        CMAX_RCLASS="${CLUSTERMAX_K8S_RUNTIME_CLASS:-}" \
        python3 "${CMAX_SHARED_DIR:-$(dirname "${BASH_SOURCE[0]}")}/vcluster_podspec.py" "$file" \
            | kubectl apply -f -
        return
    fi
    echo ">>> kubectl apply -f ${file}"
    kubectl apply -f "$file"
}

k8s_apply_file_rendered() {
    local file="${1:?manifest path required}"
    shift
    if (( $# % 2 != 0 )); then
        echo "ERROR: rendered manifest replacements must be old/new pairs" >&2
        return 2
    fi
    local rendered rc=0
    rendered="$(mktemp "${TMPDIR:-/tmp}/clustermax-k8s.XXXXXX")"
    python3 - "$file" "$rendered" "$@" <<'PY' || rc=$?
import sys

source, destination, *pairs = sys.argv[1:]
text = open(source, encoding="utf-8").read()
for old, new in zip(pairs[::2], pairs[1::2]):
    if old not in text:
        raise SystemExit(f"manifest replacement source not found: {old!r}")
    text = text.replace(old, new)
with open(destination, "w", encoding="utf-8") as f:
    f.write(text)
PY
    if (( rc == 0 )); then
        k8s_apply_file "$rendered" || rc=$?
    fi
    rm -f "$rendered"
    return "$rc"
}

k8s_delete_file() {
    local file="${1:?manifest path required}"
    echo ""
    echo ">>> kubectl delete -f ${file} --ignore-not-found=true"
    kubectl delete -f "$file" --ignore-not-found=true 2>/dev/null || true
}

k8s_delete_resource() {
    echo ""
    echo ">>> kubectl -n ${K8S_NAMESPACE} delete $* --ignore-not-found=true"
    kubectl -n "$K8S_NAMESPACE" delete "$@" --ignore-not-found=true 2>/dev/null || true
}

k8s_create_configmap_from_file() {
    local name="${1:?configmap name required}"
    local key="${2:?configmap key required}"
    local file="${3:?source file required}"
    echo ""
    echo ">>> kubectl -n ${K8S_NAMESPACE} create configmap ${name} --from-file=${key}=${file}"
    kubectl -n "$K8S_NAMESPACE" create configmap "$name" \
        "--from-file=${key}=${file}" \
        --dry-run=client -o yaml | kubectl apply -f -
}

k8s_wait_job() {
    local job="${1:?job name required}"
    local timeout="${2:-$K8S_TIMEOUT_S}"
    local start now elapsed conds beat=0 pod_state
    start="$(date +%s)"
    echo ""
    echo ">>> waiting for job/${job} to complete or fail (${timeout}s)"
    # Poll both terminal conditions. `kubectl wait --for=condition=complete`
    # blocks for the full timeout on a failing job (Complete never flips), so a
    # failed job would otherwise hang the whole run.
    while true; do
        now="$(date +%s)"
        elapsed=$((now - start))
        if [[ "$elapsed" -ge "$timeout" ]]; then
            echo "ERROR: timeout waiting for job/${job}" >&2
            return 124
        fi
        conds="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get job "$job" -o jsonpath='{range .status.conditions[*]}{.type}={.status};{end}' 2>/dev/null || true)"
        case "$conds" in
            *Complete=True*) return 0 ;;
            *Failed=True*) echo "ERROR: job/${job} failed" >&2; return 1 ;;
        esac
        # Job conditions stay empty during long image pulls; the pod phase and
        # container waiting reason are the only liveness signal, so report them
        # every CLUSTERMAX_PROGRESS_INTERVAL_S seconds.
        if (( elapsed / ${CLUSTERMAX_PROGRESS_INTERVAL_S:-30} > beat )); then
            beat=$((elapsed / ${CLUSTERMAX_PROGRESS_INTERVAL_S:-30}))
            pod_state="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get pods -l "job-name=${job}" \
                -o jsonpath='{range .items[*]}{.status.phase}{" "}{.status.containerStatuses[0].state.waiting.reason}{";"}{end}' \
                2>/dev/null || true)"
            echo "  ... job/${job}: ${elapsed}s - pods: ${pod_state:-not scheduled yet}"
            # A pod set that is entirely Pending after the grace window with a
            # FailedScheduling event naming a resource no node advertises can
            # never start (e.g. rdma/fabricN requested on an EFA cluster); the
            # scheduler will not recover on its own, so waiting out the full
            # timeout only burns the campaign clock.
            if [[ "$elapsed" -ge "${CLUSTERMAX_K8S_PENDING_GRACE_S:-180}" \
                && "$pod_state" =~ ^(Pending\ ;)+$ ]]; then
                local unsat
                unsat="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get events \
                    --field-selector reason=FailedScheduling 2>/dev/null \
                    | grep -F "$job" | grep -oE 'Insufficient [a-zA-Z0-9./-]+' | sort -u | while read -r _ res; do
                        kubectl get nodes -o jsonpath="{range .items[*]}{.status.allocatable['${res//./\\.}']}{'\n'}{end}" 2>/dev/null \
                            | grep -q '[1-9]' || printf '%s ' "$res"
                    done)"
                if [[ -n "$unsat" ]]; then
                    echo "ERROR: job/${job} pods are unschedulable: no node advertises: ${unsat}" >&2
                    return 1
                fi
            fi
        fi
        sleep 10
    done
}

# Wait for every pod in a distributed job to finish its workload while keeping
# the train container alive for result recovery. The container writes its exit
# code to a completion-index-specific marker and then sleeps for the controller
# timeout while the controller copies the files and deletes the job.
k8s_job_pod_selector() {
    local job="${1:?job name required}" job_uid
    job_uid="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get "job/$job" \
        -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    if [[ -z "$job_uid" ]]; then
        echo "ERROR: could not resolve UID for job/${job}" >&2
        return 1
    fi
    printf 'job-name=%s,batch.kubernetes.io/controller-uid=%s\n' "$job" "$job_uid"
}

k8s_wait_distributed_results_ready() {
    local job="${1:?job name required}"
    local expected="${2:?expected pod count required}"
    local timeout="${3:-$K8S_TIMEOUT_S}"
    local requested_selector="${4:-}"
    local start now elapsed selector pods pod index phase detail ready rc beat=0 pod_state
    start="$(date +%s)"
    K8S_DISTRIBUTED_RESULT_SELECTOR=""
    if [[ -n "$requested_selector" ]]; then
        selector="$requested_selector"
    else
        selector="$(k8s_job_pod_selector "$job")" || return 1
    fi
    K8S_DISTRIBUTED_RESULT_SELECTOR="$selector"
    echo ""
    echo ">>> waiting for ${expected} job/${job} pod result marker(s) (${timeout}s)"
    while true; do
        now="$(date +%s)"
        elapsed=$((now - start))
        if [[ "$elapsed" -ge "$timeout" ]]; then
            echo "ERROR: timeout waiting for job/${job} result details" >&2
            return 124
        fi
        pods="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get pods \
            -l "$selector" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
        ready=0
        rc=0
        pod_state=""
        for pod in $pods; do
            index="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get "pod/$pod" \
                -o jsonpath='{.metadata.labels.batch\.kubernetes\.io/job-completion-index}' 2>/dev/null || true)"
            phase="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get "pod/$pod" \
                -o jsonpath='{.status.phase}' 2>/dev/null || true)"
            detail=""
            if [[ "$index" =~ ^[0-9]+$ ]]; then
                detail="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s exec \
                    "$pod" -c train -- cat "/results/.cmax-details-ready-${index}" 2>/dev/null || true)"
            fi
            if [[ "$detail" =~ ^[0-9]+$ ]]; then
                ready=$((ready + 1))
                (( detail != 0 )) && rc="$detail"
                pod_state+="${pod}=ready(rc=${detail});"
            else
                pod_state+="${pod}=${phase:-unknown};"
                if [[ "$phase" == "Failed" || "$phase" == "Succeeded" ]]; then
                    echo "ERROR: pod/${pod} became ${phase} before publishing result details" >&2
                    return 1
                fi
            fi
        done
        if (( ready == expected )); then
            return "$rc"
        fi
        if (( elapsed / ${CLUSTERMAX_PROGRESS_INTERVAL_S:-30} > beat )); then
            beat=$((elapsed / ${CLUSTERMAX_PROGRESS_INTERVAL_S:-30}))
            echo "  ... job/${job}: ${elapsed}s - result details ${ready}/${expected}; ${pod_state:-not scheduled yet}"
        fi
        sleep 10
    done
}

# k8s_pod_status_watch <pod> [label]: background liveness reporter. Echoes the
# pod's phase and container waiting reason (ContainerCreating, ErrImagePull,
# ...) every CLUSTERMAX_PROGRESS_INTERVAL_S seconds - plus the newest log line
# once the pod is Running - until killed, so a long image pull or in-pod
# download reads as progress instead of a hang. Start it with & alongside a
# blocking `kubectl wait` (or poll loop) and kill it afterward:
#   k8s_pod_status_watch "$pod" "$label" & watch_pid=$!
#   kubectl ... wait ...
#   kill "$watch_pid" 2>/dev/null || true; wait "$watch_pid" 2>/dev/null || true
k8s_pod_status_watch() {
    local pod="${1:?pod name required}"
    local label="${2:-pod/$1}"
    local ns="${K8S_NAMESPACE:-default}"
    local interval="${CLUSTERMAX_PROGRESS_INTERVAL_S:-20}"
    local elapsed=0 phase reason last
    while true; do
        sleep "$interval"
        elapsed=$((elapsed + interval))
        phase="$(kubectl -n "$ns" get "pod/$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
        reason="$(kubectl -n "$ns" get "pod/$pod" -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
        last=""
        if [[ "$phase" == "Running" ]]; then
            last="$(kubectl -n "$ns" logs "pod/$pod" --tail=1 2>/dev/null | tr -d '\r' | cut -c1-160 || true)"
        fi
        echo "  ... ${label}: ${elapsed}s - pod ${phase:-not found}${reason:+ (${reason})}${last:+ - ${last}}"
    done
}

k8s_wait_selector_phase() {
    local selector="${1:?selector required}"
    local timeout="${2:-$K8S_TIMEOUT_S}"
    # Optional owner resource (e.g. "mpijob/cmax-nccl-4n"). A failed owner can
    # retry, exhaust its backoff limit, and have every pod deleted before this
    # loop samples them; without the owner check that leaves "no matching pod
    # yet" until the full timeout, long after the outcome is known.
    local owner="${3:-}"
    local start now elapsed phase owner_state
    start="$(date +%s)"
    echo ""
    echo ">>> waiting for pods matching '${selector}' (${timeout}s)"
    while true; do
        now="$(date +%s)"
        elapsed=$((now - start))
        if [[ "$elapsed" -ge "$timeout" ]]; then
            echo "ERROR: timeout waiting for selector ${selector}" >&2
            return 124
        fi
        phase="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get pods -l "$selector" -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
        case "$phase" in
            Succeeded|Completed)
                return 0
                ;;
            Failed)
                return 1
                ;;
            "")
                if [[ -n "$owner" ]]; then
                    owner_state="$(kubectl -n "$K8S_NAMESPACE" --request-timeout=30s get "$owner" \
                        -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}' 2>/dev/null \
                        | grep -Ex 'Failed|Succeeded' | head -1 || true)"
                    if [[ "$owner_state" == "Failed" ]]; then
                        echo "ERROR: ${owner} reached Failed with no pods left matching '${selector}'" >&2
                        return 1
                    elif [[ "$owner_state" == "Succeeded" ]]; then
                        return 0
                    fi
                fi
                echo "  [$(date +%H:%M:%S)] no matching pod yet"
                ;;
            *)
                echo "  [$(date +%H:%M:%S)] ${phase}"
                ;;
        esac
        sleep 15
    done
}

k8s_capture_logs() {
    local selector="${1:?selector required}"
    local prefix="${2:?log prefix required}"
    local pod phase log_path
    K8S_SUCCEEDED_LOGS=""
    echo ""
    echo ">>> capturing logs for ${selector}"
    for pod in $(kubectl -n "$K8S_NAMESPACE" get pods -l "$selector" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        log_path="${CLUSTERMAX_LOG_DIR}/${prefix}-${pod}.log"
        kubectl -n "$K8S_NAMESPACE" logs "$pod" --all-containers=true > "$log_path" 2>&1 || true
        phase="$(kubectl -n "$K8S_NAMESPACE" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
        if [[ "$phase" == "Succeeded" ]]; then
            K8S_SUCCEEDED_LOGS="${K8S_SUCCEEDED_LOGS}${K8S_SUCCEEDED_LOGS:+$'\n'}${log_path}"
        fi
    done
}

k8s_copy_results() {
    local selector="${1:?selector required}"
    local remote_path="${2:-/results/.}"
    local pods pod staging copy_error
    local failures=0
    echo ""
    echo ">>> copying results for ${selector}"
    pods="$(kubectl -n "$K8S_NAMESPACE" get pods -l "$selector" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
    if [[ -z "$pods" ]]; then
        echo "ERROR: no pods found for result selector ${selector}" >&2
        return 1
    fi
    for pod in $pods; do
        staging="$(mktemp -d "${TMPDIR:-/tmp}/clustermax-results.XXXXXX")"
        if copy_error="$(kubectl -n "$K8S_NAMESPACE" cp "${pod}:${remote_path}" "$staging" 2>&1)"; then
            if find "$staging" -type f -print -quit | grep -q .; then
                if ! cp -R "$staging"/. "$RESULT_DIR"/; then
                    echo "ERROR: could not store results copied from pod/${pod}" >&2
                    failures=$((failures + 1))
                fi
            else
                echo "ERROR: pod/${pod} produced no files under ${remote_path}" >&2
                failures=$((failures + 1))
            fi
        else
            echo "ERROR: could not copy ${remote_path} from pod/${pod}: ${copy_error}" >&2
            failures=$((failures + 1))
        fi
        rm -rf "$staging"
    done
    (( failures == 0 ))
}

# Write RESULT_DIR/<runner>.values.json. Always emits <runner>_completed=1; an
# optional 4th arg is a path to a JSON array of {metric, value, unit} rows (e.g.
# computed by a case runner) that are validated and merged in. This keeps a
# single values writer for the whole runner instead of per-case emitters.
k8s_write_values() {
    local runner="${1:?runner required}"
    local case_name="${2:-$K8S_CASE}"
    local fabric="${3:-unknown}"
    local results_file="${4:-}"
    # Optional 5th arg: a JSON object file merged into body["metadata"] (e.g.
    # {"nodeReboots": [...]} drill-in detail for the dashboard). Empty when the
    # case has no per-entity detail.
    local metadata_file="${5:-}"
    local path="${RESULT_DIR}/${runner}.values.json"
    python3 - "$path" "$runner" "$case_name" "$K8S_NAMESPACE" "$CLUSTER_NAME" "$fabric" "$results_file" "$metadata_file" <<'PY'
import json
import math
import re
import sys
from datetime import datetime, timezone

path, runner, case_name, namespace, cluster, fabric, results_file, metadata_file = sys.argv[1:9]
metric_runner = re.sub(r"[^a-z0-9]+", "_", runner.lower()).strip("_")
if not metric_runner or not metric_runner[0].isalpha():
    raise SystemExit(f"runner cannot produce a valid metric prefix: {runner!r}")

metric_re = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
results = [{"metric": f"{metric_runner}_completed", "value": 1, "unit": "bool"}]
seen = {results[0]["metric"]}
if results_file:
    with open(results_file, encoding="utf-8") as f:
        extra = json.load(f)
    if not isinstance(extra, list):
        raise SystemExit(f"{results_file}: expected a JSON array of metric rows")
    for row in extra:
        metric, value, unit = row["metric"], row["value"], row.get("unit", "count")
        if not metric_re.fullmatch(metric) or len(metric) > 80:
            raise SystemExit(f"invalid metric name: {metric!r}")
        if metric in seen:
            raise SystemExit(f"duplicate metric: {metric!r}")
        if value is not None and not (isinstance(value, (int, float)) and math.isfinite(value)):
            raise SystemExit(f"metric {metric!r} value must be a finite number or null")
        seen.add(metric)
        results.append({"metric": metric, "value": value, "unit": unit})

body = {
    "schema_version": 1,
    "runner": runner,
    "metadata": {
        "k8s": {
            "case": case_name,
            "namespace": namespace,
            "cluster": cluster,
            "fabric": fabric,
            "completed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    },
    "results": results,
}
if metadata_file:
    with open(metadata_file, encoding="utf-8") as f:
        extra_meta = json.load(f)
    if not isinstance(extra_meta, dict):
        raise SystemExit(f"{metadata_file}: expected a JSON object")
    body["metadata"].update(extra_meta)
with open(path, "w", encoding="utf-8") as f:
    json.dump(body, f, indent=2)
    f.write("\n")
PY
    echo "wrote ${path}"
}

# Run a whole workload directory inside one GPU pod and recover its values.json.
#
# This is the k8s_control equivalent of the standalone harness: it delivers the
# test's own workload/ (run.sh plus any bundled assets, nested dirs included)
# into a running pod via a tar pipe, runs `run.sh` there with RESULT_DIR=/results
# and the harness dispatch disabled, then copies detailed artifacts while the
# pod is live and recovers values/summary JSON from captured log markers. The
# in-pod run emits the *same* values.json the slurm/standalone path does, so the
# metric contract is identical by construction.
#
k8s_store_valid_json() {
    local source_path="${1:?source path required}"
    local destination_path="${2:?destination path required}"
    [[ -s "$source_path" ]] \
        && python3 -c "import json; json.load(open('$source_path'))" 2>/dev/null \
        && cp "$source_path" "$destination_path"
}

# Usage: k8s_run_workload_pod <runner> <workload_dir> [gpus] [image] [require_summary]
k8s_run_workload_pod() {
    local runner="${1:?runner required}"
    local workload_dir="${2:?workload dir required}"
    local gpus="${3:-8}"
    local image="${4:-${CLUSTERMAX_CONTAINER_NGC_PYTORCH:-nvcr.io/nvidia/pytorch:26.04-py3}}"
    local require_summary="${5:-false}"
    local ns="${K8S_NAMESPACE:-default}"
    local pod="cmax-${runner}"
    local log_dir="${CLUSTERMAX_LOG_DIR:-${RESULT_DIR}/logs}"; mkdir -p "$log_dir"
    local values_json="${RESULT_DIR}/${runner}.values.json"
    local pod_values_json="${values_json}.pod.$$"
    local summary_json="${RESULT_DIR}/${runner}.json"
    local pod_summary_json="${summary_json}.pod.$$"
    local pod_results_dir copied_values_json copied_values_valid=0
    local copied_summary_json copied_summary_valid=0 pod_summary_valid=0
    local capfile="${log_dir}/${runner}-pod.log"
    local gpu_resource="${CLUSTERMAX_K8S_GPU_RESOURCE:-nvidia.com/gpu}"
    local lib_dir rc=0 pod_values_valid=0 forward_env forward_env_block
    local secret_env secret_env_block
    local pod_claims_block="" container_claims_block="" resources_block

    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    forward_env="$(k8s_forward_env_yaml "    ")"
    secret_env=""
    if [[ -n "${CLUSTERMAX_K8S_HF_TOKEN_SECRET:-}" ]]; then
        secret_env=$'    - name: HF_TOKEN\n      valueFrom:\n        secretKeyRef:\n          name: '"${CLUSTERMAX_K8S_HF_TOKEN_SECRET}"$'\n          key: HF_TOKEN'
    fi
    forward_env_block=""
    if [[ -n "$forward_env" || -n "$secret_env" ]]; then
        forward_env_block=$'    env:\n'"${forward_env}${forward_env:+$'\n'}${secret_env}"
    fi
    secret_env_block=""
    if [[ -n "${CLUSTERMAX_K8S_ENV_SECRET:-}" ]]; then
        secret_env_block=$'    envFrom:\n    - secretRef:\n        name: '"${CLUSTERMAX_K8S_ENV_SECRET}"
    fi

    # CPU/memory requests+limits are normally omitted so the pod uses whatever
    # the node has. On clusters that inject a restrictive default LimitRange
    # (e.g. vclusters that cap unspecified containers at cpu=2 / a few GiB), an
    # 8-GPU training job is then OOM/CPU-killed (exit 137) the moment torchrun
    # spawns. Set CLUSTERMAX_POD_CPU / CLUSTERMAX_POD_MEM to pin adequate
    # resources on such clusters; unset leaves the default (no cpu/mem limits).
    local res_extra=""
    [[ -n "${CLUSTERMAX_POD_CPU:-}" ]] && res_extra+=", cpu: \"${CLUSTERMAX_POD_CPU}\""
    [[ -n "${CLUSTERMAX_POD_MEM:-}" ]] && res_extra+=", memory: ${CLUSTERMAX_POD_MEM}"
    if k8s_gpu_dra_enabled; then
        local pod_claim_entry container_claim_entry scalar_resources
        pod_claim_entry="$(k8s_gpu_dra_pod_claim_entry_yaml "$gpus" "  ")" || return $?
        container_claim_entry="$(k8s_gpu_dra_container_claim_entry_yaml "      ")" || return $?
        pod_claims_block=$'  resourceClaims:\n'"${pod_claim_entry}"$'\n'
        container_claims_block=$'      claims:\n'"${container_claim_entry}"$'\n'
        scalar_resources="${res_extra#, }"
        resources_block="${container_claims_block}      requests: { ${scalar_resources} }
      limits: { ${scalar_resources} }"
    else
        resources_block="      requests: { $gpu_resource: $gpus$res_extra }
      limits: { $gpu_resource: $gpus$res_extra }"
    fi

    # locked-down vCluster tenants: the host admission webhooks reject
    # the default pod (IPC_LOCK capability, no runtimeClass, no GPU-type affinity,
    # root user). Emit a compliant variant - non-root, no added caps, nvidia
    # runtimeClass, nvidia.com/gpu.product affinity. Other modes keep the original
    # IPC_LOCK pod unchanged. Toggle with CLUSTERMAX_K8S_MODE=vcluster.
    local runtime_line="" pod_sec="" affinity="" arch_selector="" extra_volmount="" extra_vol="" \
          pod_workdir="/workload" \
          container_sec="    securityContext: { capabilities: { add: [\"IPC_LOCK\"] } }"
    arch_selector="$(k8s_arch_node_selector_yaml "  ")"
    affinity="$(k8s_worker_affinity_yaml "  ")"
    if [[ "${CLUSTERMAX_K8S_MODE:-}" =~ ^(vcluster|cloudeka)$ ]]; then
        # Extract into a uid-owned subdir of the writable /workload emptyDir: a
        # non-root tar cannot chmod/utime the root-owned mount point itself.
        pod_workdir="/workload/w"
        local uid="${CLUSTERMAX_K8S_RUN_AS_USER:-1000}"
        runtime_line="$(k8s_runtime_class_yaml "  ")"
        pod_sec=$'  securityContext:\n    runAsNonRoot: true\n    runAsUser: '"${uid}"$'\n    fsGroup: '"${uid}"
        container_sec=$'    securityContext: { allowPrivilegeEscalation: false, runAsNonRoot: true, runAsUser: '"${uid}"$', capabilities: { drop: ["ALL"] } }'
        # The workload is delivered to /workload and writes to /results; both sit
        # at the image root, which a non-root uid cannot mkdir into. Overlay them
        # with writable emptyDirs (group-owned via fsGroup). HOME=/tmp is set on
        # the in-pod exec below.
        extra_volmount=$'    - { name: cmax-workload, mountPath: /workload }\n    - { name: cmax-results, mountPath: /results }'
        extra_vol=$'  - { name: cmax-workload, emptyDir: {} }\n  - { name: cmax-results, emptyDir: {} }'
    fi

    kubectl -n "$ns" delete pod "$pod" --ignore-not-found=true >/dev/null 2>&1 || true
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $pod
  namespace: $ns
  labels: { app.kubernetes.io/name: clustermax-bench, cmax-pod: "$pod" }
spec:
  restartPolicy: Never
${runtime_line}
${pod_sec}
${affinity}
${arch_selector}
${pod_claims_block}
  tolerations:
  - { key: $gpu_resource, operator: Exists, effect: NoSchedule }
  - { key: kubernetes.io/arch, operator: Exists, effect: NoSchedule }
  containers:
  - name: workload
    image: $image
    command: ["bash","-c","sleep 14400"]
$forward_env_block
$secret_env_block
${container_sec}
    resources:
${resources_block}
    volumeMounts:
    - { name: dshm, mountPath: /dev/shm }
${extra_volmount}
  volumes:
  - name: dshm
    emptyDir: { medium: Memory, sizeLimit: 64Gi }
${extra_vol}
EOF
    echo ""
    echo ">>> waiting for pod/${pod} to be ready"
    k8s_pod_status_watch "$pod" "${runner} pod" &
    local watch_pid=$!
    kubectl -n "$ns" wait --for=condition=ready "pod/$pod" --timeout=420s || rc=$?
    kill "$watch_pid" 2>/dev/null || true
    wait "$watch_pid" 2>/dev/null || true
    if (( rc != 0 )); then
        echo "ERROR: ${runner} pod did not become ready" >&2
        kubectl -n "$ns" describe pod "$pod" 2>/dev/null | tail -20 >&2 || true
        kubectl -n "$ns" delete pod "$pod" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
        return 1
    fi

    echo ">>> delivering workload into pod/${pod}"
    kubectl -n "$ns" exec "$pod" -- mkdir -p "$pod_workdir" /results
    # Extract into $pod_workdir. In vcluster (non-root) mode this is a uid-owned
    # subdir, so tar can set the dir's mode/mtime; the flags additionally avoid
    # restoring owner/perms that a non-root uid could not apply.
    # --no-xattrs + COPYFILE_DISABLE on the sender stop macOS bsdtar from
    # injecting com.apple.provenance xattr pax records (GNU tar in the pod warns
    # on each, one line per file of log spam) and ._ AppleDouble files; both are
    # no-ops on a Linux/GNU-tar operator.
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$workload_dir" -cf - . | kubectl -n "$ns" exec -i "$pod" -- tar -C "$pod_workdir" --no-same-owner --no-same-permissions --no-overwrite-dir -m -xf -
    # Bundle shared training helpers next to run.sh, mirroring the distributed
    # job path.
    if [[ -f "$lib_dir/parallelism.sh" ]]; then
        COPYFILE_DISABLE=1 tar --no-xattrs -C "$lib_dir" -cf - \
            parallelism.sh summarize_training_profile.py \
            training-progress-watchdog.sh training_progress_watchdog.py \
            training-stack-provenance.py |
            kubectl -n "$ns" exec -i "$pod" -- tar -C "$pod_workdir" --no-same-owner --no-same-permissions --no-overwrite-dir -m -xf -
    fi
    echo ">>> running ${runner} in pod/${pod}"
    # CLUSTERMAX_HARNESS/K8S_NAMESPACE are cleared so the in-pod run.sh takes its
    # native (non-k8s) body. values.json is printed between markers for recovery.
    kubectl -n "$ns" exec "$pod" -- bash -c "
        cd '$pod_workdir'
        env -u CLUSTERMAX_HARNESS -u K8S_NAMESPACE HOME=/tmp \
            RESULT_DIR=/results bash run.sh
        rc=\$?
        echo '===CMAX_VALUES_BEGIN==='
        cat /results/${runner}.values.json 2>/dev/null
        echo '===CMAX_VALUES_END==='
        echo '===CMAX_SUMMARY_BEGIN==='
        cat /results/${runner}.json 2>/dev/null
        echo '===CMAX_SUMMARY_END==='
        exit \$rc
    " 2>&1 | tee "$capfile" || rc=$?

    # Copy detailed artifacts (for example lifecycle.json) while the pod is
    # still available. Stage them separately so a missing/invalid pod values
    # file cannot overwrite provisional control-side evidence.
    pod_results_dir="$(mktemp -d "${TMPDIR:-/tmp}/clustermax-${runner}-results.XXXXXX")"
    kubectl -n "$ns" cp "${pod}:/results/." "$pod_results_dir" >/dev/null 2>&1 || true
    copied_values_json="${pod_results_dir}/${runner}.values.json"
    copied_summary_json="${pod_results_dir}/${runner}.json"
    if k8s_store_valid_json "$copied_values_json" "$values_json"; then
        copied_values_valid=1
    fi
    if k8s_store_valid_json "$copied_summary_json" "$summary_json"; then
        copied_summary_valid=1
    fi
    # Canonical JSON has now been independently validated and stored. Remove
    # the staging copies before the bulk evidence copy so corrupt/empty pod
    # files cannot overwrite provisional control-side artifacts.
    rm -f "$copied_values_json" "$copied_summary_json"
    cp -R "$pod_results_dir"/. "$RESULT_DIR"/ 2>/dev/null || true
    awk '/===CMAX_VALUES_BEGIN===/{f=1;next} /===CMAX_VALUES_END===/{f=0} f' "$capfile" > "$pod_values_json"
    if k8s_store_valid_json "$pod_values_json" "$values_json"; then
        rm -f "$pod_values_json"
        pod_values_valid=1
    else
        rm -f "$pod_values_json"
        (( copied_values_valid == 1 )) && pod_values_valid=1
    fi
    # Recover the detailed summary from the same captured stream so a
    # successful values marker cannot leave a stale control-side summary when
    # kubectl cp is unavailable.
    awk '/===CMAX_SUMMARY_BEGIN===/{f=1;next} /===CMAX_SUMMARY_END===/{f=0} f' "$capfile" > "$pod_summary_json"
    if k8s_store_valid_json "$pod_summary_json" "$summary_json"; then
        rm -f "$pod_summary_json"
        pod_summary_valid=1
    else
        rm -f "$pod_summary_json"
        (( copied_summary_valid == 1 )) && pod_summary_valid=1
    fi
    rm -rf "$pod_results_dir"
    kubectl -n "$ns" delete pod "$pod" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true

    if (( pod_values_valid == 0 )); then
        echo "ERROR: ${runner} k8s run produced no valid ${runner}.values.json (pod rc=${rc})" >&2
        return 1
    fi
    if [[ "$require_summary" == "true" ]] && (( pod_summary_valid == 0 )); then
        echo "ERROR: ${runner} k8s run produced no fresh ${runner}.json summary (pod rc=${rc})" >&2
        rm -f "$summary_json"
        # Distinguish incomplete result recovery from a workload failure. The
        # caller must not promote provisional evidence into false outcomes.
        return 65
    fi
    if (( rc != 0 )); then
        echo "ERROR: ${runner} k8s workload failed after publishing result details (rc=${rc})" >&2
        rm -f "$values_json"
        return "$rc"
    fi
    echo "${runner} k8s: wrote ${values_json}"
    return 0
}

# Detect GPU topology. Prints "<nodes> <gpus_per_node>" for Ready nodes that
# advertise allocatable nvidia.com/gpu; gpus_per_node is the min across them
# (homogeneity assumption). Used to size a distributed job to the whole cluster
# (HGX ~8/node, GB ~4/node). Prints "0 0" if no GPU nodes.
k8s_gpu_topology() {
    if k8s_gpu_dra_enabled; then
        kubectl get resourceslices.resource.k8s.io,nodes -o json 2>/dev/null | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
driver = os.environ.get("CLUSTERMAX_K8S_GPU_DRA_DRIVER", "gpu.nvidia.com")
eligible = set()
for item in d.get("items", []):
    if item.get("kind") != "Node":
        continue
    metadata = item.get("metadata", {})
    labels = metadata.get("labels", {})
    spec = item.get("spec", {})
    status = item.get("status", {})
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in status.get("conditions", [])
    )
    control_plane = (
        "node-role.kubernetes.io/control-plane" in labels
        or "node-role.kubernetes.io/master" in labels
    )
    if ready and not spec.get("unschedulable") and not control_plane:
        eligible.add(metadata.get("name", ""))
counts = {}
for item in d.get("items", []):
    if item.get("kind") != "ResourceSlice":
        continue
    spec = item.get("spec", {})
    if spec.get("driver") != driver:
        continue
    pool = spec.get("pool", {})
    node = spec.get("nodeName") or pool.get("name")
    if node in eligible:
        counts[node] = counts.get(node, 0) + len(spec.get("devices", []))
counts = [count for count in counts.values() if count > 0]
print(f"{len(counts)} {min(counts)}" if counts else "0 0")
'
        return
    fi
    kubectl get nodes -o json 2>/dev/null | python3 -c '
import json, os, sys
d = json.load(sys.stdin)
# Vendor-aware GPU resource: honor CLUSTERMAX_K8S_GPU_RESOURCE if set, else
# auto-detect (NVIDIA first so the existing path is unchanged, then AMD).
env = os.environ.get("CLUSTERMAX_K8S_GPU_RESOURCE")
resources = [env] if env else ["nvidia.com/gpu", "amd.com/gpu"]
def tally(res):
    counts = []
    for n in d.get("items", []):
        labels = n.get("metadata", {}).get("labels", {})
        spec = n.get("spec", {})
        st = n.get("status", {})
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in st.get("conditions", []))
        g = int(st.get("allocatable", {}).get(res, 0) or 0)
        control_plane = "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels
        if ready and not spec.get("unschedulable") and not control_plane and g > 0:
            counts.append(g)
    return counts
for res in resources:
    counts = tally(res)
    if counts:
        print(f"{len(counts)} {min(counts)}")
        break
else:
    print("0 0")
'
}

k8s_fabric_resource_yaml() {
    local fabric_kind="${1:?fabric kind required}"
    local indent="${2-                }"
    local min_gpus="${3:-1}"
    local nodes_file rc=0
    nodes_file="$(mktemp "${TMPDIR:-/tmp}/clustermax-nodes.XXXXXX")"
    kubectl get nodes -o json >"$nodes_file" 2>/dev/null || {
        rm -f "$nodes_file"
        return 1
    }
    python3 - "$fabric_kind" "$indent" "$min_gpus" "$nodes_file" <<'PY' || rc=$?
import json
import sys
from decimal import Decimal

fabric_kind, indent, min_gpus, nodes_file = sys.argv[1:]
min_gpus = int(min_gpus)

def quantity(value):
    text = str(value or "0")
    suffixes = {"k": 10**3, "M": 10**6, "G": 10**9}
    if text[-1:] in suffixes:
        return int(Decimal(text[:-1]) * suffixes[text[-1]])
    if text.endswith("m"):
        return int(Decimal(text[:-1]) / 1000)
    return int(Decimal(text))

workers = []
for node in json.load(open(nodes_file, encoding="utf-8")).get("items", []):
    labels = node.get("metadata", {}).get("labels", {})
    spec = node.get("spec", {})
    status = node.get("status", {})
    allocatable = status.get("allocatable", {})
    ready = any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in status.get("conditions", [])
    )
    control_plane = (
        "node-role.kubernetes.io/control-plane" in labels
        or "node-role.kubernetes.io/master" in labels
    )
    gpu_count = quantity(allocatable.get("nvidia.com/gpu", 0))
    if ready and not spec.get("unschedulable") and not control_plane and gpu_count >= min_gpus:
        workers.append(allocatable)

if not workers:
    raise SystemExit("no Ready schedulable GPU workers found")

if fabric_kind == "efa":
    candidates = {"vpc.amazonaws.com/efa"}
elif fabric_kind == "rdma":
    candidates = {
        key
        for allocatable in workers
        for key in allocatable
        if key.startswith("rdma/")
    }
else:
    raise SystemExit(f"unsupported fabric kind: {fabric_kind}")

common = set.intersection(
    *[
        {
            key
            for key in candidates
            if quantity(allocatable.get(key, 0)) > 0
        }
        for allocatable in workers
    ]
)
if not common:
    raise SystemExit(
        f"no common {fabric_kind} resource is allocatable on every GPU worker"
    )

for key in sorted(common):
    count = 1 if fabric_kind == "rdma" else min(
        quantity(allocatable[key]) for allocatable in workers
    )
    print(f"{indent}{key}: {count}")
PY
    rm -f "$nodes_file"
    return "$rc"
}

# True if any node advertises a RoCE fabric device (rdma/fabricN); such clusters
# get the fabric networks attached, otherwise the job uses the pod net (eth0).
k8s_cluster_has_rdma_fabric() {
    kubectl get nodes -o json 2>/dev/null | grep -q '"rdma/fabric'
}

# Return the first advertised shared RDMA extended resource (for example
# rdma/rdma_shared_device_a), excluding per-rail rdma/fabricN resources.
# Allocatable values are Kubernetes quantities and may carry SI or binary
# suffixes: the NVIDIA network operator shared device plugin advertises pools
# like "1k" (seen on Hyperstack cluster42), which bare int() rejects.
k8s_detect_shared_rdma_resource() {
    kubectl get nodes -o json 2>/dev/null | python3 -c '
import json, re, sys
from decimal import Decimal

SUFFIXES = {
    "n": Decimal("1e-9"), "u": Decimal("1e-6"), "m": Decimal("1e-3"),
    "k": 10**3, "M": 10**6, "G": 10**9, "T": 10**12, "P": 10**15, "E": 10**18,
    "Ki": 2**10, "Mi": 2**20, "Gi": 2**30, "Ti": 2**40, "Pi": 2**50, "Ei": 2**60,
}

def quantity(value):
    match = re.fullmatch(
        r"([+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))([eE][+-]?[0-9]+|[KMGTPE]i|[numkMGTPE])?",
        str(value or "0").strip(),
    )
    if not match:
        return Decimal(0)
    number, suffix = match.groups()
    if suffix and suffix[0] in "eE" and suffix[-1].isdigit():
        return Decimal(number + suffix)
    return Decimal(number) * SUFFIXES.get(suffix or "", 1)

data = json.load(sys.stdin)
keys = sorted({
    key
    for item in data.get("items", [])
    for key, value in item.get("status", {}).get("allocatable", {}).items()
    if (
        (key.startswith("rdma/") and not key.startswith("rdma/fabric"))
        or key.startswith("nvidia.com/rdma")
    ) and quantity(value) > 0
})
print(keys[0] if keys else "")
' 2>/dev/null
}

# List the Multus NetworkAttachmentDefinitions bound to an extended resource,
# comma-joined and sorted numerically by trailing index. NVIDIA Network Operator
# clusters expose one NAD per IB rail (rdma-ib-net-1..8), each annotated with
# k8s.v1.cni.cncf.io/resourceName pointing at the shared resource (e.g.
# nvidia.com/rdma_ib). Attaching these NADs moves the IB rail into the pod via
# the host-device CNI, so the pod gets InfiniBand WITHOUT hostNetwork - which is
# what lets the MPI-operator's pod-DNS rendezvous keep working.
k8s_nads_for_resource() {
    local res="$1" ns="${K8S_NAMESPACE:-default}"
    [[ -z "$res" ]] && return 0
    kubectl get network-attachment-definitions.k8s.cni.cncf.io -n "$ns" -o json 2>/dev/null \
        | RES="$res" python3 -c '
import json, os, re, sys
res = os.environ["RES"]
def idx(name):
    m = re.search(r"(\d+)$", name)
    return (int(m.group(1)) if m else 0, name)
names = [
    i.get("metadata", {}).get("name", "")
    for i in json.load(sys.stdin).get("items", [])
    if i.get("metadata", {}).get("annotations", {}).get("k8s.v1.cni.cncf.io/resourceName") == res
]
print(",".join(sorted((n for n in names if n), key=idx)))
' 2>/dev/null
}

# Return a namespace-local ResourceClaimTemplate that allocates managed RDMA
# devices through Kubernetes DRA. GKE DRANET exposes mrdma.google.com this way
# instead of an rdma/* extended resource or Multus NetworkAttachmentDefinition.
# An explicit template wins so providers can use a restricted DeviceClass.
k8s_detect_dra_rdma_claim_template() {
    local explicit="${CLUSTERMAX_K8S_RDMA_CLAIM_TEMPLATE:-}"
    local ns="${K8S_NAMESPACE:-default}"
    if [[ -n "$explicit" ]]; then
        printf '%s\n' "$explicit"
        return 0
    fi
    kubectl -n "$ns" get resourceclaimtemplates.resource.k8s.io -o json 2>/dev/null | python3 -c '
import json
import sys

templates = []
for item in json.load(sys.stdin).get("items", []):
    requests = item.get("spec", {}).get("spec", {}).get("devices", {}).get("requests", [])
    classes = []
    for request in requests:
        exactly = request.get("exactly", {})
        classes.append(exactly.get("deviceClassName", ""))
        for option in request.get("firstAvailable", []):
            classes.append(option.get("deviceClassName", ""))
    if any(value in {"mrdma.google.com", "dranet.net"} for value in classes):
        templates.append(item.get("metadata", {}).get("name", ""))
templates = sorted(name for name in templates if name)
print(templates[0] if templates else "")
' 2>/dev/null || true
}

# GB200/GB300 NVL (multi-node NVLink): NCCL requires an IMEX channel in every
# pod once it detects an MNNVL clique; without one init aborts with "Cuda
# failure 800" before any GPU work. When the NVIDIA DRA driver's channel
# device class exists, create a per-run ComputeDomain whose channel claim the
# job pods reference. numNodes stays 0 as recommended with
# IMEXDaemonsWithDNSNames: the workload's own rendezvous is the worker-count
# source of truth. CLUSTERMAX_K8S_NO_COMPUTE_DOMAIN=1 opts out.
# Returns 0 when the domain and its claim template are ready, 1 when compute
# domains are unavailable (callers proceed without a claim).
k8s_compute_domain_create() {
    local name="${1:?compute domain name required}" ns="${2:-${K8S_NAMESPACE:-default}}"
    [[ "${CLUSTERMAX_K8S_NO_COMPUTE_DOMAIN:-}" == "1" ]] && return 1
    kubectl get deviceclass compute-domain-default-channel.nvidia.com >/dev/null 2>&1 || return 1
    cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: resource.nvidia.com/v1beta1
kind: ComputeDomain
metadata:
  name: $name
  namespace: $ns
spec:
  numNodes: 0
  channel:
    resourceClaimTemplate:
      name: ${name}-channel
EOF
    local _i
    for _i in $(seq 1 30); do
        kubectl -n "$ns" get resourceclaimtemplate "${name}-channel" >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "ERROR: ComputeDomain claim template ${name}-channel did not appear" >&2
    k8s_compute_domain_delete "$name" "$ns"
    return 1
}

k8s_compute_domain_delete() {
    local name="${1:-}" ns="${2:-${K8S_NAMESPACE:-default}}"
    [[ -z "$name" ]] && return 0
    kubectl -n "$ns" delete "computedomains.resource.nvidia.com/$name" \
        --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}

# Pod-side NCCL HCA pinning for rail-attached pods. The RDMA namespace stays
# shared, so a pod sees every mlx5 device (including the storage bonds and
# other pods' rail VFs), but only its claimed VFs have a netdev in the pod's
# network namespace and therefore a usable GID. NCCL's auto-enumeration picks
# dead or bond devices mid-connect (IBV_WC_RETRY_EXC_ERR / modify_qp GID -1),
# so every rank must pin NCCL_IB_HCA to its own live set at start. Emits a
# POSIX-shell snippet for embedding in pod command args; $ stays literal in
# the callers' heredocs because substituted text is not re-expanded.
k8s_rail_hca_snippet() {
    local indent="${1:-}"
    printf '%s' "\
${indent}if [ -z \"\${NCCL_IB_HCA:-}\" ]; then
${indent}  _cmax_hcas=\"\"
${indent}  for _cmax_d in /sys/class/infiniband/*; do
${indent}    [ -n \"\$(ls \"\$_cmax_d/device/net/\" 2>/dev/null)\" ] && _cmax_hcas=\"\${_cmax_hcas}\$(basename \"\$_cmax_d\"),\"
${indent}  done
${indent}  [ -n \"\$_cmax_hcas\" ] && export NCCL_IB_HCA=\"=\${_cmax_hcas%,}\"
${indent}  echo \"rail HCA selection: NCCL_IB_HCA=\${NCCL_IB_HCA:-<none>}\"
${indent}fi
"
}

# Rail-aligned Multus RDMA: rail-optimized clusters (NVIDIA Network Operator
# with SR-IOV/OVS networks) expose one NetworkAttachmentDefinition per GPU
# rail, each annotated with a per-rail extended resource such as
# nvidia.com/rail_0. Attaching every rail NAD gives the pod one VF per rail
# with a routable GID, so NCCL runs RoCE from the pod netns without
# hostNetwork. Host-netns rail VFs carry only link-local GIDs and drop
# cross-node traffic under load (IBV_WC_RETRY_EXC_ERR), so hostNetwork is the
# wrong tool on these clusters. Prints "nad=resource,..." sorted by trailing
# rail index; CLUSTERMAX_K8S_RDMA_NETWORKS overrides detection verbatim.
k8s_detect_rail_networks() {
    if [[ -n "${CLUSTERMAX_K8S_RDMA_NETWORKS:-}" ]]; then
        printf '%s\n' "$CLUSTERMAX_K8S_RDMA_NETWORKS"
        return 0
    fi
    local ns="${K8S_NAMESPACE:-default}"
    kubectl get network-attachment-definitions.k8s.cni.cncf.io -n "$ns" -o json 2>/dev/null | python3 -c '
import json, re, sys

pairs = []
for item in json.load(sys.stdin).get("items", []):
    name = item.get("metadata", {}).get("name", "")
    res = item.get("metadata", {}).get("annotations", {}).get("k8s.v1.cni.cncf.io/resourceName", "")
    if name and res and re.search(r"rail[-_]?[0-9]+$", res):
        pairs.append((name, res))

def idx(pair):
    match = re.search(r"([0-9]+)$", pair[0])
    return (int(match.group(1)) if match else 0, pair[0])

print(",".join(f"{name}={res}" for name, res in sorted(pairs, key=idx)))
' 2>/dev/null || true
}

k8s_run_distributed_job_configmap() {
    local runner="${1:?runner required}" workload_dir="${2:?workload dir required}"
    local nodes="${3:?nodes required}" gpn="${4:?gpus_per_node required}" image="${5:?image required}"
    local ns="${K8S_NAMESPACE:-default}" stamp job svc peer_svc master
    stamp="$(date +%s)"
    job="$(k8s_distributed_name "$runner")"
    svc="$job"
    peer_svc="${svc}-peers"
    master="${svc}.${ns}.svc.cluster.local"
    local log_dir="${CLUSTERMAX_LOG_DIR:-${RESULT_DIR}/logs}"
    local values_json="${RESULT_DIR}/${runner}.values.json"
    local capfile="${log_dir}/${runner}-pod.log"
    local lib_dir temp_dir stage_dir archive chunk index cm
    local configmaps="" chunk_mounts="" chunk_volumes="" concat_cmd=""
    local rc=0 copy_rc=0 result_selector="" forward_env forward_env_block res_extra="" rdma_extra=""
    local s3_secret="" s3_env_block=""
    local result_hold_block=""
    local rdma_res rdma_claim_template pod_claims_block="" container_claims_block=""
    # Vendor-aware GPU resource, same knob as the hosted single-pod path.
    local gpu_resource="${CLUSTERMAX_K8S_GPU_RESOURCE:-nvidia.com/gpu}"
    local pod_claim_entries="" container_claim_entries="" gpu_scalar="$gpu_resource: $gpn"
    local gpu_required="${CLUSTERMAX_K8S_GPU_REQUIRED:-1}"
    local resource_items resources_block
    local hostnet_block="" topology_spread_block="" ib_mount="" ib_vol="" extra_nccl="" socket_setup gloo_socket_setup v
    # Same campaign-storage bind as the RWX path: storage-aware distributed
    # workloads must see the filesystem under test in every worker pod.
    local storage_mount_block="" storage_vol_block=""
    if [[ "${CLUSTERMAX_STORAGE_KIND:-}" == "pvc" && -n "${CLUSTERMAX_STORAGE_PVC:-}" && -n "${CLUSTERMAX_STORAGE_MOUNT:-}" ]]; then
        storage_mount_block=$'        - { name: cmax-storage, mountPath: '"${CLUSTERMAX_STORAGE_MOUNT}"$' }\n'
        storage_vol_block=$'      - { name: cmax-storage, persistentVolumeClaim: { claimName: '"${CLUSTERMAX_STORAGE_PVC}"$' } }\n'
    fi
    mkdir -p "$log_dir"
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/cmax-${runner}-workload.XXXXXX")"
    stage_dir="$temp_dir/stage"
    archive="$temp_dir/workload.tar.gz"
    mkdir -p "$stage_dir/.clustermax-shared"
    cp -a "$workload_dir"/. "$stage_dir"/
    cp "$lib_dir/parallelism.sh" "$lib_dir/summarize_training_profile.py" \
        "$lib_dir/training-progress-watchdog.sh" \
        "$lib_dir/training_progress_watchdog.py" \
        "$lib_dir/training-stack-provenance.py" "$stage_dir/"
    cp "$lib_dir/elbencho.sh" "$lib_dir/elbencho_values.py" \
        "$lib_dir/storage-client-scale.sh" "$stage_dir/.clustermax-shared/"
    COPYFILE_DISABLE=1 tar --no-xattrs --exclude='__pycache__' -C "$stage_dir" -czf "$archive" .
    split -b 700000 -a 2 "$archive" "$temp_dir/chunk-"

    index=0
    for chunk in "$temp_dir"/chunk-*; do
        cm="${job}-workload-${index}"
        kubectl -n "$ns" delete "configmap/$cm" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
        kubectl -n "$ns" create configmap "$cm" --from-file=chunk="$chunk" \
            || { rm -rf "$temp_dir"; return 1; }
        configmaps+=" $cm"
        chunk_mounts+="        - { name: payload-${index}, mountPath: /payload-${index}, readOnly: true }"$'\n'
        chunk_volumes+="      - { name: payload-${index}, configMap: { name: ${cm} } }"$'\n'
        concat_cmd+="cat /payload-${index}/chunk >> /tmp/workload.tar.gz; "
        index=$((index + 1))
    done
    rm -rf "$temp_dir"

    forward_env="$(k8s_forward_env_yaml "        ")"
    forward_env_block="$(cat <<'EOF'
        env:
        - name: JOB_COMPLETION_INDEX
          valueFrom:
            fieldRef:
              fieldPath: metadata.annotations['batch.kubernetes.io/job-completion-index']
        - name: CLUSTERMAX_HOST_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
EOF
)"
    forward_env_block+=$'\n'
    [[ -n "$forward_env" ]] && forward_env_block+="$forward_env"
    s3_secret="$(k8s_apply_s3_env_secret "${job}-s3" "$ns")" || { rm -rf "$temp_dir"; return 1; }
    if [[ -n "$s3_secret" ]]; then
        s3_env_block=$'        envFrom:\n        - secretRef: { name: '"$s3_secret"$' }\n'
    fi
    [[ -n "${CLUSTERMAX_POD_CPU:-}" ]] && res_extra+=", cpu: \"${CLUSTERMAX_POD_CPU}\""
    [[ -n "${CLUSTERMAX_POD_MEM:-}" ]] && res_extra+=", memory: ${CLUSTERMAX_POD_MEM}"
    rdma_res="${CLUSTERMAX_K8S_RDMA_RESOURCE:-$(k8s_detect_shared_rdma_resource)}"
    rdma_claim_template="$(k8s_detect_dra_rdma_claim_template)"
    if [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" == "1" ]]; then
        rdma_res=""
        rdma_claim_template=""
    fi
    local net_ann=""
    if [[ "$gpu_required" == 0 ]]; then
        gpu_scalar=""
        topology_spread_block=$'      topologySpreadConstraints:\n      - maxSkew: 1\n        topologyKey: kubernetes.io/hostname\n        whenUnsatisfiable: DoNotSchedule\n        labelSelector:\n          matchLabels: { job-name: '"$job"$' }\n'
    elif k8s_gpu_dra_enabled; then
        pod_claim_entries="$(k8s_gpu_dra_pod_claim_entry_yaml "$gpn" "      ")" || return $?
        container_claim_entries="$(k8s_gpu_dra_container_claim_entry_yaml "          ")" || return $?
        gpu_scalar=""
    fi
    if [[ -n "$rdma_res" ]]; then
        rdma_extra+=", ${rdma_res}: ${CLUSTERMAX_K8S_RDMA_COUNT:-1}"
        hostnet_block=$'      hostNetwork: true\n      dnsPolicy: ClusterFirstWithHostNet\n'
        ib_mount=$'        - { name: ib, mountPath: /dev/infiniband }\n'
        ib_vol=$'      - { name: ib, hostPath: { path: /dev/infiniband } }\n'
    elif [[ -n "$rdma_claim_template" ]]; then
        pod_claim_entries+="${pod_claim_entries:+$'\n'}      - name: rdma
        resourceClaimTemplateName: ${rdma_claim_template}"
        container_claim_entries+="${container_claim_entries:+$'\n'}          - name: rdma"
    else
        local rail_networks rail_pair
        rail_networks=""
        [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" != "1" ]] && rail_networks="$(k8s_detect_rail_networks)"
        if [[ -n "$rail_networks" ]]; then
            for rail_pair in ${rail_networks//,/ }; do
                net_ann+="${rail_pair%%=*},"
                rdma_extra+=", ${rail_pair##*=}: 1"
            done
            net_ann="${net_ann%,}"
        fi
    fi
    local compute_domain=""
    if [[ "$gpu_required" != 0 ]] && k8s_compute_domain_create "cmax-${runner}-cd-${stamp}"; then
        compute_domain="cmax-${runner}-cd-${stamp}"
        pod_claim_entries+="${pod_claim_entries:+$'\n'}      - name: imex-channel
        resourceClaimTemplateName: ${compute_domain}-channel"
        container_claim_entries+="${container_claim_entries:+$'\n'}          - name: imex-channel"
    fi
    if [[ -n "$pod_claim_entries" ]]; then
        pod_claims_block=$'      resourceClaims:\n'"${pod_claim_entries}"$'\n'
        # AKS sandbox integration cannot safely combine Dynamic Resource
        # Allocation claims with host networking. A cluster can expose GPU
        # DRA alongside a scalar shared-RDMA resource, so retain the device
        # request and /dev/infiniband mount but rendezvous on the pod network.
        hostnet_block=""
    fi
    if [[ -n "$container_claim_entries" ]]; then
        container_claims_block=$'          claims:\n'"${container_claim_entries}"$'\n'
    fi
    resource_items="${gpu_scalar}${res_extra}${rdma_extra}"
    resource_items="${resource_items#, }"
    resources_block="${container_claims_block}          requests: { ${resource_items} }
          limits: { ${resource_items} }"
    if k8s_gpu_dra_enabled \
        && [[ -z "${NCCL_MNNVL_ENABLE+x}" ]] \
        && [[ -z "${CLUSTERMAX_K8S_COMPUTE_DOMAIN_CLAIM_TEMPLATE:-}" ]] \
        && [[ -z "$compute_domain" ]]; then
        extra_nccl+="          export NCCL_MNNVL_ENABLE=0"$'\n'
        echo "${runner}: GPU DRA has no ComputeDomain channel claim; defaulting NCCL_MNNVL_ENABLE=0"
    fi
    for v in NCCL_DEBUG NCCL_DEBUG_SUBSYS NCCL_MNNVL_ENABLE NCCL_DMABUF_ENABLE NCCL_IB_HCA NCCL_IB_GID_INDEX NCCL_IB_TC NCCL_IB_SL NCCL_IB_QPS_PER_CONNECTION \
             NCCL_IB_TIMEOUT NCCL_IB_RETRY_CNT NCCL_NET_GDR_LEVEL NCCL_PXN_DISABLE NCCL_CROSS_NIC NCCL_ALGO \
             NCCL_MIN_NCHANNELS; do
        [[ -n "${!v:-}" ]] && extra_nccl+="          export ${v}='${!v}'"$'\n'
    done
    if [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" == "1" ]]; then
        extra_nccl+="          export NCCL_IB_DISABLE=1"$'\n'
    fi
    if [[ -n "${NCCL_SOCKET_IFNAME:-}" ]]; then
        socket_setup="export NCCL_SOCKET_IFNAME='${NCCL_SOCKET_IFNAME}'"
    else
        socket_setup="export NCCL_SOCKET_IFNAME=\$(awk '\$2 == \"00000000\" {print \$1; exit}' /proc/net/route)"
    fi
    gloo_socket_setup="export GLOO_SOCKET_IFNAME=\${GLOO_SOCKET_IFNAME:-\$(awk '\$2 == \"00000000\" {print \$1; exit}' /proc/net/route)}"
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        result_hold_block=$'          printf "%s\\n" "$rc" > "/results/.cmax-details-ready-${JOB_COMPLETION_INDEX:-0}"\n          sleep '"${K8S_TIMEOUT_S:-7200}"$'\n'
    fi

    echo ">>> distributed ${runner}: ${nodes} node(s) x ${gpn} GPU (world=$((nodes * gpn))), ConfigMap workload, image ${image}"
    kubectl -n "$ns" delete "job/$job" "service/$svc" "service/$peer_svc" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    sleep 3
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata: { name: $svc, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  clusterIP: None
  publishNotReadyAddresses: true
  selector:
    job-name: $job
    batch.kubernetes.io/job-completion-index: "0"
  ports: [ { name: c10d, port: 29500, targetPort: 29500 } ]
---
apiVersion: v1
kind: Service
metadata: { name: $peer_svc, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  clusterIP: None
  publishNotReadyAddresses: true
  selector: { job-name: $job }
  ports: [ { name: elbencho, port: 1611, targetPort: 1611 } ]
---
apiVersion: batch/v1
kind: Job
metadata: { name: $job, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  completionMode: Indexed
  completions: $nodes
  parallelism: $nodes
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels: { app.kubernetes.io/name: clustermax-bench, job-name: $job }
$( [[ -n "$net_ann" ]] && printf '      annotations: { k8s.v1.cni.cncf.io/networks: "%s" }' "$net_ann" )
    spec:
      restartPolicy: Never
$(k8s_arch_node_selector_yaml "      ")
$(k8s_worker_affinity_yaml "      ")
${topology_spread_block}${hostnet_block}      tolerations:
      - { key: $gpu_resource, operator: Exists, effect: NoSchedule }
      - { key: kubernetes.io/arch, operator: Exists, effect: NoSchedule }
${pod_claims_block}      initContainers:
      - name: unpack-workload
        image: ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
        command: ["/bin/bash", "-c"]
        args: [ "set -e; ${concat_cmd}tar -xzf /tmp/workload.tar.gz -C /workload" ]
        volumeMounts:
${chunk_mounts}        - { name: workload, mountPath: /workload }
      containers:
      - name: train
        image: $image
$forward_env_block
$s3_env_block
        securityContext: { capabilities: { add: ["IPC_LOCK"] } }
        command: ["/bin/bash","-c"]
        args:
        - |
          set -uo pipefail
          mkdir -p /results
          ${socket_setup}
          ${gloo_socket_setup}
          export NCCL_DEBUG=\${NCCL_DEBUG:-WARN}
${extra_nccl}          MASTER_ADDR=${master}
          for i in \$(seq 1 120); do getent hosts "\$MASTER_ADDR" >/dev/null 2>&1 && break; sleep 2; done
          echo "node_rank=\${JOB_COMPLETION_INDEX:-0} master=\$MASTER_ADDR"
          env -u CLUSTERMAX_HARNESS -u K8S_NAMESPACE \
              CLUSTERMAX_SHARED_DIR=/workload/.clustermax-shared \
              CLUSTERMAX_NNODES=$nodes CLUSTERMAX_NPROC=$gpn \
              CLUSTERMAX_NODE_RANK=\${JOB_COMPLETION_INDEX:-0} \
              CLUSTERMAX_MASTER_ADDR=\$MASTER_ADDR CLUSTERMAX_MASTER_PORT=29500 \
              CLUSTERMAX_PEER_SERVICE=${peer_svc}.${ns}.svc.cluster.local \
              RESULT_DIR=/results bash /workload/run.sh
          rc=\$?
          echo '===CMAX_VALUES_BEGIN==='
          cat /results/${runner}.values.json 2>/dev/null
          echo '===CMAX_VALUES_END==='
${result_hold_block}
          exit \$rc
        resources:
${resources_block}
        volumeMounts:
        - { name: workload, mountPath: /workload, readOnly: true }
        - { name: dshm, mountPath: /dev/shm }
${ib_mount}${storage_mount_block}      volumes:
${chunk_volumes}      - { name: workload, emptyDir: {} }
      - { name: dshm, emptyDir: { medium: Memory, sizeLimit: 64Gi } }
${ib_vol}${storage_vol_block}
EOF

    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        result_selector="$(k8s_job_pod_selector "$job")" || result_selector=""
    fi
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        k8s_wait_distributed_results_ready "$job" "$nodes" "${K8S_TIMEOUT_S:-7200}" "$result_selector" || rc=$?
    else
        k8s_wait_job "$job" "${K8S_TIMEOUT_S:-7200}" || rc=$?
    fi
    result_selector="${K8S_DISTRIBUTED_RESULT_SELECTOR:-$result_selector}"
    local pod0 pod_selector="${result_selector:-job-name=${job}}"
    k8s_capture_logs "$pod_selector" "${runner}"
    pod0="$(kubectl -n "$ns" --request-timeout=30s get pods -l "${pod_selector},batch.kubernetes.io/job-completion-index=0" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "$pod0" ]]; then
        kubectl -n "$ns" --request-timeout=120s logs "$pod0" > "$capfile" 2>&1 || true
    fi
    awk '/===CMAX_VALUES_BEGIN===/{f=1;next} /===CMAX_VALUES_END===/{f=0} f' "$capfile" > "$values_json" 2>/dev/null || true
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        if [[ -n "$result_selector" ]]; then
            k8s_copy_results "$result_selector" "/results/." || copy_rc=$?
        else
            copy_rc=1
        fi
        rm -f "$RESULT_DIR"/.cmax-details-ready-*
    fi
    kubectl -n "$ns" delete "job/$job" "service/$svc" "service/$peer_svc" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    [[ -n "$s3_secret" ]] && kubectl -n "$ns" delete "secret/$s3_secret" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    k8s_compute_domain_delete "$compute_domain" "$ns"
    for cm in $configmaps; do
        kubectl -n "$ns" delete "configmap/$cm" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    done
    if [[ ! -s "$values_json" ]] || ! python3 -c "import json,sys; json.load(open('$values_json'))" 2>/dev/null; then
        echo "ERROR: ${runner} distributed ConfigMap run produced no valid ${runner}.values.json (rc=${rc})" >&2
        rm -f "$values_json"
        return 1
    fi
    if (( copy_rc != 0 )); then
        echo "ERROR: ${runner} could not copy distributed result details" >&2
        rm -f "$values_json"
        return "$copy_rc"
    fi
    if (( rc != 0 )); then
        echo "ERROR: ${runner} distributed workload failed after publishing result details (rc=${rc})" >&2
        rm -f "$values_json"
        return "$rc"
    fi
    echo "${runner} k8s distributed: wrote ${values_json}"
    return 0
}

# Return the common fabric resource exposed to GPU workers. AWS EFA is a
# device-plugin resource and must be preferred before generic shared-RDMA
# discovery because its pods stay in the pod network namespace.
k8s_detect_fabric_resource() {
    local min_gpus="${1:-1}" efa_resource
    efa_resource="$(k8s_fabric_resource_yaml efa "" "$min_gpus" 2>/dev/null | awk -F: 'NR == 1 { print $1 }')" || efa_resource=""
    if [[ -n "$efa_resource" ]]; then
        printf '%s\n' "$efa_resource"
        return 0
    fi
    k8s_detect_shared_rdma_resource
}

k8s_fabric_resource_needs_host_network() {
    [[ "${1:-}" != "vpc.amazonaws.com/efa" ]]
}

k8s_fabric_resource_count() {
    local resource="${1:-}" min_gpus="${2:-1}" count
    if [[ "$resource" == "vpc.amazonaws.com/efa" ]]; then
        count="$(k8s_fabric_resource_yaml efa "" "$min_gpus" 2>/dev/null | awk -F: 'NR == 1 { gsub(/[[:space:]]/, "", $2); print $2 }')" || count=""
        printf '%s\n' "${count:-1}"
    else
        printf '1\n'
    fi
}

# Run a workload directory as a multi-node distributed (torchrun) job across
# <nodes> pods (one per node, <gpus_per_node> GPUs each) via an Indexed Job +
# headless Service (no operator), generalizing run_allreduce_k8s. The same
# workload/ that the single-pod path uses is delivered to every pod through an
# RWX PVC (assets are too big for a ConfigMap); each pod runs run.sh's native
# body with CLUSTERMAX_NNODES/NODE_RANK/MASTER_ADDR/NPROC set, so the body does
# multi-node torchrun static rendezvous. Rank-0 (index 0) pod's values.json is
# recovered via the same marker scrape as the single-pod path.
#
# Usage: k8s_run_distributed_job <runner> <workload_dir> <nodes> <gpus_per_node> <image>
k8s_run_distributed_job() {
    local runner="${1:?runner required}" workload_dir="${2:?workload dir required}"
    local nodes="${3:?nodes required}" gpn="${4:?gpus_per_node required}" image="${5:?image required}"
    local ns="${K8S_NAMESPACE:-default}"
    # job/svc names are deterministic (the master FQDN derives from svc). The PVC
    # and loader get a per-run suffix: NFS PVC teardown is slow/sticky on some
    # clusters, and a stuck-Terminating PVC of a fixed name would block the next
    # run from scheduling. Unique names sidestep that collision.
    local stamp; stamp="$(date +%s)"
    local job svc
    job="$(k8s_distributed_name "$runner")"
    svc="$job"
    local pvc="cmax-${runner}-wl-${stamp}" loader="cmax-${runner}-loader-${stamp}"
    local master="${svc}-0.${svc}.${ns}.svc.cluster.local"
    local sc="${CLUSTERMAX_RWX_STORAGECLASS:-}"
    # Reuse the storage class already proven by the campaign PVC when the
    # operator did not name a separate RWX class. Provider-specific class
    # names vary, while CLUSTERMAX_STORAGE_PVC is already required for hosted
    # storage/inference coverage and is a reliable local source of truth.
    if [[ -z "$sc" && -n "${CLUSTERMAX_STORAGE_PVC:-}" ]]; then
        sc="$(kubectl -n "$ns" get pvc "$CLUSTERMAX_STORAGE_PVC" \
            -o jsonpath='{.spec.storageClassName}' 2>/dev/null || true)"
    fi
    # The RWX class has no generic default: names are provider specific
    # (known-good example: nfs-subdir-external-sc-highssd on the VESSL B300
    # cluster), and a PVC that references a class the cluster does not have
    # stays Pending forever with no explanation. With no class resolved, auto
    # mode delivers the workload via ConfigMap chunks instead; explicit rwx
    # mode fails fast below rather than render a PVC that can never bind.
    local workload_mode="${CLUSTERMAX_K8S_DISTRIBUTED_WORKLOAD_MODE:-auto}" sc_provisioner=""
    if [[ "$workload_mode" == "auto" ]]; then
        if [[ -z "$sc" ]]; then
            workload_mode="configmap"
        else
            sc_provisioner="$(kubectl get storageclass "$sc" -o jsonpath='{.provisioner}' 2>/dev/null || true)"
            if [[ -z "$sc_provisioner" || "$sc_provisioner" == "rancher.io/local-path" ]]; then
                workload_mode="configmap"
            else
                workload_mode="rwx"
            fi
        fi
    fi
    if [[ "$workload_mode" == "configmap" ]]; then
        k8s_run_distributed_job_configmap "$runner" "$workload_dir" "$nodes" "$gpn" "$image"
        return $?
    fi
    if [[ "$workload_mode" != "rwx" ]]; then
        echo "ERROR: CLUSTERMAX_K8S_DISTRIBUTED_WORKLOAD_MODE must be auto, rwx, or configmap; got $workload_mode" >&2
        return 2
    fi
    if [[ -z "$sc" ]]; then
        echo "ERROR: rwx workload delivery needs an RWX StorageClass; set CLUSTERMAX_RWX_STORAGECLASS (or CLUSTERMAX_STORAGE_PVC, whose class is reused)" >&2
        return 2
    fi
    local log_dir="${CLUSTERMAX_LOG_DIR:-${RESULT_DIR}/logs}"; mkdir -p "$log_dir"
    local values_json="${RESULT_DIR}/${runner}.values.json"
    local capfile="${log_dir}/${runner}-pod.log"
    local lib_dir
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local rc=0 copy_rc=0 result_selector="" i forward_env forward_env_block
    local s3_secret="" s3_env_block=""
    local result_hold_block=""
    forward_env="$(k8s_forward_env_yaml "        ")"
    # status.hostIP is the routable node address for hostNetwork Pods. Do not
    # infer it from `hostname -I`: multi-homed GPU nodes commonly list a local
    # bridge address first, which other nodes cannot reach for rendezvous.
    forward_env_block=$'        env:\n        - name: JOB_COMPLETION_INDEX\n          valueFrom:\n            fieldRef:\n              fieldPath: metadata.annotations['"'"'batch.kubernetes.io/job-completion-index'"'"$']\n        - name: CLUSTERMAX_HOST_IP\n          valueFrom:\n            fieldRef:\n              fieldPath: status.hostIP\n'
    [[ -n "$forward_env" ]] && forward_env_block+="$forward_env"
    s3_secret="$(k8s_apply_s3_env_secret "${job}-s3" "$ns")" || return 1
    if [[ -n "$s3_secret" ]]; then
        s3_env_block=$'        envFrom:\n        - secretRef: { name: '"$s3_secret"$' }\n'
    fi

    # Per-pod cpu/mem (vclusters inject tiny default limits -> OOM otherwise) and
    # optional RoCE fabric devices, both as flow-mapping extras so they compose.
    local res_extra="" rdma_extra="" net_ann=""
    # Vendor-aware GPU resource, same knob as the hosted single-pod path.
    local gpu_resource="${CLUSTERMAX_K8S_GPU_RESOURCE:-nvidia.com/gpu}"
    [[ -n "${CLUSTERMAX_POD_CPU:-}" ]] && res_extra+=", cpu: \"${CLUSTERMAX_POD_CPU}\""
    [[ -n "${CLUSTERMAX_POD_MEM:-}" ]] && res_extra+=", memory: ${CLUSTERMAX_POD_MEM}"
    # Fabric mode: shared-device RDMA over hostNetwork (CLUSTERMAX_K8S_RDMA_RESOURCE,
    # e.g. Moonlite Spectrum-X rdma/rdma_shared_device) vs DOKS rdma/fabricN + Multus.
    # hostNetwork pods get no per-index service DNS, so rendezvous by a file on the
    # RWX workload PVC. Default (unset) path is unchanged.
    local rdma_res="${CLUSTERMAX_K8S_RDMA_RESOURCE:-$(k8s_detect_shared_rdma_resource)}"
    local rdma_claim_template="$(k8s_detect_dra_rdma_claim_template)"
    if [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" == "1" ]]; then
        rdma_res=""
        rdma_claim_template=""
    fi
    local pod_claims_block="" container_claims_block="" compute_domain=""
    local pod_claim_entries="" container_claim_entries="" gpu_scalar="$gpu_resource: $gpn"
    local gpu_required="${CLUSTERMAX_K8S_GPU_REQUIRED:-1}"
    local resource_items resources_block
    local hostnet_block="" topology_spread_block="" svc_block="" ib_mount="" ib_vol="" rdzv_mount="" rdzv_vol="" master_setup="" extra_nccl="" v
    # Storage-aware distributed workloads (datagen client-scaling sweep): bind
    # the campaign storage PVC at its mount path in every worker pod so the
    # workload measures the filesystem under test, mirroring the hosted
    # single-pod launcher's storage binding.
    local storage_mount_block="" storage_vol_block=""
    if [[ "${CLUSTERMAX_STORAGE_KIND:-}" == "pvc" && -n "${CLUSTERMAX_STORAGE_PVC:-}" && -n "${CLUSTERMAX_STORAGE_MOUNT:-}" ]]; then
        storage_mount_block=$'        - { name: cmax-storage, mountPath: '"${CLUSTERMAX_STORAGE_MOUNT}"$' }\n'
        storage_vol_block=$'      - { name: cmax-storage, persistentVolumeClaim: { claimName: '"${CLUSTERMAX_STORAGE_PVC}"$' } }\n'
    fi
    if [[ "$gpu_required" == 0 ]]; then
        gpu_scalar=""
        topology_spread_block=$'      topologySpreadConstraints:\n      - maxSkew: 1\n        topologyKey: kubernetes.io/hostname\n        whenUnsatisfiable: DoNotSchedule\n        labelSelector:\n          matchLabels: { job-name: '"$job"$' }\n'
    elif k8s_gpu_dra_enabled; then
        pod_claim_entries="$(k8s_gpu_dra_pod_claim_entry_yaml "$gpn" "      ")" || return $?
        container_claim_entries="$(k8s_gpu_dra_container_claim_entry_yaml "          ")" || return $?
        gpu_scalar=""
    fi
    if [[ -n "$rdma_res" ]]; then
        rdma_extra+=", ${rdma_res}: ${CLUSTERMAX_K8S_RDMA_COUNT:-1}"
        hostnet_block=$'      hostNetwork: true\n      dnsPolicy: ClusterFirstWithHostNet\n'
        ib_mount=$'        - { name: ib, mountPath: /dev/infiniband }\n'
        ib_vol=$'      - { name: ib, hostPath: { path: /dev/infiniband } }\n'
        # Reuse the workload PVC volume at a second mountPath. Defining the
        # same claim twice under different volume names can leave vCluster
        # workload Pods indefinitely before sandbox creation.
        rdzv_mount=$'        - { name: workload, mountPath: /rdzv }\n'
        rdzv_vol=""
        master_setup="          MARKER=/rdzv/master.${job}; if [ \"\${JOB_COMPLETION_INDEX:-0}\" = \"0\" ]; then MASTER_ADDR=\${CLUSTERMAX_HOST_IP:?status.hostIP unavailable}; echo \"\$MASTER_ADDR\" > \"\$MARKER\"; else for i in \$(seq 1 120); do [ -s \"\$MARKER\" ] && break; sleep 2; done; MASTER_ADDR=\$(cat \"\$MARKER\" 2>/dev/null); fi"
    elif [[ -n "$rdma_claim_template" ]]; then
        pod_claim_entries+="${pod_claim_entries:+$'\n'}      - name: rdma
        resourceClaimTemplateName: ${rdma_claim_template}"
        container_claim_entries+="${container_claim_entries:+$'\n'}          - name: rdma"
        svc_block=$'      subdomain: '"$svc"$'\n'
        master_setup="          MASTER_ADDR=${master}; echo \"node_rank=\${JOB_COMPLETION_INDEX:-0} waiting for ${master}\"; for i in \$(seq 1 120); do getent hosts ${master} >/dev/null 2>&1 && break; sleep 2; done"
    else
        local rail_networks rail_pair
        rail_networks=""
        [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" != "1" ]] && rail_networks="$(k8s_detect_rail_networks)"
        if [[ -n "$rail_networks" ]]; then
            for rail_pair in ${rail_networks//,/ }; do
                net_ann+="${rail_pair%%=*},"
                rdma_extra+=", ${rail_pair##*=}: 1"
            done
            net_ann="${net_ann%,}"
        elif [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" != "1" ]] && k8s_cluster_has_rdma_fabric; then
            for i in $(seq 0 15); do net_ann+="roce-net-fabric${i}@fabric${i},"; rdma_extra+=", rdma/fabric${i}: 1"; done
            net_ann="${net_ann%,}"
        fi
        svc_block=$'      subdomain: '"$svc"$'\n'
        master_setup="          MASTER_ADDR=${master}; echo \"node_rank=\${JOB_COMPLETION_INDEX:-0} waiting for ${master}\"; for i in \$(seq 1 120); do getent hosts ${master} >/dev/null 2>&1 && break; sleep 2; done"
    fi
    if [[ "$gpu_required" != 0 ]] && k8s_compute_domain_create "cmax-${runner}-cd-${stamp}"; then
        compute_domain="cmax-${runner}-cd-${stamp}"
        pod_claim_entries+="${pod_claim_entries:+$'\n'}      - name: imex-channel
        resourceClaimTemplateName: ${compute_domain}-channel"
        container_claim_entries+="${container_claim_entries:+$'\n'}          - name: imex-channel"
    fi
    if [[ -n "$pod_claim_entries" ]]; then
        pod_claims_block=$'      resourceClaims:\n'"${pod_claim_entries}"$'\n'
        # Avoid hostNetwork for any DRA claim, including the mixed case of GPU
        # DRA plus a scalar shared-RDMA resource. Keep the scalar device
        # request, but use the headless Service and pod DNS for rendezvous.
        if [[ -n "$hostnet_block" ]]; then
            hostnet_block=""
            svc_block=$'      subdomain: '"$svc"$'\n'
            master_setup="          MASTER_ADDR=${master}; echo \"node_rank=\${JOB_COMPLETION_INDEX:-0} waiting for ${master}\"; for i in \$(seq 1 120); do getent hosts ${master} >/dev/null 2>&1 && break; sleep 2; done"
        fi
    fi
    if [[ -n "$container_claim_entries" ]]; then
        container_claims_block=$'          claims:\n'"${container_claim_entries}"$'\n'
    fi
    resource_items="${gpu_scalar}${res_extra}${rdma_extra}"
    resource_items="${resource_items#, }"
    resources_block="${container_claims_block}          requests: { ${resource_items} }
          limits: { ${resource_items} }"
    if k8s_gpu_dra_enabled \
        && [[ -z "${NCCL_MNNVL_ENABLE+x}" ]] \
        && [[ -z "${CLUSTERMAX_K8S_COMPUTE_DOMAIN_CLAIM_TEMPLATE:-}" ]] \
        && [[ -z "$compute_domain" ]]; then
        extra_nccl+="          export NCCL_MNNVL_ENABLE=0"$'\n'
        echo "${runner}: GPU DRA has no ComputeDomain channel claim; defaulting NCCL_MNNVL_ENABLE=0"
    fi
    for v in NCCL_DEBUG NCCL_DEBUG_SUBSYS NCCL_MNNVL_ENABLE NCCL_DMABUF_ENABLE NCCL_IB_HCA NCCL_IB_GID_INDEX NCCL_IB_TC NCCL_IB_SL NCCL_IB_QPS_PER_CONNECTION \
             NCCL_IB_TIMEOUT NCCL_IB_RETRY_CNT NCCL_NET_GDR_LEVEL NCCL_PXN_DISABLE NCCL_CROSS_NIC NCCL_ALGO \
             NCCL_MIN_NCHANNELS; do
        [[ -n "${!v:-}" ]] && extra_nccl+="          export ${v}='${!v}'"$'\n'
    done
    if [[ "${CLUSTERMAX_K8S_NO_RDMA:-}" == "1" ]]; then
        extra_nccl+="          export NCCL_IB_DISABLE=1"$'\n'
    fi
    # Bake an explicit override into the pod, or discover the host's default
    # route interface at runtime. hostNetwork nodes do not consistently call
    # it eth0 (Lambda uses eno1), and a wrong name makes NCCL bootstrap fail.
    local socket_setup gloo_socket_setup
    if [[ -n "${NCCL_SOCKET_IFNAME:-}" ]]; then
        socket_setup="export NCCL_SOCKET_IFNAME='${NCCL_SOCKET_IFNAME}'"
    else
        socket_setup="export NCCL_SOCKET_IFNAME=\$(awk '\$2 == \"00000000\" {print \$1; exit}' /proc/net/route)"
    fi
    gloo_socket_setup="export GLOO_SOCKET_IFNAME=\${GLOO_SOCKET_IFNAME:-\$(awk '\$2 == \"00000000\" {print \$1; exit}' /proc/net/route)}"
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        result_hold_block=$'          printf "%s\\n" "$rc" > "/results/.cmax-details-ready-${JOB_COMPLETION_INDEX:-0}"\n          sleep '"${K8S_TIMEOUT_S:-7200}"$'\n'
    fi

    echo ">>> distributed ${runner}: ${nodes} node(s) x ${gpn} GPU (world=$((nodes * gpn))), image ${image}"
    kubectl -n "$ns" delete "job/$job" "service/$svc" "pvc/$pvc" "pod/$loader" \
        --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    sleep 3

    # 1. RWX PVC + loader pod; seed the workload dir + parallelism.sh into it.
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: $pvc, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  accessModes: [ ReadWriteMany ]
  storageClassName: $sc
  resources: { requests: { storage: ${CLUSTERMAX_WORKLOAD_PVC_SIZE:-50Gi} } }
---
apiVersion: v1
kind: Pod
metadata: { name: $loader, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  restartPolicy: Never
$(k8s_arch_node_selector_yaml "  ")
  tolerations:
  - { key: $gpu_resource, operator: Exists, effect: NoSchedule }
  - { key: kubernetes.io/arch, operator: Exists, effect: NoSchedule }
  containers:
  - name: loader
    # GNU tar (not busybox): busybox tar extraction blocks waiting for a stdin EOF
    # that kubectl exec -i does not promptly deliver over the vcluster proxy,
    # so the seed never returns. GNU tar exits at the archive end-of-stream.
    image: ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    command: ["sh","-c","mkdir -p /workload && sleep 1800"]
    volumeMounts: [ { name: w, mountPath: /workload } ]
  volumes: [ { name: w, persistentVolumeClaim: { claimName: $pvc } } ]
EOF
    kubectl -n "$ns" wait --for=condition=ready "pod/$loader" --timeout=180s || { echo "ERROR: loader pod not ready (PVC bind?)" >&2; return 1; }
    echo ">>> seeding workload + shared training helpers into PVC ${pvc}"
    # --no-xattrs + COPYFILE_DISABLE on the sender stop macOS bsdtar from
    # injecting com.apple.provenance xattr pax records (GNU tar in the loader
    # warns on each, one line per file of log spam) and ._ AppleDouble files;
    # both are no-ops on a Linux/GNU-tar operator.
    # The archive must not carry a "./" root entry: extracting into the PVC
    # mount root makes tar restore the archived mode of ".", which a
    # root-squashed export rejects (exit 2) even with --no-overwrite-dir.
    # Listing the top-level members explicitly keeps tar's hands off ".".
    (cd "$workload_dir" && find . -mindepth 1 -maxdepth 1 -print0 \
        | COPYFILE_DISABLE=1 tar --no-xattrs --null -T - -cf -) \
        | kubectl -n "$ns" exec -i "$loader" -- tar -C /workload --no-same-owner --no-same-permissions -m -xf -
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$lib_dir" -cf - \
        parallelism.sh summarize_training_profile.py \
        training-progress-watchdog.sh training_progress_watchdog.py \
        training-stack-provenance.py |
        kubectl -n "$ns" exec -i "$loader" -- tar -C /workload --no-same-owner --no-same-permissions -m -xf -
    kubectl -n "$ns" exec "$loader" -- mkdir -p /workload/.clustermax-shared
    COPYFILE_DISABLE=1 tar --no-xattrs -C "$lib_dir" -cf - \
        elbencho.sh elbencho_values.py storage-client-scale.sh |
        kubectl -n "$ns" exec -i "$loader" -- tar -C /workload/.clustermax-shared --no-same-owner --no-same-permissions -m -xf -
    kubectl -n "$ns" delete pod "$loader" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true

    # 2. Headless Service + Indexed Job (one pod per node), torchrun static rdzv.
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata: { name: $svc, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  clusterIP: None
  selector: { job-name: $job }
  ports: [ { name: c10d, port: 29500 } ]
---
apiVersion: batch/v1
kind: Job
metadata: { name: $job, namespace: $ns, labels: { app.kubernetes.io/name: clustermax-bench } }
spec:
  completionMode: Indexed
  completions: $nodes
  parallelism: $nodes
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels: { app.kubernetes.io/name: clustermax-bench, job-name: $job }
$( [[ -n "$net_ann" ]] && printf '      annotations: { k8s.v1.cni.cncf.io/networks: "%s" }' "$net_ann" )
    spec:
      restartPolicy: Never
$(k8s_arch_node_selector_yaml "      ")
$(k8s_worker_affinity_yaml "      ")
${topology_spread_block}${svc_block}${hostnet_block}      tolerations:
      - { key: $gpu_resource, operator: Exists, effect: NoSchedule }
      - { key: kubernetes.io/arch, operator: Exists, effect: NoSchedule }
${pod_claims_block}      containers:
      - name: train
        image: $image
$forward_env_block
$s3_env_block
        securityContext: { capabilities: { add: ["IPC_LOCK"] } }
        command: ["/bin/bash","-c"]
        args:
        - |
          set -uo pipefail
          mkdir -p /results
          ${socket_setup}
          ${gloo_socket_setup}
          export NCCL_DEBUG=\${NCCL_DEBUG:-WARN}
${extra_nccl}${master_setup}
          echo "node_rank=\${JOB_COMPLETION_INDEX:-0} master=\$MASTER_ADDR"
          env -u CLUSTERMAX_HARNESS -u K8S_NAMESPACE \\
              CLUSTERMAX_SHARED_DIR=/workload/.clustermax-shared \\
              CLUSTERMAX_NNODES=$nodes CLUSTERMAX_NPROC=$gpn \\
              CLUSTERMAX_NODE_RANK=\${JOB_COMPLETION_INDEX:-0} \\
              CLUSTERMAX_MASTER_ADDR=\$MASTER_ADDR CLUSTERMAX_MASTER_PORT=29500 \\
              CLUSTERMAX_PEER_SERVICE=${svc}.${ns}.svc.cluster.local \\
              RESULT_DIR=/results bash /workload/run.sh
          rc=\$?
          echo '===CMAX_VALUES_BEGIN==='
          cat /results/${runner}.values.json 2>/dev/null
          echo '===CMAX_VALUES_END==='
${result_hold_block}
          exit \$rc
        resources:
${resources_block}
        volumeMounts:
        - { name: workload, mountPath: /workload, readOnly: true }
        - { name: dshm, mountPath: /dev/shm }
${ib_mount}${rdzv_mount}${storage_mount_block}      volumes:
      - { name: workload, persistentVolumeClaim: { claimName: $pvc } }
      - { name: dshm, emptyDir: { medium: Memory, sizeLimit: 64Gi } }
${ib_vol}${rdzv_vol}${storage_vol_block}
EOF

    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        result_selector="$(k8s_job_pod_selector "$job")" || result_selector=""
    fi
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        k8s_wait_distributed_results_ready "$job" "$nodes" "${K8S_TIMEOUT_S:-7200}" "$result_selector" || rc=$?
    else
        k8s_wait_job "$job" "${K8S_TIMEOUT_S:-7200}" || rc=$?
    fi
    result_selector="${K8S_DISTRIBUTED_RESULT_SELECTOR:-$result_selector}"
    local pod0 pod_selector="${result_selector:-job-name=${job}}"
    # Retain evidence from every distributed rank before cleanup. Rank 0 is
    # still captured separately below because it carries the values marker.
    k8s_capture_logs "$pod_selector" "${runner}"
    pod0="$(kubectl -n "$ns" --request-timeout=30s get pods -l "${pod_selector},batch.kubernetes.io/job-completion-index=0" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [[ -n "$pod0" ]]; then
        kubectl -n "$ns" --request-timeout=120s logs "$pod0" > "$capfile" 2>&1 || true
    fi
    awk '/===CMAX_VALUES_BEGIN===/{f=1;next} /===CMAX_VALUES_END===/{f=0} f' "$capfile" > "$values_json" 2>/dev/null || true
    if [[ "${CLUSTERMAX_K8S_COPY_DISTRIBUTED_RESULTS:-0}" == "1" ]]; then
        if [[ -n "$result_selector" ]]; then
            k8s_copy_results "$result_selector" "/results/." || copy_rc=$?
        else
            copy_rc=1
        fi
        rm -f "$RESULT_DIR"/.cmax-details-ready-*
    fi
    kubectl -n "$ns" delete "job/$job" "service/$svc" "pvc/$pvc" \
        --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    [[ -n "$s3_secret" ]] && kubectl -n "$ns" delete "secret/$s3_secret" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    k8s_compute_domain_delete "$compute_domain" "$ns"

    if [[ ! -s "$values_json" ]] || ! python3 -c "import json,sys; json.load(open('$values_json'))" 2>/dev/null; then
        echo "ERROR: ${runner} distributed run produced no valid ${runner}.values.json (rc=${rc})" >&2
        rm -f "$values_json"
        return 1
    fi
    if (( copy_rc != 0 )); then
        echo "ERROR: ${runner} could not copy distributed result details" >&2
        rm -f "$values_json"
        return "$copy_rc"
    fi
    if (( rc != 0 )); then
        echo "ERROR: ${runner} distributed workload failed after publishing result details (rc=${rc})" >&2
        rm -f "$values_json"
        return "$rc"
    fi
    echo "${runner} k8s distributed: wrote ${values_json}"
    return 0
}
