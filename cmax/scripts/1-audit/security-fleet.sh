#!/bin/bash
# Fleet security evidence for the audit collectors.
#
# Each harness has one collector (cluster-audit-<harness>.sh). That collector
# reads the sampled GPU worker in full, then sources this file and calls
# merge_security_fleet before it writes its JSON. The merge reads every other
# host that a security verdict depends on:
#
#   - PwnEscape, SCTP sendall, AMD KVM, Fragnesia and Januscape facts on every
#     worker, the login host and each control-plane host (host_fleet.py).
#   - The host and container checks on every GPU host (security_fleet.py).
#   - On Kubernetes, the BMC and IPMI probe on every worker node.
#
# `cmax audit` and `cmax audit security` run the same collector, so the two
# commands always grade the same evidence. The security scope only filters
# which checks run_checks.py reports.
#
# The caller must source audit-common.sh first and define print_info,
# print_error and WORKLOAD_DIR.

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
        --rawfile facts <(printf '%s' "$facts") --arg error "$error" --argjson checked "$checked" '{
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
        SECURITY_ADVISORY_JSON=$(jq --slurpfile fleet <(printf '%s' "$fleet") '.pwnescape = $fleet[0]' \
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
    local kubelet_containerd="${6:-}"
    if [[ -z "$host_out" ]] || ! grep -q '^WORKER_HOSTNAME=' <<< "$host_out"; then
        jq -cn --arg node "$node" --arg error "$error" \
            '{node: $node, checked: false, error: $error}'
        return 0
    fi
    (
        local key value vendor driver nct=unknown runc=unknown docker=unknown
        local containerd=unknown
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
            containerd=$(sed -n 's/^WORKER_CONTAINER_SECURITY_CONTAINERD_VERSION=//p' <<< "$container_out" | head -1)
        fi
        containerd=$(resolve_containerd_version "${containerd:-unknown}" "$kubelet_containerd")
        vendor=nvidia
        if amd_gpu_check_present "${WORKER_AMD_GPU_COUNT:-0}" "${WORKER_AMD_GPU_MODEL:-}"; then
            vendor=amd
        fi
        driver="${WORKER_DRIVER_VERSION:-unknown}"
        [[ "$driver" == "unknown" || -z "$driver" ]] && driver="$label_driver"
        versions=$(build_security_version_audit "$host_out" "$driver" \
            "${nct:-unknown}" "${runc:-unknown}" "${docker:-unknown}" "$vendor" \
            "${WORKER_NVCC_VERSION:-unknown}" per-host "$containerd")
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
        jq -cn --arg node "$node" \
            --slurpfile versions <(printf '%s' "${versions:-{\}}") \
            --slurpfile advisories <(printf '%s' "${advisories:-{\}}") \
            '{node: $node, checked: true, securityVersions: $versions[0], security: $advisories[0]}' \
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
            | jq -s --slurpfile versions <(printf '%s' "$SECURITY_VERSION_AUDIT_JSON") \
                --slurpfile security <(printf '%s' "$SECURITY_ADVISORY_JSON") \
                --argjson total "$(json_int "$SECURITY_GPU_HOSTS_TOTAL")" \
                '{sampled: {securityVersions: $versions[0], security: $security[0]},
                  hostsTotal: $total, hosts: .}' \
            | python3 "$WORKLOAD_DIR/security_fleet.py" 2>/dev/null) \
            && [[ -n "$merged" ]]; then
        SECURITY_VERSION_AUDIT_JSON=$(jq -c '.securityVersions' <<< "$merged")
        SECURITY_ADVISORY_JSON=$(jq -c '.security' <<< "$merged")
    else
        local reason="The fleet grader failed, so this check covers only the sampled worker and is unverified for the other GPU hosts."
        SECURITY_VERSION_AUDIT_JSON=$(jq -c --arg reason "$reason" '
            reduce ("nvidiaDriver","amdDriver","nvidiaContainerToolkit","runc","containerd","docker","connectxFirmware","dcgm") as $k
              (.; if (.[$k] | type) == "object" and ((.[$k].status // "") | IN("fail") | not)
                  then .[$k].status = "unknown" | .[$k].detail = $reason else . end)' \
            <<< "$SECURITY_VERSION_AUDIT_JSON")
    fi
    print_info "Host-level security checks: read $(grep -c '"checked":true' <<< "$SECURITY_HOST_RECORDS" || true) of ${SECURITY_GPU_HOSTS_TOTAL} GPU host(s)"
}

# Grade the host-kernel CVEs across every node the fleet collector reached:
# workers, the login host, and every control-plane host. The sampled GPU
# worker stays the source for the fleet-scope version rows; these rows are
# fleet-scope from the start, so the merge can fold them over the sampled
# result without re-collecting.
#
# A fleet result that did not itself fail must not clear a failure the sampled
# worker already recorded. The extra host read can miss that worker. The
# failure stays in the merged object, with the fleet coverage fields beside it.
apply_host_fleet() {
    local fleet floor grace=false
    local -r keep_proven='
        def keep_proven($before; $key):
          (.[$key] // {}) as $now
          | ($before[$key] // {}) as $old
          | if (($old.status == "fail") and ($now.status != "fail"))
              or (($old.exposed == true) and ($now.exposed != true)) then
              .[$key] = ($now
                + {status: "fail", reason: ($old.reason // $now.reason)}
                + (if $old.exposed == true then {exposed: true} else {} end))
            else . end;
    '
    floor=$(minimum_version components.ubuntuNoble.packages.linuxFragnesia.abi)
    [[ "$(minimum_version_grace ubuntuNoble linuxFragnesia 2>/dev/null || true)" == "true" ]] \
        && grace=true
    if fleet=$(printf '%s' "$PWNESCAPE_HOST_RECORDS" \
            | jq -s --argjson control "$PWNESCAPE_CONTROL_PLANE_JSON" \
                --arg floor "$floor" --argjson grace "$grace" \
                '{hosts: ., controlPlane: $control, fragnesiaAbiFloor: $floor,
                  fragnesiaGrace: $grace}' \
            | python3 "$WORKLOAD_DIR/host_fleet.py" 2>/dev/null) \
            && [[ -n "$fleet" ]]; then
        SECURITY_ADVISORY_JSON=$(jq --slurpfile fleet_doc <(printf '%s' "$fleet") "$keep_proven"'
            . as $before
            | $fleet_doc[0] as $fleet
            | .pwnescape = $fleet.pwnescape
            | .sctpSendall = $fleet.sctpSendall
            | .kvmSvm = $fleet.kvmSvm
            | .fragnesia = ((.fragnesia // {})
                + {status: $fleet.fragnesia.status,
                   reason: $fleet.fragnesia.reason,
                   scope: "fleet", fleet: $fleet.fragnesia})
            | .januscape = ((.januscape // {})
                + {status: $fleet.januscape.status,
                   exposed: $fleet.januscape.exposed,
                   reason: $fleet.januscape.reason,
                   scope: "fleet", fleet: $fleet.januscape})
            | keep_proven($before; "pwnescape")
            | keep_proven($before; "sctpSendall")
            | keep_proven($before; "kvmSvm")
            | keep_proven($before; "fragnesia")
            | keep_proven($before; "januscape")
        ' <<< "$SECURITY_ADVISORY_JSON")
    else
        SECURITY_ADVISORY_JSON=$(jq "$keep_proven"'
            . as $before
            | .pwnescape = {
                status: "unknown", scope: "fleet", exploitTested: false,
                reason: "The host fleet grader failed. Every host needs CVE-specific patch evidence."
            }
            | .sctpSendall = {
                status: "unknown", scope: "fleet", exploitTested: false,
                reason: "The host fleet grader failed. Every host needs CVE-specific patch evidence."
            }
            | .kvmSvm = {
                status: "unknown", scope: "fleet", exploitTested: false,
                reason: "The host fleet grader failed. Every host needs CVE-specific patch evidence."
            }
            | .fragnesia = ((.fragnesia // {})
                + {status: "unknown", scope: "fleet",
                   reason: "The host fleet grader failed. Every host needs CVE-specific patch evidence."})
            | .januscape = ((.januscape // {})
                + {status: "unknown", exposed: "unknown", scope: "fleet",
                   reason: "The host fleet grader failed. Every host needs CVE-specific patch evidence."})
            | keep_proven($before; "pwnescape")
            | keep_proven($before; "sctpSendall")
            | keep_proven($before; "kvmSvm")
            | keep_proven($before; "fragnesia")
            | keep_proven($before; "januscape")
        ' <<< "$SECURITY_ADVISORY_JSON")
    fi
}

cleanup_k8s_security_pod() {
    if [[ -n "$K8S_SECURITY_CHECK_POD" ]]; then
        kubectl delete pod "$K8S_SECURITY_CHECK_POD" \
            -n "$K8S_SECURITY_CHECK_NS" --ignore-not-found=true --wait=false \
            --request-timeout=30s >/dev/null 2>&1 || true
        K8S_SECURITY_CHECK_POD=""
    fi
}

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
    local fragnesia_abi_minimum ubuntu_kernel_abi_minimum nvidia_branch_floors
    fragnesia_abi_minimum=$(minimum_version \
        components.ubuntuNoble.packages.linuxFragnesia.abi)
    ubuntu_kernel_abi_minimum=$(minimum_version \
        components.ubuntuNoble.packages.linux.abi)
    nvidia_branch_floors=$(nvidia_driver_floors)
    kubectl exec -i -n "$K8S_SECURITY_CHECK_NS" \
        --request-timeout=300s "$K8S_SECURITY_CHECK_POD" -- \
        chroot /host env CLUSTERMAX_AUDIT_SCOPE=security \
        CLUSTERMAX_AUDIT_HARNESS=k8s \
        CLUSTERMAX_CONTAINER_RUNTIME_SCOPE=host \
        CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$fragnesia_abi_minimum" \
        CLUSTERMAX_UBUNTU_KERNEL_ABI_MINIMUM="$ubuntu_kernel_abi_minimum" \
        CLUSTERMAX_NVIDIA_BRANCH_FLOORS="$nvidia_branch_floors" bash -s
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
        "The host-root pod returned no host evidence." "$(k8s_label_driver "$node")" \
        "$(kubelet_containerd_version "$K8S_SECURITY_NODES_JSON" "$node")"
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
            "$K8S_SECURITY_DRIVER_VERSION" \
            "$(kubelet_containerd_version "$K8S_SECURITY_NODES_JSON" "$first_node")"
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
    local floor
    floor=$(minimum_version components.ubuntuNoble.packages.linuxFragnesia.abi)
    if [[ -n "${SLURM_JOB_ID:-}" && "$SLURM_ALLOCATION_NODES" == *$'\n'"$node"$'\n'* ]]; then
        srun "${AUDIT_SRUN_FLAGS[@]}" -N1 --ntasks=1 -w "$node" --time=2:00 \
            /usr/bin/env CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$floor" \
            bash -s < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null
    else
        /usr/bin/env -u SLURM_JOB_ID -u SLURM_JOBID srun -p "$partition" -N1 --ntasks=1 \
            -w "$node" --time=2:00 --immediate=30 \
            /usr/bin/env CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$floor" \
            bash -s < "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null
    fi
}

# Read every compute node, the login host that runs this audit, and every
# slurmctld and slurmdbd host. A control host that is not a compute node is
# read over ssh in batch mode, so the audit never prompts for a credential.
collect_slurm_pwnescape_fleet() {
    local rows node partition host local_host tmp batch="" batch_size=0 concurrency
    local compute_nodes control_hosts facts floor
    floor=$(minimum_version components.ubuntuNoble.packages.linuxFragnesia.abi)
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
        "$(CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$floor" \
            bash "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null)" \
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
            facts=$(CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$floor" \
                bash "$WORKLOAD_DIR/pwnescape-host-facts.sh" 2>/dev/null)
        elif [[ "$compute_nodes" == *$'\n'"$host"$'\n'* ]]; then
            facts=$(cat "$tmp/$host.facts" 2>/dev/null)
        else
            facts=$(ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" \
                /usr/bin/env CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="$floor" bash -s \
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
    local nvidia_branch_floors
    nvidia_branch_floors=$(nvidia_driver_floors)
    if [[ -n "${SLURM_JOB_ID:-}" && "$SLURM_ALLOCATION_NODES" == *$'\n'"$node"$'\n'* ]]; then
        srun "${AUDIT_SRUN_FLAGS[@]}" -N1 --ntasks=1 -w "$node" \
            --gres=gpu:"$(slurm_job_gpus_per_node "$node")" \
            --time="$limit" /usr/bin/env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
            CLUSTERMAX_NVIDIA_BRANCH_FLOORS="$nvidia_branch_floors" \
            bash -s < "$WORKLOAD_DIR/$script" 2>/dev/null
    else
        /usr/bin/env -u SLURM_JOB_ID -u SLURM_JOBID srun -p "$partition" -N1 --ntasks=1 \
            -w "$node" --gres=gpu:1 --time="$limit" --immediate=30 \
            /usr/bin/env CLUSTERMAX_AUDIT_SCOPE=security CLUSTERMAX_AUDIT_HARNESS=slurm \
            CLUSTERMAX_NVIDIA_BRANCH_FLOORS="$nvidia_branch_floors" \
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


# Read one KEY=value line from host-check output.
security_fact() {
    sed -n "s/^$1=//p" <<< "$2" | head -1
}

# Fold the fleet evidence into JSON_OUTPUT, the JSON the collector built from
# its sampled worker. Usage: merge_security_fleet HARNESS SAMPLED_HOST_OUTPUT
#
# The collector has already graded the sampled worker. This step adds the
# other hosts and replaces each host-level verdict with the fleet verdict, the
# same verdict for `cmax audit` and `cmax audit security`. A standalone target
# is one host, so its sampled verdict is already complete.
merge_security_fleet() {
    local harness="$1" sampled_out="${2:-}" pcie runtime_enriched
    pcie=$(jq -cn \
        --argjson complete "$(json_bool_or_unknown "$(security_fact WORKER_PCIE_SCAN_COMPLETE "$sampled_out")")" \
        --argjson vfio "$(json_int "$(security_fact WORKER_PCIE_VFIO_DEVICES "$sampled_out")")" \
        --argjson unsafe "$(json_int "$(security_fact WORKER_PCIE_UNSAFE_GROUPS "$sampled_out")")" \
        '{inventoryComplete: $complete, vfioDevices: $vfio, unsafeGroups: $unsafe,
          scope: "sampled-worker-host"}')
    JSON_OUTPUT=$(jq -c --argjson pcie "$pcie" \
        '.security.pciePassthrough = ((.security.pciePassthrough // {}) + $pcie)' \
        <<< "$JSON_OUTPUT")
    [[ "$harness" == "standalone" ]] && return 0

    SECURITY_VERSION_AUDIT_JSON=$(jq -c '.securityVersions // {}' <<< "$JSON_OUTPUT")
    SECURITY_ADVISORY_JSON=$(jq -c '.security // {}' <<< "$JSON_OUTPUT")
    print_section "Security fleet evidence"
    if [[ "$harness" == "slurm" ]]; then
        WORKER_CHECK_OUTPUT="$sampled_out"
        collect_slurm_pwnescape_fleet
        collect_slurm_security_host_fleet
    elif [[ "$harness" == "k8s" ]]; then
        if prepare_k8s_security_pod; then
            # collect_k8s_host_fleet moves K8S_SECURITY_NODE from node to node.
            K8S_SAMPLED_SECURITY_NODE="$K8S_SECURITY_NODE"
            WORKER_CHECK_OUTPUT=$(run_k8s_security_script \
                < "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || true)
            CONTAINER_CHECK_OUTPUT=""
            if [[ -f "$WORKLOAD_DIR/container-check.sh" ]]; then
                CONTAINER_CHECK_OUTPUT=$(run_k8s_security_script \
                    < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || true)
            fi
            collect_k8s_host_fleet
            SECURITY_ADVISORY_JSON=$(jq -c --argjson bmc "$K8S_BMC_IPMI_JSON" \
                '.bmcIpmi = $bmc' <<< "$SECURITY_ADVISORY_JSON")
        else
            cleanup_k8s_security_pod
            print_warn "Security fleet: the host-root pod could not start; host-level checks cover only the sampled worker"
        fi
    fi
    apply_security_host_fleet
    apply_host_fleet
    # The fleet JSON can pass the kernel limit for one argument, so jq reads
    # it from a file descriptor, not from the command line.
    # A merge failure keeps the collected JSON, so one bad step cannot empty
    # the whole audit.
    local merged_json
    if merged_json=$(jq -c --slurpfile versions <(printf '%s' "$SECURITY_VERSION_AUDIT_JSON") \
            --slurpfile security <(printf '%s' "$SECURITY_ADVISORY_JSON") \
            '.securityVersions = $versions[0] | .security = $security[0]' <<< "$JSON_OUTPUT") \
            && [[ -n "$merged_json" ]]; then
        JSON_OUTPUT=$merged_json
    else
        print_warn "Security fleet: the fleet verdicts could not be merged; security checks use the sampled worker only"
    fi

    if [[ "$harness" == "k8s" ]]; then
        if runtime_enriched=$(printf '%s' "$JSON_OUTPUT" | python3 \
                "${WORKLOAD_DIR}/k8s_runtime_software.py" \
                --node "${K8S_SAMPLED_SECURITY_NODE:-$K8S_SECURITY_NODE}"); then
            JSON_OUTPUT="$runtime_enriched"
        else
            JSON_OUTPUT=$(jq -c '
              .runtimeSoftware.cudaToolkit = {coverageComplete:false,error:"runtime software collector failed"}
              | if .securityVersions.cudaToolkit.status != "fail" then
                  .securityVersions.cudaToolkit.status = "unknown"
                  | .securityVersions.cudaToolkit.detail = "Runtime software collector failed; patch status is unverified"
                else . end' <<< "$JSON_OUTPUT")
        fi
    fi
}
