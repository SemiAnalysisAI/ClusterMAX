#!/bin/bash
# =============================================================================
# SLURM Cluster Audit Script
# =============================================================================
# Audits SLURM cluster configuration, GPU setup, networking, storage, and
# container support. Outputs JSON for tracking multiple clusters over time.
#
# Usage:
#   ./cluster-audit-slurm.sh [options]
#
# Options:
#   --name <name>      Custom cluster name for output file
#   --output-dir <dir> Directory for JSON output (default: ./audit-results)
#   --json-only        Output JSON to stdout only, no file
#   --help             Show this help message
#
# Requirements:
#   - Run on SLURM head node with sinfo/scontrol access
#   - jq installed for JSON processing
#   - Optional: sudo access for some checks
# =============================================================================

set -o pipefail

# Directory of this collector; host-check.sh is a sibling, shared by
# all harness collectors so the node-level check is defined once.
WORKLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$WORKLOAD_DIR/audit-common.sh"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Formatting functions
# Parse command line arguments
CUSTOM_NAME=""
OUTPUT_DIR=""
JSON_ONLY="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        --name)
            CUSTOM_NAME="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --json-only)
            JSON_ONLY="true"
            shift
            ;;
        --help)
            head -30 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    echo "Install with: sudo apt install jq"
    exit 1
fi

# Check for SLURM
# sinfo/scontrol may be group-restricted on some clusters; srun/sbatch are usually world-executable.
# We proceed as long as at least srun is available; sinfo/scontrol calls degrade gracefully.
SINFO_OK="false"
SCONTROL_OK="false"
if command -v sinfo &>/dev/null && sinfo --version &>/dev/null 2>&1; then
    SINFO_OK="true"
elif command -v srun &>/dev/null; then
    echo "Warning: sinfo/scontrol not accessible (permission restricted). Falling back to slurm.conf + srun."
else
    echo "Error: No SLURM commands accessible. Run this on a SLURM login node."
    exit 1
fi
# Check scontrol availability. In SLURM 25.x `scontrol show version` is not
# valid syntax (it expects an entity like nodes/partition/job); use `--version`
# which is supported across all SLURM versions and exits 0 when scontrol works.
if command -v scontrol &>/dev/null && scontrol --version &>/dev/null 2>&1; then
    SCONTROL_OK="true"
fi

# Helper: read a value from slurm.conf when scontrol is unavailable
SLURM_CONF_FILE="${SLURM_CONF:-/etc/slurm/slurm.conf}"
slurm_conf_get() {
    # Usage: slurm_conf_get KEY
    grep -m1 "^${1}=" "$SLURM_CONF_FILE" 2>/dev/null | cut -d= -f2- | tr -d ' ' || echo ""
}

# Wrapper: sinfo that falls back to sudo snodes / slurm.conf parsing
run_sinfo() {
    if [[ "$SINFO_OK" == "true" ]]; then
        sinfo "$@" 2>/dev/null
    elif command -v sudo &>/dev/null && sudo -n /usr/local/bin/snodes &>/dev/null 2>&1; then
        sudo -n /usr/local/bin/snodes 2>/dev/null
    fi
}

# Wrapper: scontrol that falls back to slurm.conf
run_scontrol() {
    if [[ "$SCONTROL_OK" == "true" ]]; then
        scontrol "$@" 2>/dev/null
    fi
}

# Nested srun checks must share an existing allocation when this audit is run
# from preflight or another runner. Without --overlap they can block behind the
# parent shell step and report false failures.
AUDIT_SRUN_FLAGS=()
if [[ -n "${SLURM_JOB_ID:-}" ]]; then
    AUDIT_SRUN_FLAGS=(--jobid="$SLURM_JOB_ID" --overlap)
fi

# Build SLURM_CONFIG_FULL: try scontrol first; if restricted, transform slurm.conf into
# the same "KEY = VALUE" format that all subsequent grep/awk patterns expect.
if [[ "$SCONTROL_OK" == "true" ]]; then
    SLURM_CONFIG_FULL=$(scontrol show config 2>/dev/null || echo "")
else
    # Transform KEY=VALUE → KEY = VALUE so existing grep "^KEY" | awk '{print $3}' patterns work
    SLURM_CONFIG_FULL=$(grep -v '^\s*#\|^\s*$' "${SLURM_CONF_FILE}" 2>/dev/null \
        | sed 's/[[:space:]]*=[[:space:]]*/  =  /g' || echo "")
fi

# Timestamps
AUDIT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_TIMESTAMP_FILE=$(date +"%Y%m%d-%H%M%S")

# =============================================================================
# SECTION 1: SLURM Version & Cluster Identity
# =============================================================================
print_header "1. SLURM VERSION & CLUSTER IDENTITY"

# Get SLURM version
SLURM_VERSION=$(sinfo --version 2>/dev/null | head -1 || srun --version 2>/dev/null | head -1 || echo "unknown")
SLURM_VERSION_NUM=$(echo "$SLURM_VERSION" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "0.0.0")

print_section "SLURM Version"
print_info "Version: ${SLURM_VERSION}"

# Get cluster name from SLURM config
CLUSTER_NAME=$(echo "$SLURM_CONFIG_FULL" | grep "^ClusterName" | awk '{print $3}' || echo "unknown")
CONTROL_MACHINE=$(echo "$SLURM_CONFIG_FULL" | grep "^SlurmctldHost" | awk '{print $3}' | head -1 || echo "unknown")
SLURM_USER=$(echo "$SLURM_CONFIG_FULL" | grep "^SlurmUser" | awk '{print $3}' || echo "slurm")

print_section "Cluster Identity"
print_info "Cluster Name: ${CLUSTER_NAME}"
print_info "Control Machine: ${CONTROL_MACHINE}"
print_info "SLURM User: ${SLURM_USER}"
print_info "Hostname: $(hostname)"

# Check SLURM daemons. A local `pgrep` only sees daemons on this host, but the
# control plane frequently runs elsewhere: a dedicated controller node, or a pod
# on Slurm-on-Kubernetes clusters (soperator / Slinky / SUNK), where the login
# node this audit runs on has neither slurmctld nor slurmdbd. Before warning,
# ask Slurm itself (`scontrol ping` for slurmctld, `sacctmgr ping` / a live
# accounting query for slurmdbd) so a remote-but-healthy control plane is
# reported as running instead of a false "not running" / "not detected" warning.
print_section "SLURM Services"
SLURMCTLD_RUNNING=$(pgrep -x slurmctld &>/dev/null && echo "true" || echo "false")
SLURMD_RUNNING=$(pgrep -x slurmd &>/dev/null && echo "true" || echo "false")
SLURMDBD_RUNNING=$(pgrep -x slurmdbd &>/dev/null && echo "true" || echo "false")

# slurmctld: local process first, otherwise reachable via `scontrol ping`.
if [[ "$SLURMCTLD_RUNNING" == "true" ]]; then
    print_info "slurmctld: Running (local process)"
elif [[ "$SCONTROL_OK" == "true" ]] && scontrol ping 2>/dev/null | grep -q 'UP'; then
    SLURMCTLD_RUNNING="true"
    CTLD_HOST=$(scontrol ping 2>/dev/null | grep -m1 'UP' | sed -E 's/.* at ([^ ]+) .*/\1/')
    print_info "slurmctld: Running (reachable via scontrol ping${CTLD_HOST:+ at ${CTLD_HOST}}; controller on a separate node/pod)"
else
    print_warn "slurmctld: Not running here and not reachable via scontrol ping"
fi

# slurmd is a compute-node daemon; its absence on the head/login node is normal.
[[ "$SLURMD_RUNNING" == "true" ]] && print_info "slurmd: Running" || print_detail "slurmd: Not running (head node may not be compute)"

# slurmdbd: local process, else reachable via accounting; only warn when
# accounting_storage/slurmdbd is configured but the daemon cannot be reached.
DBD_CONFIGURED=$(echo "$SLURM_CONFIG_FULL" | grep -i "AccountingStorageType" | grep -qi "slurmdbd" && echo "true" || echo "false")
if [[ "$SLURMDBD_RUNNING" == "true" ]]; then
    print_info "slurmdbd: Running (local process)"
elif command -v sacctmgr &>/dev/null && sacctmgr ping 2>/dev/null | grep -q 'UP'; then
    SLURMDBD_RUNNING="true"
    print_info "slurmdbd: Running (reachable via sacctmgr ping; on a separate node/pod)"
elif [[ "$DBD_CONFIGURED" == "true" ]] && command -v sacctmgr &>/dev/null && sacctmgr -n show cluster &>/dev/null; then
    SLURMDBD_RUNNING="true"
    print_info "slurmdbd: Running (accounting reachable via sacctmgr; on a separate node/pod)"
elif [[ "$DBD_CONFIGURED" == "true" ]]; then
    print_warn "slurmdbd: Configured (accounting_storage/slurmdbd) but not reachable"
else
    print_detail "slurmdbd: Not configured (no accounting_storage/slurmdbd)"
fi

# Server geolocation - determine physical location of cluster
print_section "Server Location"
GEO_REGION=""
GEO_CITY=""
GEO_COUNTRY=""
GEO_IP=""
GEO_ORG=""
GEO_LOC=""

# Try ipinfo.io for external IP + geolocation (10s timeout)
GEO_JSON=$(curl -sf --max-time 10 "https://ipinfo.io/json" 2>/dev/null || echo "{}")

if echo "$GEO_JSON" | jq -e '.ip' &>/dev/null; then
    GEO_IP=$(echo "$GEO_JSON" | jq -r '.ip // ""')
    GEO_CITY=$(echo "$GEO_JSON" | jq -r '.city // ""')
    GEO_COUNTRY=$(echo "$GEO_JSON" | jq -r '.country // ""')
    GEO_REGION=$(echo "$GEO_JSON" | jq -r '.region // ""')
    GEO_ORG=$(echo "$GEO_JSON" | jq -r '.org // ""')
    GEO_LOC=$(echo "$GEO_JSON" | jq -r '.loc // ""')  # lat,lon
    print_info "External IP: ${GEO_IP}"
    print_info "Location: ${GEO_CITY}, ${GEO_REGION}, ${GEO_COUNTRY}"
    print_info "ISP/Org: ${GEO_ORG}"
    [[ -n "$GEO_LOC" ]] && print_detail "Coordinates: ${GEO_LOC}"
else
    print_warn "Could not determine server location (no egress or API unreachable)"
fi

# =============================================================================
# SECTION 2: Node Inventory
# =============================================================================
print_header "2. NODE INVENTORY"

# Get node information - use scontrol if available, else parse snodes + slurm.conf
NODES_JSON="[]"
TOTAL_NODES=0; IDLE_NODES=0; ALLOCATED_NODES=0; DOWN_NODES=0; TOTAL_CPUS=0; TOTAL_MEMORY_GB=0
POWERED_DOWN_NODES=0
GPU_NODE_COUNT=0; GPUS_PER_NODE=0; GPU_TOTAL_CPUS=0; GPU_TOTAL_MEMORY_GB=0
GPU_INVENTORY_TOTAL=0

if [[ "$SCONTROL_OK" == "true" ]]; then
    NODES_JSON=$(scontrol show nodes -o 2>/dev/null | while read -r line; do
        node_name=$(echo "$line" | grep -oP 'NodeName=\K[^ ]+')
        state=$(echo "$line" | grep -oP 'State=\K[^ ]+')
        cpus=$(echo "$line" | grep -oP 'CPUTot=\K[0-9]+')
        memory=$(echo "$line" | grep -oP 'RealMemory=\K[0-9]+')
        # Match Gres=gpu:N or Gres=gpu:type:N (with optional type tag), capture trailing count.
        # Old regex `Gres=gpu[^,]*:([0-9]+)` was greedy - it walked past slurm timestamps
        # like LastBusyTime=...T05:44:08 and captured the wrong digits.
        gpus=$(echo "$line" | grep -oP 'Gres=gpu(?::[A-Za-z0-9_.-]+)?:\K[0-9]+' | head -1)
        [[ -z "$gpus" ]] && gpus="0"
        echo "{\"name\":\"$node_name\",\"state\":\"$state\",\"cpus\":$cpus,\"memory\":$memory,\"gpus\":$gpus}"
    done | jq -s '.')
    # Count states with exact token matching. A substring test on "DOWN" also
    # matches the POWERED_DOWN / POWERING_DOWN power-save flags, which made
    # idle cloud nodes report as down or drained.
    NODE_STATE_SUMMARY=$(count_slurm_node_states "$NODES_JSON" 2>/dev/null || echo "{}")
    TOTAL_NODES=$(echo "$NODE_STATE_SUMMARY" | jq -r '.total // 0')
    IDLE_NODES=$(echo "$NODE_STATE_SUMMARY" | jq -r '.idle // 0')
    ALLOCATED_NODES=$(echo "$NODE_STATE_SUMMARY" | jq -r '.allocated // 0')
    DOWN_NODES=$(echo "$NODE_STATE_SUMMARY" | jq -r '.downDrained // 0')
    POWERED_DOWN_NODES=$(echo "$NODE_STATE_SUMMARY" | jq -r '.poweredDown // 0')
    TOTAL_CPUS=$(echo "$NODES_JSON" | jq '[.[].cpus] | add // 0')
    TOTAL_MEMORY_GB=$(echo "$NODES_JSON" | jq '([.[].memory] | add // 0) / 1024 | floor')
    GPU_NODE_SUMMARY=$(summarize_gpu_nodes "$NODES_JSON" 2>/dev/null || echo "{}")
    GPU_NODE_COUNT=$(echo "$GPU_NODE_SUMMARY" | jq -r '.nodeCount // 0')
    GPUS_PER_NODE=$(echo "$GPU_NODE_SUMMARY" | jq -r '.perNode // 0')
    GPU_INVENTORY_TOTAL=$(echo "$GPU_NODE_SUMMARY" | jq -r '.totalGpus // 0')
    GPU_TOTAL_CPUS=$(echo "$GPU_NODE_SUMMARY" | jq -r '.totalCpus // 0')
    GPU_TOTAL_MEMORY_GB=$(echo "$GPU_NODE_SUMMARY" | jq -r '.totalMemoryGB // 0')
else
    # Use sudo snodes wrapper output
    SNODES_OUT=$(sudo -n /usr/local/bin/snodes 2>/dev/null || echo "")
    if [[ -n "$SNODES_OUT" ]]; then
        # Strip the sinfo state suffix before the comparison. "idle~" is a
        # power-saved idle node, not a down node.
        SNODES_SUMMARY=$(count_snodes_states "$SNODES_OUT" 2>/dev/null || echo "{}")
        TOTAL_NODES=$(echo "$SNODES_SUMMARY" | jq -r '.total // 0')
        IDLE_NODES=$(echo "$SNODES_SUMMARY" | jq -r '.idle // 0')
        ALLOCATED_NODES=$(echo "$SNODES_SUMMARY" | jq -r '.allocated // 0')
        DOWN_NODES=$(echo "$SNODES_SUMMARY" | jq -r '.downDrained // 0')
        NODES_JSON=$(echo "$SNODES_OUT" | tail -n +2 | awk '{print "{\"name\":\""$6"\",\"state\":\""$5"\",\"cpus\":0,\"memory\":0,\"gpus\":0}"}' | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

print_section "Node Summary"
print_info "Total Nodes: ${TOTAL_NODES}"
print_info "Idle: ${IDLE_NODES}"
print_info "Allocated: ${ALLOCATED_NODES}"
[[ "$DOWN_NODES" -gt 0 ]] && print_warn "Down/Drained: ${DOWN_NODES}" || print_info "Down/Drained: ${DOWN_NODES}"
[[ "$POWERED_DOWN_NODES" -gt 0 ]] && print_info "Powered Down (cloud power save): ${POWERED_DOWN_NODES}"
[[ "$TOTAL_CPUS" -gt 0 ]] && print_info "Total CPUs: ${TOTAL_CPUS}"
[[ "$TOTAL_MEMORY_GB" -gt 0 ]] && print_info "Total Memory: ${TOTAL_MEMORY_GB} GB"
if [[ "$GPU_NODE_COUNT" -gt 0 && "$GPU_NODE_COUNT" -ne "$TOTAL_NODES" ]]; then
    print_info "GPU Nodes: ${GPU_NODE_COUNT}"
fi

# Partition information
print_section "Partitions"
PARTITIONS_JSON="[]"
DEFAULT_PARTITION="none"

if [[ "$SCONTROL_OK" == "true" ]]; then
    PARTITIONS_JSON=$(scontrol show partition -o 2>/dev/null | while read -r line; do
        part_name=$(echo "$line" | grep -oP 'PartitionName=\K[^ ]+')
        state=$(echo "$line" | grep -oP 'State=\K[^ ]+')
        nodes=$(echo "$line" | grep -oP 'TotalNodes=\K[0-9]+')
        default=$(echo "$line" | grep -oP 'Default=\K[^ ]+')
        max_time=$(echo "$line" | grep -oP 'MaxTime=\K[^ ]+')
        echo "{\"name\":\"$part_name\",\"state\":\"$state\",\"nodes\":$nodes,\"default\":\"$default\",\"maxTime\":\"$max_time\"}"
    done | jq -s '.')
    echo "$PARTITIONS_JSON" | jq -r '.[] | "\(.name)|\(.state)|\(.nodes)|\(.default)|\(.maxTime)"' | while IFS='|' read -r name state nodes default max_time; do
        [[ "$default" == "YES" ]] && print_info "${name} (DEFAULT): ${nodes} nodes, max ${max_time}" || print_info "${name}: ${nodes} nodes, max ${max_time}"
    done
    DEFAULT_PARTITION=$(echo "$PARTITIONS_JSON" | jq -r '.[] | select(.default=="YES") | .name' | head -1)
    DEFAULT_PARTITION=${DEFAULT_PARTITION:-"none"}
else
    # Parse PartitionName lines from slurm.conf
    while IFS= read -r pline; do
        part=$(echo "$pline" | grep -oP 'PartitionName=\K\S+')
        [[ -z "$part" ]] && continue
        def=$(echo "$pline" | grep -oP 'Default=\K\S+' || echo "NO")
        maxtime=$(echo "$pline" | grep -oP 'MaxTime=\K\S+' || echo "INFINITE")
        print_info "${part}: maxTime=${maxtime} default=${def}"
        PARTITIONS_JSON=$(echo "$PARTITIONS_JSON" | jq ". + [{\"name\":\"$part\",\"state\":\"UP\",\"nodes\":0,\"default\":\"$def\",\"maxTime\":\"$maxtime\"}]")
        [[ "$def" == "YES" ]] && DEFAULT_PARTITION="$part"
    done < <(grep "^PartitionName=" "$SLURM_CONF_FILE" 2>/dev/null || \
             grep -r "^PartitionName=" /etc/slurm/ 2>/dev/null)
    # Also show snodes partition list
    sudo -n /usr/local/bin/snodes 2>/dev/null | tail -n +2 | awk '{print $1}' | sort -u | while read -r p; do
        print_detail "  snodes partition: ${p}"
    done
fi

# Identify a partition whose nodes all advertise GPU GRES. Broad partitions
# such as "all" may contain both CPU and GPU nodes; selecting the first row
# containing "gpu" can therefore send no-GRES checks to CPU-only nodes.
GPU_PARTITION="${CLUSTERMAX_GPU_PARTITION:-${GPU_PARTITION:-}}"
GPU_PARTITION_SOURCE="override"
SINFO_NODE_PARTITION_ROWS=""
if [[ -z "$GPU_PARTITION" && "$SINFO_OK" == "true" ]]; then
    SINFO_NODE_PARTITION_ROWS=$(sinfo -N -o "%P|%N|%G" --noheader 2>/dev/null || echo "")
    GPU_PARTITION=$(select_gpu_partition "$SINFO_NODE_PARTITION_ROWS")
    GPU_PARTITION_SOURCE="sinfo"
fi
if [[ -z "$GPU_PARTITION" && -n "${SLURM_JOB_PARTITION:-}" ]]; then
    GPU_PARTITION="$SLURM_JOB_PARTITION"
    GPU_PARTITION_SOURCE="allocation"
fi
if [[ -z "$GPU_PARTITION" ]]; then
    # From snodes: look for partition with GB3 nodes (B300) or GPU in name
    GPU_PARTITION=$(sudo -n /usr/local/bin/snodes 2>/dev/null | tail -n +2 | awk '{print $1}' | grep -i "gpu\|b3\|gb3\|group" | sed 's/\*//' | head -1 || echo "")
    GPU_PARTITION_SOURCE="snodes"
fi
if [[ -n "$GPU_PARTITION" ]]; then
    print_info "GPU Partition (${GPU_PARTITION_SOURCE}): ${GPU_PARTITION}"
else
    print_warn "GPU Partition: none detected"
fi

# A nested srun step is already constrained to its parent allocation. Passing
# another partition can conflict when the allocation was obtained through a
# broad partition such as "all", so only add -p when launching without one.
GPU_SRUN_SCOPE_ARGS=()
if [[ -z "${SLURM_JOB_ID:-}" && -n "$GPU_PARTITION" ]]; then
    GPU_SRUN_SCOPE_ARGS=(-p "$GPU_PARTITION")
fi

# =============================================================================
# SECTION 2.5: WORKER NODE CHECK
# Run a single srun job to collect all GPU/IB/software facts from a compute node.
# Everything that depends on the actual hardware (GPU, IB HCAs, DCGM) must come
# from here - the head/login node typically has no GPU and a management NIC only.
# =============================================================================
print_header "2.5. WORKER NODE CHECK (via srun)"

WORKER_CHECK_OK="false"
WORKER_HOSTNAME="none"

# Initialize all worker variables to "unknown" so later sections degrade cleanly
WORKER_GPU_MODEL="unknown"
WORKER_DRIVER_VERSION="unknown"
WORKER_CUDA_VERSION="unknown"
WORKER_GPU_MEMORY="0"
WORKER_GPU_COUNT="0"
WORKER_PEERMEM="false"
WORKER_PEERMEM_LEGACY="false"
WORKER_NVIDIA_OPEN="false"
WORKER_NVIDIA_DMABUF="false"
WORKER_AMD_PEERMEM_LEGACY="unknown"
WORKER_AMD_DMABUF="unknown"
WORKER_GDRCOPY_LIB="not-found"
WORKER_GDRCOPY_GDRDRV="false"
WORKER_GDRCOPY_DEV="false"
# PCIe ACS (Access Control Services). ACS ON for a switch on the GPU<->backend-NIC
# path forces P2P traffic through the CPU root complex and breaks GPUDirect RDMA,
# slowing NCCL/RCCL collectives. We only care about the switches attached to the
# backend NICs and GPUs - ACS on unrelated bridges is fine. host-check.sh scopes
# this to the shared GPU<->NIC PCIe switches; the fields below are path-scoped.
WORKER_ACS_CHECK_OK="false"
WORKER_ACS_SUPPORTED="false"
WORKER_ACS_BRIDGES="0"
WORKER_ACS_ENABLED_COUNT="0"
WORKER_ACS_ENABLED="unknown"
WORKER_ACS_TOTAL_BRIDGES="0"
WORKER_ACS_SCOPED="false"
WORKER_AMD_GPU_MODEL=""
WORKER_AMD_DRIVER_VERSION=""
WORKER_AMD_GPU_COUNT="0"
WORKER_ROCM_SMI_PATH=""
WORKER_AMD_SMI_PATH=""
WORKER_AMD_SMI_VERSION=""
WORKER_ROCM_VERSION=""
WORKER_ROCM_CT_PATH=""
WORKER_GPU_IDLE_TEMP_MAX="unknown"
WORKER_GPU_IDLE_POWER_MAX="unknown"
WORKER_DMESG_XIDS_COUNT="unknown"
WORKER_DMESG_XID_LAST="unknown"
WORKER_DMESG_AMDGPU_ERRORS_COUNT="unknown"
WORKER_NCCL_GID_INDEX="unset"
WORKER_NCU_PATH=""
WORKER_NCU_VERSION="unknown"
WORKER_NCU_COUNTER_ACCESS="unknown"
WORKER_PERF_PATH=""
WORKER_PERF_EVENT_PARANOID="unknown"
WORKER_KPTR_RESTRICT="unknown"
WORKER_PERF_STAT_ACCESS="unknown"
WORKER_PERF_TOP_ACCESS="unknown"
WORKER_NVCC_PATH=""
WORKER_NVCC_VERSION="unknown"
WORKER_MPIRUN_PATH=""
WORKER_MPIRUN_VERSION="unknown"
WORKER_HPCX_DETECTED="false"
WORKER_NCCL_LIB=""
WORKER_NCCL_VERSION="unknown"
WORKER_NCCL_CONF_OVERRIDES="false"
WORKER_DCGM_ACTIVE="false"
WORKER_DCGM_VERSION="unknown"
WORKER_DCGM_HEALTH_OK="false"
WORKER_HEALTH_PROGRAM_DCGM="false"
WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE="none"
WORKER_NHC_INSTALLED="false"
WORKER_NHC_PATH="none"
WORKER_NHC_CONF_CHECKS="0"
WORKER_IB_DEVICES=""
WORKER_IBHOSTS_COUNT="0"
WORKER_IBHOSTS_SAMPLE=""
# Storage / drive config (collected by check, parsed after)
WORKER_BOOT_DEVICE="unknown"
WORKER_BOOT_FSTYPE="unknown"
WORKER_BOOT_SIZE="unknown"
WORKER_NVME_DEVICES=""
WORKER_NVME_COUNT="0"
WORKER_NVME_TOTAL_GB="0"

if [[ -n "$GPU_PARTITION" ]]; then
    print_section "Checking compute node via srun (partition: ${GPU_PARTITION})"
    print_detail "Running single srun job to gather GPU, IB, and software facts..."

    # Deliver the check to the worker over srun's stdin (bash -s), reading it
    # from the login node. Staging to a file under $HOME assumed a shared
    # filesystem mounted on every compute node; that does not hold on
    # Slurm-on-Kubernetes, where each node is a pod with its own ephemeral
    # overlay (the login pod's $HOME is not the worker's). host-check.sh is
    # self-contained for exactly this delivery, and the K8s audit ships it the
    # same way (cluster-audit-k8s.sh: `bash -s < host-check.sh`).
    #
    # Requesting GPU GRES is mandatory: without it, mixed partitions can place
    # this hardware check on a CPU-only node.
    WORKER_CHECK_OUTPUT=$(srun "${AUDIT_SRUN_FLAGS[@]}" \
        "${GPU_SRUN_SCOPE_ARGS[@]}" \
        -N1 --ntasks=1 \
        --gres=gpu:1 \
        --time=5:00 \
        bash -s < "$WORKLOAD_DIR/host-check.sh" 2>/dev/null || echo "SRUN_FAILED")
    if [[ -z "$WORKER_CHECK_OUTPUT" || ! "$WORKER_CHECK_OUTPUT" =~ WORKER_HOSTNAME ]]; then
        WORKER_CHECK_OUTPUT="SRUN_FAILED"
    fi

    if [[ "$WORKER_CHECK_OUTPUT" == "SRUN_FAILED" || -z "$WORKER_CHECK_OUTPUT" ]]; then
        print_warn "srun check failed (no idle nodes, partition inaccessible, or timeout)"
        print_detail "GPU, IB, and DCGM checks will fall back to head-node values (may be inaccurate)"
    else
        WORKER_CHECK_OK="true"
        # Parse all KEY=VALUE lines from check output
        while IFS='=' read -r key val; do
            [[ -z "$key" || "$key" =~ ^# ]] && continue
            # Only accept lines that look like our check variables
            if [[ "$key" =~ ^WORKER_[A-Za-z0-9_]*$ ]]; then
                printf -v "$key" '%s' "$val"
            fi
        done < <(echo "$WORKER_CHECK_OUTPUT" | grep '^WORKER_')

        print_info "Worker check: SUCCESS (node: ${WORKER_HOSTNAME})"
        print_info "GPU model: ${WORKER_GPU_MODEL}"
        print_info "Driver: ${WORKER_DRIVER_VERSION} / CUDA cap: ${WORKER_CUDA_VERSION}"
        print_info "IB devices: ${WORKER_IB_DEVICES:-none}"
        print_info "DCGM active: ${WORKER_DCGM_ACTIVE}"
        print_info "NVMe drives: ${WORKER_NVME_COUNT} (${WORKER_NVME_TOTAL_GB} GB)"
        print_info "Boot device: ${WORKER_BOOT_DEVICE} (${WORKER_BOOT_FSTYPE})"
    fi
else
    print_warn "No GPU partition detected - skipping worker node check"
    print_detail "Set CLUSTERMAX_GPU_PARTITION or ensure GPU nodes advertise GRES"
fi

# Build worker drive config JSON from parsed check variables.
# WORKER_BLKDEV_* and WORKER_SHAREDMNT_*/WORKER_MNTDF_* are dynamic keys
# that were set by printf -v in the parsing loop above.
WORKER_BLKDEV_JSON="["
WORKER_BLKDEV_FIRST="true"
while IFS='=' read -r key val; do
    [[ "$key" =~ ^WORKER_BLKDEV_ ]] || continue
    devname="${key#WORKER_BLKDEV_}"
    IFS='|' read -r btype bsize bmp bfs btran <<< "$val"
    # Classify
    classification="other"
    case "$devname" in
        nvme*) classification="local-nvme" ;;
        sd*)   classification="local-sata" ;;
        vd*|xvd*) classification="virtual-disk" ;;
    esac
    [[ "$bmp" == "/" || "$bmp" == "/boot" || "$bmp" == "/boot/efi" ]] && classification="boot"
    # Transport fallback
    transport="${btran}"
    [[ -z "$transport" ]] && case "$devname" in nvme*) transport="nvme";; sd*) transport="sata";; vd*) transport="virtio";; *) transport="unknown";; esac
    size_human=""
    if command -v numfmt &>/dev/null && [[ -n "$bsize" && "$bsize" != "0" ]]; then
        size_human=$(numfmt --to=iec --suffix=B "$bsize" 2>/dev/null || echo "${bsize}")
    else
        size_human="${bsize}"
    fi
    [[ "$WORKER_BLKDEV_FIRST" == "true" ]] && WORKER_BLKDEV_FIRST="false" || WORKER_BLKDEV_JSON+=","
    WORKER_BLKDEV_JSON+="{\"name\":\"${devname}\",\"type\":\"${btype}\",\"size\":\"${size_human}\",\"sizeBytes\":${bsize:-0},\"transport\":\"${transport}\",\"mountpoint\":\"${bmp}\",\"fstype\":\"${bfs}\",\"classification\":\"${classification}\"}"
done < <(echo "$WORKER_CHECK_OUTPUT" | grep '^WORKER_BLKDEV_' 2>/dev/null || true)
WORKER_BLKDEV_JSON+="]"

# Worker shared mounts JSON
WORKER_SHARED_MOUNTS_JSON="["
WORKER_SMNT_FIRST="true"
while IFS='=' read -r key val; do
    [[ "$key" =~ ^WORKER_SHAREDMNT_ ]] || continue
    safe_target="${key#WORKER_SHAREDMNT_}"
    IFS='|' read -r target src fstype opts <<< "$val"
    # Look for matching df data
    df_size="" df_used="" df_avail=""
    df_key="WORKER_MNTDF_${safe_target}"
    df_val=""
    if [[ "$df_key" =~ ^WORKER_[A-Za-z0-9_]*$ ]]; then
        df_val="${!df_key:-}"
    fi
    if [[ -n "$df_val" ]]; then
        IFS='|' read -r _dfs df_size df_used df_avail <<< "$df_val"
    fi
    [[ "$WORKER_SMNT_FIRST" == "true" ]] && WORKER_SMNT_FIRST="false" || WORKER_SHARED_MOUNTS_JSON+=","
    WORKER_SHARED_MOUNTS_JSON+="{\"mountpoint\":\"${target}\",\"fstype\":\"${fstype}\",\"source\":\"${src}\",\"size\":\"${df_size}\",\"used\":\"${df_used}\",\"available\":\"${df_avail}\",\"options\":\"${opts}\"}"
done < <(echo "$WORKER_CHECK_OUTPUT" | grep '^WORKER_SHAREDMNT_' 2>/dev/null || true)
# Also add any MNTDF entries that were not captured by findmnt (well-known paths)
while IFS='=' read -r key val; do
    [[ "$key" =~ ^WORKER_MNTDF_ ]] || continue
    safe_target="${key#WORKER_MNTDF_}"
    # Skip if already captured via SHAREDMNT
    echo "$WORKER_CHECK_OUTPUT" | grep -q "^WORKER_SHAREDMNT_${safe_target}=" 2>/dev/null && continue
    target=$(echo "$safe_target" | sed 's/^_*/\//;s/_/\//g')
    IFS='|' read -r fstype df_size df_used df_avail <<< "$val"
    # Only include if it looks like a shared filesystem
    case "$fstype" in
        nfs|nfs4|lustre|gpfs|wekafs|cephfs|glusterfs|beegfs|panfs|fuse.weka|fuse.lustre|fuse.ceph) ;;
        *) continue ;;
    esac
    [[ "$WORKER_SMNT_FIRST" == "true" ]] && WORKER_SMNT_FIRST="false" || WORKER_SHARED_MOUNTS_JSON+=","
    WORKER_SHARED_MOUNTS_JSON+="{\"mountpoint\":\"${target}\",\"fstype\":\"${fstype}\",\"source\":\"\",\"size\":\"${df_size}\",\"used\":\"${df_used}\",\"available\":\"${df_avail}\",\"options\":\"\"}"
done < <(echo "$WORKER_CHECK_OUTPUT" | grep '^WORKER_MNTDF_' 2>/dev/null || true)
WORKER_SHARED_MOUNTS_JSON+="]"

# Worker NVMe devices JSON array
WORKER_NVME_DEVS_JSON="["
if [[ -n "$WORKER_NVME_DEVICES" ]]; then
    NVME_FIRST="true"
    IFS=',' read -ra NVME_ARR <<< "$WORKER_NVME_DEVICES"
    for d in "${NVME_ARR[@]}"; do
        [[ -z "$d" ]] && continue
        [[ "$NVME_FIRST" == "true" ]] && NVME_FIRST="false" || WORKER_NVME_DEVS_JSON+=","
        WORKER_NVME_DEVS_JSON+="\"${d}\""
    done
fi
WORKER_NVME_DEVS_JSON+="]"

# =============================================================================
# SECTION 3: GPU Configuration
# =============================================================================
print_header "3. GPU CONFIGURATION"

# Compute node OS / image. The "image management" criterion covers offering
# Ubuntu, RHEL, Rocky, etc.; this records what's actually on the worker.
print_section "Compute Node OS / Image"
WORKER_OS_ID_VAL="${WORKER_OS_ID:-unknown}"
WORKER_OS_VERSION_VAL="${WORKER_OS_VERSION_ID:-unknown}"
WORKER_OS_PRETTY_VAL="${WORKER_OS_PRETTY_NAME:-unknown}"
WORKER_KERNEL_VAL="${WORKER_KERNEL:-unknown}"
WORKER_ARCH_VAL="${WORKER_ARCH:-unknown}"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    print_info "OS: ${WORKER_OS_PRETTY_VAL}"
    print_detail "ID=${WORKER_OS_ID_VAL}, Version=${WORKER_OS_VERSION_VAL}, Kernel=${WORKER_KERNEL_VAL}, Architecture=${WORKER_ARCH_VAL}"
    case "$WORKER_OS_ID_VAL" in
        ubuntu|debian|rhel|rocky|almalinux|centos|sles|opensuse-leap|opensuse-tumbleweed|amzn|ol)
            print_info "OS family supported (mainstream Linux distribution)"
            ;;
        unknown)
            print_warn "OS family unrecognized (could not parse /etc/os-release)"
            ;;
        *)
            print_warn "OS family ${WORKER_OS_ID_VAL} is non-standard - check provider image catalog"
            ;;
    esac
else
    # Head-node fallback
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        WORKER_OS_ID_VAL="${ID:-unknown}"
        WORKER_OS_VERSION_VAL="${VERSION_ID:-unknown}"
        WORKER_OS_PRETTY_VAL="${PRETTY_NAME:-unknown}"
        WORKER_KERNEL_VAL="$(uname -r 2>/dev/null || echo unknown)"
    fi
    print_warn "Compute node OS unknown (worker check unavailable; reporting head node OS)"
    print_detail "OS: ${WORKER_OS_PRETTY_VAL}, Kernel: ${WORKER_KERNEL_VAL}, Compute architecture: unknown"
fi

# Compute node CPU inventory (check-collected). Surfaces OEM-configurable
# facts: the RAPL package power limit (cTDP) and the frequency ceiling.
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    print_section "Compute Node CPU"
    print_info "CPU: ${WORKER_CPU_MODEL:-unknown}"
    print_detail "Sockets=${WORKER_CPU_SOCKETS:-unknown}, Cores/socket=${WORKER_CPU_CORES_PER_SOCKET:-unknown}, Threads=${WORKER_CPU_THREADS:-unknown} (${WORKER_CPU_THREADS_PER_CORE:-unknown} per core)"
    print_detail "Clocks MHz: base=${WORKER_CPU_BASE_MHZ:-unknown}, max=${WORKER_CPU_MAX_MHZ:-unknown}, current=${WORKER_CPU_CUR_MHZ:-unknown}; governors=${WORKER_CPU_GOVERNOR:-unknown}"
    print_detail "RAPL package power limit W=${WORKER_CPU_PACKAGE_POWER_LIMIT_W:-unknown} (packages=${WORKER_CPU_RAPL_PACKAGES:-unknown})"
    print_detail "Memory: DIMMs=${WORKER_MEM_DIMMS:-unknown} x ${WORKER_MEM_DIMM_SIZES_GB:-unknown}GB ${WORKER_MEM_TYPES:-unknown}, MT/s rated=${WORKER_MEM_RATED_SPEED_MTS:-unknown} configured=${WORKER_MEM_CONFIGURED_SPEED_MTS:-unknown} (${WORKER_MEM_SOURCE:-unknown})"
    print_detail "Memory BW GB/s: per socket=${WORKER_MEM_BW_PER_SOCKET_GBS:-unknown}, per logical core=${WORKER_MEM_BW_PER_CORE_GBS:-unknown}"
fi

# GPU totals from SLURM GRES. Prefer scontrol's per-node Gres counts.
# Mixed clusters may include CPU-only nodes, so GPU node count and per-node
# shape must come from the GRES-bearing subset rather than TOTAL_NODES.
# The worker check requests one GPU to obtain hardware facts, so a count of
# one from that check is not node inventory. HGX-style nodes default to eight
# GPUs; set CLUSTERMAX_GPUS_PER_NODE for clusters with another node shape.
TOTAL_GPUS="$GPU_INVENTORY_TOTAL"
DEFAULT_GPUS_PER_NODE="${CLUSTERMAX_GPUS_PER_NODE:-8}"
if [[ "$TOTAL_GPUS" -eq 0 && "$SINFO_OK" == "true" ]]; then
    # sinfo -N prints one row per node and partition, so a node in several
    # partitions is counted once per partition; dedupe on node name (this
    # doubled oracle-gb300, whose nodes sit in two partitions). Capture the
    # count right after gpu[:type]: the pattern must stop there and not walk
    # into socket-affinity suffixes such as gpu:B300:4(S:0-1) - the old
    # greedy `gpu[^,]*:` parse read the socket index, reporting 0 GPUs on
    # every node.
    SINFO_GPU_ROWS=$(sinfo -N -o "%N %G" --noheader 2>/dev/null | awk '!seen[$1]++')
    TOTAL_GPUS=$(echo "$SINFO_GPU_ROWS" | grep -oP 'gpu(?::[A-Za-z0-9_.-]+)?:\K[0-9]+' | paste -sd+ | bc 2>/dev/null || echo "0")
    if [[ "$GPU_NODE_COUNT" -eq 0 ]]; then
        GPU_NODE_COUNT=$(echo "$SINFO_GPU_ROWS" | grep -cP 'gpu(?::[A-Za-z0-9_.-]+)?:[0-9]+' || true)
    fi
elif [[ "$TOTAL_GPUS" -eq 0 ]]; then
    # Count GPUs from gres.conf
    TOTAL_GPUS=$(grep -h "^Name=gpu" /etc/slurm/gres.conf /etc/slurm/*.conf 2>/dev/null | grep -oP 'Count=\K[0-9]+' | paste -sd+ | bc 2>/dev/null || echo "0")
fi
[[ -z "$TOTAL_GPUS" || "$TOTAL_GPUS" == "" ]] && TOTAL_GPUS=0
if [[ "$GPUS_PER_NODE" -eq 0 && "$TOTAL_GPUS" -gt 0 && "$GPU_NODE_COUNT" -gt 0 ]]; then
    GPUS_PER_NODE=$(( TOTAL_GPUS / GPU_NODE_COUNT ))
fi

# Use worker check values (authoritative); fall back to head-node nvidia-smi only if check unavailable
GPU_MODEL="unknown"
DRIVER_VERSION="unknown"
SECURITY_DRIVER_VERSION="unknown"
CUDA_VERSION="unknown"
GPU_MEMORY="0"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    GPU_MODEL="$WORKER_GPU_MODEL"
    DRIVER_VERSION="$WORKER_DRIVER_VERSION"
    SECURITY_DRIVER_VERSION="$WORKER_DRIVER_VERSION"
    CUDA_VERSION="$WORKER_CUDA_VERSION"
    GPU_MEMORY="$WORKER_GPU_MEMORY"
    # The check may expose all devices if it ran without a GPU allocation.
    # Otherwise its single visible GPU is constrained by --gres=gpu:1.
    if [[ "$TOTAL_GPUS" -eq 0 && -n "$WORKER_GPU_COUNT" && "$WORKER_GPU_COUNT" -gt 1 ]]; then
        ESTIMATED_GPU_NODES="$TOTAL_NODES"
        [[ "$GPU_NODE_COUNT" -gt 0 ]] && ESTIMATED_GPU_NODES="$GPU_NODE_COUNT"
        GPUS_PER_NODE="$WORKER_GPU_COUNT"
        TOTAL_GPUS=$(( WORKER_GPU_COUNT * ESTIMATED_GPU_NODES ))
        print_detail "(GPU count estimated from check: ${WORKER_GPU_COUNT}/node × ${ESTIMATED_GPU_NODES} nodes)"
    elif [[ "$TOTAL_GPUS" -eq 0 && -n "$WORKER_GPU_COUNT" && "$WORKER_GPU_COUNT" -gt 0 ]]; then
        ESTIMATED_GPU_NODES="$TOTAL_NODES"
        [[ "$GPU_NODE_COUNT" -gt 0 ]] && ESTIMATED_GPU_NODES="$GPU_NODE_COUNT"
        GPUS_PER_NODE="$DEFAULT_GPUS_PER_NODE"
        TOTAL_GPUS=$(( DEFAULT_GPUS_PER_NODE * ESTIMATED_GPU_NODES ))
        print_detail "(GPU count defaulted: ${DEFAULT_GPUS_PER_NODE}/node × ${ESTIMATED_GPU_NODES} nodes; single-GPU check has constrained visibility)"
    fi
    print_section "GPU Inventory (from compute node: ${WORKER_HOSTNAME})"
else
    # Head-node fallback - warn that this may not reflect compute nodes
    print_section "GPU Inventory (HEAD NODE FALLBACK - check unavailable)"
    if command -v nvidia-smi &> /dev/null; then
        GPU_MODEL=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | tr ' ' '-' || echo "unknown")
        DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo "unknown")
        CUDA_VERSION=$(nvidia-smi 2>/dev/null | grep -oP 'CUDA Version: \K[0-9.]+' || echo "unknown")
        GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "0")
        print_warn "nvidia-smi ran on HEAD NODE - values may not reflect compute nodes"
    else
        print_warn "nvidia-smi: Not available on head node and worker check failed"
    fi
fi

if [[ "$TOTAL_GPUS" -gt 0 ]]; then
    print_info "Total GPUs (SLURM GRES): ${TOTAL_GPUS}"
    print_info "Model: ${GPU_MODEL}"
    print_info "Memory: ${GPU_MEMORY:-unknown} MB"
    print_info "Driver: ${DRIVER_VERSION}"
    print_info "CUDA cap: ${CUDA_VERSION}"
else
    print_warn "No GPUs detected in SLURM GRES configuration"
fi

# Check GPUDirect RDMA - must come from worker node.
#
# Only the dma_buf path PASSES. dma_buf is the Linus Torvalds-blessed
# upstream Linux interface, shipped natively in the nvidia-open kernel
# module (default on driver 565+ open builds) and what NVIDIA currently
# recommends.
#
# The legacy out-of-tree nvidia_peermem module has been moved to
# deprecated mode by NVIDIA. A cluster running ONLY nvidia_peermem is
# behind the recommended config and should be flagged: GPUDirect RDMA is
# functional today, but on the deprecated path. Treat as FAIL with a
# clear "deprecated path, migrate to nvidia-open" note.
#
# Result categories:
#   PASS  - dma_buf detected (with or without nvidia_peermem also loaded)
#   FAIL  - only nvidia_peermem detected (legacy / deprecated)
#   FAIL  - neither path detected (totally missing)
print_section "GPUDirect RDMA"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ "$WORKER_NVIDIA_DMABUF" == "true" || "$WORKER_NVIDIA_OPEN" == "true" ]]; then
        if [[ "$WORKER_NVIDIA_DMABUF" == "true" ]]; then
            print_info "GPUDirect RDMA: dma_buf path detected (nvidia driver exports dma_buf, recommended)"
        else
            print_info "GPUDirect RDMA: nvidia-open kernel module detected (dma_buf path expected)"
        fi
        if [[ "$WORKER_PEERMEM_LEGACY" == "true" ]]; then
            print_detail "nvidia_peermem also loaded but not required - dma_buf supersedes it"
        fi
        GPUDIRECT_RDMA="true"
    elif [[ "$WORKER_PEERMEM_LEGACY" == "true" ]]; then
        print_error "GPUDirect RDMA: only nvidia_peermem detected (legacy path)"
        print_detail "nvidia_peermem is deprecated by NVIDIA. The dma_buf path (nvidia-open kernel module, upstream Linux) is the recommended replacement."
        print_detail "RDMA may still function via the legacy module today, but this cluster is behind the recommended config."
        print_detail "Fix: install nvidia-open driver (driver 565+); dma_buf is built-in."
        GPUDIRECT_RDMA="false"
    else
        print_error "GPUDirect RDMA: not enabled on compute node (totally missing)"
        print_detail "Neither dma_buf (nvidia-open) nor nvidia_peermem detected."
        print_detail "Fix: install nvidia-open driver (driver 565+); dma_buf is built-in."
        GPUDIRECT_RDMA="false"
    fi
else
    # Head-node fallback. The login node usually has no GPU, so this is
    # a weak signal at best. Same grading rules apply.
    NVIDIA_PEERMEM=$(lsmod 2>/dev/null | grep -c '^nvidia_peermem ' | tr -d '[:space:]' || echo "0")
    HEAD_NVIDIA_OPEN="false"
    if [[ -r /proc/driver/nvidia/version ]] && \
            grep -qi "open kernel" /proc/driver/nvidia/version 2>/dev/null; then
        HEAD_NVIDIA_OPEN="true"
    fi
    if [[ "$HEAD_NVIDIA_OPEN" == "true" ]]; then
        print_warn "GPUDirect RDMA: nvidia-open driver on HEAD NODE (unconfirmed on compute, dma_buf path expected)"
        GPUDIRECT_RDMA="true"
    elif [[ "$NVIDIA_PEERMEM" -gt 0 ]]; then
        print_error "GPUDirect RDMA: only nvidia_peermem on HEAD NODE - legacy path, deprecated"
        print_detail "nvidia_peermem is deprecated. Install nvidia-open (565+) for the recommended dma_buf path."
        GPUDIRECT_RDMA="false"
    else
        print_warn "GPUDirect RDMA: no dma_buf or nvidia_peermem on head node (worker check unavailable)"
        GPUDIRECT_RDMA="false"
    fi
fi

# PCIe ACS (Access Control Services) - paired with GPUDirect RDMA above.
#
# ACS forces peer-to-peer PCIe transactions up through the CPU root complex.
# When it is ON for a switch on the GPU<->backend-NIC path, GPUDirect RDMA can
# no longer take the direct GPU<->PCIe-switch<->NIC route - traffic is rerouted
# through the root complex and NCCL/RCCL collectives get dramatically slower
# (or hang). On bare metal we want ACS DISABLED on those switches. This is the
# classic footgun SemiAnalysis calls out in ClusterMAX: "not disabling ACS, or
# not enabling GPUDirect RDMA" is listed as a critical failure.
#
# Scope (per review): we ONLY flag the PCIe switches attached to the backend
# NICs and GPUs - i.e. the bridges that are a shared ancestor of both a GPU and
# a backend RDMA NIC. ACS on unrelated bridges (management NICs, boot storage,
# etc.) is fine and we deliberately do not flag it. host-check.sh resolves this
# topology from sysfs and sets WORKER_ACS_SCOPED=true when it could; if it could
# not resolve the GPU<->NIC topology it sets WORKER_ACS_SCOPED=false and we only
# WARN (never fail) because we cannot tell which bridges matter.
#   ClusterMAX 2.0: https://newsletter.semianalysis.com/p/clustermax-20-the-industry-standard
#   Criteria:       https://www.clustermax.ai/slurm
#   NCCL docs:      https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/troubleshooting.html
#   AMD (switch):   https://docs.amd.com/r/en-US/ug1801-ai-nic-pollara-400-ops-guide
#
# Result categories:
#   PASS    - ACS disabled on all GPU<->NIC path switches (ACS_ENABLED_COUNT == 0)
#   FAIL    - ACS enabled on a GPU<->NIC path switch (GPUDirect RDMA at risk)
#   PASS    - no ACS-capable switch on the GPU<->NIC path (nothing to disable)
#   UNKNOWN - topology not resolvable, or lspci -vvv unreadable (no root)
print_section "PCIe ACS (Access Control Services)"
ACS_ENABLED="unknown"
ACS_SUPPORTED="${WORKER_ACS_SUPPORTED:-false}"
ACS_BRIDGES="${WORKER_ACS_BRIDGES:-0}"
ACS_ENABLED_COUNT="${WORKER_ACS_ENABLED_COUNT:-0}"
ACS_TOTAL_BRIDGES="${WORKER_ACS_TOTAL_BRIDGES:-0}"
ACS_SCOPED="${WORKER_ACS_SCOPED:-false}"
ACS_METHOD="${WORKER_ACS_METHOD:-config}"
ACS_FUNCTIONAL_PAIR="${WORKER_ACS_FUNCTIONAL_PAIR:-none}"
ACS_FUNCTIONAL_SYNDROME="${WORKER_ACS_FUNCTIONAL_SYNDROME:-}"
if [[ "${WORKER_ACS_METHOD:-config}" == "functional" ]]; then
    # No-root GDR self-test decided this (host-check.sh). It exercises the PIX
    # pair directly, so it is authoritative even when lspci -vvv was unreadable.
    ACS_SCOPED="true"; ACS_SUPPORTED="true"
    if [[ "${WORKER_ACS_ENABLED:-unknown}" == "true" ]]; then
        print_error "PCIe ACS: ENABLED (functional) - GPUDirect RDMA self-test on PIX pair ${ACS_FUNCTIONAL_PAIR} faulted (syndrome ${ACS_FUNCTIONAL_SYNDROME:-?}) while host-memory RDMA on the same NIC passed"
        print_detail "Same-switch GPU<->NIC peer DMA is blocked - the signature of ACS P2P redirect breaking GPUDirect RDMA. NCCL/RCCL collectives run slow or hang."
        print_detail "Fix: disable ACS for the GPU<->NIC PCIe switches in BIOS (often tied to VT-d / IOMMU), or per-reboot with setpci. See https://www.clustermax.ai/slurm"
        ACS_ENABLED="true"
    elif [[ "${WORKER_ACS_ENABLED:-unknown}" == "false" ]]; then
        print_info "PCIe ACS: functional GPUDirect RDMA self-test on PIX pair ${ACS_FUNCTIONAL_PAIR} passed (good - GPUDirect RDMA unobstructed)"
        ACS_ENABLED="false"
    else
        ACS_ENABLED="unknown"
    fi
elif [[ "$WORKER_CHECK_OK" == "true" && "${WORKER_ACS_CHECK_OK:-false}" == "true" ]]; then
    if [[ "${WORKER_ACS_VIRTUALIZED:-false}" == "true" && "${WORKER_ACS_SCOPED:-false}" != "true" ]]; then
        # Virtualized / passthrough node: the guest sees each GPU and NIC behind
        # its own emulated bridge, so it cannot resolve or change the real PCIe
        # switch ACS state, which lives on the hypervisor. This is not a tenant
        # finding. GPUDirect RDMA correctness is confirmed functionally instead
        # (the GPUDirect RDMA check above and any NCCL/perftest GDR result).
        print_info "PCIe ACS: not applicable on this virtualized node - the GPU<->NIC PCIe switches and their ACS state are on the hypervisor, not visible or changeable from the guest"
        print_detail "The ${WORKER_ACS_TOTAL_BRIDGES} ACS-capable bridge(s) the guest sees are emulated; guest ACS does not gate GPUDirect RDMA here."
        print_detail "Confirm GPUDirect RDMA functionally: the GPUDirect RDMA check above, plus a GPU-to-NIC RDMA test (ib_write_bw --use_cuda) or NCCL busbw."
        ACS_ENABLED="unknown"
    elif [[ "${WORKER_ACS_SCOPED:-false}" != "true" ]]; then
        print_warn "PCIe ACS: topology not resolved - could not map GPU<->backend-NIC switches"
        print_detail "Found ${WORKER_ACS_TOTAL_BRIDGES} ACS-capable bridge(s) host-wide, but we only flag switches on the GPU<->NIC path and could not resolve it from sysfs."
        print_detail "Check manually which switch the GPU and its backend NIC share, then: sudo lspci -vvv -s <bridge> | grep ACSCtl"
        ACS_ENABLED="unknown"
    elif [[ "${WORKER_ACS_SUPPORTED:-false}" != "true" ]]; then
        # supported=false can mean "no ACS-capable switch on the path" (good) OR
        # "path switches exist but could not be read" (host-check reports
        # enabled=unknown). Only the former is a pass; the latter is inconclusive.
        if [[ "${WORKER_ACS_ENABLED:-unknown}" == "unknown" ]]; then
            print_warn "PCIe ACS: GPU<->NIC path switch(es) present but unread (lspci) - inconclusive"
            ACS_ENABLED="unknown"
        else
            print_info "PCIe ACS: no ACS-capable switch on the GPU<->NIC path (nothing to disable)"
            ACS_ENABLED="false"
        fi
    elif [[ "${WORKER_ACS_ENABLED:-unknown}" == "true" ]]; then
        print_error "PCIe ACS: ENABLED on ${WORKER_ACS_ENABLED_COUNT}/${WORKER_ACS_BRIDGES} GPU<->NIC path switch(es) - GPUDirect RDMA degraded"
        print_detail "ACS on a switch shared by the GPU and its backend NIC routes P2P traffic through the CPU root complex, so NCCL/RCCL collectives run slow or hang."
        print_detail "This is the ClusterMAX footgun: ACS must be OFF on the GPU<->NIC PCIe switches for GPUDirect RDMA to work (you do NOT need to disable ACS on every switch)."
        print_detail "Fix: disable ACS for those switches in BIOS (often tied to VT-d / IOMMU / IO virtualization), or per-reboot with setpci. See https://www.clustermax.ai/slurm"
        print_detail "Verify: sudo lspci -vvv | grep ACSCtl  (a trailing '+' such as SrcValid+ means that bit is enabled)"
        ACS_ENABLED="true"
    elif [[ "${WORKER_ACS_ENABLED:-unknown}" == "false" ]]; then
        print_info "PCIe ACS: disabled on all ${WORKER_ACS_BRIDGES} GPU<->NIC path switch(es) (good - GPUDirect RDMA unobstructed)"
        ACS_ENABLED="false"
    else
        print_warn "PCIe ACS: UNKNOWN (ACSCtl not readable on path switches; rerun audit with root for lspci -vvv)"
        ACS_ENABLED="unknown"
    fi
else
    print_warn "PCIe ACS: UNTESTED (worker check unavailable or lspci -vvv not readable without root)"
    print_detail "Check manually: sudo lspci -vvv | grep ACSCtl  (any trailing '+' means ACS is enabled on that bridge; only the GPU<->NIC path switches matter)"
    ACS_ENABLED="unknown"
fi

# GDRCopy: userspace GPU memory mapping for low-overhead CPU-driven copies.
# https://github.com/nvidia/gdrcopy
print_section "GDRCopy"
GDRCOPY_INSTALLED="false"
GDRCOPY_GDRDRV_LOADED="false"
GDRCOPY_LIB_PATH=""
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    GDRCOPY_LIB_PATH="$WORKER_GDRCOPY_LIB"
    GDRCOPY_GDRDRV_LOADED="$WORKER_GDRCOPY_GDRDRV"
    if [[ "$GDRCOPY_LIB_PATH" != "not-found" ]]; then
        GDRCOPY_INSTALLED="true"
        print_info "libgdrapi: ${GDRCOPY_LIB_PATH} (compute node ${WORKER_HOSTNAME})"
    else
        print_warn "libgdrapi: not found on compute node"
        print_detail "Install: https://github.com/NVIDIA/gdrcopy"
    fi
    if [[ "$GDRCOPY_GDRDRV_LOADED" == "true" ]]; then
        print_info "gdrdrv kernel module: loaded"
    else
        print_warn "gdrdrv kernel module: NOT loaded"
        print_detail "Load with: modcheck gdrdrv  (or build/install gdrcopy first)"
    fi
    [[ "$WORKER_GDRCOPY_DEV" == "true" ]] && print_info "/dev/gdrdrv: present" || print_detail "/dev/gdrdrv: missing (gdrdrv not loaded or no permissions)"
else
    print_warn "GDRCopy: UNTESTED (worker check unavailable)"
fi

# AMD GPU stack: only meaningful when MI300/MI325/MI355 are present.
# Many fields are empty on NVIDIA-only clusters; we still record so JSON
# consumers can see "AMD checked, none present".
print_section "AMD GPU Stack (rocm-smi, amd-smi, amd_peermem)"
AMD_GPUS_PRESENT="false"
ROCM_SMI_AVAILABLE="false"
AMD_SMI_AVAILABLE="false"
AMD_PEERMEM_LOADED="false"
ROCM_CONTAINER_TOOLKIT="false"
RDC_INSTALLED="false"
ROCM_BANDWIDTH_TEST_INSTALLED="false"
ROCPROF_INSTALLED="false"
ROCM_COUNTER_ACCESS="untested"
RVS_INSTALLED="false"
TRANSFERBENCH_INSTALLED="false"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if amd_gpu_check_present "$WORKER_AMD_GPU_COUNT" "$WORKER_AMD_GPU_MODEL"; then
        AMD_GPUS_PRESENT="true"
        print_info "AMD GPU: ${WORKER_AMD_GPU_MODEL:-unknown} × ${WORKER_AMD_GPU_COUNT:-?}"
        print_info "AMD driver: ${WORKER_AMD_DRIVER_VERSION}"
    fi
    if [[ -n "$WORKER_ROCM_SMI_PATH" ]]; then
        ROCM_SMI_AVAILABLE="true"
        print_info "rocm-smi: ${WORKER_ROCM_SMI_PATH}"
    else
        print_detail "rocm-smi: not installed (NVIDIA-only cluster?)"
    fi
    if [[ -n "$WORKER_AMD_SMI_PATH" ]]; then
        AMD_SMI_AVAILABLE="true"
        print_info "amd-smi: ${WORKER_AMD_SMI_PATH} (${WORKER_AMD_SMI_VERSION:-?})"
    fi
    if [[ -n "$WORKER_ROCM_VERSION" ]]; then
        print_info "ROCm: ${WORKER_ROCM_VERSION}"
    fi
    # AMD GPUDirect RDMA grading. Mirrors the NVIDIA rule: only dma_buf
    # passes. amd_peermem is on the same deprecation path as
    # nvidia_peermem; ROCm 6+ routes RDMA through dma_buf via in-tree
    # amdgpu, which is the recommended path.
    #
    #   PASS  - dma_buf via amdgpu detected (regardless of amd_peermem)
    #   FAIL  - only amd_peermem detected (legacy / deprecated)
    #   FAIL  - neither path detected (totally missing)
    if [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        if [[ "${WORKER_AMD_DMABUF:-unknown}" == "true" ]]; then
            AMD_PEERMEM_LOADED="true"
            print_info "AMD GPUDirect RDMA: dma_buf path detected via amdgpu (recommended)"
            if [[ "${WORKER_AMD_PEERMEM_LEGACY:-unknown}" == "true" ]]; then
                print_detail "amd_peermem also loaded but not required - dma_buf supersedes it"
            fi
        elif [[ "${WORKER_AMD_PEERMEM_LEGACY:-unknown}" == "true" ]]; then
            AMD_PEERMEM_LOADED="false"
            print_error "AMD GPUDirect RDMA: only amd_peermem detected (legacy path)"
            print_detail "amd_peermem is deprecated. ROCm 6+ uses dma_buf via the in-tree amdgpu driver, which is the recommended path."
            print_detail "RDMA may still function via the legacy module today, but this cluster is behind the recommended config."
        else
            AMD_PEERMEM_LOADED="false"
            print_error "AMD GPUDirect RDMA: not enabled (totally missing)"
            print_detail "Neither dma_buf via amdgpu nor amd_peermem detected. Recommended fix: ROCm 6+ ships dma_buf support in the in-tree amdgpu driver."
        fi
    else
        AMD_PEERMEM_LOADED="false"
        print_detail "AMD GPUDirect RDMA: skipped (no AMD GPUs)"
    fi
    if [[ -n "$WORKER_ROCM_CT_PATH" ]]; then
        ROCM_CONTAINER_TOOLKIT="true"
        print_info "ROCm container toolkit: ${WORKER_ROCM_CT_PATH}"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_warn "ROCm container toolkit: not detected (needed for containerized AMD workloads)"
    fi
    if [[ -n "${WORKER_RDC_PATH:-}" ]]; then
        RDC_INSTALLED="true"
        print_info "RDC: ${WORKER_RDC_PATH} (${WORKER_RDC_VERSION:-unknown})"
        case "${WORKER_RDC_SMOKE:-unknown}" in
            pass) print_info "RDC smoke test: PASS" ;;
            fail) print_warn "RDC smoke test: FAILED" ;;
            *) print_detail "RDC smoke test: ${WORKER_RDC_SMOKE:-unknown}" ;;
        esac
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_warn "RDC: not detected (AMD monitoring/diagnostics unavailable)"
    fi
    if [[ -n "${WORKER_ROCM_BANDWIDTH_TEST_PATH:-}" ]]; then
        ROCM_BANDWIDTH_TEST_INSTALLED="true"
        print_info "rocm-bandwidth-test: ${WORKER_ROCM_BANDWIDTH_TEST_PATH}"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_warn "rocm-bandwidth-test: not detected"
    fi
    # rocprofv3 is the ncu equivalent on ROCm. rocprof-compute (formerly
    # omniperf) is the guided-analysis layer above it.
    if [[ -n "${WORKER_ROCPROF_PATH:-}" ]]; then
        ROCPROF_INSTALLED="true"
        print_info "ROCm profiler: ${WORKER_ROCPROF_PATH} (${WORKER_ROCPROF_VERSION:-unknown})"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_warn "ROCm profiler: not detected (rocprofv3 is the ncu equivalent)"
    fi
    # ROCm has no NVreg_RestrictProfilingToAdminUsers equivalent. Counter access
    # is allowed when the user can open /dev/kfd and a /dev/dri render node,
    # which usually comes from render/video group membership.
    if [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        ROCM_COUNTER_ACCESS="$(rocm_counter_access_state \
            "${WORKER_ROCM_KFD_ACCESS:-unknown}" \
            "${WORKER_ROCM_RENDER_ACCESS:-unknown}")"
        if [[ "$ROCM_COUNTER_ACCESS" == "allowed" ]]; then
            print_info "ROCm counter access: allowed (groups: ${WORKER_ROCM_PROFILING_GROUPS:-none})"
        elif [[ "$ROCM_COUNTER_ACCESS" == "denied" ]]; then
            print_warn "ROCm counter access: denied (kfd=${WORKER_ROCM_KFD_ACCESS:-unknown}, render=${WORKER_ROCM_RENDER_ACCESS:-unknown})"
            print_detail "Add the tenant user to the render and video groups, or expose /dev/kfd and /dev/dri to the job."
        else
            print_detail "ROCm counter access: untested (kfd=${WORKER_ROCM_KFD_ACCESS:-unknown}, render=${WORKER_ROCM_RENDER_ACCESS:-unknown})"
        fi
    fi
    # ROCm Validation Suite is the active-diagnostic equivalent of dcgmi diag.
    if [[ -n "${WORKER_RVS_PATH:-}" ]]; then
        RVS_INSTALLED="true"
        print_info "ROCm Validation Suite: ${WORKER_RVS_PATH} (${WORKER_RVS_VERSION:-unknown}), configs: ${WORKER_RVS_CONF_DIR:-none}"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_warn "ROCm Validation Suite: not detected (rvs is the dcgmi diag equivalent)"
    fi
    if [[ -n "${WORKER_TRANSFERBENCH_PATH:-}" ]]; then
        TRANSFERBENCH_INSTALLED="true"
        print_info "TransferBench: ${WORKER_TRANSFERBENCH_PATH}"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
        print_detail "TransferBench: not detected (optional XGMI bandwidth harness)"
    fi
else
    print_warn "AMD stack: UNTESTED (worker check unavailable)"
fi

# Per-GPU-class idle power ceiling, in watts. This is the KNOWN-GOOD idle
# threshold table: a single flat 150 W ceiling false-warns on newer parts whose
# static power is higher. Idle draw scales with the part: Hopper (H100/H200)
# idles ~50-90 W; Blackwell SXM (B200/B300) ~120-180 W; Grace-Blackwell
# superchips (GB200/GB300) idle ~150-200 W at P0 with SM clocks gated low
# (measured: NVIDIA GB300 idles ~170 W at P0 / 120 MHz, 1400 W limit). The
# ceiling below is "clearly abnormal" per class (measured idle plus headroom);
# above it usually means a stuck workload or clocks pinned high. Raise a class
# here when a new part idles higher; do not lower the flat default.
gpu_idle_power_ceiling() {
    # $1 = GPU model string (spaces already converted to dashes, any case).
    local m
    m=$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')
    case "$m" in
        *GB300*|*GB200*) echo 300 ;;   # Grace-Blackwell superchip
        *B300*|*B200*)   echo 250 ;;   # Blackwell SXM
        *H100*|*H200*|*H800*) echo 150 ;;  # Hopper
        *) echo 150 ;;                 # conservative default for unknown parts
    esac
}

# GPU idle thermals/power: a 1-sample read with no workload.
# Hot/idle = wrong fan curve, stuck clocks, or a noisy neighbor.
print_section "GPU Idle Thermal/Power (single sample)"
GPU_IDLE_TEMP_MAX="${WORKER_GPU_IDLE_TEMP_MAX:-unknown}"
GPU_IDLE_POWER_MAX="${WORKER_GPU_IDLE_POWER_MAX:-unknown}"
if [[ "$WORKER_CHECK_OK" == "true" && "$GPU_IDLE_TEMP_MAX" != "unknown" ]]; then
    print_info "Hottest GPU at idle: ${GPU_IDLE_TEMP_MAX} °C"
    print_info "Highest GPU power at idle: ${GPU_IDLE_POWER_MAX} W"
    # Soft thresholds: H100/H200 typically idle 30-45 °C, 50-90 W; B200/B300 a bit higher.
    if [[ "$GPU_IDLE_TEMP_MAX" =~ ^[0-9]+$ ]]; then
        if (( GPU_IDLE_TEMP_MAX > 60 )); then
            print_warn "Idle temperature > 60 °C - check airflow / fan curves / noisy neighbor"
        fi
    fi
    # Strip decimal for comparison
    POWER_INT=${GPU_IDLE_POWER_MAX%%.*}
    if [[ "$POWER_INT" =~ ^[0-9]+$ ]]; then
        IDLE_POWER_CEIL=$(gpu_idle_power_ceiling "$GPU_MODEL")
        if (( POWER_INT > IDLE_POWER_CEIL )); then
            print_warn "Idle power > ${IDLE_POWER_CEIL} W for ${GPU_MODEL} - GPUs may be running a workload or stuck at high clocks"
        fi
    fi
else
    print_detail "Idle thermal/power: not collected (no GPU sampler available)"
fi

# Read seven days of retained kernel history on every node in the allocation.
# Without an allocation, keep the representative worker dmesg result.
print_section "GPU kernel error history"
DMESG_XIDS_COUNT="${WORKER_DMESG_XIDS_COUNT:-unknown}"
DMESG_XID_LAST="${WORKER_DMESG_XID_LAST:-unknown}"
DMESG_AMDGPU_ERRORS_COUNT="${WORKER_DMESG_AMDGPU_ERRORS_COUNT:-unknown}"
GPU_ERROR_NODES_TOTAL="${SLURM_NNODES:-${GPU_NODE_COUNT:-1}}"
[[ "$GPU_ERROR_NODES_TOTAL" =~ ^[1-9][0-9]*$ ]] || GPU_ERROR_NODES_TOTAL=1
GPU_ERROR_NODES_CHECKED=0
[[ "$DMESG_XIDS_COUNT" =~ ^[0-9]+$ ]] && GPU_ERROR_NODES_CHECKED=1
if [[ -n "${SLURM_JOB_ID:-}" ]]; then
    GPU_ERROR_OUTPUT=$(srun "${AUDIT_SRUN_FLAGS[@]}" -N"$GPU_ERROR_NODES_TOTAL" \
        --ntasks="$GPU_ERROR_NODES_TOTAL" --ntasks-per-node=1 --time=2:00 \
        bash -c "$(gpu_error_scan_script)" 2>/dev/null || true)
    aggregate_gpu_error_history "$GPU_ERROR_OUTPUT" || true
fi
if (( GPU_ERROR_NODES_CHECKED > 0 )); then
    case "$DMESG_XIDS_COUNT" in
        unavailable) print_detail "Xid scan: dmesg unavailable (CAP_SYSLOG required for non-root)" ;;
        0)           print_info "Xids: 0 (${GPU_ERROR_NODES_CHECKED}/${GPU_ERROR_NODES_TOTAL} node(s) checked)" ;;
        *[0-9]*)
            if (( DMESG_XIDS_COUNT > 0 )); then
                print_warn "Xids: ${DMESG_XIDS_COUNT} across ${GPU_ERROR_NODES_CHECKED}/${GPU_ERROR_NODES_TOTAL} node(s) (last=Xid ${DMESG_XID_LAST:-?})"
            fi
            ;;
    esac
    case "$DMESG_AMDGPU_ERRORS_COUNT" in
        unavailable|"") ;;
        0)              [[ "$AMD_GPUS_PRESENT" == "true" ]] && print_info "amdgpu errors in dmesg: 0" ;;
        *[0-9]*)
            if (( DMESG_AMDGPU_ERRORS_COUNT > 0 )); then
                print_warn "amdgpu error/fault/fail entries in dmesg: ${DMESG_AMDGPU_ERRORS_COUNT}"
            fi
            ;;
    esac
else
    print_warn "GPU kernel error history: UNTESTED (no readable node history)"
fi

# Check GRES configuration
print_section "GRES Configuration"
GRES_CONF=$(echo "$SLURM_CONFIG_FULL" | grep "^GresTypes" | awk '{print $3}')
if [[ -n "$GRES_CONF" ]]; then
    print_info "GresTypes: ${GRES_CONF}"
else
    print_warn "GresTypes: Not configured"
fi

# NCU (NVIDIA Nsight Compute) - checked on compute node
print_section "NCU (NVIDIA Nsight Compute)"
NCU_INSTALLED="false"
NCU_VERSION="unknown"
NCU_PATH=""

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    NCU_PATH="$WORKER_NCU_PATH"
    NCU_VERSION="$WORKER_NCU_VERSION"
    if [[ -n "$NCU_PATH" && "$NCU_VERSION" != "not-found" ]]; then
        NCU_INSTALLED="true"
        print_info "ncu: ${NCU_PATH} (on compute node ${WORKER_HOSTNAME})"
        print_info "Version: ${NCU_VERSION}"
        NCU_YEAR=$(echo "$NCU_VERSION" | cut -d. -f1)
        NCU_MINOR=$(echo "$NCU_VERSION" | cut -d. -f2)
        if [[ "$NCU_YEAR" =~ ^[0-9]+$ && "$NCU_YEAR" -ge 2024 ]]; then
            if [[ "$NCU_YEAR" -gt 2024 || "${NCU_MINOR:-0}" -ge 3 ]]; then
                print_info "Version meets B300 requirement (>= 2024.3)"
            else
                print_warn "Version ${NCU_VERSION} may be too old for B300 (need >= 2024.3)"
            fi
        else
            print_warn "Cannot parse version to verify B300 requirement (>= 2024.3)"
        fi
    else
        print_warn "ncu: Not found in PATH on compute node"
        print_detail "B300 requires ncu >= 2024.3 (CUDA 12.6+). Install CUDA toolkit or Nsight Compute."
    fi
else
    # Head-node fallback
    NCU_PATH=$(which ncu 2>/dev/null || echo "")
    if [[ -n "$NCU_PATH" ]]; then
        NCU_INSTALLED="true"
        NCU_VERSION=$(ncu --version 2>/dev/null | grep -oiP 'version\s+\K[0-9.]+' | head -1 || echo "unknown")
        print_warn "ncu: ${NCU_PATH} (HEAD NODE FALLBACK - unconfirmed on compute)"
        print_info "Version: ${NCU_VERSION}"
    else
        print_warn "ncu: Not found on head node (worker check unavailable - cannot confirm on compute)"
    fi
fi

# NCU Profiling Permissions
# Without this, every user gets: ==ERROR== ERR_NVGPUCTRPERM: Permission denied
# Ref: https://gist.github.com/msaroufim/9e56ce5d42a5e9ccd5e938c83181ea47
print_section "NCU Profiling Permissions (NVreg_RestrictProfilingToAdminUsers)"
NCU_PROFILING_ENABLED="unknown"
NCU_PROFILING_CONF_FOUND="false"

# This is a property of the driver as configured/loaded on the COMPUTE node, so
# read it from the worker check. The head/login node usually has no NVIDIA
# driver loaded, so a head-node check reports a false RESTRICTED. The live
# counter test (hardwareCounterAccess) is authoritative; this is the config.
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    NCU_PROFILING_ENABLED="${WORKER_NCU_PROFILING_ENABLED:-unknown}"
    if [[ "$NCU_PROFILING_ENABLED" == "true" ]]; then
        NCU_PROFILING_CONF_FOUND="true"
        print_info "NCU profiling: Unrestricted on compute node ${WORKER_HOSTNAME} (source: ${WORKER_NCU_PROFILING_SOURCE:-unknown})"
    elif [[ "$NCU_PROFILING_ENABLED" == "false" ]]; then
        print_error "NCU profiling: RESTRICTED on compute node ${WORKER_HOSTNAME} (NVreg_RestrictProfilingToAdminUsers not set to 0)"
        print_detail "Users will get: ==ERROR== ERR_NVGPUCTRPERM: Permission denied"
        print_detail "Fix (run once per compute node, then reboot):"
        print_detail "  echo 'options nvidia NVreg_RestrictProfilingToAdminUsers=0' | sudo tee /etc/modcheck.d/nvprof.conf"
        print_detail "  sudo reboot"
        print_detail "Docker users also need: --cap-add SYS_ADMIN or --privileged"
    else
        print_warn "NCU profiling: unknown on compute node ${WORKER_HOSTNAME} (driver configuration was unreadable)"
    fi
else
    # No head-node fallback: the NVreg config lives on the GPU node, and a failed
    # worker check aborts publishing (validate_audit.py) anyway.
    print_warn "NCU profiling: skipped (worker check unavailable; not checking head node)"
fi

# NCU Hardware Counter Access (live test on compute node)
# Config checks above verify NVreg_RestrictProfilingToAdminUsers is set.
# This section runs ncu with hardware counter metrics on the compute node
# to confirm end-to-end access (config can be correct while access still fails).
print_section "NCU Hardware Counter Access (Live Test)"
NCU_COUNTER_ACCESS="unknown"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    NCU_COUNTER_ACCESS="$WORKER_NCU_COUNTER_ACCESS"
    case "$NCU_COUNTER_ACCESS" in
        granted)
            print_info "Hardware counters: ACCESSIBLE (live ncu profiling succeeded on ${WORKER_HOSTNAME})"
            ;;
        denied)
            print_error "Hardware counters: DENIED (ERR_NVGPUCTRPERM on ${WORKER_HOSTNAME})"
            print_detail "ncu is installed but cannot access GPU performance counters."
            print_detail "This means profiling tools (ncu, nsys with GPU metrics) will fail at runtime."
            print_detail "Verify NVreg_RestrictProfilingToAdminUsers=0 is set AND the driver was reloaded."
            print_detail "Docker/container users also need: --cap-add SYS_ADMIN or --privileged"
            ;;
        timeout)
            print_error "Hardware counters: TIMED OUT on ${WORKER_HOSTNAME}"
            print_detail "The live ncu check exceeded AUDIT_NCU_COUNTER_TIMEOUT_S (default: 60 seconds)."
            print_detail "This can indicate a profiling-permission or driver interaction that leaves ncu attached."
            ;;
        error)
            print_error "Hardware counters: live ncu check failed on ${WORKER_HOSTNAME}"
            print_detail "ncu returned a non-zero status without the expected permission-denied signature."
            ;;
        compile-failed)
            print_warn "Hardware counters: UNTESTED (nvcc failed to compile test kernel)"
            print_detail "Could not compile trivial CUDA kernel for live ncu test."
            ;;
        no-nvcc)
            print_warn "Hardware counters: UNTESTED (nvcc not available to compile test kernel)"
            print_detail "Install CUDA toolkit on compute nodes to enable live counter test."
            ;;
        no-ncu)
            print_warn "Hardware counters: UNTESTED (ncu not installed)"
            ;;
        *)
            print_warn "Hardware counters: UNKNOWN (unexpected check result: ${NCU_COUNTER_ACCESS})"
            ;;
    esac
else
    print_warn "Hardware counters: UNTESTED (worker check unavailable)"
fi

# perf top / perf stat access (Linux performance counters on compute node)
# perf is essential for CPU-side profiling - identifying bottlenecks in data
# loading, preprocessing, kernel launch overhead, and host-device sync.
#
# Access issues typically come down to:
#   1. perf_event_paranoid - controls who can use perf events:
#      -1 = no restrictions (allow all)
#       0 = allow raw tracepoint access for non-root
#       1 = allow non-root per-process monitoring (default on many distros)
#       2 = allow non-root per-process only, no kernel profiling
#       3 = no perf event access for non-root at all (Ubuntu default since ~20.04)
#   2. kptr_restrict - hides kernel symbol addresses from non-root:
#      0 = visible to all
#      1 = hidden from non-root (perf top shows [unknown] for kernel functions)
#      2 = always hidden
#      Also need linux-tools-$(uname -r) and possibly linux-image-$(uname -r)-dbgsym
#   3. Container/VM - host perf subsystem may not be accessible; need --privileged
#      or CAP_SYS_ADMIN / CAP_PERFMON (Linux 5.8+). With Pyxis/enroot: pass via
#      --container-mounts or srun flags.
#   4. SELinux/AppArmor - can block perf access even if paranoid is permissive.
#
# Quick fix (temporary):
#   sudo sysctl -w kernel.perf_event_paranoid=-1
#   sudo sysctl -w kernel.kptr_restrict=0
# Persistent: add to /etc/sysctl.conf or /etc/sysctl.d/99-perf.conf
print_section "perf Access (Linux Performance Counters)"
PERF_INSTALLED="false"
PERF_EVENT_PARANOID="unknown"
PERF_KPTR_RESTRICT="unknown"
PERF_STAT_ACCESS="unknown"
PERF_TOP_ACCESS="unknown"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ -n "$WORKER_PERF_PATH" ]]; then
        PERF_INSTALLED="true"
        PERF_EVENT_PARANOID="$WORKER_PERF_EVENT_PARANOID"
        PERF_KPTR_RESTRICT="$WORKER_KPTR_RESTRICT"
        PERF_STAT_ACCESS="$WORKER_PERF_STAT_ACCESS"
        PERF_TOP_ACCESS="$WORKER_PERF_TOP_ACCESS"

        print_info "perf: ${WORKER_PERF_PATH} (on compute node ${WORKER_HOSTNAME})"

        # Report perf_event_paranoid
        case "$PERF_EVENT_PARANOID" in
            -1) print_info "perf_event_paranoid = -1 (no restrictions - full profiling)" ;;
            0)  print_info "perf_event_paranoid = 0 (allow raw tracepoint access for non-root)" ;;
            1)  print_warn "perf_event_paranoid = 1 (user-space per-process only, no kernel profiling)" ;;
            2)  print_warn "perf_event_paranoid = 2 (restrictive - per-process counters only)" ;;
            3|4) print_error "perf_event_paranoid = ${PERF_EVENT_PARANOID} (perf_event_open denied for non-root)"
                print_detail "Fix: sudo sysctl -w kernel.perf_event_paranoid=-1"
                print_detail "Persistent: echo 'kernel.perf_event_paranoid = -1' | sudo tee /etc/sysctl.d/99-perf.conf" ;;
            *)  print_warn "perf_event_paranoid = ${PERF_EVENT_PARANOID} (could not parse)" ;;
        esac

        # Report kptr_restrict
        case "$PERF_KPTR_RESTRICT" in
            0) print_info "kptr_restrict = 0 (kernel symbols visible)" ;;
            1) print_warn "kptr_restrict = 1 (kernel symbols hidden - perf top shows [unknown] for kernel functions)"
               print_detail "Fix: sudo sysctl -w kernel.kptr_restrict=0"
               print_detail "Also install: linux-tools-\$(uname -r) and linux-image-\$(uname -r)-dbgsym" ;;
            2) print_error "kptr_restrict = 2 (kernel symbols always hidden)"
               print_detail "Fix: sudo sysctl -w kernel.kptr_restrict=0" ;;
        esac

        # Report live test results
        case "$PERF_STAT_ACCESS" in
            granted) print_info "perf stat: PASS (live test succeeded)" ;;
            partial) print_warn "perf stat: PARTIAL (some counters not supported or not counted)" ;;
            denied)  print_error "perf stat: DENIED"
                     print_detail "Container users need: --privileged or CAP_SYS_ADMIN / CAP_PERFMON (Linux 5.8+)" ;;
        esac
        case "$PERF_TOP_ACCESS" in
            granted) print_info "perf top: PASS (live test succeeded)" ;;
            warning) print_warn "perf top: WARNING (partial access - check perf_event_paranoid)" ;;
            denied)  print_error "perf top: DENIED"
                     print_detail "Need perf_event_paranoid ≤ 1, or CAP_SYS_ADMIN / CAP_PERFMON in containers" ;;
        esac
    else
        print_warn "perf: Not found in PATH on compute node"
        print_detail "Install: apt install linux-tools-\$(uname -r) OR yum install perf"
    fi
else
    print_warn "perf access: UNTESTED (worker check unavailable)"
fi

# =============================================================================
# SECTION 4: NVIDIA HPC SDK & Software Stack
# Primary source: worker node check. Head-node checks are secondary/fallback.
# =============================================================================
print_header "4. NVIDIA HPC SDK & SOFTWARE STACK"

# NVCC / CUDA - use worker check (compute node is authoritative)
print_section "CUDA Toolkit (on compute node)"
NVCC_PATH=""
NVCC_IN_PATH="false"
NVCC_VERSION="unknown"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    NVCC_PATH="$WORKER_NVCC_PATH"
    NVCC_VERSION="$WORKER_NVCC_VERSION"
    if [[ -n "$NVCC_PATH" && "$NVCC_VERSION" != "not-found" ]]; then
        NVCC_IN_PATH="true"
        print_info "nvcc: ${NVCC_PATH} (in PATH on compute node ${WORKER_HOSTNAME}, no sourcing needed)"
        print_info "CUDA Toolkit Version: ${NVCC_VERSION}"
        NVCC_MAJOR=$(echo "$NVCC_VERSION" | cut -d. -f1)
        NVCC_MINOR=$(echo "$NVCC_VERSION" | cut -d. -f2)
        if [[ "$NVCC_MAJOR" =~ ^[0-9]+$ && "$NVCC_MAJOR" -ge 12 ]]; then
            if [[ "$NVCC_MAJOR" -gt 12 || "${NVCC_MINOR:-0}" -ge 8 ]]; then
                print_info "CUDA version meets B300 requirement (>= 12.8)"
            else
                print_warn "CUDA ${NVCC_VERSION} is below B300 minimum (need >= 12.8)"
            fi
        fi
    else
        print_warn "nvcc: Not found in PATH on compute node (users need to load a module or set PATH)"
        # Fall back to head-node check to at least see if it's installed somewhere
        NVCC_HEAD=$(which nvcc 2>/dev/null || echo "")
        [[ -n "$NVCC_HEAD" ]] && print_detail "  (nvcc is in PATH on head node: ${NVCC_HEAD} - may need explicit PATH setup on compute)"
    fi
    # Driver vs toolkit compat check
    if [[ "$CUDA_VERSION" != "unknown" && "$NVCC_VERSION" != "unknown" && "$NVCC_VERSION" != "not-found" ]]; then
        print_info "Driver CUDA cap: ${CUDA_VERSION} / Toolkit: ${NVCC_VERSION}"
        DRV_MAJOR=$(echo "$CUDA_VERSION" | cut -d. -f1)
        TK_MAJOR=$(echo "$NVCC_VERSION" | cut -d. -f1)
        if [[ "$TK_MAJOR" =~ ^[0-9]+$ && "$DRV_MAJOR" =~ ^[0-9]+$ && "$TK_MAJOR" -gt "$DRV_MAJOR" ]]; then
            print_warn "Toolkit (${NVCC_VERSION}) newer than driver CUDA cap (${CUDA_VERSION}) - may cause issues"
        fi
    fi
else
    print_warn "Worker check unavailable - checking nvcc on HEAD NODE (may not reflect compute)"
    NVCC_PATH=$(which nvcc 2>/dev/null || echo "")
    if [[ -n "$NVCC_PATH" ]]; then
        NVCC_IN_PATH="true"
        NVCC_VERSION=$(nvcc --version 2>/dev/null | grep -oP 'release \K[0-9.]+' || echo "unknown")
        print_warn "nvcc: ${NVCC_PATH} (head node only)"
        print_info "Version: ${NVCC_VERSION}"
    else
        print_warn "nvcc: Not found on head node"
    fi
fi

CUDA_HOME_VAL="${CUDA_HOME:-}"
if [[ -n "$CUDA_HOME_VAL" ]]; then
    print_info "CUDA_HOME: ${CUDA_HOME_VAL}"
elif [[ -d "/usr/local/cuda" ]]; then
    print_info "CUDA found: /usr/local/cuda"
else
    print_detail "CUDA_HOME: Not set on head node, /usr/local/cuda not found"
fi

# NVIDIA HPC SDK - from worker check (/opt is typically node-local, so the head
# node's /opt does not reflect the compute image).
print_section "NVIDIA HPC SDK (on compute node)"
NVHPC_INSTALLED="false"
NVHPC_STATUS="unknown"
NVHPC_VERSION="unknown"
NVHPC_MINIMUM=$(minimum_version components.nvhpc.minimum)
NVHPC_CURRENT=$(minimum_version components.nvhpc.current)
NVHPC_COMPONENTS_MISSING="not-checked"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    NVHPC_INSTALLED="${WORKER_NVHPC_INSTALLED:-false}"
    NVHPC_VERSION="${WORKER_NVHPC_VERSION:-unknown}"
    NVHPC_COMPONENTS_MISSING="${WORKER_NVHPC_COMPONENTS_MISSING:-not-checked}"
    if [[ "$NVHPC_INSTALLED" == "true" ]]; then
        print_info "HPC SDK ${NVHPC_VERSION} found on ${WORKER_HOSTNAME}: ${WORKER_NVHPC_PATH:-/opt/nvidia/hpc_sdk}"
        print_detail "Supported release window: ${NVHPC_MINIMUM} through ${NVHPC_CURRENT}"
        print_detail "Compilers: nvc=${WORKER_NVHPC_NVC_VERSION:-not-found}, nvc++=${WORKER_NVHPC_NVCXX_VERSION:-not-found}, nvfortran=${WORKER_NVHPC_NVFORTRAN_VERSION:-not-found}"
        if [[ "${WORKER_NVHPC_COMPILERS_OK:-false}" != true ]]; then
            NVHPC_STATUS="fail"
            print_error "HPC SDK compiler drivers are missing or do not match release ${NVHPC_VERSION}"
        elif [[ "${WORKER_NVHPC_COMPONENTS_OK:-false}" != true ]]; then
            NVHPC_STATUS="fail"
            print_error "HPC SDK ${NVHPC_VERSION} is incomplete: missing ${NVHPC_COMPONENTS_MISSING}"
        elif [[ "$NVHPC_MINIMUM" == unknown || "$NVHPC_CURRENT" == unknown \
                || "$NVHPC_VERSION" == unknown ]]; then
            print_warn "HPC SDK release could not be graded"
        elif ! version_ge "$NVHPC_VERSION" "$NVHPC_MINIMUM"; then
            NVHPC_STATUS="fail"
            print_error "HPC SDK ${NVHPC_VERSION} is older than supported minimum ${NVHPC_MINIMUM} (current ${NVHPC_CURRENT})"
        elif ! version_ge "$NVHPC_CURRENT" "$NVHPC_VERSION"; then
            NVHPC_STATUS="fail"
            print_error "HPC SDK ${NVHPC_VERSION} is newer than the validated current release ${NVHPC_CURRENT}"
        else
            NVHPC_STATUS="pass"
            print_info "HPC SDK compiler and component manifest is complete"
        fi
    else
        NVHPC_STATUS="fail"
        print_warn "NVIDIA HPC SDK: Not found on compute node ${WORKER_HOSTNAME}"
        print_detail "Install a supported SDK release with nvc, nvc++, nvfortran, communication libraries, math libraries, and profiling tools"
    fi
else
    # No head-node fallback: /opt is node-local, so the head node is not
    # representative, and a failed worker check aborts publishing anyway.
    print_warn "NVIDIA HPC SDK: skipped (worker check unavailable; not checking head node)"
fi

# Head-vs-worker consistency (additive; the worker check above stays
# authoritative). This extra login-node glance exists only to flag a split
# install - present on one node class and absent on the other - which is an
# operator-visible inconsistency worth calling out while access is live.
NVHPC_ON_WORKERS="${WORKER_NVHPC_INSTALLED:-false}"
NVHPC_ON_HEAD="false"
if [[ -d "/opt/nvidia/hpc_sdk" ]] || find /opt -maxdepth 4 -type d -name "hpc_sdk" 2>/dev/null | grep -q .; then
    NVHPC_ON_HEAD="true"
fi
if [[ "$WORKER_CHECK_OK" == "true" && "$NVHPC_ON_HEAD" != "$NVHPC_ON_WORKERS" ]]; then
    print_warn "NVIDIA HPC SDK: present on only one node class (head=${NVHPC_ON_HEAD}, workers=${NVHPC_ON_WORKERS})"
fi

# NCCL - use worker check (libnccl.so must be visible on compute nodes)
print_section "NCCL (on compute node)"
NCCL_VERSION="unknown"
NCCL_INSTALLED="false"
NCCL_PATH="none"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ -n "$WORKER_NCCL_LIB" && "$WORKER_NCCL_VERSION" != "not-found" ]]; then
        NCCL_INSTALLED="true"
        NCCL_PATH="$WORKER_NCCL_LIB"
        NCCL_VERSION="$WORKER_NCCL_VERSION"
        print_info "NCCL: Found at ${NCCL_LIB:-$NCCL_PATH} (on compute node ${WORKER_HOSTNAME})"
        print_info "Version: ${NCCL_VERSION}"
        NCCL_MAJOR=$(echo "$NCCL_VERSION" | cut -d. -f1)
        NCCL_MINOR=$(echo "$NCCL_VERSION" | cut -d. -f2)
        NCCL_PATCH=$(echo "$NCCL_VERSION" | cut -d. -f3)
        if [[ "$NCCL_VERSION" != "installed" && "$NCCL_MAJOR" =~ ^[0-9]+$ ]]; then
            if [[ "$NCCL_MAJOR" -gt 2 ]] || \
               [[ "$NCCL_MAJOR" -eq 2 && "$NCCL_MINOR" -gt 21 ]] || \
               [[ "$NCCL_MAJOR" -eq 2 && "$NCCL_MINOR" -eq 21 && "${NCCL_PATCH:-0}" -ge 5 ]]; then
                print_info "Version meets minimum requirement (>= 2.21.5)"
            else
                print_warn "NCCL ${NCCL_VERSION} is below minimum 2.21.5 - upgrade recommended (latest: 2.25.x)"
            fi
        fi
    else
        print_warn "NCCL: Not found on compute node"
    fi
else
    print_warn "Worker check unavailable - searching for NCCL on HEAD NODE (may not reflect compute)"
    NCCL_LIB=$(find_host_nccl_candidates | grep -v "\.so\." | head -1 || echo "")
    [[ -z "$NCCL_LIB" ]] && NCCL_LIB=$(find_host_nccl_candidates | head -1 || echo "")
    if [[ -n "$NCCL_LIB" ]]; then
        NCCL_INSTALLED="true"
        NCCL_PATH="$NCCL_LIB"
        NCCL_VERSION=$(strings "$NCCL_LIB" 2>/dev/null | grep -oP 'NCCL version \K[0-9.]+' | head -1 || echo "installed")
        print_warn "NCCL: ${NCCL_LIB} (head node only - ${NCCL_VERSION})"
    else
        print_warn "NCCL: Not found on head node"
    fi
fi

# Check NCCL config - check both head node and worker (via check)
NCCL_CONF="/etc/nccl.conf"
print_section "NCCL Auto-Config Check (/etc/nccl.conf)"
NCCL_CONF_OVERRIDES="false"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ "$WORKER_NCCL_CONF_OVERRIDES" == "true" ]]; then
        NCCL_CONF_OVERRIDES="true"
        print_error "NCCL_MIN_NCHANNELS / NCCL_PROTO / NCCL_ALGO found in /etc/nccl.conf on compute node"
        print_detail "These override NCCL's auto-tuning and degrade performance - remove them"
    else
        print_info "/etc/nccl.conf on compute node: No performance-degrading overrides (PASS)"
    fi
else
    # Head-node fallback
    if [[ -f "$NCCL_CONF" ]]; then
        if grep -qE "NCCL_MIN_NCHANNELS|NCCL_PROTO|NCCL_ALGO" "$NCCL_CONF" 2>/dev/null; then
            NCCL_CONF_OVERRIDES="true"
            print_error "NCCL auto-tuning overrides found in ${NCCL_CONF} (head node)"
        else
            print_info "${NCCL_CONF} exists, no overrides (head node check only)"
        fi
        if grep -q "NCCL_IB_GID_INDEX" "$NCCL_CONF" 2>/dev/null; then
            print_info "RoCEv2 GID index configured in nccl.conf"
        fi
    else
        print_info "/etc/nccl.conf: Not present on head node (using NCCL defaults)"
    fi
fi

# MPI / HPC-X - use worker check (mpirun must work on compute nodes)
print_section "MPI & HPC-X (on compute node)"
MPIRUN_PATH=""
MPI_INSTALLED="false"
HPCX_IN_PATH="false"
HPCX_PATH=""

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    MPIRUN_PATH="$WORKER_MPIRUN_PATH"
    HPCX_IN_PATH="$WORKER_HPCX_DETECTED"
    if [[ -n "$MPIRUN_PATH" && "$WORKER_MPIRUN_VERSION" != "not-found" ]]; then
        MPI_INSTALLED="true"
        print_info "mpirun: ${MPIRUN_PATH} (in PATH on compute node ${WORKER_HOSTNAME}, no sourcing needed)"
        print_detail "${WORKER_MPIRUN_VERSION}"
        if [[ "$HPCX_IN_PATH" == "true" ]]; then
            print_info "HPC-X: Detected in mpirun on compute node"
        else
            print_warn "mpirun found but is NOT HPC-X (may be generic OpenMPI)"
            print_detail "HPC-X is required for optimal NCCL + IB performance on B300"
        fi
    else
        print_warn "mpirun: Not found in PATH on compute node"
        # Check head node as fallback indicator
        MPIRUN_HEAD=$(which mpirun 2>/dev/null || echo "")
        [[ -n "$MPIRUN_HEAD" ]] && print_detail "  (mpirun is on head node: ${MPIRUN_HEAD} - PATH may not propagate to compute)"
    fi
else
    print_warn "Worker check unavailable - checking mpirun on HEAD NODE"
    MPIRUN_PATH=$(which mpirun 2>/dev/null || echo "")
    if [[ -n "$MPIRUN_PATH" ]]; then
        MPI_INSTALLED="true"
        MPI_VERSION=$(mpirun --version 2>/dev/null | head -1 || echo "unknown")
        print_warn "mpirun: ${MPIRUN_PATH} (head node only - ${MPI_VERSION})"
        if mpirun --version 2>/dev/null | grep -qi "hpcx\|hpc-x" || ompi_info --version 2>/dev/null | grep -qi "hpcx\|hpc.x"; then
            HPCX_IN_PATH="true"
            print_info "HPC-X: Detected on head node"
        else
            print_warn "mpirun on head node is not HPC-X"
        fi
    else
        print_warn "mpirun: Not found on head node"
    fi
fi

# HPC-X install tree under /opt - from worker check (/opt is typically
# node-local; the in-PATH signal is already worker-checked via HPCX_IN_PATH).
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    HPCX_OPT_PATH="${WORKER_HPCX_OPT_PATH:-}"
else
    # No head-node fallback: /opt is node-local; a failed worker check aborts
    # publishing anyway.
    HPCX_OPT_PATH=""
fi
if [[ -n "$HPCX_OPT_PATH" ]]; then
    HPCX_PATH="$HPCX_OPT_PATH"
    if [[ "$HPCX_IN_PATH" == "false" || "$HPCX_IN_PATH" == "" ]]; then
        # HPC-X installed but not on the default PATH is normal, not a failure.
        # HPC-X ships an mpirun that users opt into by sourcing hpcx-init.sh or
        # loading a module, and the sanctioned launcher on this cluster is
        # srun --mpi=pmix (see the srun MPI plugins check below). The capability
        # is present; it just is not auto-sourced into every login shell.
        print_info "HPC-X installed at ${HPCX_PATH} (not on the default PATH on compute nodes)"
        print_detail "Load it when needed: source ${HPCX_OPT_PATH}/hpcx-init.sh  (or 'module load hpcx' where a module exists)"
        print_detail "For process launch, srun --mpi=pmix is the recommended path on this cluster; see the srun MPI plugins check below"
    else
        print_info "HPC-X installation directory: ${HPCX_PATH}"
    fi
elif [[ "$HPCX_IN_PATH" == "false" || "$HPCX_IN_PATH" == "" ]]; then
    print_warn "HPC-X: Not found in /opt and not detected in PATH on compute nodes"
fi

# srun --mpi=list / PMIx integration
# Validates that the MPI implementation is wired into SLURM via PMIx so users
# can launch with `srun --mpi=pmix` instead of relying on `mpirun` for process
# launch. PMIx is the standard interconnect.
print_section "srun MPI plugins (--mpi=list)"
SRUN_MPI_LIST=""
SRUN_MPI_PMIX="false"
SRUN_MPI_LIST=$(srun --mpi=list 2>&1 | tr -d '\r' | head -50 || true)
if [[ -n "$SRUN_MPI_LIST" ]]; then
    print_detail "srun --mpi=list output:"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        print_detail "  ${line}"
    done <<< "$SRUN_MPI_LIST"
    if echo "$SRUN_MPI_LIST" | grep -qi "pmix"; then
        SRUN_MPI_PMIX="true"
        print_info "srun --mpi=list: pmix plugin available (users can: srun --mpi=pmix)"
    else
        print_error "srun --mpi=list: pmix plugin NOT available"
        print_detail "Install slurm-pmix or build SLURM with PMIx support, then restart slurmd"
    fi
else
    print_warn "srun --mpi=list: command produced no output (srun unavailable?)"
fi

# =============================================================================
# SECTION 5: Module System (Lmod)
# =============================================================================
print_header "5. MODULE SYSTEM"

print_section "Lmod"
MODULE_CMD=$(which module 2>/dev/null || type -t module 2>/dev/null || echo "")
LMOD_INSTALLED="false"
HAS_CUDA_MODULE="false"
HAS_HPCX_MODULE="false"
HAS_NCCL_MODULE="false"

if [[ -n "$MODULE_CMD" ]] || type module &>/dev/null 2>&1; then
    LMOD_INSTALLED="true"
    print_info "module command: Available (works without sourcing any profile)"

    # Try to get module version
    LMOD_VERSION=$(module --version 2>&1 | grep -oP 'Version \K[0-9.]+' || echo "unknown")
    print_info "Lmod Version: ${LMOD_VERSION}"

    # Show sample of available modules
    print_detail "Sample of available modules (module avail | head -30):"
    MODULE_AVAIL_OUT=$(module avail 2>&1 | head -30 || echo "  (unable to list modules)")
    while IFS= read -r modline; do
        print_detail "  ${modline}"
    done <<< "$MODULE_AVAIL_OUT"

    # Count available modules
    MODULE_COUNT=$(module avail 2>&1 | grep -c "/" || echo "0")
    print_info "Available modules: ~${MODULE_COUNT}"

    # Check for key modules
    if module avail 2>&1 | grep -qi "cuda"; then
        HAS_CUDA_MODULE="true"
        print_info "CUDA module: Available"
    else
        print_warn "CUDA module: Not found - users will need manual PATH setup"
    fi

    if module avail 2>&1 | grep -qi "hpcx\|hpc-x\|hpc_x"; then
        HAS_HPCX_MODULE="true"
        print_info "HPC-X module: Available"
    else
        print_warn "HPC-X module: Not found"
    fi

    if module avail 2>&1 | grep -qi "nccl"; then
        HAS_NCCL_MODULE="true"
        print_info "NCCL module: Available"
    else
        print_warn "NCCL module: Not found"
    fi

    if module avail python 2>&1 | grep -qi python; then
        print_info "Python modules: Available"
    else
        print_warn "Python modules: Not found"
    fi
else
    print_warn "Lmod: Not installed or not configured"
    print_detail "Install from: https://github.com/TACC/Lmod"
fi

# Test module without login shell (should work by default for users)
print_section "Module Shell Availability"
MODULE_NO_LOGIN=$(bash --norc --noprofile -c 'module avail 2>&1 | head -5' 2>/dev/null | head -5 || echo "")
if [[ -n "$MODULE_NO_LOGIN" && ! "$MODULE_NO_LOGIN" =~ "command not found" ]]; then
    print_info "module works in non-login shells (accessible by default)"
else
    print_warn "module may require login shell or profile sourcing"
    print_detail "Test: bash --norc --noprofile -c 'module avail'"
fi

# =============================================================================
# SECTION 6: Container Support
# =============================================================================
print_header "6. CONTAINER SUPPORT"

pyxis_cli_is_available() {
    local help_output=""
    help_output=$(srun --help 2>&1) || return 1
    grep -q -- '--container-image' <<< "$help_output"
}

detect_pyxis_version() {
    local version=""
    if command -v dpkg-query >/dev/null 2>&1; then
        version=$(dpkg-query -W -f='${Version}' nvslurm-plugin-pyxis 2>/dev/null) \
            || version=""
    fi
    if [[ -z "$version" ]] && command -v rpm >/dev/null 2>&1; then
        version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' nvslurm-plugin-pyxis 2>/dev/null) \
            || version=""
    fi
    printf '%s\n' "${version:-unknown}"
}

# Pyxis is a Slurm SPANK plugin, so its command-line interface appears directly
# in srun. This check avoids a container image pull and a queued GPU allocation.
print_section "Pyxis (SLURM Container Plugin)"
PYXIS_INSTALLED="false"
PYXIS_RUNTIME_WORKS="false"
PYXIS_CLI_AVAILABLE="false"
PYXIS_VERSION=$(detect_pyxis_version)
PYXIS_INSTALL_DOCS="https://github.com/NVIDIA/pyxis#installation"
if [[ "$PYXIS_VERSION" != "unknown" ]]; then
    PYXIS_INSTALLED="true"
    print_info "Pyxis version: ${PYXIS_VERSION}"
fi
if pyxis_cli_is_available; then
    PYXIS_CLI_AVAILABLE="true"
    PYXIS_INSTALLED="true"
    PYXIS_RUNTIME_WORKS="true"
    print_info "Pyxis CLI: available through srun --container-image"
    if [[ "$PYXIS_VERSION" == "unknown" ]]; then
        print_detail "Package version metadata is unavailable; Pyxis can be a source installation"
    fi
else
    print_warn "Pyxis CLI: srun does not expose the Pyxis container options"
    if [[ "$PYXIS_VERSION" == "unknown" ]]; then
        print_warn "Pyxis version: package metadata not found"
    fi
    print_detail "Installation: ${PYXIS_INSTALL_DOCS}"
fi
CONTAINER_CONFIG=$(echo "$SLURM_CONFIG_FULL" | grep -i "container" || echo "")
[[ -n "$CONTAINER_CONFIG" ]] && print_detail "Container config found on control plane"

# All host-runtime checks below execute in one GPU worker allocation.  Keeping
# the check in a shared script also lets the K8s collector run the same checks
# against a Kubernetes worker host.
CONTAINER_WORKER_CHECK_OK="false"
CONTAINER_WORKER_NODE="none"
DOCKER_INSTALLED="false"
DOCKER_ON_WORKERS="false"
DOCKER_VERSION="unknown"
DOCKER_VERSION_OK="false"
NVIDIA_CONTAINER_TOOLKIT="false"
NVIDIA_CT_VERSION="unknown"
NVIDIA_CT_VERSION_OK="false"
# Operational recommendations come from the generated minimum table, the same
# source the security grading reads. They were hardcoded here and in
# cluster-audit-standalone.sh, and the NVIDIA Container Toolkit literal (1.19.0)
# fell below the minimum version the June 2026 bulletin set (1.19.1, CVE-2026-24260),
# so the audit recommended a version its own security check fails. The two
# verdicts stay separate; only the duplicated literal is gone.
DOCKER_RECOMMENDED_MIN=$(minimum_version components.docker.minimum)
NVIDIA_CT_RECOMMENDED_MIN=$(minimum_version components.nvidiaContainerToolkit.minimum)
if [[ "$DOCKER_RECOMMENDED_MIN" == "unknown" || "$NVIDIA_CT_RECOMMENDED_MIN" == "unknown" ]]; then
    print_warn "Container version recommendations unavailable: the minimum version table could not be read"
    print_detail "Docker: ${DOCKER_RECOMMENDED_MIN}, NVIDIA Container Toolkit: ${NVIDIA_CT_RECOMMENDED_MIN}"
    print_detail "Versions stay not-verified (false) rather than being graded against a guessed minimum"
fi
DOCKER_NVIDIA_RUNTIME_CONFIGURED="false"
RUNC_INSTALLED="false"
RUNC_VERSION="unknown"
SECURITY_DOCKER_VERSION="unknown"
SECURITY_NCT_VERSION="unknown"
SECURITY_RUNC_VERSION="unknown"
ENROOT_INSTALLED="false"
ENROOT_VERSION="unknown"
ENROOT_IMPORT_WORKS="false"
SINGULARITY_INSTALLED="false"
SINGULARITY_VERSION="unknown"

# Honor the same worker-step TMPDIR opt-in as the bench launcher
# (CLUSTERMAX_STEP_TMPDIR in bench/harnesses/slurm/default.sbatch). On
# clusters whose worker /tmp is an overlayfs pod root, enroot's aufs2ovlfs
# cannot create OCI whiteouts there (mknod returns EPERM), so image imports
# fail and these checks would report a broken container runtime that the
# actual campaign, running with the same knob, does not have. Forward the
# knob explicitly: a restrictive SLURM_EXPORT_ENV would otherwise strip it.
AUDIT_STEP_TMPDIR_EXPORT_ARGS=()
if [[ -n "${CLUSTERMAX_STEP_TMPDIR:-}" ]]; then
    AUDIT_STEP_TMPDIR_EXPORT_ARGS=(--export="ALL,CLUSTERMAX_STEP_TMPDIR=${CLUSTERMAX_STEP_TMPDIR},TMPDIR=${CLUSTERMAX_STEP_TMPDIR}")
fi

if [[ -n "$GPU_PARTITION" && -f "$WORKLOAD_DIR/container-check.sh" ]]; then
    print_section "Container Runtime on Compute Node"
    # Delivered over srun stdin (no shared $HOME required); see the host-check
    # note above and the matching K8s audit pattern.
    CONTAINER_CHECK_OUTPUT=$(srun "${AUDIT_SRUN_FLAGS[@]}" "${GPU_SRUN_SCOPE_ARGS[@]}" \
        "${AUDIT_STEP_TMPDIR_EXPORT_ARGS[@]}" \
        -N1 --ntasks=1 --gres=gpu:1 --time=2:00 \
        bash -s < "$WORKLOAD_DIR/container-check.sh" 2>/dev/null || echo "SRUN_FAILED")

    if [[ "$CONTAINER_CHECK_OUTPUT" != "SRUN_FAILED" ]] && \
            grep -q '^WORKER_CONTAINER_HOSTNAME=' <<< "$CONTAINER_CHECK_OUTPUT"; then
        CONTAINER_WORKER_CHECK_OK="true"
        while IFS='=' read -r key val; do
            case "$key" in
                WORKER_CONTAINER_HOSTNAME|WORKER_CONTAINER_RUNTIME_SCOPE|WORKER_CONTAINER_DOCKER_INSTALLED|WORKER_CONTAINER_DOCKER_PATH|WORKER_CONTAINER_DOCKER_VERSION|WORKER_CONTAINER_DOCKER_SERVER_VERSION|WORKER_CONTAINER_DOCKER_ACCESSIBLE|WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED|WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED|WORKER_CONTAINER_NVIDIA_TOOLKIT_PATH|WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION|WORKER_CONTAINER_RUNC_INSTALLED|WORKER_CONTAINER_RUNC_PATH|WORKER_CONTAINER_RUNC_VERSION|WORKER_CONTAINER_SECURITY_DOCKER_VERSION|WORKER_CONTAINER_SECURITY_NCT_VERSION|WORKER_CONTAINER_SECURITY_RUNC_VERSION|WORKER_CONTAINER_ENROOT_INSTALLED|WORKER_CONTAINER_ENROOT_PATH|WORKER_CONTAINER_ENROOT_VERSION|WORKER_CONTAINER_ENROOT_IMPORT|WORKER_CONTAINER_SINGULARITY_INSTALLED|WORKER_CONTAINER_SINGULARITY_PATH|WORKER_CONTAINER_SINGULARITY_VERSION)
                    printf -v "$key" '%s' "$val"
                    ;;
            esac
        done < <(grep '^WORKER_CONTAINER_' <<< "$CONTAINER_CHECK_OUTPUT")

        CONTAINER_WORKER_NODE="${WORKER_CONTAINER_HOSTNAME}"
        DOCKER_INSTALLED="${WORKER_CONTAINER_DOCKER_INSTALLED:-false}"
        DOCKER_ON_WORKERS="${WORKER_CONTAINER_DOCKER_ACCESSIBLE:-false}"
        DOCKER_VERSION="${WORKER_CONTAINER_DOCKER_VERSION:-unknown}"
        NVIDIA_CONTAINER_TOOLKIT="${WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED:-false}"
        NVIDIA_CT_VERSION="${WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION:-unknown}"
        DOCKER_NVIDIA_RUNTIME_CONFIGURED="${WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED:-false}"
        RUNC_INSTALLED="${WORKER_CONTAINER_RUNC_INSTALLED:-false}"
        RUNC_VERSION="${WORKER_CONTAINER_RUNC_VERSION:-unknown}"
        SECURITY_DOCKER_VERSION="${WORKER_CONTAINER_SECURITY_DOCKER_VERSION:-unknown}"
        SECURITY_NCT_VERSION="${WORKER_CONTAINER_SECURITY_NCT_VERSION:-unknown}"
        SECURITY_RUNC_VERSION="${WORKER_CONTAINER_SECURITY_RUNC_VERSION:-unknown}"
        ENROOT_INSTALLED="${WORKER_CONTAINER_ENROOT_INSTALLED:-false}"
        ENROOT_VERSION="${WORKER_CONTAINER_ENROOT_VERSION:-unknown}"
        SINGULARITY_INSTALLED="${WORKER_CONTAINER_SINGULARITY_INSTALLED:-false}"
        SINGULARITY_VERSION="${WORKER_CONTAINER_SINGULARITY_VERSION:-unknown}"
        # version_meets_minimum, not version_ge: an unresolved minimum must leave
        # these false (not verified) instead of passing every version.
        version_meets_minimum "$DOCKER_VERSION" "$DOCKER_RECOMMENDED_MIN" && DOCKER_VERSION_OK="true"
        version_meets_minimum "$NVIDIA_CT_VERSION" "$NVIDIA_CT_RECOMMENDED_MIN" && NVIDIA_CT_VERSION_OK="true"
        # Recommended enroot minimum is 3.4.0 (matches the standalone collector's gate).
        [[ "${WORKER_CONTAINER_ENROOT_IMPORT:-}" == "pass" ]] && ENROOT_IMPORT_WORKS="true"

        print_info "Worker container check: ${CONTAINER_WORKER_NODE}"
        if [[ "$DOCKER_ON_WORKERS" == "true" ]]; then
            print_info "Docker: ${DOCKER_VERSION} (available to the audit user)"
        elif [[ "$DOCKER_INSTALLED" == "true" ]]; then
            print_warn "Docker: installed but the audit user cannot query the worker daemon"
        else
            print_warn "Docker: not installed on worker"
        fi
        [[ "$NVIDIA_CONTAINER_TOOLKIT" == "true" ]] && print_info "NVIDIA Container Toolkit: ${NVIDIA_CT_VERSION}" || print_warn "NVIDIA Container Toolkit: not found on worker"
        [[ "$ENROOT_INSTALLED" == "true" ]] && print_info "Enroot: ${ENROOT_VERSION}; import=${WORKER_CONTAINER_ENROOT_IMPORT}" || print_warn "Enroot: not found on worker"
        [[ "$SINGULARITY_INSTALLED" == "true" ]] && print_info "Singularity/Apptainer: ${SINGULARITY_VERSION}" || print_warn "Singularity/Apptainer: not found on worker"
    else
        print_warn "Worker container check could not run (no idle GPU node, inaccessible partition, or timeout) - Docker / NVIDIA runtime unverified from this vantage; not evidence of absence, provider attestation required"
    fi
else
    print_warn "Worker container check skipped (no GPU partition or check script unavailable) - Docker / NVIDIA runtime unverified from this vantage; not evidence of absence"
fi

# Head-vs-worker consistency for container runtimes (additive; the worker check
# above stays authoritative). These lightweight login-node checks exist only to
# flag a split install between node classes, which operators need called out
# while access is live. Only meaningful when the worker check actually ran.
if [[ "$CONTAINER_WORKER_CHECK_OK" == "true" ]]; then
    # NVIDIA Container Toolkit. Mirror container-check.sh's worker-side
    # detection exactly (command names on PATH, package managers, then a
    # configured Docker nvidia runtime), so the head-node check never disagrees
    # with the worker purely because it checked fewer signals. That mismatch
    # would raise a false split-install warning.
    NVIDIA_CT_ON_WORKERS="${WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED:-false}"
    NVIDIA_CT_ON_HEAD="false"
    NCT_HEAD_NVIDIA_RUNTIME_CONFIGURED="false"
    NCT_HEAD_PATH=$(command -v nvidia-container-toolkit 2>/dev/null \
        || command -v nvidia-ctk 2>/dev/null \
        || command -v nvidia-container-runtime 2>/dev/null || true)
    NCT_HEAD_VERSION=""
    if [[ -z "$NCT_HEAD_PATH" ]] && command -v dpkg-query >/dev/null 2>&1; then
        NCT_HEAD_VERSION=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
    fi
    if [[ -z "$NCT_HEAD_PATH" && -z "$NCT_HEAD_VERSION" ]] && command -v rpm >/dev/null 2>&1; then
        NCT_HEAD_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' nvidia-container-toolkit 2>/dev/null || true)
    fi
    if command -v docker >/dev/null 2>&1; then
        NCT_HEAD_DOCKER_RUNTIMES=$(docker info --format '{{json .Runtimes}}' 2>/dev/null || true)
        if grep -qi nvidia <<< "$NCT_HEAD_DOCKER_RUNTIMES"; then
            NCT_HEAD_NVIDIA_RUNTIME_CONFIGURED="true"
        fi
    fi
    if [[ -n "$NCT_HEAD_PATH" || -n "$NCT_HEAD_VERSION" \
        || "$NCT_HEAD_NVIDIA_RUNTIME_CONFIGURED" == "true" ]]; then
        NVIDIA_CT_ON_HEAD="true"
    fi
    if [[ "$NVIDIA_CT_ON_HEAD" != "$NVIDIA_CT_ON_WORKERS" ]]; then
        print_warn "NVIDIA Container Toolkit: present on only one node class (head=${NVIDIA_CT_ON_HEAD}, workers=${NVIDIA_CT_ON_WORKERS})"
    fi

    # Singularity / Apptainer
    SINGULARITY_ON_WORKERS="${WORKER_CONTAINER_SINGULARITY_INSTALLED:-false}"
    SINGULARITY_ON_HEAD="false"
    if command -v singularity >/dev/null 2>&1 || command -v apptainer >/dev/null 2>&1; then
        SINGULARITY_ON_HEAD="true"
    fi
    if [[ "$SINGULARITY_ON_HEAD" != "$SINGULARITY_ON_WORKERS" ]]; then
        print_warn "Singularity/Apptainer: present on only one node class (head=${SINGULARITY_ON_HEAD}, workers=${SINGULARITY_ON_WORKERS})"
    fi
fi

# =============================================================================
# SECTION 7: Networking & InfiniBand
# =============================================================================
print_header "7. NETWORKING & INFINIBAND"
print_detail "NOTE: IB device checks use WORKER NODE data from check (compute node HCAs, not head node management NIC)"

# IB device data comes from worker check; head-node ibstat/ibhosts are only fallback
IB_INSTALLED="false"
RDMA_TYPE="none"
HCA_DEVICES_LIST=()
HCA_DEVICES_JSON="[]"
MLNX_DEVICES="none"

# MOFED version - from worker check. The login node often has only a management
# NIC and no MOFED, so a head-node check misreports clusters whose workers have it.
print_section "MOFED (Mellanox OFED) (on compute node)"
MOFED_VERSION="none"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    MOFED_VERSION="${WORKER_MOFED_VERSION:-none}"
    MOFED_FLAVOR="${WORKER_MOFED_FLAVOR:-none}"
    MLX5_DRIVER_VERSION="${WORKER_MLX5_DRIVER_VERSION:-unknown}"
    case "$MOFED_VERSION" in
        none)    print_warn "MOFED: Not detected on compute node ${WORKER_HOSTNAME} (ofed_info / /etc/mlnx-release absent, no MLNX rdma-core)" ;;
        unknown) print_warn "MOFED: present on compute node ${WORKER_HOSTNAME} but version could not be parsed" ;;
        DOCA-OFED*)
                 print_info "Mellanox fabric stack: ${MOFED_VERSION} (compute node ${WORKER_HOSTNAME})"
                 print_detail "DOCA-OFED replaces classic MLNX_OFED; ofed_info and /etc/mlnx-release are absent by design" ;;
        *)       print_info "MOFED Version: ${MOFED_VERSION} (compute node ${WORKER_HOSTNAME})" ;;
    esac
    [[ "$MLX5_DRIVER_VERSION" != unknown ]] && print_detail "mlx5_core driver: ${MLX5_DRIVER_VERSION}"
else
    # No head-node fallback: the login node is often management-only (no MOFED),
    # and a failed worker check aborts publishing anyway.
    print_warn "MOFED: skipped (worker check unavailable; not checking head node)"
fi

# InfiniBand devices - use worker check (compute nodes have HPC fabric HCAs)
print_section "InfiniBand Devices (on compute node)"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ -n "$WORKER_IB_DEVICES" ]]; then
        IB_INSTALLED="true"
        RDMA_TYPE="infiniband"
        MLNX_DEVICES="$WORKER_IB_DEVICES"
        IFS=',' read -ra HCA_DEVICES_LIST <<< "$WORKER_IB_DEVICES"
        HCA_DEVICES_JSON=$(printf '%s\n' "${HCA_DEVICES_LIST[@]}" | jq -R . | jq -s .)
        print_info "IB devices on ${WORKER_HOSTNAME}: ${WORKER_IB_DEVICES}"
        # Print per-device rate and state from check variables
        for dev in "${HCA_DEVICES_LIST[@]}"; do
            rate_var="WORKER_IB_RATE_${dev}"
            state_var="WORKER_IB_STATE_${dev}"
            print_detail "  ${dev}: rate=${!rate_var:-unknown} Gb/s, state=${!state_var:-unknown}"
        done
    else
        print_warn "No IB devices found on compute node ${WORKER_HOSTNAME}"
    fi
else
    print_warn "Worker check unavailable - falling back to HEAD NODE ibstat"
    print_detail "HEAD NODE HCAs may be management NICs, not the HPC fabric used by GPU jobs"
    if command -v ibstat &>/dev/null; then
        IB_DEV_RAW=$(ibstat -l 2>/dev/null | grep -v bond || echo "")
        if [[ -n "$IB_DEV_RAW" ]]; then
            IB_INSTALLED="true"
            RDMA_TYPE="infiniband"
            while IFS= read -r dev; do
                [[ -z "$dev" ]] && continue
                HCA_DEVICES_LIST+=("$dev")
            done <<< "$IB_DEV_RAW"
            MLNX_DEVICES=$(IFS=','; echo "${HCA_DEVICES_LIST[*]}")
            HCA_DEVICES_JSON=$(printf '%s\n' "${HCA_DEVICES_LIST[@]}" | jq -R . | jq -s .)
            print_warn "HEAD NODE IB devices: ${MLNX_DEVICES}"
        else
            print_warn "No IB devices on head node (and worker check unavailable)"
        fi
    else
        print_warn "ibstat not available on head node; install infiniband-diags"
    fi
fi

# HCA Naming Validation - mlx5_N standard required for NCCL auto-detection
print_section "HCA Naming Validation (NCCL auto-detection)"
HCA_NAMING_VALID="false"
HCA_NON_STANDARD=()

if [[ ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    HCA_ROCE_RAILS=()
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        if [[ "$dev" =~ ^mlx5_[0-9]+$ ]]; then
            : # standard mlx5_N - NCCL auto-detects
        elif [[ "$dev" =~ ^roce_p[0-9]+_rail[0-9]+$ ]]; then
            HCA_ROCE_RAILS+=("$dev")  # B300 RoCE rail naming - valid but needs NCCL_IB_HCA
        else
            HCA_NON_STANDARD+=("$dev")
        fi
    done
    if [[ ${#HCA_NON_STANDARD[@]} -eq 0 ]]; then
        HCA_NAMING_VALID="true"
        if [[ ${#HCA_ROCE_RAILS[@]} -gt 0 ]]; then
            print_info "HCA naming: ${#HCA_ROCE_RAILS[@]} B300 RoCE rails (roce_pN_railN) + mlx5_N devices"
            print_detail "B300 RoCE rails require explicit: NCCL_IB_HCA=^mlx5 (or list rails explicitly)"
            print_detail "NCCL will NOT auto-detect roce_p* devices without NCCL_IB_HCA set"
        else
            print_info "HCA naming: All ${#HCA_DEVICES_LIST[@]} devices use standard mlx5_N naming"
            print_detail "NCCL will auto-detect these devices without NCCL_IB_HCA override"
        fi
    else
        print_error "HCA naming: Non-standard device names: ${HCA_NON_STANDARD[*]}"
        print_detail "Names like ibp*, rdmap*, or mlx4_* prevent NCCL IB auto-detection"
        print_detail "Fix: rename devices to mlx5_N, OR set NCCL_IB_HCA=<device_list> explicitly"
    fi
else
    print_warn "No IB devices available to validate naming"
fi

# IB PKey Check - use worker check data
print_section "IB Partition Key (PKey) Configuration"
IB_PKEYS_CONFIGURED="false"
IB_PKEY_COUNT=0
ROCE_MODE="false"

if [[ "$WORKER_CHECK_OK" == "true" && ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        pkey_var="WORKER_PKEYS_${dev}"
        pkey_val="${!pkey_var:-}"
        print_detail "PKeys for ${dev}: ${pkey_val:-none}"
        if [[ -n "$pkey_val" ]]; then
            IFS=',' read -ra pkeys <<< "$pkey_val"
            for pk in "${pkeys[@]}"; do
                if [[ "$pk" =~ ^0xffff$|^0x8001$ ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    print_detail "  ${pk} (default partition - PASS)"
                elif [[ "$pk" =~ ^0x[78a][0-9a-fA-F]{3}$ ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    IB_PKEY_COUNT=$((IB_PKEY_COUNT + 1))
                    print_detail "  ${pk} (custom tenant partition key)"
                else
                    print_detail "  ${pk}"
                fi
            done
        else
            print_error "  ${dev}: No valid PKeys found - tenant isolation not configured"
        fi
    done
    [[ "$IB_PKEYS_CONFIGURED" == "true" ]] && print_info "IB PKeys: Configured" || print_warn "IB PKeys: No valid partition keys found"
elif [[ ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    # Head-node fallback: read sysfs directly
    print_warn "Reading PKeys from head node sysfs (may be management fabric, not HPC fabric)"
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        PKEY_DIR="/sys/class/infiniband/${dev}/ports/1/pkeys"
        if [[ -d "$PKEY_DIR" ]]; then
            print_detail "PKeys for ${dev}:"
            pkey_seen=0
            for pf in "$PKEY_DIR"/*; do
                pkey_seen=$((pkey_seen + 1))
                [[ "$pkey_seen" -gt 16 ]] && break
                idx="${pf##*/}"
                pv=$(timeout 1s cat "$pf" 2>/dev/null | tr -d '[:space:]' || echo "")
                [[ "$pv" == "0x0000" ]] && continue
                if [[ "$pv" =~ ^0xffff$|^0x8001$ ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    print_detail "  ${idx}: ${pv} (default partition)"
                elif [[ -n "$pv" ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    IB_PKEY_COUNT=$((IB_PKEY_COUNT + 1))
                    print_detail "  ${idx}: ${pv}"
                fi
            done
        fi
    done
fi

# RoCE vs IB Detection - use worker check data
print_section "RoCE vs InfiniBand Detection"
if [[ "$WORKER_CHECK_OK" == "true" && ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        roce_var="WORKER_ROCE_${dev}"
        if [[ "${!roce_var:-false}" == "true" ]]; then
            ROCE_MODE="true"
            RDMA_TYPE="roce"
            print_warn "${dev}: RoCE v2 GID types detected (this is RoCE, not native IB)"
            print_detail "Ensure NCCL_IB_GID_INDEX is set correctly for RoCEv2"
        else
            print_info "${dev}: Native InfiniBand (not RoCE)"
        fi
    done
elif [[ ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    # Head-node fallback
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        GID_DIR="/sys/class/infiniband/${dev}/ports/1/gid_attrs/types"
        if [[ -d "$GID_DIR" ]] && grep -rl "RoCE v2\|roce_v2\|RoCEv2" "$GID_DIR" 2>/dev/null | grep -q .; then
            ROCE_MODE="true"
            RDMA_TYPE="roce"
            print_warn "${dev}: RoCE v2 detected on head node"
        else
            print_info "${dev}: Not RoCE (head node sysfs)"
        fi
    done
else
    print_detail "No IB devices to check for RoCE"
fi

# NIC Fabric Classification
# Confirms each NIC is recorded as InfiniBand or RoCE (or EFA / Ethernet),
# and labels the fabric class so downstream consumers can spot misconfigured
# clusters (e.g., NDR cabled at HDR speeds, RoCE NIC reported as native IB).
# Classes:
#   InfiniBand: SDR/DDR/QDR/FDR/EDR/HDR/NDR/XDR + raw Gb/sec (HDR100 noted)
#   Ethernet:  ${rate}GbE [+ RoCEv2 when GID type indicates it]
#   AWS EFA:   PCI vendor 0x1d0f -> "EFA <rate>G"
#   Otherwise: "other" with link_layer + rate captured for triage.
print_section "NIC Fabric Classification"

# classify_nic_fabric link_layer rate_raw vendor_id roce_flag -> fabric class
NIC_FABRIC_JSON_ITEMS=()
declare -A NIC_FABRIC_COUNTS=()
NIC_HAS_INFINIBAND="false"
NIC_HAS_ROCE="false"
NIC_HAS_EFA="false"
NIC_HAS_OTHER="false"

if [[ ${#HCA_DEVICES_LIST[@]} -gt 0 ]]; then
    for dev in "${HCA_DEVICES_LIST[@]}"; do
        if [[ "$WORKER_CHECK_OK" == "true" ]]; then
            ll_var="WORKER_IB_LINK_LAYER_${dev}"
            rate_var="WORKER_IB_RATE_${dev}"
            vendor_var="WORKER_IB_PCI_VENDOR_${dev}"
            roce_var="WORKER_ROCE_${dev}"
            ll="${!ll_var:-unknown}"
            rate_raw="${!rate_var:-unknown}"
            vendor="${!vendor_var:-unknown}"
            roce_flag="${!roce_var:-false}"
        else
            ll=$(cat "/sys/class/infiniband/${dev}/ports/1/link_layer" 2>/dev/null || echo unknown)
            rate_raw=$(cat "/sys/class/infiniband/${dev}/ports/1/rate" 2>/dev/null || echo unknown)
            vendor=$(cat "/sys/class/infiniband/${dev}/device/vendor" 2>/dev/null || echo unknown)
            roce_flag="false"
            if [[ -d "/sys/class/infiniband/${dev}/ports/1/gid_attrs/types" ]] && \
               grep -rl "RoCE v2\|roce_v2\|RoCEv2" "/sys/class/infiniband/${dev}/ports/1/gid_attrs/types" 2>/dev/null | grep -q .; then
                roce_flag="true"
            fi
        fi

        fabric_class=$(classify_nic_fabric "$ll" "$rate_raw" "$vendor" "$roce_flag")
        gb_only=$(echo "$rate_raw" | grep -oE '^[0-9]+' | head -1)
        [[ -z "$gb_only" ]] && gb_only=0

        # Per-device line with everything an operator needs to verify cabling.
        if [[ "$vendor" == "0x1d0f" ]]; then
            print_info "  ${dev}: ${fabric_class} (vendor=AWS, rate='${rate_raw}')"
            NIC_HAS_EFA="true"
        elif [[ "$ll" == "InfiniBand" ]]; then
            print_info "  ${dev}: ${fabric_class} (link_layer=InfiniBand, rate='${rate_raw}')"
            NIC_HAS_INFINIBAND="true"
        elif [[ "$ll" == "Ethernet" ]]; then
            if [[ "$roce_flag" == "true" ]]; then
                print_info "  ${dev}: ${fabric_class} (link_layer=Ethernet, RoCEv2 GIDs present, rate='${rate_raw}')"
                NIC_HAS_ROCE="true"
            else
                print_info "  ${dev}: ${fabric_class} (link_layer=Ethernet, no RoCE GIDs, rate='${rate_raw}')"
            fi
        else
            print_warn "  ${dev}: ${fabric_class}"
            NIC_HAS_OTHER="true"
        fi

        NIC_FABRIC_COUNTS["$fabric_class"]=$(( ${NIC_FABRIC_COUNTS["$fabric_class"]:-0} + 1 ))

        NIC_FABRIC_JSON_ITEMS+=("$(jq -n \
            --arg device "$dev" \
            --arg linkLayer "$ll" \
            --arg rateRaw "$rate_raw" \
            --argjson rateGbps "${gb_only:-0}" \
            --arg vendorId "$vendor" \
            --arg fabricClass "$fabric_class" \
            --argjson roce "$([ "$roce_flag" = true ] && echo true || echo false)" \
            '{device:$device, linkLayer:$linkLayer, rateRaw:$rateRaw, rateGbps:$rateGbps, pciVendorId:$vendorId, fabricClass:$fabricClass, roceV2:$roce}')")
    done
else
    print_detail "No NICs to classify"
fi

# Roll-up: which fabric classes are present and how many of each.
NIC_FABRIC_SUMMARY=""
if [[ ${#NIC_FABRIC_COUNTS[@]} -gt 0 ]]; then
    print_detail ""
    print_detail "Fabric class roll-up:"
    for class in "${!NIC_FABRIC_COUNTS[@]}"; do
        cnt="${NIC_FABRIC_COUNTS[$class]}"
        print_detail "  ${cnt} x ${class}"
        if [[ -z "$NIC_FABRIC_SUMMARY" ]]; then
            NIC_FABRIC_SUMMARY="${cnt} x ${class}"
        else
            NIC_FABRIC_SUMMARY="${NIC_FABRIC_SUMMARY}, ${cnt} x ${class}"
        fi
    done
fi

# Pick the highest-rate non-EFA InfiniBand or RoCE class as the likely
# compute fabric (EFA is its own thing). Useful for the JSON roll-up.
COMPUTE_FABRIC_CLASS="unknown"
COMPUTE_FABRIC_COUNT=0
COMPUTE_FABRIC_GBPS=0
for class in "${!NIC_FABRIC_COUNTS[@]}"; do
    cnt="${NIC_FABRIC_COUNTS[$class]}"
    gb=$(echo "$class" | grep -oE '[0-9]+' | head -1)
    [[ -z "$gb" ]] && gb=0
    if [[ "$gb" -gt "$COMPUTE_FABRIC_GBPS" ]]; then
        COMPUTE_FABRIC_GBPS="$gb"
        COMPUTE_FABRIC_CLASS="$class"
        COMPUTE_FABRIC_COUNT="$cnt"
    fi
done
if [[ "$COMPUTE_FABRIC_CLASS" != "unknown" ]]; then
    print_info "Compute fabric (highest-rate class): ${COMPUTE_FABRIC_COUNT} x ${COMPUTE_FABRIC_CLASS}"
fi

# AWS EFA standalone detection: surface even when no IB sysfs entries present.
if [[ "$WORKER_CHECK_OK" == "true" && -n "${WORKER_EFA_DEVICES:-}" ]]; then
    NIC_HAS_EFA="true"
    print_info "AWS EFA devices: ${WORKER_EFA_DEVICES}"
elif [[ "${WORKER_EFA_LIBFABRIC:-false}" == "true" ]]; then
    print_detail "libfabric efa provider available (EFA tooling installed)"
fi

# Update RDMA_TYPE if EFA is the only fabric present.
if [[ "$NIC_HAS_EFA" == "true" && "$NIC_HAS_INFINIBAND" == "false" && "$NIC_HAS_ROCE" == "false" ]]; then
    RDMA_TYPE="efa"
fi

# Build NIC fabric JSON array (empty if no devices).
if [[ ${#NIC_FABRIC_JSON_ITEMS[@]} -gt 0 ]]; then
    NIC_FABRIC_JSON=$(printf '%s\n' "${NIC_FABRIC_JSON_ITEMS[@]}" | jq -s .)
else
    NIC_FABRIC_JSON="[]"
fi

print_section "RDMA / HCA Diagnostic Utilities"
NETUTILS_JSON_ENTRIES=()
add_netutil_status IBDEV2NETDEV ibdev2netdev
add_netutil_status IBV_DEVICES ibv_devices
add_netutil_status RDMA_LINK_SHOW rdmaLinkShow
add_netutil_status RDMA_DEV_SHOW rdmaDevShow
add_netutil_status IBSTAT ibstat
add_netutil_status IBSTATUS ibstatus
add_netutil_status LSPCI lspci
NETWORK_UTILITIES_JSON="{$(IFS=,; echo "${NETUTILS_JSON_ENTRIES[*]}")}"

# NCCL_IB_GID_INDEX value validation: RoCEv2 needs index 3 (Ethernet-typed GID).
# We already detect "is anything in /etc/nccl.conf" at line ~1457. Here we
# inspect the actual value and flag it against ROCE_MODE.
NCCL_GID_INDEX_VALUE="${WORKER_NCCL_GID_INDEX:-unset}"
if [[ "$ROCE_MODE" == "true" ]]; then
    if [[ "$NCCL_GID_INDEX_VALUE" == "3" ]]; then
        print_info "NCCL_IB_GID_INDEX=3 in /etc/nccl.conf (correct for RoCEv2)"
    elif [[ "$NCCL_GID_INDEX_VALUE" == "unset" || -z "$NCCL_GID_INDEX_VALUE" ]]; then
        print_error "NCCL_IB_GID_INDEX not set in /etc/nccl.conf (RoCEv2 needs =3)"
    else
        print_error "NCCL_IB_GID_INDEX=${NCCL_GID_INDEX_VALUE} - RoCEv2 expects 3"
    fi
elif [[ "$NCCL_GID_INDEX_VALUE" != "unset" && -n "$NCCL_GID_INDEX_VALUE" ]]; then
    print_detail "NCCL_IB_GID_INDEX=${NCCL_GID_INDEX_VALUE} (only meaningful for RoCEv2)"
fi

# IB Tenant Isolation - use worker check ibhosts data
print_section "IB Tenant Isolation"
IB_TENANT_ISOLATION="unknown"
if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ "${WORKER_IBHOSTS_COUNT:-0}" -gt 0 ]]; then
        print_info "ibhosts on compute node: ${WORKER_IBHOSTS_COUNT} hosts visible on fabric"
        print_detail "Verify ALL of these are your tenant's nodes (none should be external):"
        IFS='|' read -ra IBHOSTS_LINES <<< "$WORKER_IBHOSTS_SAMPLE"
        for line in "${IBHOSTS_LINES[@]}"; do
            [[ -n "$line" ]] && print_detail "  ${line}"
        done
        IB_TENANT_ISOLATION="pass"
    else
        print_warn "ibhosts returned 0 results on compute node (ibhosts not installed or fabric unreachable)"
    fi
else
    # Head-node fallback
    IBHOSTS_OUT=$(ibhosts 2>/dev/null | head -20 || echo "")
    if [[ -n "$IBHOSTS_OUT" ]]; then
        IBHOSTS_COUNT=$(ibhosts 2>/dev/null | wc -l || echo "0")
        print_warn "ibhosts on HEAD NODE: ${IBHOSTS_COUNT} hosts (may be management fabric, not HPC)"
        echo "$IBHOSTS_OUT" | head -5 | while IFS= read -r line; do print_detail "  ${line}"; done
        IB_TENANT_ISOLATION="pass"
    else
        print_warn "ibhosts not available; cannot verify tenant isolation"
    fi
fi

# saquery (requires sudo; run from head node or any IB-connected node)
SAQUERY_OUT=$(sudo -n saquery NodeRecord 2>/dev/null | grep NodeDescription | wc -l | tr -d '[:space:]' || echo "0")
if [[ "$SAQUERY_OUT" -gt 0 ]]; then
    print_info "saquery NodeRecord: ${SAQUERY_OUT} node records visible via SM"
    print_detail "Verify this count matches your allocated nodes (no external tenants visible)"
else
    print_detail "saquery: Requires sudo or SM access - run manually: sudo saquery NodeRecord | grep NodeDescription"
fi

# SMKey / SAKey / OpenSM check
print_section "Subnet Manager & SM Key"
IB_SM_KEY_CONFIGURED="false"
OPENSM_CONF="/etc/opensm/opensm.conf"

SMINFO_OUT=$(sminfo 2>/dev/null); SMINFO_RC=$?
if [[ $SMINFO_RC -eq 0 && -n "$SMINFO_OUT" ]]; then
    SM_LID=$(echo "$SMINFO_OUT" | grep -oP 'LID \K[0-9]+' | head -1 || echo "unknown")
    print_info "SM info: ${SMINFO_OUT}"
    print_info "SM LID: ${SM_LID}"
    # Check if this node is running SM (it should NOT be a compute node running SM)
    if pgrep -x opensm &>/dev/null; then
        print_warn "OpenSM: Running on this node - ensure this is the designated SM node, not a compute node"
    else
        print_info "OpenSM: Not running on this node (correct for compute/login nodes)"
    fi
fi

if [[ -f "$OPENSM_CONF" ]]; then
    SM_KEY_VAL=$(grep "^sm_key" "$OPENSM_CONF" 2>/dev/null | awk '{print $2}' | head -1 || echo "")
    if [[ -n "$SM_KEY_VAL" && "$SM_KEY_VAL" != "0x0000000000000000" && "$SM_KEY_VAL" != "0" ]]; then
        IB_SM_KEY_CONFIGURED="true"
        print_info "OpenSM SM_KEY: Non-zero (configured) - good for security"
    else
        print_warn "OpenSM SM_KEY: Zero or unset at ${OPENSM_CONF} - SM key not secured"
    fi
else
    print_detail "OpenSM config: Not at ${OPENSM_CONF} (may be on SM node only)"
fi

# SHARP check - from worker check. sharp_hello, the SHARP tree, and the AM-key
# config are compute/fabric-node properties; the login node may lack them.
print_section "SHARP (Scalable Hierarchical Aggregation and Reduction Protocol)"
SHARP_AVAILABLE="false"
SHARP_AM_KEY_CONFIGURED="false"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ -n "${WORKER_SHARP_HELLO_PATH:-}" ]]; then
        SHARP_AVAILABLE="true"
        print_info "sharp_hello: Found at ${WORKER_SHARP_HELLO_PATH} (compute node ${WORKER_HOSTNAME})"
    elif [[ "${WORKER_SHARP_ENV:-false}" == "true" ]]; then
        SHARP_AVAILABLE="true"
        print_info "SHARP env vars set on compute node ${WORKER_HOSTNAME}"
    else
        print_warn "SHARP: Not detected on compute node ${WORKER_HOSTNAME} (sharp_hello not found, no SHARP env vars)"
        print_detail "SHARP enables in-network compute reductions - confirm with provider if available"
    fi
    if [[ "${WORKER_SHARP_AM_KEY_CONFIGURED:-false}" == "true" ]]; then
        SHARP_AM_KEY_CONFIGURED="true"
        print_info "SHARP AM Key: Configured (${WORKER_SHARP_CONF:-unknown})"
    elif [[ -n "${WORKER_SHARP_CONF:-}" ]]; then
        print_warn "SHARP AM Key: Not configured in ${WORKER_SHARP_CONF}"
    fi
else
    # No head-node fallback: SHARP tooling/config lives on compute/fabric nodes,
    # and a failed worker check aborts publishing anyway.
    print_warn "SHARP: skipped (worker check unavailable; not checking head node)"
fi

audit_ufm_secured_profile "$RDMA_TYPE"

# Topology configuration (enhanced for B300)
print_section "SLURM Topology"
TOPOLOGY_CONF=$(echo "$SLURM_CONFIG_FULL" | grep "TopologyPlugin" | awk '{print $3}')
if [[ -n "$TOPOLOGY_CONF" && "$TOPOLOGY_CONF" != "(null)" ]]; then
    print_info "TopologyPlugin: ${TOPOLOGY_CONF}"

    # topology/tree and topology/block are both optimized for B300 NVSwitch.
    # Slurm 25.05+ topology.yaml can define multiple topologies (tree and/or block)
    # selected per-partition; the active plugin still reports via TopologyPlugin.
    if [[ "$TOPOLOGY_CONF" == "topology/tree" ]]; then
        print_info "Topology plugin is tree - optimal for B300 NVSwitch topology"
    elif [[ "$TOPOLOGY_CONF" == "topology/block" ]]; then
        print_info "Topology plugin is block - optimal for B300 NVSwitch topology"
    elif [[ "$TOPOLOGY_CONF" == "topology/none" || "$TOPOLOGY_CONF" == "topology/linear" || "$TOPOLOGY_CONF" == "topology/flat" ]]; then
        print_warn "TopologyPlugin=${TOPOLOGY_CONF}: NCCL routing will not be optimized"
        print_detail "B300 nodes with NVSwitch require topology/tree or topology/block for correct routing"
        print_detail "Set TopologyPlugin=topology/tree (or topology/block) and configure topology.conf or topology.yaml"
    fi

    # Resolve candidate Slurm config directories. topology.{conf,yaml} must live in
    # the same directory as slurm.conf, so derive that dir first, then fall back to
    # the common locations used across distros / packaging.
    TOPO_SEARCH_DIRS=()
    if [[ -n "${SLURM_CONF_FILE:-}" && "$SLURM_CONF_FILE" != "/dev/null" && -f "$SLURM_CONF_FILE" ]]; then
        TOPO_SEARCH_DIRS+=("$(dirname "$SLURM_CONF_FILE")")
    fi
    if [[ -n "${SLURM_CONF:-}" && -f "${SLURM_CONF}" ]]; then
        TOPO_SEARCH_DIRS+=("$(dirname "${SLURM_CONF}")")
    fi
    TOPO_SEARCH_DIRS+=(/etc/slurm /etc/slurm-llnl /usr/local/etc/slurm /etc/slurm/conf)

    # Locate the active topology file. topology.yaml takes precedence over
    # topology.conf (per Slurm: if topology.yaml exists, topology.conf is ignored).
    TOPO_FILE=""
    TOPO_FILE_KIND=""
    _topo_seen_dirs=""
    for d in "${TOPO_SEARCH_DIRS[@]}"; do
        [[ -z "$d" ]] && continue
        case "$_topo_seen_dirs" in *"|$d|"*) continue ;; esac
        _topo_seen_dirs="${_topo_seen_dirs}|$d|"
        if [[ -f "$d/topology.yaml" ]]; then
            TOPO_FILE="$d/topology.yaml"; TOPO_FILE_KIND="yaml"; break
        elif [[ -f "$d/topology.conf" && -z "$TOPO_FILE" ]]; then
            TOPO_FILE="$d/topology.conf"; TOPO_FILE_KIND="conf"
            # keep scanning: a later dir may have topology.yaml (higher precedence)
        fi
    done

    # Prefer live data from scontrol; fall back to reading the located file directly
    # (useful when scontrol is restricted for end-users).
    TOPO_OUTPUT=""
    TOPO_SOURCE=""
    if [[ "$SCONTROL_OK" == "true" ]] && scontrol show topo &>/dev/null 2>&1; then
        TOPO_OUTPUT=$(scontrol show topo 2>/dev/null || echo "")
        TOPO_SOURCE="scontrol show topology"
    elif [[ -n "$TOPO_FILE" ]]; then
        TOPO_OUTPUT=$(cat "$TOPO_FILE" 2>/dev/null || echo "")
        TOPO_SOURCE="$TOPO_FILE"
    fi

    if [[ -n "$TOPO_FILE" ]]; then
        print_info "Topology definition file: ${TOPO_FILE} (${TOPO_FILE_KIND})"
    else
        print_warn "No topology.conf or topology.yaml found in: ${TOPO_SEARCH_DIRS[*]}"
    fi

    if [[ -n "$TOPO_OUTPUT" ]]; then
        [[ -n "$TOPO_SOURCE" ]] && print_detail "Topology source: ${TOPO_SOURCE}"
        # Count topology units across formats. topology/tree conf + scontrol use
        # SwitchName; topology/block conf + scontrol use BlockName (this was
        # previously not counted, so a valid topology/block config with defined
        # blocks reported 0 units and false-warned); topology.yaml lists switches
        # (tree) / blocks (block) as '- switch:' / '- block:' list items (the bare
        # 'block:'/'tree:' plugin-type keys are NOT counted).
        # grep -c prints '0' and exits non-zero on no match, so coerce to a single int.
        _topo_count() { local n; n=$(printf '%s\n' "$1" | grep -cE "$2"); printf '%s' "${n:-0}"; }
        TOPO_SWITCHES=$(_topo_count "$TOPO_OUTPUT" "SwitchName")
        TOPO_BLOCKS=$(_topo_count "$TOPO_OUTPUT" "BlockName")
        TOPO_YAML_SWITCHES=$(_topo_count "$TOPO_OUTPUT" "^[[:space:]]*-[[:space:]]+switch:")
        TOPO_YAML_BLOCKS=$(_topo_count "$TOPO_OUTPUT" "^[[:space:]]*-[[:space:]]+block:")
        TOPO_UNITS=$(( TOPO_SWITCHES + TOPO_BLOCKS + TOPO_YAML_SWITCHES + TOPO_YAML_BLOCKS ))
        print_info "Configured topology units (switches/blocks): ${TOPO_UNITS}"
        if [[ "$TOPO_UNITS" -lt 1 ]]; then
            print_warn "No switches or blocks in topology - a multi-node cluster should define at least 1 switch/block"
        fi

        # Show topology entries (conf SwitchName / BlockName lines + yaml topology:/switch:/block: list items)
        echo "$TOPO_OUTPUT" | grep -E "SwitchName|BlockName|^[[:space:]]*-[[:space:]]+topology:|^[[:space:]]*-[[:space:]]+switch:|^[[:space:]]*-[[:space:]]+block:" | while IFS= read -r tline; do
            print_detail "  ${tline}"
        done

        # Verify GPU nodes appear in topology (handles SLURM bracket range notation)
        if [[ -n "$GPU_PARTITION" && "$GPU_PARTITION" != "none" ]]; then
            # Expand all Nodes= entries from topology.conf into a flat list of node names
            # Handles patterns like: aic-gb3a-[310001-310025] or node[01-04],node05
            _expand_slurm_range() {
                local spec="$1"
                local prefix="" suffix="" range_part=""
                if [[ "$spec" =~ ^([^[]*)\[([0-9]+-[0-9]+)\](.*)$ ]]; then
                    prefix="${BASH_REMATCH[1]}"
                    range_part="${BASH_REMATCH[2]}"
                    suffix="${BASH_REMATCH[3]}"
                    local lo="${range_part%%-*}" hi="${range_part##*-}"
                    local width=${#lo}
                    for ((n=10#$lo; n<=10#$hi; n++)); do
                        printf '%s%0*d%s\n' "$prefix" "$width" "$n" "$suffix"
                    done
                else
                    echo "$spec"
                fi
            }

            # Build expanded node list from topology. Handles both:
            #   conf/scontrol:  Nodes=node[01-04],node05
            #   topology.yaml:  nodes: node[01-04]
            TOPO_EXPANDED=""
            while IFS= read -r tline; do
                # Extract the node spec after 'Nodes=' (conf) or 'nodes:' (yaml)
                node_specs=$(echo "$tline" | grep -oiP '(?<=Nodes=)\S+' || echo "")
                if [[ -z "$node_specs" ]]; then
                    node_specs=$(echo "$tline" | grep -oiP '(?<=nodes:)\s*\S+' | tr -d ' ' || echo "")
                fi
                [[ -z "$node_specs" ]] && continue
                IFS=',' read -ra specs <<< "$node_specs"
                for spec in "${specs[@]}"; do
                    TOPO_EXPANDED+=$'\n'"$(_expand_slurm_range "$spec")"
                done
            done <<< "$(echo "$TOPO_OUTPUT" | grep -iE 'Nodes=|nodes:')"

            GPU_NODES=$(sudo -n /usr/local/bin/snodes 2>/dev/null | grep "$GPU_PARTITION" | awk '{print $NF}' | tr ',' '\n' | sort -u || echo "")
            TOPO_MISSING=()
            while IFS= read -r gnode; do
                [[ -z "$gnode" ]] && continue
                # Check literal match OR presence in the expanded topology node list
                if ! echo "$TOPO_OUTPUT" | grep -qF "$gnode" && \
                   ! echo "$TOPO_EXPANDED" | grep -qxF "$gnode"; then
                    TOPO_MISSING+=("$gnode")
                fi
            done <<< "$GPU_NODES"
            if [[ ${#TOPO_MISSING[@]} -gt 0 ]]; then
                print_warn "GPU nodes not in topology: ${TOPO_MISSING[*]}"
            else
                [[ -n "$GPU_NODES" ]] && print_info "All GPU partition nodes appear in topology"
            fi
        fi
    fi  # end TOPO_OUTPUT
else
    print_warn "TopologyPlugin: Not configured (NCCL routing will not be optimized)"
    print_detail "B300 with NVSwitch: set TopologyPlugin=topology/tree (or topology/block) and define topology.conf or topology.yaml"
    print_detail "Verify the live topology with: scontrol show topology"
fi

# =============================================================================
# SECTION 8: Storage & Filesystem (Head Node Drive Config)
# =============================================================================
print_header "8. STORAGE & FILESYSTEM"

# --- Head node boot drive ---
print_section "Boot Drive (head node)"
HEAD_BOOT_DEV=""
HEAD_BOOT_FSTYPE=""
HEAD_BOOT_SIZE=""

if command -v findmnt &>/dev/null; then
    HEAD_BOOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || echo "unknown")
    HEAD_BOOT_FSTYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || echo "unknown")
else
    HEAD_BOOT_DEV=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
    HEAD_BOOT_FSTYPE=$(df -T / 2>/dev/null | tail -1 | awk '{print $2}')
fi
HEAD_BOOT_SIZE=$(df -h / 2>/dev/null | tail -1 | awk '{print $2}')
HEAD_BOOT_DEV="${HEAD_BOOT_DEV:-unknown}"
HEAD_BOOT_FSTYPE="${HEAD_BOOT_FSTYPE:-unknown}"
HEAD_BOOT_SIZE="${HEAD_BOOT_SIZE:-unknown}"
print_info "Device: ${HEAD_BOOT_DEV}"
print_info "Filesystem: ${HEAD_BOOT_FSTYPE}"
print_info "Size: ${HEAD_BOOT_SIZE}"

# --- Head node block devices ---
print_section "Block Devices (head node)"
HEAD_BLKDEV_JSON="["
HEAD_BLKDEV_FIRST="true"

if command -v lsblk &>/dev/null; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        NAME="" TYPE="" SIZE="" MOUNTPOINT="" FSTYPE="" TRAN=""
        eval "$line" 2>/dev/null || continue
        [[ -z "$NAME" ]] && continue

        transport="${TRAN}"
        [[ -z "$transport" ]] && case "$NAME" in nvme*) transport="nvme";; sd*) transport="sata";; vd*) transport="virtio";; *) transport="unknown";; esac
        classification="other"
        case "$NAME" in nvme*) classification="local-nvme";; sd*) classification="local-sata";; vd*|xvd*) classification="virtual-disk";; esac
        [[ "$MOUNTPOINT" == "/" || "$MOUNTPOINT" == "/boot" || "$MOUNTPOINT" == "/boot/efi" ]] && classification="boot"
        size_human=""
        if command -v numfmt &>/dev/null && [[ -n "$SIZE" && "$SIZE" != "0" ]]; then
            size_human=$(numfmt --to=iec --suffix=B "$SIZE" 2>/dev/null || echo "$SIZE")
        else
            size_human="${SIZE}"
        fi

        print_info "${NAME}: ${TYPE}, ${size_human}, ${transport}, ${classification}"
        [[ -n "$MOUNTPOINT" ]] && print_detail "Mounted at: ${MOUNTPOINT} (${FSTYPE})"

        [[ "$HEAD_BLKDEV_FIRST" == "true" ]] && HEAD_BLKDEV_FIRST="false" || HEAD_BLKDEV_JSON+=","
        HEAD_BLKDEV_JSON+="{\"name\":\"${NAME}\",\"type\":\"${TYPE}\",\"size\":\"${size_human}\",\"sizeBytes\":${SIZE:-0},\"transport\":\"${transport}\",\"mountpoint\":\"${MOUNTPOINT}\",\"fstype\":\"${FSTYPE}\",\"classification\":\"${classification}\"}"
    done < <(lsblk -d -b -o NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,TRAN -P -n 2>/dev/null)
else
    print_warn "lsblk not available on head node"
fi
HEAD_BLKDEV_JSON+="]"

# --- Head node NVMe drives ---
print_section "NVMe Drives (head node)"
HEAD_NVME_COUNT=0
HEAD_NVME_TOTAL_GB=0
HEAD_NVME_DEVS_JSON="["

if command -v lsblk &>/dev/null; then
    HEAD_NVME_FIRST="true"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        NAME="" SIZE=""
        eval "$line" 2>/dev/null || continue
        [[ "$NAME" != nvme* ]] && continue
        HEAD_NVME_COUNT=$(( HEAD_NVME_COUNT + 1 ))
        HEAD_NVME_TOTAL_GB=$(( HEAD_NVME_TOTAL_GB + ${SIZE:-0} / 1073741824 ))
        [[ "$HEAD_NVME_FIRST" == "true" ]] && HEAD_NVME_FIRST="false" || HEAD_NVME_DEVS_JSON+=","
        HEAD_NVME_DEVS_JSON+="\"${NAME}\""
    done < <(lsblk -d -b -o NAME,SIZE -P -n 2>/dev/null)
fi
HEAD_NVME_DEVS_JSON+="]"

if [[ $HEAD_NVME_COUNT -gt 0 ]]; then
    print_info "${HEAD_NVME_COUNT} NVMe device(s), ${HEAD_NVME_TOTAL_GB} GB total"
else
    print_info "No NVMe devices on head node"
fi

# --- Head node shared mounts ---
print_section "Shared Filesystems (head node)"
SHARED_FS=()
HEAD_SHARED_MOUNTS_JSON="["
HEAD_SMNT_FIRST="true"

# Scan via findmnt for shared filesystem types
if command -v findmnt &>/dev/null; then
    while read -r target source fstype opts; do
        [[ -z "$target" ]] && continue
        SHARED_FS+=("${target}:${fstype}")
        df_line=$(df -h "$target" 2>/dev/null | tail -1)
        df_size=$(echo "$df_line" | awk '{print $2}')
        df_used=$(echo "$df_line" | awk '{print $3}')
        df_avail=$(echo "$df_line" | awk '{print $4}')
        print_info "${target}: ${fstype} (${df_size})"
        print_detail "Source: ${source}"
        [[ "$HEAD_SMNT_FIRST" == "true" ]] && HEAD_SMNT_FIRST="false" || HEAD_SHARED_MOUNTS_JSON+=","
        HEAD_SHARED_MOUNTS_JSON+="{\"mountpoint\":\"${target}\",\"fstype\":\"${fstype}\",\"source\":\"${source}\",\"size\":\"${df_size}\",\"used\":\"${df_used}\",\"available\":\"${df_avail}\",\"options\":\"${opts}\"}"
    done < <(findmnt -t nfs,nfs4,lustre,gpfs,ceph,glusterfs,fuse.weka,fuse.lustre,fuse.ceph,fuse.beegfs,beegfs,wekafs,panfs \
        -n -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null || true)
fi

# Also scan well-known paths
declare -A HEAD_SEEN_MOUNTS=()
for entry in "${SHARED_FS[@]}"; do
    mnt="${entry%%:*}"
    HEAD_SEEN_MOUNTS["$mnt"]=1
done

for mnt in /home /scratch /data /shared /work /projects /lustre /gpfs /weka /beegfs; do
    [[ -n "${HEAD_SEEN_MOUNTS[$mnt]:-}" ]] && continue
    if [[ -d "$mnt" ]] && mountpoint -q "$mnt" 2>/dev/null; then
        fstype=$(df -T "$mnt" 2>/dev/null | tail -1 | awk '{print $2}')
        case "$fstype" in
            nfs|nfs4|lustre|gpfs|wekafs|cephfs|glusterfs|beegfs|panfs|fuse.weka|fuse.lustre|fuse.ceph)
                source_dev=$(df "$mnt" 2>/dev/null | tail -1 | awk '{print $1}')
                df_line=$(df -h "$mnt" 2>/dev/null | tail -1)
                df_size=$(echo "$df_line" | awk '{print $2}')
                df_used=$(echo "$df_line" | awk '{print $3}')
                df_avail=$(echo "$df_line" | awk '{print $4}')
                opts=""
                command -v findmnt &>/dev/null && opts=$(findmnt -n -o OPTIONS "$mnt" 2>/dev/null || echo "")
                print_info "${mnt}: ${fstype} (${df_size})"
                SHARED_FS+=("${mnt}:${fstype}")
                [[ "$HEAD_SMNT_FIRST" == "true" ]] && HEAD_SMNT_FIRST="false" || HEAD_SHARED_MOUNTS_JSON+=","
                HEAD_SHARED_MOUNTS_JSON+="{\"mountpoint\":\"${mnt}\",\"fstype\":\"${fstype}\",\"source\":\"${source_dev}\",\"size\":\"${df_size}\",\"used\":\"${df_used}\",\"available\":\"${df_avail}\",\"options\":\"${opts}\"}"
                ;;
        esac
    fi
done
HEAD_SHARED_MOUNTS_JSON+="]"

if [[ ${#SHARED_FS[@]} -eq 0 ]]; then
    print_warn "No shared filesystems detected at common mount points"
fi

print_section "Home Directory"
HOME_DIR="$HOME"
if [[ -d "$HOME_DIR" ]]; then
    HOME_FS_TYPE=$(df -T "$HOME_DIR" 2>/dev/null | tail -1 | awk '{print $2}')
    HOME_QUOTA=$(quota -s 2>/dev/null | tail -1 | awk '{print $2}' || echo "unknown")
    print_info "Home: ${HOME_DIR}"
    print_info "Filesystem: ${HOME_FS_TYPE}"
    [[ "$HOME_QUOTA" != "unknown" ]] && print_info "Quota: ${HOME_QUOTA}"
else
    print_warn "Home directory not accessible"
fi

# =============================================================================
# SECTION 9: Health Checks & Monitoring
# =============================================================================
print_header "9. HEALTH CHECKS & MONITORING"

# SLURM Health Check
print_section "SLURM Health Check"
HEALTH_CHECK_PROGRAM=$(echo "$SLURM_CONFIG_FULL" | grep "HealthCheckProgram" | awk '{print $3}')
HEALTH_CHECK_INTERVAL=$(echo "$SLURM_CONFIG_FULL" | grep "HealthCheckInterval" | awk '{print $3}')
HEALTH_CHECK_CONFIGURED="false"

if [[ -n "$HEALTH_CHECK_PROGRAM" && "$HEALTH_CHECK_PROGRAM" != "(null)" ]]; then
    print_info "HealthCheckProgram: ${HEALTH_CHECK_PROGRAM}"
    print_info "HealthCheckInterval: ${HEALTH_CHECK_INTERVAL:-not set}"
    HEALTH_CHECK_CONFIGURED="true"
else
    print_warn "HealthCheckProgram: Not configured"
    HEALTH_CHECK_CONFIGURED="false"
fi

# DCGM Integration with SLURM
# DCGM runs on compute nodes (alongside GPUs), not the head node.
# Primary source: worker check. Head node is fallback for dcgmi binary check only.
print_section "DCGM (Data Center GPU Manager) - on compute node"
DCGM_INSTALLED="false"
DCGM_SLURM="false"
DCGM_HEALTH_WATCHES_ENABLED="false"
DCGM_DIAG_R1="${WORKER_DCGM_DIAG_R1:-untested}"
DCGM_DIAG_R2="${WORKER_DCGM_DIAG_R2:-untested}"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    if [[ "$WORKER_DCGM_VERSION" != "not-found" && -n "$WORKER_DCGM_VERSION" ]]; then
        DCGM_INSTALLED="true"
        print_info "dcgmi: Available on compute node ${WORKER_HOSTNAME}"
        print_detail "Version: ${WORKER_DCGM_VERSION}"
    else
        print_error "DCGM: dcgmi not found on compute node ${WORKER_HOSTNAME}"
        print_detail "Install: sudo apt install datacenter-gpu-manager"
    fi

    if [[ "$WORKER_DCGM_ACTIVE" == "true" ]]; then
        print_info "DCGM service: Active on compute node (dcgm systemd or nv-hostengine running)"
        DCGM_INSTALLED="true"
    else
        [[ "$DCGM_INSTALLED" == "true" ]] && print_warn "DCGM binary found but service NOT active on compute node" \
            || print_error "DCGM service: Not running on compute node"
        print_detail "Start with: sudo systemctl enable --now dcgm"
    fi

    if [[ "$WORKER_DCGM_HEALTH_OK" == "true" ]]; then
        DCGM_HEALTH_WATCHES_ENABLED="true"
        print_info "DCGM health watches: Enabled on compute node (dcgmi health -g 0 -s a OK)"
    else
        print_warn "DCGM health watches: Could not enable on compute node (dcgmi health -g 0 -s a failed)"
        print_detail "Ensure GPU group 0 exists: dcgmi group -c mygroup && dcgmi health -g <id> -s a"
    fi
    case "$DCGM_DIAG_R1" in
        pass) print_info "DCGM diag -r 1: PASS" ;;
        timeout) print_warn "DCGM diag -r 1: TIMED OUT" ;;
        fail) print_error "DCGM diag -r 1: FAILED" ;;
        *) print_warn "DCGM diag -r 1: ${DCGM_DIAG_R1}" ;;
    esac
    case "$DCGM_DIAG_R2" in
        pass) print_info "DCGM diag -r 2: PASS" ;;
        timeout) print_warn "DCGM diag -r 2: TIMED OUT" ;;
        fail) print_error "DCGM diag -r 2: FAILED" ;;
        skipped) print_detail "DCGM diag -r 2: skipped (set AUDIT_DCGM_DIAG_R2=true to run)" ;;
        *) print_warn "DCGM diag -r 2: ${DCGM_DIAG_R2}" ;;
    esac
else
    # Head-node fallback - DCGM typically not on head node, but check anyway
    print_warn "Worker check unavailable - checking dcgmi on HEAD NODE (likely not meaningful)"
    if command -v dcgmi &>/dev/null; then
        DCGM_INSTALLED="true"
        print_warn "dcgmi found on head node - confirm it is also running on compute nodes"
        DCGM_SERVICE_ACTIVE=$(systemctl is-active dcgm 2>/dev/null || echo "")
        NV_HOSTENGINE_RUNNING=$(pgrep nv-hostengine &>/dev/null && echo "true" || echo "false")
        [[ "$DCGM_SERVICE_ACTIVE" == "active" || "$NV_HOSTENGINE_RUNNING" == "true" ]] \
            && print_info "DCGM service: Active on head node" \
            || print_warn "DCGM service: Not active on head node"
    else
        print_warn "DCGM: dcgmi not found on head node"
    fi
fi

# Check if HealthCheckProgram points to DCGM (scontrol - always valid from head node)
if [[ "$HEALTH_CHECK_CONFIGURED" == "true" ]]; then
    if echo "$HEALTH_CHECK_PROGRAM" | grep -qi "dcgm"; then
        DCGM_SLURM="true"
        print_info "DCGM integrated with SLURM HealthCheckProgram: ${HEALTH_CHECK_PROGRAM}"
    elif [[ "${WORKER_HEALTH_PROGRAM_DCGM:-false}" == "true" ]]; then
        DCGM_SLURM="true"
        print_info "DCGM integrated with SLURM HealthCheckProgram plugin: ${WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE}"
    else
        print_warn "HealthCheckProgram is set but is NOT dcgm-based: ${HEALTH_CHECK_PROGRAM}"
        print_detail "For GPU health: set HealthCheckProgram=/usr/bin/dcgm-health-check in slurm.conf"
    fi
else
    print_error "HealthCheckProgram not set - DCGM health checks not integrated with SLURM"
    print_detail "Unhealthy GPUs will NOT be automatically drained from the cluster"
    print_detail "Set in slurm.conf: HealthCheckProgram=/usr/bin/dcgm-health-check"
    print_detail "              and: HealthCheckInterval=30"
fi

# Prolog/Epilog
print_section "Prolog/Epilog"
PROLOG=$(echo "$SLURM_CONFIG_FULL" | awk '$1 ~ /^Prolog(\[[0-9]+\])?$/ {print $3; exit}')
EPILOG=$(echo "$SLURM_CONFIG_FULL" | awk '$1 ~ /^Epilog(\[[0-9]+\])?$/ {print $3; exit}')
TASK_PROLOG=$(echo "$SLURM_CONFIG_FULL" | grep "TaskProlog" | awk '{print $3}')

[[ -n "$PROLOG" && "$PROLOG" != "(null)" ]] && print_info "Prolog: ${PROLOG}" || print_detail "Prolog: Not configured"
[[ -n "$EPILOG" && "$EPILOG" != "(null)" ]] && print_info "Epilog: ${EPILOG}" || print_detail "Epilog: Not configured"
[[ -n "$TASK_PROLOG" && "$TASK_PROLOG" != "(null)" ]] && print_info "TaskProlog: ${TASK_PROLOG}"

# Prolog runtime: AUDIT-CRITERIA expects a full-GPU-node `srun ... --pty bash` to
# return in under 30 s. We emulate with a non-pty srun that just runs `true`,
# which exercises the same prolog path. Request the audited per-node GPU count:
# a fixed gpu:8 is unsatisfiable on 4-GPU nodes (e.g. GB300). Any fallback
# remains GPU-constrained so mixed partitions cannot place it on a CPU node.
PROLOG_RUNTIME_SEC="unmeasured"
PROLOG_FAST="unknown"
if [[ -n "$GPU_PARTITION" && "$WORKER_CHECK_OK" == "true" ]]; then
    print_section "Prolog Runtime (timed srun)"
    PROLOG_GRES_COUNT="$DEFAULT_GPUS_PER_NODE"
    if [[ "$GPUS_PER_NODE" -gt 0 ]]; then
        PROLOG_GRES_COUNT="$GPUS_PER_NODE"
    fi
    print_detail "Timing GPU-node prolog with --gres=gpu:${PROLOG_GRES_COUNT}"
    PROLOG_T0=$(date +%s)
    if srun "${AUDIT_SRUN_FLAGS[@]}" "${GPU_SRUN_SCOPE_ARGS[@]}" \
        -N1 --gres="gpu:${PROLOG_GRES_COUNT}" --time=1:00 true 2>/dev/null; then
        PROLOG_T1=$(date +%s)
        PROLOG_RUNTIME_SEC=$((PROLOG_T1 - PROLOG_T0))
        if (( PROLOG_RUNTIME_SEC < 30 )); then
            PROLOG_FAST="true"
            print_info "Prolog runtime: ${PROLOG_RUNTIME_SEC}s (under 30s threshold)"
        else
            PROLOG_FAST="false"
            print_warn "Prolog runtime: ${PROLOG_RUNTIME_SEC}s (over 30s threshold - prolog/epilog scripts are heavy)"
        fi
    else
        # Keep the fallback GPU-constrained so a mixed partition cannot place
        # the timing check on a CPU-only node.
        PROLOG_T0=$(date +%s)
        if srun "${AUDIT_SRUN_FLAGS[@]}" "${GPU_SRUN_SCOPE_ARGS[@]}" \
            -N1 --gres=gpu:1 --time=1:00 true 2>/dev/null; then
            PROLOG_T1=$(date +%s)
            PROLOG_RUNTIME_SEC=$((PROLOG_T1 - PROLOG_T0))
            if (( PROLOG_RUNTIME_SEC < 30 )); then
                PROLOG_FAST="true"
                print_warn "Prolog runtime (1-GPU fallback): ${PROLOG_RUNTIME_SEC}s (under 30s; full-node request failed)"
            else
                PROLOG_FAST="false"
                print_warn "Prolog runtime (1-GPU fallback): ${PROLOG_RUNTIME_SEC}s (over 30s)"
            fi
        else
            print_warn "Prolog timing: srun check failed"
        fi
    fi
fi

# NHC (Node Health Check) — supplemental health checks beyond DCGM.
# https://github.com/mej/nhc
print_section "Node Health Check (NHC)"
NHC_INSTALLED="false"
NHC_PATH=""
if command -v nhc &>/dev/null; then
    NHC_INSTALLED="true"
    NHC_PATH=$(which nhc)
    print_info "nhc binary: ${NHC_PATH} (head node)"
elif [[ -x /usr/sbin/nhc || -x /usr/local/sbin/nhc ]]; then
    NHC_INSTALLED="true"
    NHC_PATH=$(ls /usr/sbin/nhc /usr/local/sbin/nhc 2>/dev/null | head -1)
    print_info "nhc binary: ${NHC_PATH} (head node)"
elif [[ "$WORKER_NHC_INSTALLED" == "true" ]]; then
    # NHC lives on the compute nodes (where slurmd runs the
    # HealthCheckProgram); many clusters do not install it on the head or
    # login node at all, so the worker check is the authoritative check.
    NHC_INSTALLED="true"
    NHC_PATH="${WORKER_NHC_PATH}"
    print_info "nhc binary: ${NHC_PATH} (compute node ${WORKER_HOSTNAME}; not on head node)"
else
    print_detail "nhc not installed (https://github.com/mej/nhc) — DCGM is the only health check source"
fi
if [[ -f /etc/nhc/nhc.conf ]]; then
    NHC_CONF_LINES=$(grep -cv -E '^\s*(#|$)' /etc/nhc/nhc.conf 2>/dev/null || echo 0)
    [[ "$NHC_CONF_LINES" -gt 0 ]] && print_info "/etc/nhc/nhc.conf: ${NHC_CONF_LINES} active checks"
elif [[ "${WORKER_NHC_CONF_CHECKS:-0}" -gt 0 ]]; then
    print_info "/etc/nhc/nhc.conf: ${WORKER_NHC_CONF_CHECKS} active checks (compute node ${WORKER_HOSTNAME})"
fi

# Monitoring stack detection: prometheus / dcgm-exporter / grafana / node-exporter.
# We check listening ports (best signal — exporters expose HTTP) and systemd unit names.
print_section "Monitoring Stack"
PROMETHEUS_DETECTED="false"
DCGM_EXPORTER_DETECTED="false"
NODE_EXPORTER_DETECTED="false"
GRAFANA_DETECTED="false"
SLURM_EXPORTER_DETECTED="false"
# ss is faster + sandbox-safe than netstat
if command -v ss &>/dev/null; then
    LISTENING=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}')
else
    LISTENING=$(netstat -tlnp 2>/dev/null | awk 'NR>2 {print $4}')
fi
echo "$LISTENING" | grep -qE ':9090(\s|$)'  && PROMETHEUS_DETECTED="true"
echo "$LISTENING" | grep -qE ':9100(\s|$)'  && NODE_EXPORTER_DETECTED="true"
echo "$LISTENING" | grep -qE ':9400(\s|$)'  && DCGM_EXPORTER_DETECTED="true"
echo "$LISTENING" | grep -qE ':3000(\s|$)'  && GRAFANA_DETECTED="true"
echo "$LISTENING" | grep -qE ':8080(\s|$)'  && SLURM_EXPORTER_DETECTED="maybe"

# systemd fallback for things not running on head node (e.g. dcgm-exporter on workers)
if systemctl is-active dcgm-exporter &>/dev/null; then DCGM_EXPORTER_DETECTED="true"; fi
if systemctl is-active prometheus &>/dev/null; then PROMETHEUS_DETECTED="true"; fi
if systemctl is-active grafana-server &>/dev/null; then GRAFANA_DETECTED="true"; fi
if systemctl is-active node-exporter prometheus-node-exporter &>/dev/null; then NODE_EXPORTER_DETECTED="true"; fi
# Containerized and tarball Grafana installs can run without a systemd unit,
# and unprivileged `ss -p` may hide process details. The executable comm name
# remains visible through procfs.
if pgrep -x grafana &>/dev/null || pgrep -x grafana-server &>/dev/null; then GRAFANA_DETECTED="true"; fi

[[ "$PROMETHEUS_DETECTED"   == "true" ]] && print_info "Prometheus: detected (port 9090 or systemd active)"     || print_detail "Prometheus: not detected"
[[ "$DCGM_EXPORTER_DETECTED" == "true" ]] && print_info "dcgm-exporter: detected (port 9400 or systemd active)" || print_detail "dcgm-exporter: not detected"
[[ "$NODE_EXPORTER_DETECTED" == "true" ]] && print_info "node-exporter: detected (port 9100 or systemd active)" || print_detail "node-exporter: not detected"
[[ "$GRAFANA_DETECTED"      == "true" ]] && print_info "Grafana: detected (port 3000 or systemd active)"        || print_detail "Grafana: not detected"
if [[ "$SLURM_EXPORTER_DETECTED" == "maybe" ]]; then
    print_detail "Something on :8080 (could be slurm-exporter or other)"
fi

# Auto-remediation: SLURM ResumeProgram, ReturnToService, UnkillableStepProgram.
# These wire automatic recovery when nodes go DOWN/DRAIN due to health checks.
print_section "Auto-Remediation"
RESUME_PROGRAM=$(echo "$SLURM_CONFIG_FULL" | grep "^ResumeProgram" | awk '{print $3}')
RETURN_TO_SERVICE=$(echo "$SLURM_CONFIG_FULL" | grep "^ReturnToService" | awk '{print $3}')
UNKILLABLE_STEP=$(echo "$SLURM_CONFIG_FULL" | grep "^UnkillableStepProgram" | awk '{print $3}')
SUSPEND_PROGRAM=$(echo "$SLURM_CONFIG_FULL" | grep "^SuspendProgram" | awk '{print $3}')
AUTO_REMEDIATION_CONFIGURED="false"

if [[ -n "$RESUME_PROGRAM" && "$RESUME_PROGRAM" != "(null)" ]]; then
    print_info "ResumeProgram: ${RESUME_PROGRAM} (auto-resume on node failure)"
    AUTO_REMEDIATION_CONFIGURED="true"
else
    print_warn "ResumeProgram: not configured (no automatic node recovery on failure)"
fi
case "${RETURN_TO_SERVICE:-0}" in
    0)  print_warn "ReturnToService=0 (down nodes do NOT auto-return; manual scontrol update required)" ;;
    1)  print_info "ReturnToService=1 (down nodes auto-return when slurmd reports them up)" ;;
    2)  print_info "ReturnToService=2 (down nodes auto-return on slurmctld restart or first heartbeat)"; AUTO_REMEDIATION_CONFIGURED="true" ;;
    *)  print_detail "ReturnToService=${RETURN_TO_SERVICE} (uncommon value)" ;;
esac
[[ -n "$UNKILLABLE_STEP" && "$UNKILLABLE_STEP" != "(null)" ]] && \
    print_info "UnkillableStepProgram: ${UNKILLABLE_STEP}" || \
    print_detail "UnkillableStepProgram: not configured (stuck steps remain stuck)"
[[ -n "$SUSPEND_PROGRAM" && "$SUSPEND_PROGRAM" != "(null)" ]] && print_info "SuspendProgram: ${SUSPEND_PROGRAM}"

# =============================================================================
# SECTION 10: Access & Authentication
# =============================================================================
print_header "10. ACCESS & AUTHENTICATION"

print_section "SSH Configuration"
SSH_CONFIG="/etc/ssh/sshd_config"
PASSWORDLESS_SSH="unknown"
if [[ -f "$SSH_CONFIG" ]]; then
    if grep -q "^PubkeyAuthentication yes" "$SSH_CONFIG" 2>/dev/null; then
        print_info "PubkeyAuthentication: Enabled"
        PASSWORDLESS_SSH="enabled"
    fi
fi

if [[ -f ~/.ssh/known_hosts ]]; then
    KNOWN_HOSTS_COUNT=$(wc -l < ~/.ssh/known_hosts)
    print_info "Known hosts: ${KNOWN_HOSTS_COUNT} entries"
fi

# SSH to compute nodes
print_section "SSH to Compute Nodes"
SSH_TO_COMPUTE="false"
FIRST_COMPUTE_NODE=""

FIRST_COMPUTE_NODE=""
if [[ "$SINFO_OK" == "true" ]]; then
    FIRST_COMPUTE_NODE=$(sinfo -N --noheader 2>/dev/null | head -1 | awk '{print $1}' || echo "")
else
    # Use the worker hostname we already checked, or parse from snodes
    FIRST_COMPUTE_NODE="${WORKER_HOSTNAME:-}"
    [[ "$FIRST_COMPUTE_NODE" == "none" || -z "$FIRST_COMPUTE_NODE" ]] && \
        FIRST_COMPUTE_NODE=$(sudo -n /usr/local/bin/snodes 2>/dev/null | tail -n +2 | awk '{print $NF}' | head -1 | tr -d '[]' | sed 's/\[.*//' || echo "")
fi
if [[ -n "$FIRST_COMPUTE_NODE" ]]; then
    print_detail "Testing SSH to first compute node: ${FIRST_COMPUTE_NODE}"
    SSH_RESULT=$(ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes \
        "$FIRST_COMPUTE_NODE" hostname 2>/dev/null || echo "ssh-failed")
    if [[ -n "$SSH_RESULT" && "$SSH_RESULT" != "ssh-failed" ]]; then
        SSH_TO_COMPUTE="true"
        print_info "SSH to ${FIRST_COMPUTE_NODE}: SUCCESS (returned hostname: ${SSH_RESULT})"
    else
        print_error "SSH to ${FIRST_COMPUTE_NODE}: FAILED (requires password or timed out)"
        print_detail "Passwordless SSH between nodes is required for MPI and NCCL jobs"
    fi
else
    print_warn "SSH test: No compute nodes found via sinfo"
fi

print_section "Accounting"
ACCOUNTING_STORAGE=$(echo "$SLURM_CONFIG_FULL" | grep "AccountingStorageType" | awk '{print $3}')
SACCT_AVAILABLE="false"
if [[ -n "$ACCOUNTING_STORAGE" && "$ACCOUNTING_STORAGE" != "(null)" ]]; then
    print_info "AccountingStorage: ${ACCOUNTING_STORAGE}"

    if sacct --version &>/dev/null; then
        print_info "sacct: Functional"
        SACCT_AVAILABLE="true"
    else
        print_warn "sacct: Not working"
    fi
else
    print_warn "Accounting: Not configured"
fi

print_section "Essential Tools (head node)"
# Universal tools any GPU cluster head node should have.
ESSENTIAL_TOOLS=("python3" "git" "curl" "wget" "vim" "nano" "jq" "ssh" "rsync" "lspci" "ip" "numactl" "tmux" "screen")
# Package manager is distro-conditional. apt warns falsely on RHEL family
# (and vice versa), so detect via /etc/os-release and only check the
# manager that actually belongs on this distro.
HEAD_OS_ID="unknown"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    HEAD_OS_ID=$(. /etc/os-release && echo "${ID:-unknown}")
fi
case "$HEAD_OS_ID" in
    ubuntu|debian) ESSENTIAL_TOOLS+=("apt") ;;
    rhel|rocky|almalinux|centos|amzn|ol) ESSENTIAL_TOOLS+=("dnf") ;;
    sles|opensuse-leap|opensuse-tumbleweed) ESSENTIAL_TOOLS+=("zypper") ;;
esac
TOOLS_JSON_ENTRIES=()
for tool in "${ESSENTIAL_TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        TOOLS_JSON_ENTRIES+=("\"$tool\": true")
        print_info "${tool}: Available"
    else
        TOOLS_JSON_ENTRIES+=("\"$tool\": false")
        print_warn "${tool}: Not found"
    fi
done
ESSENTIAL_TOOLS_JSON="{$(IFS=,; echo "${TOOLS_JSON_ENTRIES[*]}")}"

print_section "BMC / IPMI Exposure (compute node)"
IPMITOOL_INSTALLED="false"
IPMI_USER_ACCESS="${WORKER_IPMI_USER_ACCESS:-untested}"
IPMI_SUDO_ACCESS="${WORKER_IPMI_SUDO_ACCESS:-untested}"
IPMI_EXPOSED="false"
if [[ -n "${WORKER_IPMITOOL_PATH:-}" ]]; then
    IPMITOOL_INSTALLED="true"
    print_info "ipmitool: ${WORKER_IPMITOOL_PATH}"
else
    print_detail "ipmitool: not installed on sampled compute node"
fi
case "$IPMI_USER_ACCESS" in
    allowed)
        IPMI_EXPOSED="true"
        print_error "ipmitool mc info: accessible without sudo"
        ;;
    blocked)
        print_info "ipmitool mc info: blocked for tenant user"
        ;;
    not-installed)
        print_detail "ipmitool user check: skipped (not installed)"
        ;;
    *)
        print_warn "ipmitool user check: ${IPMI_USER_ACCESS}"
        ;;
esac
case "$IPMI_SUDO_ACCESS" in
    allowed)
        IPMI_EXPOSED="true"
        print_error "sudo ipmitool chassis status: accessible"
        ;;
    blocked)
        print_info "sudo ipmitool chassis status: blocked"
        ;;
    no-passwordless-sudo|not-installed)
        print_detail "sudo ipmitool check: ${IPMI_SUDO_ACCESS}"
        ;;
    *)
        print_warn "sudo ipmitool check: ${IPMI_SUDO_ACCESS}"
        ;;
esac

print_section "Sudo Access"
SUDO_AVAILABLE="false"
if sudo -n true 2>/dev/null; then
    print_info "sudo: Available (passwordless)"
    SUDO_AVAILABLE="true"
else
    print_warn "sudo: Not available or requires password"
fi

# Standard SLURM commands available (AUDIT-CRITERIA: sinfo, squeue, scontrol, salloc, sbatch, srun)
print_section "Standard SLURM Commands"
SLURM_CMDS_OK="true"
declare -A SLURM_CMD_AVAIL=()
for cmd in sinfo squeue scontrol salloc sbatch srun sacct; do
    if command -v "$cmd" &>/dev/null; then
        SLURM_CMD_AVAIL[$cmd]="true"
        print_info "${cmd}: $(command -v "$cmd")"
    else
        SLURM_CMD_AVAIL[$cmd]="false"
        SLURM_CMDS_OK="false"
        print_error "${cmd}: NOT FOUND"
    fi
done

# User management tools (AUDIT-CRITERIA: easy to add new users and groups via CLI).
# Presence on the head node + SUDO_AVAILABLE means a cluster admin can provision users.
print_section "User Management Tools"
USERADD_AVAILABLE="false"
GROUPADD_AVAILABLE="false"
command -v useradd  &>/dev/null && USERADD_AVAILABLE="true"
command -v groupadd &>/dev/null && GROUPADD_AVAILABLE="true"
[[ "$USERADD_AVAILABLE"  == "true" ]] && print_info "useradd: $(command -v useradd)"   || print_warn "useradd: not found"
[[ "$GROUPADD_AVAILABLE" == "true" ]] && print_info "groupadd: $(command -v groupadd)" || print_warn "groupadd: not found"

# External IDP (Okta / Google / GitHub via OIDC, LDAP, SSSD).
# Heuristic: SSSD running -> external IDP integration likely. PAM modules also flag this.
print_section "External IDP / SSO Integration"
IDP_DETECTED="false"
IDP_TYPE="none"
if systemctl is-active sssd &>/dev/null || pgrep sssd &>/dev/null; then
    IDP_DETECTED="true"
    IDP_TYPE="sssd"
    print_info "SSSD: active (likely backed by LDAP/AD/IPA — check /etc/sssd/sssd.conf)"
fi
if [[ -d /etc/sssd ]] && grep -hE '^id_provider' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 2>/dev/null | head -1 | grep -q .; then
    IDP_PROVIDER=$(grep -hE '^id_provider' /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    [[ -n "$IDP_PROVIDER" ]] && print_detail "SSSD id_provider: ${IDP_PROVIDER}"
fi
if grep -rqE 'pam_oauth2|pam_okta|pam_oidc|pam_google_auth|pam_ldap' /etc/pam.d/ 2>/dev/null; then
    IDP_DETECTED="true"
    [[ "$IDP_TYPE" == "none" ]] && IDP_TYPE="pam"
    PAM_MODS=$(grep -rhE 'pam_oauth2|pam_okta|pam_oidc|pam_google_auth|pam_ldap' /etc/pam.d/ 2>/dev/null | awk '{print $3}' | sort -u | tr '\n' ',' | sed 's/,$//')
    print_info "PAM IDP modules: ${PAM_MODS}"
fi
[[ "$IDP_DETECTED" == "false" ]] && print_warn "No external IDP integration detected (local /etc/passwd auth only)"

# =============================================================================
# SECTION 11: SLURM Default Resource Limits
# =============================================================================
print_header "11. SLURM DEFAULT RESOURCE LIMITS"

print_section "CPU & Memory Defaults"
# SLURM_CONFIG_FULL already built at startup from scontrol or slurm.conf fallback

DEF_CPUS_PER_TASK=$(echo "$SLURM_CONFIG_FULL" | grep "DefCPUsPerTask\|DefaultCPUsPerTask" | awk '{print $3}' | head -1 || echo "")
DEF_MEM_PER_CPU=$(echo "$SLURM_CONFIG_FULL" | grep "DefMemPerCPU\b\|DefMemPerCpu\b" | awk '{print $3}' | head -1 || echo "0")
DEF_MEM_PER_GPU=$(echo "$SLURM_CONFIG_FULL" | grep "DefMemPerGPU\b\|DefMemPerGpu\b" | awk '{print $3}' | head -1 || echo "0")
DEF_MEM_PER_NODE=$(echo "$SLURM_CONFIG_FULL" | grep "DefMemPerNode\b" | awk '{print $3}' | head -1 || echo "0")
MAX_MEM_PER_CPU=$(echo "$SLURM_CONFIG_FULL" | grep "MaxMemPerCPU\b\|MaxMemPerCpu\b" | awk '{print $3}' | head -1 || echo "0")
MAX_MEM_PER_NODE=$(echo "$SLURM_CONFIG_FULL" | grep "MaxMemPerNode\b" | awk '{print $3}' | head -1 || echo "0")

# Coerce SLURM memory sentinels (UNLIMITED, (null), empty) to 0 for valid JSON
for _mem_var in DEF_MEM_PER_CPU DEF_MEM_PER_GPU DEF_MEM_PER_NODE MAX_MEM_PER_CPU MAX_MEM_PER_NODE; do
    if ! [[ "${!_mem_var}" =~ ^[0-9]+$ ]]; then
        eval "${_mem_var}=0"
    fi
done
unset _mem_var
CPU_FREQ_DEF=$(echo "$SLURM_CONFIG_FULL" | grep "CpuFreqDef\b" | awk '{print $3}' | head -1 || echo "")
CPU_FREQ_GOV=$(echo "$SLURM_CONFIG_FULL" | grep "CpuFreqGovernors\b" | awk '{print $3}' | head -1 || echo "")
TASK_PLUGIN=$(echo "$SLURM_CONFIG_FULL" | grep "^TaskPlugin\b" | awk '{print $3}' | head -1 || echo "")
PROCTRACK_TYPE=$(echo "$SLURM_CONFIG_FULL" | grep "^ProctrackType\b" | awk '{print $3}' | head -1 || echo "")

# DefCPUsPerTask
if [[ -n "$DEF_CPUS_PER_TASK" && "$DEF_CPUS_PER_TASK" != "(null)" ]]; then
    print_info "DefCPUsPerTask: ${DEF_CPUS_PER_TASK}"
    if [[ "$DEF_CPUS_PER_TASK" == "1" ]]; then
        print_warn "DefCPUsPerTask=1 may restrict multi-threaded jobs (users must specify --cpus-per-task)"
    fi
else
    print_info "DefCPUsPerTask: Not set (defaults to 1 - users must specify --cpus-per-task for multi-threaded)"
    DEF_CPUS_PER_TASK="1"
fi

# DefMemPerCPU
if [[ -n "$DEF_MEM_PER_CPU" && "$DEF_MEM_PER_CPU" != "0" && "$DEF_MEM_PER_CPU" != "(null)" ]]; then
    print_info "DefMemPerCPU: ${DEF_MEM_PER_CPU} MB"
    if [[ "$DEF_MEM_PER_CPU" -lt 2048 ]]; then
        print_warn "DefMemPerCPU=${DEF_MEM_PER_CPU} MB is very low - B300 nodes (2TB RAM, 192 CPUs) should have >= 4096 MB/CPU"
    elif [[ "$DEF_MEM_PER_CPU" -lt 4096 ]]; then
        print_warn "DefMemPerCPU=${DEF_MEM_PER_CPU} MB - recommend >= 4096 MB for B300 nodes"
    else
        print_info "DefMemPerCPU=${DEF_MEM_PER_CPU} MB - adequate for B300 nodes"
    fi
else
    print_detail "DefMemPerCPU: Not set (${DEF_MEM_PER_CPU:-0})"
fi

if [[ -n "$DEF_MEM_PER_NODE" && "$DEF_MEM_PER_NODE" != "0" && "$DEF_MEM_PER_NODE" != "(null)" ]]; then
    print_info "DefMemPerNode: ${DEF_MEM_PER_NODE} MB"
fi

# DefMemPerGPU - SLURM 23+ default memory per GPU. UNLIMITED (0 / unset) is
# preferred; setting it to a small value forces users to override at submission.
if [[ -n "$DEF_MEM_PER_GPU" && "$DEF_MEM_PER_GPU" != "0" && "$DEF_MEM_PER_GPU" != "(null)" ]]; then
    print_info "DefMemPerGPU: ${DEF_MEM_PER_GPU} MB"
    if [[ "$DEF_MEM_PER_GPU" =~ ^[0-9]+$ && "$DEF_MEM_PER_GPU" -lt 16384 ]]; then
        print_warn "DefMemPerGPU=${DEF_MEM_PER_GPU} MB is restrictive - large-memory GPUs (H100/H200/B200/B300) need >= 65536 MB"
    fi
else
    print_info "DefMemPerGPU: Not set (unlimited) - good"
fi

# MaxMemPerNode - SLURM cluster-wide cap on per-node memory. Also expected
# UNLIMITED on a GPU cluster so jobs can claim the full node RAM.
if [[ -n "$MAX_MEM_PER_NODE" && "$MAX_MEM_PER_NODE" != "0" && "$MAX_MEM_PER_NODE" != "(null)" ]]; then
    print_warn "MaxMemPerNode: ${MAX_MEM_PER_NODE} MB (set; UNLIMITED is recommended on GPU clusters)"
else
    print_info "MaxMemPerNode: 0 (unlimited) - good"
fi

# MaxMemPerCPU
if [[ -n "$MAX_MEM_PER_CPU" && "$MAX_MEM_PER_CPU" != "0" && "$MAX_MEM_PER_CPU" != "(null)" ]]; then
    print_info "MaxMemPerCPU: ${MAX_MEM_PER_CPU} MB"
    if [[ "$MAX_MEM_PER_CPU" -lt 16384 ]]; then
        print_warn "MaxMemPerCPU=${MAX_MEM_PER_CPU} MB is restrictive - should be 0 (unlimited) or very high for B300 nodes"
    fi
else
    print_info "MaxMemPerCPU: 0 (unlimited) - good"
fi

# CPU Frequency
print_section "CPU Frequency Scaling"
if [[ -n "$CPU_FREQ_DEF" && "$CPU_FREQ_DEF" != "(null)" ]]; then
    print_info "CpuFreqDef: ${CPU_FREQ_DEF}"
else
    print_detail "CpuFreqDef: Not set"
fi
if [[ -n "$CPU_FREQ_GOV" && "$CPU_FREQ_GOV" != "(null)" ]]; then
    print_info "CpuFreqGovernors: ${CPU_FREQ_GOV}"
else
    print_detail "CpuFreqGovernors: Not set (all governors allowed)"
fi

# TaskPlugin & ProctrackType
print_section "Process Management"
if [[ -n "$TASK_PLUGIN" && "$TASK_PLUGIN" != "(null)" ]]; then
    print_info "TaskPlugin: ${TASK_PLUGIN}"
    if echo "$TASK_PLUGIN" | grep -q "cgroup"; then
        print_info "cgroup-based task management: Configured (proper isolation)"
    else
        print_warn "TaskPlugin does not include task/cgroup - job isolation may be limited"
    fi
else
    print_warn "TaskPlugin: Not set"
    TASK_PLUGIN="unknown"
fi

if [[ -n "$PROCTRACK_TYPE" && "$PROCTRACK_TYPE" != "(null)" ]]; then
    print_info "ProctrackType: ${PROCTRACK_TYPE}"
    if [[ "$PROCTRACK_TYPE" == "proctrack/cgroup" ]]; then
        print_info "cgroup process tracking: Configured (recommended)"
    else
        print_warn "ProctrackType=${PROCTRACK_TYPE} - proctrack/cgroup is recommended"
    fi
else
    print_warn "ProctrackType: Not set"
    PROCTRACK_TYPE="unknown"
fi

# GPU Partition-specific limits
print_section "GPU Partition Resource Limits"
if [[ -n "$GPU_PARTITION" && "$GPU_PARTITION" != "none" ]]; then
    GPU_PART_INFO=""
    if [[ "$SCONTROL_OK" == "true" ]]; then
        GPU_PART_INFO=$(scontrol show partition "$GPU_PARTITION" 2>/dev/null || echo "")
    else
        # Parse from slurm.conf partition line
        GPU_PART_LINE=$(grep -h "^PartitionName=${GPU_PARTITION}" /etc/slurm/slurm.conf /etc/slurm/*.conf 2>/dev/null | head -1 || echo "")
        [[ -n "$GPU_PART_LINE" ]] && GPU_PART_INFO="$GPU_PART_LINE"
    fi
    if [[ -n "$GPU_PART_INFO" ]]; then
        print_info "Partition: ${GPU_PARTITION}"
        PART_DEF_MEM=$(echo "$GPU_PART_INFO" | grep -oP 'DefMemPerNode=\K[^ ]+' | head -1 || echo "")
        PART_MAX_TIME=$(echo "$GPU_PART_INFO" | grep -oP 'MaxTime=\K[^ ]+' | head -1 || echo "")
        PART_MAX_CPUS=$(echo "$GPU_PART_INFO" | grep -oP 'MaxCPUsPerNode=\K[^ ]+' | head -1 || echo "")
        PART_STATE=$(echo "$GPU_PART_INFO" | grep -oP 'State=\K[^ ]+' | head -1 || echo "")
        [[ -n "$PART_STATE" ]] && print_info "  State: ${PART_STATE}"
        [[ -n "$PART_DEF_MEM" ]] && print_info "  DefMemPerNode: ${PART_DEF_MEM} MB" || print_detail "  DefMemPerNode: Not set (using cluster default)"
        [[ -n "$PART_MAX_TIME" ]] && print_info "  MaxTime: ${PART_MAX_TIME}"
        [[ -n "$PART_MAX_CPUS" ]] && print_info "  MaxCPUsPerNode: ${PART_MAX_CPUS}" || print_detail "  MaxCPUsPerNode: Unlimited"
    fi
fi

# =============================================================================
# SECTION 12: GitHub Source
# =============================================================================
print_header "12. GITHUB SOURCE"

print_section "Git Remote"
SCRIPT_DIR_GIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_REMOTE_RAW=$(git -C "$SCRIPT_DIR_GIT" remote get-url origin 2>/dev/null || echo "")
GIT_REMOTE=$(sanitize_git_remote_url "$GIT_REMOTE_RAW")
GIT_COMMIT=$(git -C "$SCRIPT_DIR_GIT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git -C "$SCRIPT_DIR_GIT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

if [[ -n "$GIT_REMOTE" ]]; then
    if echo "$GIT_REMOTE" | grep -q "github.com"; then
        print_info "Git remote: ${GIT_REMOTE}"
        print_info "Branch: ${GIT_BRANCH} (${GIT_COMMIT})"
    else
        print_warn "Git remote: ${GIT_REMOTE} (not a github.com URL)"
    fi
else
    print_warn "Git remote: Not configured or not a git repository"
fi

# =============================================================================
# SECTION 13: Summary
# =============================================================================
print_header "13. SUMMARY"

print_section "Cluster Overview"
echo ""
echo "  Cluster Name:          ${CLUSTER_NAME}"
echo "  SLURM Version:         ${SLURM_VERSION_NUM}"
echo "  Nodes:                 ${TOTAL_NODES} total (${IDLE_NODES} idle, ${DOWN_NODES} down)"
echo "  CPUs:                  ${TOTAL_CPUS}"
echo "  GPUs:                  ${TOTAL_GPUS} × ${GPU_MODEL}"
echo "  AMD GPUs:              ${AMD_GPUS_PRESENT} (${WORKER_AMD_GPU_MODEL:-none})"
echo "  GDRCopy installed:     ${GDRCOPY_INSTALLED} (gdrdrv loaded: ${GDRCOPY_GDRDRV_LOADED})"
echo "  GPU idle (max):        ${GPU_IDLE_TEMP_MAX} °C / ${GPU_IDLE_POWER_MAX} W"
echo "  Xids in dmesg:         ${DMESG_XIDS_COUNT}"
echo "  RDMA:                  ${RDMA_TYPE}"
echo "  Compute fabric:        ${COMPUTE_FABRIC_CLASS} (${COMPUTE_FABRIC_COUNT} NICs)"
echo "  NIC fabric roll-up:    ${NIC_FABRIC_SUMMARY:-none}"
echo "  GPUDirect RDMA:        ${GPUDIRECT_RDMA}"
echo "  NCCL_IB_GID_INDEX:     ${NCCL_GID_INDEX_VALUE}"
echo "  Containers:            Pyxis=${PYXIS_INSTALLED} (${PYXIS_VERSION}), Enroot=${ENROOT_INSTALLED}, Docker(workers)=${DOCKER_ON_WORKERS}, NCT=${NVIDIA_CONTAINER_TOOLKIT}"
echo "  Lmod:                  ${LMOD_INSTALLED}"
echo "  Health Checks:         ${HEALTH_CHECK_CONFIGURED}"
echo "  DCGM-SLURM:            ${DCGM_SLURM}"
echo "  HCA Naming Valid:      ${HCA_NAMING_VALID}"
echo "  NCCL Version:          ${NCCL_VERSION}"
echo "  NHC installed:         ${NHC_INSTALLED}"
echo "  Monitoring stack:      prom=${PROMETHEUS_DETECTED} dcgm-exp=${DCGM_EXPORTER_DETECTED} grafana=${GRAFANA_DETECTED}"
echo "  Auto-remediation:      ${AUTO_REMEDIATION_CONFIGURED} (ResumeProgram: ${RESUME_PROGRAM:-none})"
echo "  Prolog runtime:        ${PROLOG_RUNTIME_SEC}s (under 30s: ${PROLOG_FAST})"
echo "  External IDP:          ${IDP_DETECTED} (${IDP_TYPE})"
echo "  NCU Available:         ${NCU_INSTALLED} (${NCU_VERSION})"
echo "  NCU HW Counters:      ${NCU_COUNTER_ACCESS}"
echo "  perf Installed:        ${PERF_INSTALLED} (paranoid=${PERF_EVENT_PARANOID}, kptr=${PERF_KPTR_RESTRICT})"
echo "  perf stat:             ${PERF_STAT_ACCESS}"
echo "  perf top:              ${PERF_TOP_ACCESS}"
echo "  HPC-X in PATH:         ${HPCX_IN_PATH}"
echo "  SSH to Compute:        ${SSH_TO_COMPUTE} (${FIRST_COMPUTE_NODE})"
echo "  TaskPlugin:            ${TASK_PLUGIN}"
echo "  Boot Drive (head):     ${HEAD_BOOT_DEV} (${HEAD_BOOT_FSTYPE})"
echo "  Boot Drive (worker):   ${WORKER_BOOT_DEVICE} (${WORKER_BOOT_FSTYPE})"
echo "  NVMe (head):           ${HEAD_NVME_COUNT} drives, ${HEAD_NVME_TOTAL_GB} GB"
echo "  NVMe (worker):         ${WORKER_NVME_COUNT} drives, ${WORKER_NVME_TOTAL_GB} GB"
echo "  Shared Filesystems:    ${#SHARED_FS[@]} detected"
echo ""

# =============================================================================
# GENERATE JSON OUTPUT
# =============================================================================

# Vendor gate for the security version minimums. Gate on the vendor alone, the
# way cluster-audit-k8s.sh passes GPU_VENDOR unconditionally.
#
# This deliberately does NOT also require DRIVER_VERSION to be unknown. That
# clause made the gate depend on the AMD driver promotion not existing on this
# harness: porting the k8s reconciliation block here for AMD parity, which is a
# natural next step, would silently flip an AMD cluster back to "nvidia" and
# grade an amdgpu version against NVIDIA's driver minimums.
SECURITY_GPU_VENDOR="nvidia"
if [[ "${AMD_GPUS_PRESENT:-false}" == "true" ]]; then
    SECURITY_GPU_VENDOR="amd"
fi
SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit \
    "$WORKER_CHECK_OUTPUT" "$SECURITY_DRIVER_VERSION" "$SECURITY_NCT_VERSION" \
    "$SECURITY_RUNC_VERSION" "$SECURITY_DOCKER_VERSION" "$SECURITY_GPU_VENDOR")

# Determine cluster name for file
if [[ -n "$CUSTOM_NAME" ]]; then
    AUDIT_CLUSTER_NAME="$CUSTOM_NAME"
else
    AUDIT_CLUSTER_NAME=$(echo "$CLUSTER_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-64)
fi

# Build JSON
AUDIT_TYPE="slurm"
JSON_OUTPUT=$(build_audit_json)

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

    echo "$JSON_OUTPUT" | jq . > "$OUTPUT_FILE"

    print_section "Output"
    print_info "JSON saved: ${OUTPUT_FILE}"
    echo ""
fi
