#!/bin/bash
# =============================================================================
# Standalone Cluster Audit Script
# =============================================================================
# Port of cluster-audit-slurm.sh (same dir) for single-node / standalone hosts.
# Runs on the host itself (no SLURM head node, no srun fan-out). Collects the
# same GPU / driver / NCCL / storage / container / health facts; sections
# that depend on SLURM orchestration (cluster-wide node inventory, partitions,
# Lmod, default resource limits, slurm.conf parsing) are dropped or report
# "standalone" / "n/a" so the JSON shape stays compatible with the slurm
# audit's consumers (the committed run artifact, the standalone
# audit runner shim, etc.).
#
# Usage:
#   ./cluster-audit-standalone.sh [options]
#
# Options:
#   --name <name>      Custom cluster name for output file
#   --output-dir <dir> Directory for JSON output (default: ./audit-results)
#   --json-only        Output JSON to stdout only, no file
#   --help             Show this help message
#
# Requirements:
#   - Run on the host you want to audit (typically a GPU compute node)
#   - jq installed for JSON processing
#   - Optional: sudo access for some checks
# =============================================================================

set -o pipefail

# A single standalone host has no cluster scale-out target. Keep these checks
# disabled as a harness policy, with no environment variable that can enable them.
readonly SCALE_OUT_CHECKS_ENABLED=false

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

# Timestamps
AUDIT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_TIMESTAMP_FILE=$(date +"%Y%m%d-%H%M%S")

# =============================================================================
# SECTION 1: Host Identity & Geolocation (standalone replacement for slurm
# Sections 1 and 2). No SLURM version, controlMachine, or node inventory -
# this is a single host, so cluster size is fixed at 1.
# =============================================================================
print_header "1. HOST IDENTITY"

# Standalone defaults for the slurm/* JSON keys that downstream consumers expect.
SLURM_VERSION="n/a (standalone)"
SLURM_VERSION_NUM="0.0.0"
CLUSTER_NAME="${CUSTOM_NAME:-$(hostname)}"
CONTROL_MACHINE="n/a"
SLURM_USER="n/a"
SLURMCTLD_RUNNING="false"
SLURMD_RUNNING="false"
SLURMDBD_RUNNING="false"

print_section "Host Identity"
print_info "Hostname: $(hostname)"
print_info "Cluster Name: ${CLUSTER_NAME}"
print_info "Orchestrator: standalone (no SLURM/k8s)"

# Server geolocation - determine physical location of host
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
# SECTION 2: Node Inventory (single-host)
# Cluster size is fixed at 1 for standalone; CPU/mem counts come from this
# host directly via nproc / /proc/meminfo so the totals carry real values
# instead of zeros.
# =============================================================================
print_header "2. NODE INVENTORY (single host)"

TOTAL_NODES=1
IDLE_NODES=1
ALLOCATED_NODES=0
DOWN_NODES=0
TOTAL_CPUS=$(nproc 2>/dev/null || echo 0)
# /proc/meminfo MemTotal is in kB; convert to GB (integer).
TOTAL_MEMORY_GB=$(awk '/^MemTotal:/ {printf "%d\n", $2/1024/1024}' /proc/meminfo 2>/dev/null || echo 0)

NODES_JSON=$(cat <<EOF
[{"name":"$(hostname)","state":"IDLE","cpus":${TOTAL_CPUS},"memory":$((TOTAL_MEMORY_GB*1024)),"gpus":0}]
EOF
)

# Standalone has no SLURM partition concept; keep the JSON keys but stub.
PARTITIONS_JSON='[]'
DEFAULT_PARTITION="n/a"
GPU_PARTITION="standalone"  # non-empty so Section 2.5 enters the check branch

print_section "Host Summary"
print_info "Hostname: $(hostname)"
print_info "Total CPUs: ${TOTAL_CPUS}"
print_info "Total Memory: ${TOTAL_MEMORY_GB} GB"

# =============================================================================
# SECTION 2.5: WORKER NODE CHECK
# In standalone mode the "worker" IS this host - the check script below runs
# locally instead of being shipped over srun. The check body itself is
# unchanged from the slurm port so JSON fields stay identical; only the
# execution wrapper differs.
# =============================================================================
print_header "2.5. WORKER NODE CHECK (local)"

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

if true; then
    print_section "Checking local host (standalone)"
    print_detail "Running check inline to gather GPU and software facts..."

    WORKER_CHECK_SCRIPT=$(cat "$WORKLOAD_DIR/host-check.sh")

    # Run the check inline. /tmp is fine here - we are not crossing nodes.
    WORKER_CHECK_TMPFILE=$(mktemp /tmp/cluster-audit-check-XXXXXX.sh)
    echo "$WORKER_CHECK_SCRIPT" > "$WORKER_CHECK_TMPFILE"
    chmod +x "$WORKER_CHECK_TMPFILE"

    WORKER_CHECK_OUTPUT=$(CLUSTERMAX_AUDIT_HARNESS=standalone \
        bash "$WORKER_CHECK_TMPFILE" 2>/dev/null || echo "CHECK_FAILED")

    rm -f "$WORKER_CHECK_TMPFILE"

    if [[ "$WORKER_CHECK_OUTPUT" == "CHECK_FAILED" || -z "$WORKER_CHECK_OUTPUT" || ! "$WORKER_CHECK_OUTPUT" =~ WORKER_HOSTNAME ]]; then
        print_warn "Local check failed (script error or empty output)"
        print_detail "GPU and DCGM checks will report 'unknown'"
    else
        WORKER_CHECK_OK="true"
        # Parse all KEY=VALUE lines from check output
        while IFS='=' read -r key val; do
            [[ -z "$key" || "$key" =~ ^# ]] && continue
            # Only accept lines that look like our check variables
            if [[ "$key" =~ ^WORKER_ ]]; then
                printf -v "$key" '%s' "$val"
            fi
        done < <(echo "$WORKER_CHECK_OUTPUT" | grep '^WORKER_')

        print_info "Local check: SUCCESS (host: ${WORKER_HOSTNAME})"
        print_info "GPU model: ${WORKER_GPU_MODEL}"
        print_info "Driver: ${WORKER_DRIVER_VERSION} / CUDA cap: ${WORKER_CUDA_VERSION}"
        print_info "DCGM active: ${WORKER_DCGM_ACTIVE}"
        print_info "NVMe drives: ${WORKER_NVME_COUNT} (${WORKER_NVME_TOTAL_GB} GB)"
        print_info "Boot device: ${WORKER_BOOT_DEVICE} (${WORKER_BOOT_FSTYPE})"
    fi
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
    # host-check.sh carries the real mountpoint as the first value field, so read
    # it from the value rather than lossily reconstructing it from the safe key.
    IFS='|' read -r target src fstype opts <<< "$val"
    # Look for matching df data
    df_size="" df_used="" df_avail=""
    df_key="WORKER_MNTDF_${safe_target}"
    df_val="${!df_key:-}"
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
        WORKER_ARCH_VAL="$(uname -m 2>/dev/null || echo unknown)"
    fi
    print_warn "Compute node OS unknown (worker check unavailable; reporting head node OS)"
    print_detail "OS: ${WORKER_OS_PRETTY_VAL}, Kernel: ${WORKER_KERNEL_VAL}, Architecture: ${WORKER_ARCH_VAL}"
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

# GPU totals: standalone uses the local check (which already ran nvidia-smi).
# Single host -> total == per-host count == WORKER_GPU_COUNT.
TOTAL_GPUS="${WORKER_GPU_COUNT:-0}"
[[ -z "$TOTAL_GPUS" || "$TOTAL_GPUS" == "" ]] && TOTAL_GPUS=0

# Use worker check values (authoritative); fall back to head-node nvidia-smi only if check unavailable
GPU_MODEL="unknown"
DRIVER_VERSION="unknown"
CUDA_VERSION="unknown"
GPU_MEMORY="0"

if [[ "$WORKER_CHECK_OK" == "true" ]]; then
    GPU_MODEL="$WORKER_GPU_MODEL"
    DRIVER_VERSION="$WORKER_DRIVER_VERSION"
    CUDA_VERSION="$WORKER_CUDA_VERSION"
    GPU_MEMORY="$WORKER_GPU_MEMORY"
    # Use the local check count when it reports GPUs.
    if [[ "$TOTAL_GPUS" -eq 0 && -n "$WORKER_GPU_COUNT" && "$WORKER_GPU_COUNT" -gt 0 ]]; then
        TOTAL_GPUS=$(( WORKER_GPU_COUNT * TOTAL_NODES ))
        print_detail "(GPU count estimated from check: ${WORKER_GPU_COUNT}/node × ${TOTAL_NODES} nodes)"
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
    print_info "Total GPUs: ${TOTAL_GPUS}"
    print_info "Model: ${GPU_MODEL}"
    print_info "Memory: ${GPU_MEMORY:-unknown} MB"
    print_info "Driver: ${DRIVER_VERSION}"
    print_info "CUDA cap: ${CUDA_VERSION}"
else
    print_warn "No GPUs detected on the standalone host"
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
if [[ "${SCALE_OUT_CHECKS_ENABLED:-false}" == "true" ]]; then
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
#   Criteria:       https://www.clustermax.ai/standalone
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
        print_detail "Fix: disable ACS for the GPU<->NIC PCIe switches in BIOS (often tied to VT-d / IOMMU), or per-reboot with setpci. See https://www.clustermax.ai/standalone"
        ACS_ENABLED="true"
    elif [[ "${WORKER_ACS_ENABLED:-unknown}" == "false" ]]; then
        print_info "PCIe ACS: functional GPUDirect RDMA self-test on PIX pair ${ACS_FUNCTIONAL_PAIR} passed (good - GPUDirect RDMA unobstructed)"
        ACS_ENABLED="false"
    else
        ACS_ENABLED="unknown"
    fi
elif [[ "$WORKER_CHECK_OK" == "true" && "${WORKER_ACS_CHECK_OK:-false}" == "true" ]]; then
    if [[ "${WORKER_ACS_SCOPED:-false}" != "true" ]]; then
        print_warn "PCIe ACS: topology not resolved - could not map GPU<->backend-NIC switches"
        print_detail "Found ${WORKER_ACS_TOTAL_BRIDGES} ACS-capable bridge(s) host-wide, but we only flag switches on the GPU<->NIC path and could not resolve it from sysfs."
        print_detail "Check manually which switch the GPU and its backend NIC share, then: sudo lspci -vvv -s <bridge> | grep ACSCtl"
        ACS_ENABLED="unknown"
    elif [[ "${WORKER_ACS_SUPPORTED:-false}" != "true" ]]; then
        # supported=false is only a pass when the path switches were actually read
        # and none were ACS-capable; enabled=unknown means they were unread.
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
        print_detail "Fix: disable ACS for those switches in BIOS (often tied to VT-d / IOMMU / IO virtualization), or per-reboot with setpci. See https://www.clustermax.ai/standalone"
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
else
    GPUDIRECT_RDMA=false
    ACS_ENABLED=unknown
    ACS_SUPPORTED=false
    ACS_BRIDGES=0
    ACS_ENABLED_COUNT=0
    ACS_TOTAL_BRIDGES=0
    ACS_SCOPED=false
    ACS_METHOD=skipped
    ACS_FUNCTIONAL_PAIR=none
    ACS_FUNCTIONAL_SYNDROME=""
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
    if [[ "${SCALE_OUT_CHECKS_ENABLED:-false}" != "true" ]]; then
        AMD_PEERMEM_LOADED="false"
    elif [[ "$AMD_GPUS_PRESENT" == "true" ]]; then
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
        if (( POWER_INT > 150 )); then
            print_warn "Idle power > 150 W - GPUs may be running a workload or stuck at high clocks"
        fi
    fi
else
    print_detail "Idle thermal/power: not collected (no GPU sampler available)"
fi

# Read seven days of retained kernel history on this host.
print_section "GPU kernel error history"
DMESG_XIDS_COUNT="${WORKER_DMESG_XIDS_COUNT:-unknown}"
DMESG_XID_LAST="${WORKER_DMESG_XID_LAST:-unknown}"
DMESG_AMDGPU_ERRORS_COUNT="${WORKER_DMESG_AMDGPU_ERRORS_COUNT:-unknown}"
GPU_ERROR_NODES_TOTAL=1
GPU_ERROR_NODES_CHECKED=0
GPU_ERROR_OUTPUT=$(bash -c "$(gpu_error_scan_script)" 2>/dev/null || true)
aggregate_gpu_error_history "$GPU_ERROR_OUTPUT" || true
if (( GPU_ERROR_NODES_CHECKED > 0 )); then
    case "$DMESG_XIDS_COUNT" in
        unavailable) print_detail "Xid scan: dmesg unavailable (CAP_SYSLOG required for non-root)" ;;
        0)           print_info "Xids: 0" ;;
        *[0-9]*)
            if (( DMESG_XIDS_COUNT > 0 )); then
                print_warn "Xids: ${DMESG_XIDS_COUNT} (last=Xid ${DMESG_XID_LAST:-?})"
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
    print_warn "GPU kernel error history: UNTESTED (no readable host history)"
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
        NCU_VERSION=$(ncu --version 2>/dev/null | grep -oP 'version \K[0-9.]+' | head -1 || echo "unknown")
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

# Prefer the running driver parameter because it determines current access.
if [[ -r /proc/driver/nvidia/params ]]; then
    if grep -q "RmProfilingAdminOnly: 0" /proc/driver/nvidia/params 2>/dev/null; then
        NCU_PROFILING_ENABLED="true"
        print_info "NCU profiling: Unrestricted (RmProfilingAdminOnly=0 in /proc/driver/nvidia/params)"
    else
        NCU_PROFILING_ENABLED="false"
    fi
else
    for conf_file in /etc/modcheck.d/*.conf /etc/modcheck.conf; do
        [[ -f "$conf_file" ]] || continue
        if grep -q "NVreg_RestrictProfilingToAdminUsers=" "$conf_file" 2>/dev/null; then
            NCU_PROFILING_ENABLED="false"
            if grep -q "NVreg_RestrictProfilingToAdminUsers=0" "$conf_file" 2>/dev/null; then
                NCU_PROFILING_ENABLED="true"
                NCU_PROFILING_CONF_FOUND="true"
                print_info "NCU profiling: Unrestricted (NVreg_RestrictProfilingToAdminUsers=0 in ${conf_file})"
            fi
            break
        fi
    done
fi

if [[ "$NCU_PROFILING_ENABLED" == "false" ]]; then
    print_error "NCU profiling: RESTRICTED (NVreg_RestrictProfilingToAdminUsers not set to 0)"
    print_detail "Users will get: ==ERROR== ERR_NVGPUCTRPERM: Permission denied"
    print_detail "Fix (run once per compute node, then reboot):"
    print_detail "  echo 'options nvidia NVreg_RestrictProfilingToAdminUsers=0' | sudo tee /etc/modcheck.d/nvprof.conf"
    print_detail "  sudo reboot"
    print_detail "Docker users also need: --cap-add SYS_ADMIN or --privileged"
elif [[ "$NCU_PROFILING_ENABLED" == "unknown" ]]; then
    print_warn "NCU profiling: unknown (driver configuration was unreadable)"
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

# NVIDIA HPC SDK (head-node filesystem check - shared FS covers compute nodes too)
print_section "NVIDIA HPC SDK"
NVHPC_INSTALLED="false"
if [[ -d "/opt/nvidia/hpc_sdk" ]]; then
    NVHPC_INSTALLED="true"
    # NVHPC ships under Linux_<arch>/. Check both x86_64 and aarch64 so
    # Grace boxes (GB200/GB300) report the right version instead of
    # 'unknown'.
    NVHPC_ARCH_DIR=""
    for d in /opt/nvidia/hpc_sdk/Linux_x86_64 /opt/nvidia/hpc_sdk/Linux_aarch64; do
        [[ -d "$d" ]] && { NVHPC_ARCH_DIR="$d"; break; }
    done
    if [[ -n "$NVHPC_ARCH_DIR" ]]; then
        NVHPC_VERSIONS=$(ls "$NVHPC_ARCH_DIR/" 2>/dev/null | tr '\n' ',' | sed 's/,$//' || echo "unknown")
    else
        NVHPC_VERSIONS="unknown"
    fi
    print_info "HPC SDK found: /opt/nvidia/hpc_sdk"
    print_detail "Versions: ${NVHPC_VERSIONS}"
else
    NVHPC_ALT=$(find /opt -maxdepth 4 -type d -name "hpc_sdk" 2>/dev/null | head -1 || echo "")
    if [[ -n "$NVHPC_ALT" ]]; then
        NVHPC_INSTALLED="true"
        print_info "HPC SDK found: ${NVHPC_ALT}"
    else
        print_warn "NVIDIA HPC SDK: Not found at /opt/nvidia/hpc_sdk"
        print_detail "B300 workloads benefit from HPC SDK (nvfortran, nvc++)"
    fi
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
    NCCL_LIB=$(find /usr /opt /lib /lib64 -name "libnccl.so*" 2>/dev/null | grep -v "\.so\." | head -1 || echo "")
    [[ -z "$NCCL_LIB" ]] && NCCL_LIB=$(find /usr /opt /lib /lib64 -name "libnccl.so*" 2>/dev/null | head -1 || echo "")
    if [[ -n "$NCCL_LIB" ]]; then
        NCCL_INSTALLED="true"
        NCCL_PATH="$NCCL_LIB"
        NCCL_VERSION=$(strings "$NCCL_LIB" 2>/dev/null | grep -oP 'NCCL version \K[0-9.]+' | head -1 || echo "installed")
        print_warn "NCCL: ${NCCL_LIB} (head node only - ${NCCL_VERSION})"
    else
        print_warn "NCCL: Not found on head node"
    fi
fi

# Scale-out configuration does not apply to a single standalone host.
NCCL_CONF="/etc/nccl.conf"
NCCL_CONF_OVERRIDES="false"
MPIRUN_PATH=""
MPI_INSTALLED="false"
HPCX_IN_PATH="false"
HPCX_PATH=""
SRUN_MPI_PMIX="false"

# =============================================================================
# SECTION 5: Module System (Lmod) - SKIPPED for standalone
# Lmod is an HPC head-node convenience. Standalone hosts use direct PATH /
# container tooling. Stubs below keep the JSON shape stable.
# =============================================================================
LMOD_INSTALLED="false"
LMOD_VERSION="n/a"
HAS_CUDA_MODULE="false"
HAS_HPCX_MODULE="false"
HAS_NCCL_MODULE="false"

# =============================================================================
# SECTION 6: Container Support
# =============================================================================
print_header "6. CONTAINER SUPPORT"

# Keep compatibility values for the shared JSON builder. The standalone
# collector does not inspect the Slurm Pyxis configuration.
PYXIS_INSTALLED="false"

# Enroot
print_section "Enroot"
ENROOT_INSTALLED="false"
ENROOT_VERSION="unknown"
ENROOT_PATH=$(which enroot 2>/dev/null || echo "")
ENROOT_IMPORT_WORKS="false"

if [[ -n "$ENROOT_PATH" ]]; then
    ENROOT_INSTALLED="true"
    ENROOT_VERSION=$(enroot version 2>/dev/null || echo "unknown")
    print_info "Enroot: ${ENROOT_PATH}"
    print_info "Version: ${ENROOT_VERSION}"

    # Version gate: >= 3.4.0
    ENROOT_MAJOR=$(echo "$ENROOT_VERSION" | cut -d. -f1)
    ENROOT_MINOR=$(echo "$ENROOT_VERSION" | cut -d. -f2)
    if [[ -n "$ENROOT_MAJOR" ]]; then
        if [[ "$ENROOT_MAJOR" -gt 3 ]] || [[ "$ENROOT_MAJOR" -eq 3 && "${ENROOT_MINOR:-0}" -ge 4 ]]; then
            print_info "Version meets minimum requirement (>= 3.4.0)"
        else
            print_warn "Enroot ${ENROOT_VERSION} is below recommended 3.4.0"
        fi
    fi

    # Test enroot import from Docker Hub (non-destructive, short timeout)
    print_section "Enroot Import Test (docker://hello-world)"
    ENROOT_SQSH="/tmp/enroot-audit-hello-world-$$.sqsh"
    print_detail "Running: timeout 30 enroot import -o ${ENROOT_SQSH} docker://hello-world"
    ENROOT_IMPORT_OUT=$(timeout 30 enroot import -o "$ENROOT_SQSH" docker://hello-world 2>&1)
    ENROOT_IMPORT_RC=$?
    if [[ $ENROOT_IMPORT_RC -eq 0 && -f "$ENROOT_SQSH" ]]; then
        ENROOT_IMPORT_WORKS="true"
        print_info "enroot import: SUCCESS (Docker Hub accessible)"
        rm -f "$ENROOT_SQSH"
    elif [[ $ENROOT_IMPORT_RC -eq 124 ]]; then
        print_warn "enroot import: TIMED OUT after 30s (network may be slow or Docker Hub blocked)"
        rm -f "$ENROOT_SQSH"
    else
        print_warn "enroot import: FAILED (exit ${ENROOT_IMPORT_RC})"
        print_detail "Output: $(echo "$ENROOT_IMPORT_OUT" | head -3)"
        rm -f "$ENROOT_SQSH"
    fi
else
    print_warn "Enroot: Not found"
    print_detail "Install from: https://github.com/NVIDIA/enroot"
fi

# Docker (login node)
print_section "Docker"
DOCKER_INSTALLED="false"
DOCKER_PATH=$(which docker 2>/dev/null || echo "")
DOCKER_ON_WORKERS="false"
# Standalone: the local host IS the worker, so these container checks always run
# on the compute node. Mark the worker check OK so a genuinely-absent component
# is still reported (and audit_findings does not downgrade it to "unverified"),
# while the slurm/k8s worker-check-unavailable gate stays a false-negative guard.
CONTAINER_WORKER_CHECK_OK="true"
CONTAINER_WORKER_NODE=$(hostname 2>/dev/null || echo "localhost")
DOCKER_NVIDIA_RUNTIME_CONFIGURED="false"
NVIDIA_CONTAINER_TOOLKIT="false"
NVIDIA_CT_VERSION="unknown"
DOCKER_VERSION="unknown"
DOCKER_VERSION_OK="false"
NVIDIA_CT_VERSION_OK="false"
RUNC_INSTALLED="false"
RUNC_VERSION="unknown"
# Operational recommendations come from the generated minimum table, the same
# source the security grading reads. They were hardcoded here and in
# cluster-audit-slurm.sh, and the NVIDIA Container Toolkit literal (1.19.0) fell
# below the minimum version the June 2026 bulletin set (1.19.1, CVE-2026-24260),
# so the audit recommended a version its own security check fails. The two
# verdicts stay separate; only the duplicated literal is gone.
DOCKER_RECOMMENDED_MIN=$(minimum_version components.docker.minimum)
NVIDIA_CT_RECOMMENDED_MIN=$(minimum_version components.nvidiaContainerToolkit.minimum)
if [[ "$DOCKER_RECOMMENDED_MIN" == "unknown" || "$NVIDIA_CT_RECOMMENDED_MIN" == "unknown" ]]; then
    print_warn "Container version recommendations unavailable: the minimum version table could not be read"
    print_detail "Docker: ${DOCKER_RECOMMENDED_MIN}, NVIDIA Container Toolkit: ${NVIDIA_CT_RECOMMENDED_MIN}"
    print_detail "Versions stay not-verified (false) rather than being graded against a guessed minimum"
fi

if [[ -n "$DOCKER_PATH" ]]; then
    DOCKER_INSTALLED="true"
    DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oP 'Docker version \K[0-9.]+' || echo "unknown")
    print_info "Docker: ${DOCKER_PATH}"
    print_info "Version: ${DOCKER_VERSION}"
    # version_meets_minimum, not version_ge: an unresolved minimum must leave this
    # not-verified instead of passing every version.
    if version_meets_minimum "$DOCKER_VERSION" "$DOCKER_RECOMMENDED_MIN"; then
        DOCKER_VERSION_OK="true"
        print_info "Docker version meets recommended >= ${DOCKER_RECOMMENDED_MIN}"
    elif [[ "$DOCKER_RECOMMENDED_MIN" == "unknown" ]]; then
        print_warn "Docker ${DOCKER_VERSION}: recommended minimum unknown, version not verified"
    else
        print_warn "Docker ${DOCKER_VERSION} is below recommended ${DOCKER_RECOMMENDED_MIN}"
    fi

    if docker info 2>/dev/null | grep -qi nvidia; then
        print_info "NVIDIA Container Toolkit: Configured in Docker"
        NVIDIA_CONTAINER_TOOLKIT="true"
        DOCKER_NVIDIA_RUNTIME_CONFIGURED="true"
    else
        print_warn "NVIDIA Container Toolkit: Not detected in docker info"
    fi
else
    print_warn "Docker: Not found on login node"
fi

DOCKER_ON_HEAD="$DOCKER_INSTALLED"

# nvidia-container-toolkit version check (independent of docker)
NCT_VERSION_CMD=$(nvidia-container-toolkit --version 2>/dev/null | grep -oP 'version \K[0-9.]+' | head -1 || nvidia-ctk --version 2>/dev/null | grep -oP 'version \K[0-9.]+' | head -1 || echo "")
if [[ -n "$NCT_VERSION_CMD" ]]; then
    NVIDIA_CT_VERSION="$NCT_VERSION_CMD"
    NVIDIA_CONTAINER_TOOLKIT="true"
    if version_meets_minimum "$NCT_VERSION_CMD" "$NVIDIA_CT_RECOMMENDED_MIN"; then
        print_info "nvidia-container-toolkit: ${NCT_VERSION_CMD} (meets >= ${NVIDIA_CT_RECOMMENDED_MIN})"
        NVIDIA_CT_VERSION_OK="true"
    elif [[ "$NVIDIA_CT_RECOMMENDED_MIN" == "unknown" ]]; then
        print_warn "nvidia-container-toolkit: ${NCT_VERSION_CMD}, recommended minimum unknown, version not verified"
    else
        print_warn "nvidia-container-toolkit: ${NCT_VERSION_CMD} is below recommended ${NVIDIA_CT_RECOMMENDED_MIN}"
    fi
else
    NCT_DEB=$(dpkg -l nvidia-container-toolkit 2>/dev/null | grep '^ii' | awk '{print $3}' || echo "")
    if [[ -n "$NCT_DEB" ]]; then
        NVIDIA_CT_VERSION="$NCT_DEB"
        print_info "nvidia-container-toolkit (dpkg): ${NCT_DEB}"
        NVIDIA_CONTAINER_TOOLKIT="true"
        if version_meets_minimum "$NCT_DEB" "$NVIDIA_CT_RECOMMENDED_MIN"; then
            NVIDIA_CT_VERSION_OK="true"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if NCT_RPM=$(rpm -q --qf '%{VERSION}-%{RELEASE}' nvidia-container-toolkit 2>/dev/null); then
            NVIDIA_CT_VERSION="$NCT_RPM"
            NVIDIA_CONTAINER_TOOLKIT="true"
            if version_meets_minimum "$NCT_RPM" "$NVIDIA_CT_RECOMMENDED_MIN"; then
                NVIDIA_CT_VERSION_OK="true"
            fi
            print_info "nvidia-container-toolkit (rpm): ${NCT_RPM}"
        fi
    fi
fi

if command -v runc >/dev/null 2>&1; then
    RUNC_INSTALLED="true"
    RUNC_VERSION=$(runc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([^[:space:]]*)?' | head -1 || echo unknown)
elif command -v dpkg-query >/dev/null 2>&1; then
    RUNC_VERSION=$(dpkg-query -W -f='${Version}' runc 2>/dev/null || true)
    [[ -n "$RUNC_VERSION" ]] && RUNC_INSTALLED="true"
    RUNC_VERSION="${RUNC_VERSION:-unknown}"
elif command -v rpm >/dev/null 2>&1; then
    if RUNC_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' runc 2>/dev/null); then
        RUNC_INSTALLED="true"
    else
        RUNC_VERSION="unknown"
    fi
fi

SECURITY_DOCKER_VERSION="unknown"
SECURITY_NCT_VERSION="unknown"
SECURITY_RUNC_VERSION="unknown"
CONTAINER_RUNTIME_SCOPE="nested-container"
if [[ ! -f /.dockerenv && ! -f /run/.containerenv \
    && -x "$(command -v systemd-detect-virt 2>/dev/null)" ]] \
    && ! systemd-detect-virt --container >/dev/null 2>&1; then
    CONTAINER_RUNTIME_SCOPE="host"
    if [[ "$DOCKER_INSTALLED" == "true" ]]; then
        SECURITY_DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)
    else
        SECURITY_DOCKER_VERSION="not-installed"
    fi
    SECURITY_NCT_VERSION="$([[ "$NVIDIA_CONTAINER_TOOLKIT" == "true" ]] \
        && echo "${NVIDIA_CT_VERSION:-unknown}" || echo not-installed)"
    SECURITY_RUNC_VERSION="$([[ "$RUNC_INSTALLED" == "true" ]] \
        && echo "${RUNC_VERSION:-unknown}" || echo not-installed)"
elif docker info >/dev/null 2>&1; then
    SECURITY_DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)
fi

# Docker on the host (standalone: head == worker == this host).
DOCKER_ON_WORKERS="$DOCKER_INSTALLED"
if [[ "$DOCKER_INSTALLED" == "false" ]]; then
    print_error "Docker: Not available - container-based benchmarks (fio, storage, ROCm) will fail"
    print_detail "Install Docker to enable the standalone runners"
fi

# Singularity/Apptainer
print_section "Singularity/Apptainer"
SINGULARITY_INSTALLED="false"
SINGULARITY_PATH=$(which singularity 2>/dev/null || which apptainer 2>/dev/null || echo "")
if [[ -n "$SINGULARITY_PATH" ]]; then
    SINGULARITY_INSTALLED="true"
    SINGULARITY_VERSION=$(singularity --version 2>/dev/null || apptainer --version 2>/dev/null || echo "unknown")
    print_info "Singularity/Apptainer: ${SINGULARITY_PATH}"
    print_info "Version: ${SINGULARITY_VERSION}"
else
    print_warn "Singularity/Apptainer: Not found"
fi

# =============================================================================
# SECTION 7: Networking & InfiniBand
# =============================================================================
if [[ "${SCALE_OUT_CHECKS_ENABLED:-false}" == "true" ]]; then
print_header "7. NETWORKING & INFINIBAND"
print_detail "NOTE: IB device checks use WORKER NODE data from check (compute node HCAs, not head node management NIC)"

# IB device data comes from worker check; head-node ibstat/ibhosts are only fallback
IB_INSTALLED="false"
RDMA_TYPE="none"
HCA_DEVICES_LIST=()
HCA_DEVICES_JSON="[]"
MLNX_DEVICES="none"

# MOFED version - package is same across nodes; head-node check is valid
print_section "MOFED (Mellanox OFED)"
MOFED_VERSION="none"
if command -v ofed_info &> /dev/null; then
    MOFED_VERSION=$(ofed_info -s 2>/dev/null | grep -oP 'MLNX_OFED_LINUX-\K[0-9.-]+' || echo "unknown")
    print_info "MOFED Version: ${MOFED_VERSION}"
elif [[ -f /etc/mlnx-release ]]; then
    MOFED_VERSION=$(head -1 /etc/mlnx-release 2>/dev/null || echo "unknown")
    print_info "MOFED: ${MOFED_VERSION}"
else
    print_warn "MOFED: Not detected (ofed_info not found, /etc/mlnx-release missing)"
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
            for pf in "$PKEY_DIR"/*; do
                pv=$(cat "$pf" 2>/dev/null | tr -d '[:space:]' || echo "")
                [[ "$pv" == "0x0000" ]] && continue
                if [[ "$pv" =~ ^0xffff$|^0x8001$ ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    print_detail "  $(basename $pf): ${pv} (default partition)"
                elif [[ -n "$pv" ]]; then
                    IB_PKEYS_CONFIGURED="true"
                    IB_PKEY_COUNT=$((IB_PKEY_COUNT + 1))
                    print_detail "  $(basename $pf): ${pv}"
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

# SHARP check
print_section "SHARP (Scalable Hierarchical Aggregation and Reduction Protocol)"
SHARP_AVAILABLE="false"
SHARP_AM_KEY_CONFIGURED="false"

SHARP_HELLO=$(which sharp_hello 2>/dev/null || find /opt /usr -name "sharp_hello" 2>/dev/null | head -1 || echo "")
if [[ -n "$SHARP_HELLO" ]]; then
    SHARP_AVAILABLE="true"
    print_info "sharp_hello: Found at ${SHARP_HELLO}"
elif [[ -n "${SHARP_HOME:-}" || -n "${HPCX_SHARP_DIR:-}" ]]; then
    SHARP_AVAILABLE="true"
    print_info "SHARP env vars set: SHARP_HOME=${SHARP_HOME:-} HPCX_SHARP_DIR=${HPCX_SHARP_DIR:-}"
else
    print_warn "SHARP: Not detected (sharp_hello not found, no SHARP env vars)"
    print_detail "SHARP enables in-network compute reductions - confirm with provider if available"
fi

# Check SHARP AM auth config
for SHARP_CONF in /etc/sharp/sharp_am_auth.conf /opt/mellanox/sharp/share/sharp/conf/sharp_am.cfg; do
    if [[ -f "$SHARP_CONF" ]]; then
        print_info "SHARP config: ${SHARP_CONF} exists"
        AM_KEY=$(grep -i "am_key\|amkey\|key" "$SHARP_CONF" 2>/dev/null | grep -v "^#" | head -1 || echo "")
        if [[ -n "$AM_KEY" ]]; then
            SHARP_AM_KEY_CONFIGURED="true"
            print_info "SHARP AM Key: Configured"
        else
            print_warn "SHARP AM Key: Not configured in ${SHARP_CONF}"
        fi
    fi
done

audit_ufm_secured_profile "$RDMA_TYPE"
else
    IB_INSTALLED=false
    RDMA_TYPE=none
    HCA_DEVICES_LIST=()
    HCA_DEVICES_JSON="[]"
    MLNX_DEVICES=none
    MOFED_VERSION=none
    HCA_NAMING_VALID=false
    IB_PKEYS_CONFIGURED=false
    IB_PKEY_COUNT=0
    ROCE_MODE=false
    NIC_FABRIC_JSON="[]"
    NIC_FABRIC_SUMMARY=none
    COMPUTE_FABRIC_CLASS=not_applicable
    COMPUTE_FABRIC_COUNT=0
    COMPUTE_FABRIC_GBPS=0
    NIC_HAS_INFINIBAND=false
    NIC_HAS_ROCE=false
    NIC_HAS_EFA=false
    NIC_HAS_OTHER=false
    NETWORK_UTILITIES_JSON="{}"
    NCCL_GID_INDEX_VALUE=unset
    IB_TENANT_ISOLATION=not_applicable
    IB_SM_KEY_CONFIGURED=false
    SHARP_AVAILABLE=false
    SHARP_AM_KEY_CONFIGURED=false
    UFM_SECURED_PROFILE_JSON='{"applicable":false,"status":"not_applicable","profile":"Secured Bare Metal Cloud","verification":"not applicable to standalone","requiredControls":[]}'
fi

# The shared JSON builder still emits its historical Slurm topology fields.
# An empty compatibility value keeps those fields false without running a
# Slurm topology check on this standalone host.
TOPOLOGY_CONF=""

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

# Compatibility values for scheduler fields in the shared JSON builder. The
# standalone collector does not run Slurm health, prolog, NHC, or remediation
# checks.
HEALTH_CHECK_PROGRAM=""
HEALTH_CHECK_INTERVAL=""
HEALTH_CHECK_CONFIGURED="false"
DCGM_SLURM="false"
PROLOG_RUNTIME_SEC="n/a"
PROLOG_FAST="n/a"
NHC_INSTALLED="false"
AUTO_REMEDIATION_CONFIGURED="false"

# DCGM runs on this standalone compute host. The local worker check is the
# primary source, and the local command path is the fallback.
print_section "DCGM (Data Center GPU Manager) - on compute node"
DCGM_INSTALLED="false"
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

# Monitoring stack detection: prometheus / dcgm-exporter / grafana / node-exporter.
# We check listening ports (best signal — exporters expose HTTP) and systemd unit names.
print_section "Monitoring Stack"
PROMETHEUS_DETECTED="false"
DCGM_EXPORTER_DETECTED="false"
NODE_EXPORTER_DETECTED="false"
GRAFANA_DETECTED="false"
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

# systemd fallback for things not running on head node (e.g. dcgm-exporter on workers)
if systemctl is-active dcgm-exporter &>/dev/null; then DCGM_EXPORTER_DETECTED="true"; fi
if systemctl is-active prometheus &>/dev/null; then PROMETHEUS_DETECTED="true"; fi
if systemctl is-active grafana-server &>/dev/null; then GRAFANA_DETECTED="true"; fi
if systemctl is-active node-exporter prometheus-node-exporter &>/dev/null; then NODE_EXPORTER_DETECTED="true"; fi
# Containerized and tarball Grafana installs can run without a systemd unit,
# and unprivileged `ss -p` may hide process details. The executable comm name
# remains visible through procfs.
if pgrep -x grafana &>/dev/null || pgrep -x grafana-server &>/dev/null; then GRAFANA_DETECTED="true"; fi
# Same shape for dcgm-exporter, and it carries more weight here: on standalone
# this flag decides between "not-installed" and "unknown", so a miss is a clean
# grade for a host that runs an exporter. A compose monitoring stack puts
# Prometheus and dcgm-exporter on one bridge network, where the exporter is
# scraped over that network with no published host port and no systemd unit, so
# neither check above sees it. The audit runs in the host PID view, so procfs
# shows the container process regardless of its network namespace. This is also
# the only check that still works when neither `ss` nor `netstat` is installed.
if pgrep -x dcgm-exporter &>/dev/null; then DCGM_EXPORTER_DETECTED="true"; fi

[[ "$PROMETHEUS_DETECTED"   == "true" ]] && print_info "Prometheus: detected (port 9090 or systemd active)"     || print_detail "Prometheus: not detected"
[[ "$DCGM_EXPORTER_DETECTED" == "true" ]] && print_info "dcgm-exporter: detected (port 9400 or systemd active)" || print_detail "dcgm-exporter: not detected"
[[ "$NODE_EXPORTER_DETECTED" == "true" ]] && print_info "node-exporter: detected (port 9100 or systemd active)" || print_detail "node-exporter: not detected"
[[ "$GRAFANA_DETECTED"      == "true" ]] && print_info "Grafana: detected (port 3000 or systemd active)"        || print_detail "Grafana: not detected"

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

# SSH to other compute nodes - n/a on standalone (single host).
SSH_TO_COMPUTE="false"
FIRST_COMPUTE_NODE="$(hostname)"

# SLURM accounting (sacctmgr / sacct) - n/a on standalone.
ACCOUNTING_STORAGE="none"
SACCT_AVAILABLE="false"

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

# Standard SLURM commands - not applicable on standalone.
SLURM_CMDS_OK="false"
declare -A SLURM_CMD_AVAIL=()

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
# SECTION 11: SLURM Default Resource Limits - SKIPPED for standalone
# All values are SLURM scheduler limits; no equivalent on a standalone host.
# Stub the variables that the final JSON references.
# =============================================================================
DEF_CPUS_PER_TASK="1"
DEF_MEM_PER_CPU=0
DEF_MEM_PER_GPU=0
DEF_MEM_PER_NODE=0
MAX_MEM_PER_CPU=0
MAX_MEM_PER_NODE=0
CPU_FREQ_DEF=""
CPU_FREQ_GOV=""
TASK_PLUGIN="n/a"
PROCTRACK_TYPE="n/a"

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

print_section "Host Overview"
echo ""
echo "  Host:                  $(hostname)"
echo "  Cluster Name:          ${CLUSTER_NAME}"
echo "  Orchestrator:          standalone"
echo "  CPUs:                  ${TOTAL_CPUS}"
echo "  Memory:                ${TOTAL_MEMORY_GB} GB"
echo "  GPUs:                  ${TOTAL_GPUS} × ${GPU_MODEL}"
echo "  AMD GPUs:              ${AMD_GPUS_PRESENT} (${WORKER_AMD_GPU_MODEL:-none})"
echo "  GDRCopy installed:     ${GDRCOPY_INSTALLED} (gdrdrv loaded: ${GDRCOPY_GDRDRV_LOADED})"
echo "  GPU idle (max):        ${GPU_IDLE_TEMP_MAX} °C / ${GPU_IDLE_POWER_MAX} W"
echo "  Xids in dmesg:         ${DMESG_XIDS_COUNT}"
echo "  Containers:            Enroot=${ENROOT_INSTALLED}, Docker=${DOCKER_INSTALLED}"
echo "  NCCL Version:          ${NCCL_VERSION}"
echo "  Monitoring stack:      prom=${PROMETHEUS_DETECTED} dcgm-exp=${DCGM_EXPORTER_DETECTED} grafana=${GRAFANA_DETECTED}"
echo "  External IDP:          ${IDP_DETECTED} (${IDP_TYPE})"
echo "  NCU Available:         ${NCU_INSTALLED} (${NCU_VERSION})"
echo "  NCU HW Counters:       ${NCU_COUNTER_ACCESS}"
echo "  perf Installed:        ${PERF_INSTALLED} (paranoid=${PERF_EVENT_PARANOID}, kptr=${PERF_KPTR_RESTRICT})"
echo "  perf stat:             ${PERF_STAT_ACCESS}"
echo "  perf top:              ${PERF_TOP_ACCESS}"
echo "  Boot Drive:            ${WORKER_BOOT_DEVICE} (${WORKER_BOOT_FSTYPE})"
echo "  NVMe:                  ${WORKER_NVME_COUNT} drives, ${WORKER_NVME_TOTAL_GB} GB"
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
# natural next step, would silently flip an AMD cluster back to "nvidia". This
# collector is the worse case, because the call below passes DRIVER_VERSION
# itself as the security driver version, so the promoted amdgpu version would
# be graded directly against NVIDIA's driver minimums.
SECURITY_GPU_VENDOR="nvidia"
if [[ "${AMD_GPUS_PRESENT:-false}" == "true" ]]; then
    SECURITY_GPU_VENDOR="amd"
fi
# This host is the whole fleet, so the monitoring-stack scan above is a complete
# search for dcgm-exporter: it read this machine's listening sockets and its
# systemd units, and there is no other node it could be running on. A negative
# result is therefore evidence of absence and grades "not-installed" instead of
# "unknown", which stops every exporter-free standalone audit from raising a
# "requires provider attestation" finding that no operator can answer.
#
# The Slurm collector deliberately does NOT do this. It runs on the head node
# and scans only head-node sockets and head-node systemd, while the exporter
# normally runs on the workers, so a negative there proves nothing about the
# fleet and must stay "unknown".
DCGM_EXPORTER_PRESENT="${DCGM_EXPORTER_DETECTED:-unknown}"
SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit \
    "$WORKER_CHECK_OUTPUT" "$DRIVER_VERSION" "$SECURITY_NCT_VERSION" \
    "$SECURITY_RUNC_VERSION" "$SECURITY_DOCKER_VERSION" "$SECURITY_GPU_VENDOR" \
    "" "standalone")

# Determine cluster name for file
if [[ -n "$CUSTOM_NAME" ]]; then
    AUDIT_CLUSTER_NAME="$CUSTOM_NAME"
else
    AUDIT_CLUSTER_NAME=$(echo "$CLUSTER_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-64)
fi

# Build JSON
AUDIT_TYPE="standalone"
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
