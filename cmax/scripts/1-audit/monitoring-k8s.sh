#!/bin/bash
# =============================================================================
# Kubernetes GPU Cluster Monitoring Audit Script
# =============================================================================
# Audits monitoring infrastructure on GPU Kubernetes clusters.
# Checks for DCGM, Prometheus, Grafana, alerting, and related components.
#
# Usage:
#   ./00-monitoring-audit.sh [options]
#
# Options:
#   --name <name>      Custom cluster name for output file
#   --output-dir <dir> Directory for JSON output (default: ./audit-results)
#   --json-only        Output JSON to stdout only, no file
#   --help             Show this help message
#
# Reference: https://www.clustermax.ai/monitoring
# =============================================================================

set -o pipefail

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Formatting functions
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

# Parse arguments
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
            head -20 "$0" | tail -15
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check prerequisites
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq not found"
    exit 1
fi

if ! kubectl cluster-info &> /dev/null 2>&1; then
    echo "Error: Cannot connect to Kubernetes cluster"
    exit 1
fi

# Timestamps
AUDIT_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_TIMESTAMP_FILE=$(date +"%Y%m%d-%H%M%S")

# Get cluster info
CLUSTER_NAME=$(kubectl config current-context 2>/dev/null || echo "unknown")

# Initialize all variables with defaults
SM_COUNT=0
ALERT_RULES_COUNT=0
GRAFANA_DASHBOARDS=0
DCGM_METRICS_COUNT=0
DCGM_POD=""

print_header "GPU CLUSTER MONITORING AUDIT"
echo "Cluster: ${CLUSTER_NAME}"
echo "Time: ${AUDIT_TIMESTAMP}"

# =============================================================================
# SECTION 1: DCGM (NVIDIA Data Center GPU Manager)
# =============================================================================
print_header "1. DCGM EXPORTER"

DCGM_INSTALLED="false"
DCGM_NAMESPACE=""
DCGM_VERSION=""
DCGM_PODS_RUNNING=0
DCGM_SERVICE_MONITOR="false"
DCGM_POD=""

print_section "DCGM Exporter Detection"

# Check for dcgm-exporter in various namespaces
for ns in gpu-operator gpu-operator-resources nvidia-gpu-operator nvidia monitoring prometheus dcgm default; do
    DCGM_PODS=$(kubectl get pods -n "$ns" -l app=nvidia-dcgm-exporter --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$DCGM_PODS" -gt 0 ]]; then
        DCGM_INSTALLED="true"
        DCGM_NAMESPACE="$ns"
        DCGM_POD=$(kubectl get pods -n "$ns" -l app=nvidia-dcgm-exporter -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        DCGM_PODS_RUNNING=$(kubectl get pods -n "$ns" -l app=nvidia-dcgm-exporter --no-headers 2>/dev/null | grep -c Running 2>/dev/null || true)
        DCGM_PODS_RUNNING=${DCGM_PODS_RUNNING//[^0-9]/}
        break
    fi

    # Also check by name pattern
    DCGM_PODS=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -c "dcgm-exporter" || true)
    DCGM_PODS=${DCGM_PODS//[^0-9]/}
    DCGM_PODS=${DCGM_PODS:-0}
    if [[ "$DCGM_PODS" -gt 0 ]]; then
        DCGM_INSTALLED="true"
        DCGM_NAMESPACE="$ns"
        DCGM_POD=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | awk '$1 ~ /dcgm-exporter/ {print $1; exit}')
        DCGM_PODS_RUNNING=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep "dcgm-exporter" | grep -c Running 2>/dev/null || true)
        DCGM_PODS_RUNNING=${DCGM_PODS_RUNNING//[^0-9]/}
        break
    fi
done

# Managed providers can place the exporter in a branded namespace and use the
# current app.kubernetes.io labels. Scan every visible namespace before the
# audit concludes that the exporter is absent.
if [[ "$DCGM_INSTALLED" == "false" ]]; then
    DCGM_RECORD=$(kubectl get pods --all-namespaces -o json 2>/dev/null \
        | jq -r '
            [.items[]
             | select(.metadata.name | test("(^|-)dcgm-exporter(-|$)"; "i"))
             | {namespace: .metadata.namespace, name: .metadata.name,
                running: (.status.phase == "Running")}]
            | sort_by([if .running then 0 else 1 end, .namespace, .name])
            | first // empty
            | [.namespace, .name] | @tsv' 2>/dev/null || true)
    if [[ -n "$DCGM_RECORD" ]]; then
        IFS=$'\t' read -r DCGM_NAMESPACE DCGM_POD <<< "$DCGM_RECORD"
        DCGM_INSTALLED="true"
        DCGM_PODS_RUNNING=$(kubectl get pods -n "$DCGM_NAMESPACE" -o json 2>/dev/null \
            | jq '[.items[] | select((.metadata.name | test("(^|-)dcgm-exporter(-|$)"; "i")) and .status.phase == "Running")] | length' 2>/dev/null || echo 0)
    fi
fi
# End cross-namespace DCGM exporter discovery.

if [[ "$DCGM_INSTALLED" == "true" ]]; then
    print_info "DCGM Exporter: Installed in ${DCGM_NAMESPACE}"
    print_info "Running pods: ${DCGM_PODS_RUNNING}"

    # Get version from pod image
    DCGM_IMAGE=$(kubectl get pod -n "$DCGM_NAMESPACE" "$DCGM_POD" -o json 2>/dev/null \
        | jq -r '.spec.containers as $containers
            | [$containers[] | select(.image | test("dcgm-exporter"; "i")) | .image]
            | first // $containers[0].image // ""' 2>/dev/null)
    if [[ -n "$DCGM_IMAGE" ]]; then
        DCGM_VERSION=$(echo "$DCGM_IMAGE" | sed 's/.*://' | sed 's/@.*//' || echo "$DCGM_IMAGE")
        print_info "Image: ${DCGM_IMAGE}"
    fi

    # Check for ServiceMonitor
    if kubectl get servicemonitor -n "$DCGM_NAMESPACE" -l app=nvidia-dcgm-exporter -o name 2>/dev/null | grep -q .; then
        DCGM_SERVICE_MONITOR="true"
        print_info "ServiceMonitor: Configured"
    elif kubectl get servicemonitor --all-namespaces 2>/dev/null | grep -qi dcgm; then
        DCGM_SERVICE_MONITOR="true"
        print_info "ServiceMonitor: Found (different namespace)"
    else
        print_warn "ServiceMonitor: Not found"
    fi

    # Check DCGM service
    DCGM_SVC=$(kubectl get svc -n "$DCGM_NAMESPACE" --no-headers 2>/dev/null | awk '$1 ~ /dcgm-exporter/ {print; exit}')
    if [[ -n "$DCGM_SVC" ]]; then
        DCGM_SERVICE_NAME=$(awk '{print $1}' <<< "$DCGM_SVC")
        DCGM_PORT=$(kubectl get svc -n "$DCGM_NAMESPACE" "$DCGM_SERVICE_NAME" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
        print_info "Service: Port ${DCGM_PORT:-9400}"
    fi
else
    print_warn "DCGM Exporter: Not detected"
    print_detail "Install via GPU Operator or standalone dcgm-exporter"
fi

# Check for DCGM metrics availability
print_section "DCGM Metrics"
DCGM_METRICS_AVAILABLE="false"
DCGM_METRICS_COUNT=0

if [[ "$DCGM_INSTALLED" == "true" ]]; then
    # Try to get metrics endpoint
    if [[ -n "$DCGM_POD" ]]; then
        # Check if metrics endpoint responds
        METRICS_BODY=$(kubectl exec -n "$DCGM_NAMESPACE" "$DCGM_POD" -- curl -s http://localhost:9400/metrics 2>/dev/null || true)
        if [[ -z "$METRICS_BODY" ]]; then
            # Distroless exporter images do not contain curl. The API server
            # pod proxy tests the same endpoint without requiring a utility in
            # the container image.
            METRICS_BODY=$(kubectl get --raw "/api/v1/namespaces/${DCGM_NAMESPACE}/pods/${DCGM_POD}:9400/proxy/metrics" 2>/dev/null || true)
        fi
        METRICS_CHECK=$(printf '%s\n' "$METRICS_BODY" | head -5)
        if [[ -n "$METRICS_CHECK" ]]; then
            DCGM_METRICS_AVAILABLE="true"
            DCGM_METRICS_COUNT=$(printf '%s\n' "$METRICS_BODY" | grep -c "^DCGM_" 2>/dev/null || true)
            DCGM_METRICS_COUNT=${DCGM_METRICS_COUNT//[^0-9]/}
            DCGM_METRICS_COUNT=${DCGM_METRICS_COUNT:-0}
            print_info "Metrics endpoint: Responding"
            print_info "DCGM metrics count: ${DCGM_METRICS_COUNT}"
        else
            print_warn "Metrics endpoint: Not responding"
        fi
    fi
fi

# =============================================================================
# SECTION 1b: AMD GPU Metrics Exporter (device-metrics-exporter)
# =============================================================================
# AMD clusters export GPU telemetry via amd-device-metrics-exporter, the AMD
# analog of NVIDIA's dcgm-exporter. The DCGM section above only matches NVIDIA,
# so without this block AMD clusters are scored as having no GPU metrics even
# when they export full GPU telemetry. See https://www.clustermax.ai/monitoring
print_header "1b. AMD GPU METRICS EXPORTER"

AMD_GPU_EXPORTER_INSTALLED="false"
AMD_GPU_EXPORTER_NAMESPACE=""
AMD_GPU_EXPORTER_PODS_RUNNING=0

print_section "AMD device-metrics-exporter Detection"

for ns in kube-amd-gpu amd-gpu amd-gpu-operator mxgpu monitoring gpu-operator default; do
    AMD_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=amd-device-metrics-exporter --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$AMD_PODS" -gt 0 ]]; then
        AMD_GPU_EXPORTER_INSTALLED="true"
        AMD_GPU_EXPORTER_NAMESPACE="$ns"
        AMD_GPU_EXPORTER_PODS_RUNNING=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=amd-device-metrics-exporter --no-headers 2>/dev/null | grep -c Running 2>/dev/null || true)
        break
    fi

    # Also check by name pattern
    AMD_PODS=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -cE "device-metrics-exporter|amdgpu-metrics" || true)
    AMD_PODS=${AMD_PODS//[^0-9]/}
    AMD_PODS=${AMD_PODS:-0}
    if [[ "$AMD_PODS" -gt 0 ]]; then
        AMD_GPU_EXPORTER_INSTALLED="true"
        AMD_GPU_EXPORTER_NAMESPACE="$ns"
        AMD_GPU_EXPORTER_PODS_RUNNING=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -E "device-metrics-exporter|amdgpu-metrics" | grep -c Running 2>/dev/null || true)
        break
    fi
done

# Fallback: scan all namespaces (helm release names vary across providers)
if [[ "$AMD_GPU_EXPORTER_INSTALLED" == "false" ]]; then
    AMD_NS=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | grep -E "amd-device-metrics-exporter|amdgpu-metrics-exporter" | head -1 | awk '{print $1}')
    if [[ -n "$AMD_NS" ]]; then
        AMD_GPU_EXPORTER_INSTALLED="true"
        AMD_GPU_EXPORTER_NAMESPACE="$AMD_NS"
        AMD_GPU_EXPORTER_PODS_RUNNING=$(kubectl get pods -n "$AMD_NS" --no-headers 2>/dev/null | grep -E "amd-device-metrics-exporter|amdgpu-metrics-exporter" | grep -c Running 2>/dev/null || true)
    fi
fi
AMD_GPU_EXPORTER_PODS_RUNNING=${AMD_GPU_EXPORTER_PODS_RUNNING//[^0-9]/}
AMD_GPU_EXPORTER_PODS_RUNNING=${AMD_GPU_EXPORTER_PODS_RUNNING:-0}

if [[ "$AMD_GPU_EXPORTER_INSTALLED" == "true" ]]; then
    print_info "AMD device-metrics-exporter: Installed in ${AMD_GPU_EXPORTER_NAMESPACE} (${AMD_GPU_EXPORTER_PODS_RUNNING} pods)"
else
    print_warn "AMD device-metrics-exporter: Not detected"
fi

# Vendor-neutral GPU-metrics-exporter signal: true if either NVIDIA dcgm-exporter
# or AMD device-metrics-exporter is present.
GPU_METRICS_EXPORTER_INSTALLED="false"
GPU_METRICS_VENDOR="none"
if [[ "$DCGM_INSTALLED" == "true" ]]; then
    GPU_METRICS_EXPORTER_INSTALLED="true"
    GPU_METRICS_VENDOR="nvidia"
elif [[ "$AMD_GPU_EXPORTER_INSTALLED" == "true" ]]; then
    GPU_METRICS_EXPORTER_INSTALLED="true"
    GPU_METRICS_VENDOR="amd"
fi

# Per-job / per-pod GPU attribution: is the GPU-metrics exporter configured to
# label each metric with the *consuming workload* (pod/namespace/container), not
# just the exporter's own pod? Without this you cannot tell which job/user is
# driving which GPUs.
#   - NVIDIA dcgm-exporter: DCGM_EXPORTER_KUBERNETES=true (or --kubernetes arg)
#     attaches pod/namespace/container labels (surface as exported_* after SD).
#   - AMD device-metrics-exporter: pod association via its config (kube
#     pod-resources); detected from container args/env.
# The exporter config is the reliable signal (the raw /metrics scrape is often
# not reachable from the audit context).
print_section "Per-job GPU attribution"
GPU_METRICS_JOB_ATTRIBUTION="false"
GPU_METRICS_ATTRIBUTION_METHOD="none"
if [[ "$DCGM_INSTALLED" == "true" ]]; then
    DCGM_K8S_ENV=$(kubectl get pod -n "$DCGM_NAMESPACE" "$DCGM_POD" -o jsonpath='{.spec.containers[0].env[?(@.name=="DCGM_EXPORTER_KUBERNETES")].value}' 2>/dev/null)
    DCGM_ARGS=$(kubectl get pod -n "$DCGM_NAMESPACE" "$DCGM_POD" -o jsonpath='{.spec.containers[0].args}' 2>/dev/null)
    if [[ "$DCGM_K8S_ENV" == "true" || "$DCGM_ARGS" == *"kubernetes"* ]]; then
        GPU_METRICS_JOB_ATTRIBUTION="true"
        GPU_METRICS_ATTRIBUTION_METHOD="dcgm-kubernetes"
    fi
elif [[ "$AMD_GPU_EXPORTER_INSTALLED" == "true" ]]; then
    # amd-device-metrics-exporter: look for a kubernetes / pod-resources config
    # in the args/env of the EXPORTER pods only (scope by name — the exporter's
    # namespace also holds kube-prometheus-stack pods whose args contain
    # "kubernetes", which would otherwise false-positive).
    AMD_POD_CFG=$(kubectl get pods -n "$AMD_GPU_EXPORTER_NAMESPACE" -o json 2>/dev/null \
        | jq -r '.items[]
                 | select(.metadata.name | test("device-metrics-exporter|amdgpu-metrics"))
                 | .spec.containers[] | ((.args // []) + ([.env[]?.name] // [])) | .[]' 2>/dev/null \
        | grep -iE 'kubernetes|pod-resources|pod_resources|k8s-pod' | head -1)
    if [[ -n "$AMD_POD_CFG" ]]; then
        GPU_METRICS_JOB_ATTRIBUTION="true"
        GPU_METRICS_ATTRIBUTION_METHOD="amd-pod-resources"
    fi
fi
if [[ "$GPU_METRICS_JOB_ATTRIBUTION" == "true" ]]; then
    print_info "Per-job GPU attribution: enabled (${GPU_METRICS_ATTRIBUTION_METHOD})"
else
    print_warn "Per-job GPU attribution: not configured (metrics not labelled by workload pod/job)"
fi

# =============================================================================
# SECTION 2: Prometheus
# =============================================================================
print_header "2. PROMETHEUS"

PROMETHEUS_INSTALLED="false"
PROMETHEUS_NAMESPACE=""
PROMETHEUS_VERSION=""
PROMETHEUS_TYPE=""  # operator, standalone, managed

print_section "Prometheus Detection"

# Check for Prometheus Operator CRDs
if kubectl api-resources 2>/dev/null | grep -q "prometheuses.monitoring.coreos.com"; then
    PROMETHEUS_TYPE="operator"
    print_info "Prometheus Operator CRDs: Detected"
fi

# Find Prometheus installation
for ns in monitoring prometheus observability openshift-monitoring cattle-monitoring-system kube-prometheus-stack; do
    # Check for Prometheus pods
    PROM_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=prometheus --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$PROM_PODS" -gt 0 ]]; then
        PROMETHEUS_INSTALLED="true"
        PROMETHEUS_NAMESPACE="$ns"
        break
    fi

    # Alternative label
    PROM_PODS=$(kubectl get pods -n "$ns" -l app=prometheus --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$PROM_PODS" -gt 0 ]]; then
        PROMETHEUS_INSTALLED="true"
        PROMETHEUS_NAMESPACE="$ns"
        break
    fi

    # Check by name pattern
    PROM_PODS=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -E "prometheus-[^k]" | wc -l | tr -d ' ')
    if [[ "$PROM_PODS" -gt 0 ]]; then
        PROMETHEUS_INSTALLED="true"
        PROMETHEUS_NAMESPACE="$ns"
        break
    fi
done

# Fallback: a Prometheus deployed in a namespace outside the common allowlist
# (e.g. a provider-specific monitoring namespace) is otherwise reported as
# absent. Scan every namespace by the well-known label, then by name pattern.
if [[ "$PROMETHEUS_INSTALLED" != "true" ]]; then
    PROM_NS=$(kubectl get pods --all-namespaces -l app.kubernetes.io/name=prometheus -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
    [[ -z "$PROM_NS" ]] && PROM_NS=$(kubectl get pods --all-namespaces -l app=prometheus -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
    [[ -z "$PROM_NS" ]] && PROM_NS=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | awk '$2 ~ /^prometheus-[^k]/ {print $1; exit}')
    if [[ -n "$PROM_NS" ]]; then
        PROMETHEUS_INSTALLED="true"
        PROMETHEUS_NAMESPACE="$PROM_NS"
    fi
fi

# VictoriaMetrics vmagent is a Prometheus-compatible collector. Managed
# clusters can expose vmagent while the remote storage and user interface stay
# in the provider control plane. Record the collector that is visible to this
# Kubernetes identity instead of reporting that metrics collection is absent.
if [[ "$PROMETHEUS_INSTALLED" != "true" ]]; then
    VMAGENT_RECORD=$(kubectl get pods --all-namespaces -l app.kubernetes.io/name=vmagent -o json 2>/dev/null \
        | jq -r '[.items[] | select(.status.phase == "Running")][0]
            | if . then [.metadata.namespace,
                ([.spec.containers[] | select(.image | test("vmagent"; "i")) | .image] | first // "")]
              | @tsv else empty end' 2>/dev/null || true)
    if [[ -n "$VMAGENT_RECORD" ]]; then
        IFS=$'\t' read -r PROMETHEUS_NAMESPACE VMAGENT_IMAGE <<< "$VMAGENT_RECORD"
        PROMETHEUS_INSTALLED="true"
        PROMETHEUS_TYPE="victoria-metrics-vmagent"
        PROMETHEUS_VERSION=$(printf '%s\n' "$VMAGENT_IMAGE" | sed 's/.*:v*//' | grep -oE '^[0-9.]+' || true)
        PROMETHEUS_VERSION=${PROMETHEUS_VERSION:-unknown}
    fi
fi

if [[ "$PROMETHEUS_INSTALLED" == "true" ]]; then
    if [[ "$PROMETHEUS_TYPE" == "victoria-metrics-vmagent" ]]; then
        print_info "Prometheus-compatible collector: VictoriaMetrics vmagent in ${PROMETHEUS_NAMESPACE}"
    else
        print_info "Prometheus: Installed in ${PROMETHEUS_NAMESPACE}"
    fi

    # Get version
    PROM_IMAGE=""
    if [[ "$PROMETHEUS_TYPE" != "victoria-metrics-vmagent" ]]; then
        PROM_IMAGE=$(kubectl get pods -n "$PROMETHEUS_NAMESPACE" -l app.kubernetes.io/name=prometheus -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null || \
                     kubectl get pods -n "$PROMETHEUS_NAMESPACE" -l app=prometheus -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)
    fi
    if [[ -n "$PROM_IMAGE" ]]; then
        PROMETHEUS_VERSION=$(echo "$PROM_IMAGE" | sed 's/.*:v*//' | grep -oE '^[0-9.]+' || echo "unknown")
        print_info "Version: ${PROMETHEUS_VERSION}"
    fi

    # Check Prometheus resources (if operator)
    if [[ "$PROMETHEUS_TYPE" == "operator" ]]; then
        PROM_CR_COUNT=$(kubectl get prometheus --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
        print_info "Prometheus CRs: ${PROM_CR_COUNT}"
    fi

    # Check retention
    RETENTION=$(kubectl get prometheus -n "$PROMETHEUS_NAMESPACE" -o jsonpath='{.items[0].spec.retention}' 2>/dev/null)
    [[ -n "$RETENTION" ]] && print_info "Retention: ${RETENTION}"

    # Check storage
    STORAGE_SIZE=$(kubectl get prometheus -n "$PROMETHEUS_NAMESPACE" -o jsonpath='{.items[0].spec.storage.volumeClaimTemplate.spec.resources.requests.storage}' 2>/dev/null)
    [[ -n "$STORAGE_SIZE" ]] && print_info "Storage: ${STORAGE_SIZE}"
else
    print_warn "Prometheus: Not detected"
fi

# Check ServiceMonitors
print_section "ServiceMonitors"
if kubectl api-resources 2>/dev/null | grep -q "servicemonitors"; then
    SM_COUNT=$(kubectl get servicemonitor --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
    SM_COUNT=${SM_COUNT//[^0-9]/}
    SM_COUNT=${SM_COUNT:-0}
    print_info "ServiceMonitors: ${SM_COUNT} configured"

    # Check for GPU-related ServiceMonitors
    GPU_SM=$(kubectl get servicemonitor --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name | test("gpu|dcgm|nvidia"; "i")) | .metadata.name' | head -5)
    if [[ -n "$GPU_SM" ]]; then
        print_info "GPU-related ServiceMonitors:"
        echo "$GPU_SM" | while read -r sm; do
            print_detail "• $sm"
        done
    fi
else
    print_warn "ServiceMonitor CRD: Not available"
fi

# =============================================================================
# SECTION 3: Grafana
# =============================================================================
print_header "3. GRAFANA"

GRAFANA_INSTALLED="false"
GRAFANA_NAMESPACE=""
GRAFANA_VERSION=""
GRAFANA_DASHBOARDS=0

print_section "Grafana Detection"

for ns in monitoring grafana observability prometheus cattle-monitoring-system kube-prometheus-stack; do
    GRAFANA_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=grafana --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$GRAFANA_PODS" -gt 0 ]]; then
        GRAFANA_INSTALLED="true"
        GRAFANA_NAMESPACE="$ns"
        break
    fi

    GRAFANA_PODS=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -c "grafana" || true)
    GRAFANA_PODS=${GRAFANA_PODS//[^0-9]/}
    GRAFANA_PODS=${GRAFANA_PODS:-0}
    if [[ "$GRAFANA_PODS" -gt 0 ]]; then
        GRAFANA_INSTALLED="true"
        GRAFANA_NAMESPACE="$ns"
        break
    fi
done

# Fallback: a Grafana deployed outside the common namespace allowlist is
# otherwise reported as absent. Scan every namespace by label, then by name.
if [[ "$GRAFANA_INSTALLED" != "true" ]]; then
    GRAFANA_NS=$(kubectl get pods --all-namespaces -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null)
    [[ -z "$GRAFANA_NS" ]] && GRAFANA_NS=$(kubectl get pods --all-namespaces --no-headers 2>/dev/null | awk '$2 ~ /grafana/ {print $1; exit}')
    if [[ -n "$GRAFANA_NS" ]]; then
        GRAFANA_INSTALLED="true"
        GRAFANA_NAMESPACE="$GRAFANA_NS"
    fi
fi

if [[ "$GRAFANA_INSTALLED" == "true" ]]; then
    print_info "Grafana: Installed in ${GRAFANA_NAMESPACE}"

    # Get version
    GRAFANA_IMAGE=$(kubectl get pods -n "$GRAFANA_NAMESPACE" -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].spec.containers[0].image}' 2>/dev/null)
    if [[ -n "$GRAFANA_IMAGE" ]]; then
        GRAFANA_VERSION=$(echo "$GRAFANA_IMAGE" | sed 's/.*://' | grep -oE '^[0-9.]+' || echo "unknown")
        print_info "Version: ${GRAFANA_VERSION}"
    fi

    # Check for ConfigMaps with dashboards
    DASHBOARD_CMS=$(kubectl get configmap -n "$GRAFANA_NAMESPACE" -l grafana_dashboard=1 --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$DASHBOARD_CMS" -gt 0 ]]; then
        GRAFANA_DASHBOARDS=$DASHBOARD_CMS
        print_info "Dashboard ConfigMaps: ${DASHBOARD_CMS}"
    fi

    # Check for GPU dashboards
    GPU_DASHBOARDS=$(kubectl get configmap -n "$GRAFANA_NAMESPACE" -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name | test("gpu|dcgm|nvidia"; "i")) | .metadata.name')
    if [[ -n "$GPU_DASHBOARDS" ]]; then
        print_info "GPU Dashboards found:"
        echo "$GPU_DASHBOARDS" | while read -r dash; do
            print_detail "• $dash"
        done
    else
        print_warn "No GPU-specific dashboards detected"
    fi

    # Check Grafana service
    GRAFANA_SVC=$(kubectl get svc -n "$GRAFANA_NAMESPACE" -l app.kubernetes.io/name=grafana -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if [[ -n "$GRAFANA_SVC" ]]; then
        GRAFANA_PORT=$(kubectl get svc -n "$GRAFANA_NAMESPACE" "$GRAFANA_SVC" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null)
        print_info "Service: ${GRAFANA_SVC}:${GRAFANA_PORT}"
    fi
else
    print_warn "Grafana: Not detected"
fi

# =============================================================================
# SECTION 4: Alertmanager
# =============================================================================
print_header "4. ALERTMANAGER"

ALERTMANAGER_INSTALLED="false"
ALERTMANAGER_NAMESPACE=""
ALERT_RULES_COUNT=0

print_section "Alertmanager Detection"

for ns in monitoring prometheus observability cattle-monitoring-system kube-prometheus-stack; do
    AM_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=alertmanager --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$AM_PODS" -gt 0 ]]; then
        ALERTMANAGER_INSTALLED="true"
        ALERTMANAGER_NAMESPACE="$ns"
        break
    fi
done

if [[ "$ALERTMANAGER_INSTALLED" == "true" ]]; then
    print_info "Alertmanager: Installed in ${ALERTMANAGER_NAMESPACE}"

    # Check replicas
    AM_REPLICAS=$(kubectl get pods -n "$ALERTMANAGER_NAMESPACE" -l app.kubernetes.io/name=alertmanager --no-headers 2>/dev/null | grep -c Running || true)
    print_info "Running replicas: ${AM_REPLICAS}"
else
    print_warn "Alertmanager: Not detected"
fi

# Check PrometheusRules
print_section "Alert Rules"
if kubectl api-resources 2>/dev/null | grep -q "prometheusrules"; then
    ALERT_RULES_COUNT=$(kubectl get prometheusrule --all-namespaces --no-headers 2>/dev/null | wc -l | tr -d ' ')
    ALERT_RULES_COUNT=${ALERT_RULES_COUNT//[^0-9]/}
    ALERT_RULES_COUNT=${ALERT_RULES_COUNT:-0}
    print_info "PrometheusRules: ${ALERT_RULES_COUNT} configured"

    # Check for GPU-related rules
    GPU_RULES=$(kubectl get prometheusrule --all-namespaces -o json 2>/dev/null | jq -r '.items[] | select(.metadata.name | test("gpu|dcgm|nvidia"; "i")) | "\(.metadata.namespace)/\(.metadata.name)"')
    if [[ -n "$GPU_RULES" ]]; then
        print_info "GPU-related AlertRules:"
        echo "$GPU_RULES" | while read -r rule; do
            print_detail "• $rule"
        done
    else
        print_warn "No GPU-specific alert rules found"
    fi
else
    print_warn "PrometheusRule CRD: Not available"
fi

# =============================================================================
# SECTION 5: Additional Monitoring Components
# =============================================================================
print_header "5. ADDITIONAL COMPONENTS"

# kube-state-metrics
print_section "kube-state-metrics"
KSM_INSTALLED="false"
for ns in monitoring kube-system prometheus; do
    KSM_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=kube-state-metrics --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$KSM_PODS" -gt 0 ]]; then
        KSM_INSTALLED="true"
        print_info "kube-state-metrics: Installed in ${ns}"
        break
    fi
done
[[ "$KSM_INSTALLED" == "false" ]] && print_warn "kube-state-metrics: Not detected"

# node-exporter
print_section "node-exporter"
NODE_EXPORTER_INSTALLED="false"
for ns in monitoring prometheus kube-system; do
    NE_PODS=$(kubectl get pods -n "$ns" -l app.kubernetes.io/name=node-exporter --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$NE_PODS" -gt 0 ]]; then
        NODE_EXPORTER_INSTALLED="true"
        print_info "node-exporter: Installed in ${ns} (${NE_PODS} pods)"
        break
    fi

    # Alternative label
    NE_PODS=$(kubectl get pods -n "$ns" -l app=prometheus-node-exporter --no-headers 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$NE_PODS" -gt 0 ]]; then
        NODE_EXPORTER_INSTALLED="true"
        print_info "node-exporter: Installed in ${ns} (${NE_PODS} pods)"
        break
    fi
done

# Fallback: scan all namespaces (node-exporter is often outside the default set,
# e.g. a kube-prometheus-stack release in its own namespace). kube-prometheus-stack
# labels its node-exporter `app.kubernetes.io/name=prometheus-node-exporter`, which
# matches neither of the default selectors above.
if [[ "$NODE_EXPORTER_INSTALLED" == "false" ]]; then
    for sel in "app.kubernetes.io/name=node-exporter" "app.kubernetes.io/name=prometheus-node-exporter" "app=prometheus-node-exporter"; do
        NE_PODS=$(kubectl get pods --all-namespaces -l "$sel" --no-headers 2>/dev/null | wc -l | tr -d ' ')
        NE_PODS=${NE_PODS:-0}
        if [[ "$NE_PODS" -gt 0 ]]; then
            NODE_EXPORTER_INSTALLED="true"
            print_info "node-exporter: Installed (${NE_PODS} pods, cross-namespace; ${sel})"
            break
        fi
    done
fi
[[ "$NODE_EXPORTER_INSTALLED" == "false" ]] && print_warn "node-exporter: Not detected"

# Metrics Server
print_section "Metrics Server"
METRICS_SERVER_INSTALLED="false"
if kubectl get deployment metrics-server -n kube-system &>/dev/null 2>&1; then
    METRICS_SERVER_INSTALLED="true"
    print_info "Metrics Server: Installed"
    # Test if metrics work
    if kubectl top nodes &>/dev/null 2>&1; then
        print_info "kubectl top: Working"
    else
        print_warn "kubectl top: Not working"
    fi
else
    print_warn "Metrics Server: Not detected"
fi

# GPU Feature Discovery
print_section "GPU Feature Discovery"
GFD_INSTALLED="false"
GFD_LABELS="false"
find_gfd_namespace() {
    local ns pods
    for ns in gpu-operator gpu-operator-resources nvidia-gpu-operator nvidia gpu; do
        pods=$(kubectl get pods -n "$ns" -l app=gpu-feature-discovery --no-headers 2>/dev/null | wc -l | tr -d ' ')
        if [[ "$pods" -gt 0 ]]; then
            printf '%s\n' "$ns"
            return 0
        fi
    done
    ns=$(kubectl get pods --all-namespaces -l app=gpu-feature-discovery \
        -o jsonpath='{.items[0].metadata.namespace}' 2>/dev/null || true)
    if [[ -n "$ns" ]]; then
        printf '%s\n' "$ns"
        return 0
    fi
    return 1
}

GFD_NAMESPACE=$(find_gfd_namespace || true)
if [[ -n "$GFD_NAMESPACE" ]]; then
    GFD_INSTALLED="true"
    print_info "GPU Feature Discovery: Installed in ${GFD_NAMESPACE}"
fi

# Check for GFD labels on nodes
GFD_LABELED_NODES=$(kubectl get nodes -o json 2>/dev/null | jq '[.items[] | select(.metadata.labels["nvidia.com/gpu.product"] != null)] | length')
if [[ "$GFD_LABELED_NODES" -gt 0 ]]; then
    GFD_LABELS="true"
    print_info "Nodes with GPU labels: ${GFD_LABELED_NODES}"
fi

[[ "$GFD_INSTALLED" == "false" ]] && print_warn "GPU Feature Discovery: Not detected"

# =============================================================================
# SECTION 6: Logging Stack
# =============================================================================
print_header "6. LOGGING STACK"

print_section "Log Aggregation"
LOGGING_STACK="none"

# Check for common logging solutions
if kubectl get pods --all-namespaces -l app.kubernetes.io/name=loki --no-headers 2>/dev/null | grep -q Running; then
    LOGGING_STACK="loki"
    print_info "Loki: Detected"
fi

if kubectl get pods --all-namespaces -l app=elasticsearch --no-headers 2>/dev/null | grep -q Running; then
    LOGGING_STACK="elasticsearch"
    print_info "Elasticsearch: Detected"
fi

if kubectl get pods --all-namespaces -l app.kubernetes.io/name=fluentd --no-headers 2>/dev/null | grep -q Running; then
    print_info "Fluentd: Detected"
fi

if kubectl get pods --all-namespaces -l app.kubernetes.io/name=fluent-bit --no-headers 2>/dev/null | grep -q Running; then
    print_info "Fluent Bit: Detected"
fi

if [[ $(kubectl get pods --all-namespaces -l app=promtail -o json 2>/dev/null | jq '[.items[] | select(.status.phase == "Running")] | length' 2>/dev/null || echo 0) -gt 0 ]] \
    || [[ $(kubectl get pods --all-namespaces -l app.kubernetes.io/name=promtail -o json 2>/dev/null | jq '[.items[] | select(.status.phase == "Running")] | length' 2>/dev/null || echo 0) -gt 0 ]]; then
    [[ "$LOGGING_STACK" == "none" ]] && LOGGING_STACK="promtail"
    print_info "Promtail: Detected"
fi

[[ "$LOGGING_STACK" == "none" ]] && print_warn "No log aggregation detected"

# =============================================================================
# SECTION 7: Health Check Integration
# =============================================================================
print_header "7. HEALTH CHECK INTEGRATION"

print_section "DCGM Health Monitoring"
DCGM_HEALTH_ENABLED="false"

# Check if DCGM health watches are configured
if [[ "$DCGM_INSTALLED" == "true" && -n "$DCGM_POD" ]]; then
    # Check DCGM config for health watches
    HEALTH_CONFIG=$(kubectl exec -n "$DCGM_NAMESPACE" "$DCGM_POD" -- cat /etc/dcgm-exporter/default-counters.csv 2>/dev/null | head -20)
    if [[ -n "$HEALTH_CONFIG" ]]; then
        print_info "DCGM counters config: Found"
        DCGM_HEALTH_ENABLED="true"
    fi
fi

# Check for GPU health checks in node problem detector
print_section "Node Problem Detector"
NPD_INSTALLED="false"
if [[ $(kubectl get pods --all-namespaces -l app=node-problem-detector -o json 2>/dev/null | jq '[.items[] | select(.status.phase == "Running")] | length' 2>/dev/null || echo 0) -gt 0 ]]; then
    NPD_INSTALLED="true"
    print_info "Node Problem Detector: Installed"
elif [[ $(kubectl get pods --all-namespaces -l app.kubernetes.io/name=node-problem-detector -o json 2>/dev/null | jq '[.items[] | select(.status.phase == "Running")] | length' 2>/dev/null || echo 0) -gt 0 ]]; then
    NPD_INSTALLED="true"
    print_info "Node Problem Detector: Installed"
else
    print_warn "Node Problem Detector: Not detected"
fi

# =============================================================================
# SECTION 8: Monitoring Readiness Summary
# =============================================================================
print_header "8. MONITORING READINESS SUMMARY"

print_section "Component Status"
echo ""

# Calculate readiness score
SCORE=0
TOTAL=10

[[ "$GPU_METRICS_EXPORTER_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ GPU metrics exporter (${GPU_METRICS_VENDOR})" || echo "  ✗ GPU metrics exporter"
[[ "$DCGM_SERVICE_MONITOR" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ DCGM ServiceMonitor" || echo "  ✗ DCGM ServiceMonitor"
[[ "$PROMETHEUS_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ Prometheus" || echo "  ✗ Prometheus"
[[ "$GRAFANA_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ Grafana" || echo "  ✗ Grafana"
[[ "$ALERTMANAGER_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ Alertmanager" || echo "  ✗ Alertmanager"
[[ "${ALERT_RULES_COUNT:-0}" -gt 0 ]] && SCORE=$((SCORE+1)) && echo "  ✓ Alert Rules (${ALERT_RULES_COUNT})" || echo "  ✗ Alert Rules"
[[ "$KSM_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ kube-state-metrics" || echo "  ✗ kube-state-metrics"
[[ "$NODE_EXPORTER_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ node-exporter" || echo "  ✗ node-exporter"
[[ "$GFD_INSTALLED" == "true" ]] && SCORE=$((SCORE+1)) && echo "  ✓ GPU Feature Discovery" || echo "  ✗ GPU Feature Discovery"
[[ "$LOGGING_STACK" != "none" ]] && SCORE=$((SCORE+1)) && echo "  ✓ Log Aggregation (${LOGGING_STACK})" || echo "  ✗ Log Aggregation"

echo ""
print_section "Readiness Score"
echo ""
echo "  Monitoring Readiness: ${SCORE}/${TOTAL}"

if [[ "$SCORE" -ge 8 ]]; then
    echo -e "  Status: ${GREEN}Production Ready${NC}"
    MONITORING_STATUS="production"
elif [[ "$SCORE" -ge 5 ]]; then
    echo -e "  Status: ${YELLOW}Partial Monitoring${NC}"
    MONITORING_STATUS="partial"
else
    echo -e "  Status: ${RED}Minimal Monitoring${NC}"
    MONITORING_STATUS="minimal"
fi
echo ""

# =============================================================================
# GENERATE JSON OUTPUT
# =============================================================================

if [[ -n "$CUSTOM_NAME" ]]; then
    AUDIT_CLUSTER_NAME="$CUSTOM_NAME"
else
    AUDIT_CLUSTER_NAME=$(echo "$CLUSTER_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g' | cut -c1-64)
fi

JSON_OUTPUT=$(cat <<EOF
{
  "audit": {
    "version": "1.0",
    "type": "monitoring",
    "timestamp": "${AUDIT_TIMESTAMP}",
    "clusterName": "${AUDIT_CLUSTER_NAME}"
  },
  "dcgm": {
    "installed": ${DCGM_INSTALLED},
    "namespace": "${DCGM_NAMESPACE:-none}",
    "version": "${DCGM_VERSION:-unknown}",
    "podsRunning": ${DCGM_PODS_RUNNING},
    "serviceMonitor": ${DCGM_SERVICE_MONITOR},
    "metricsAvailable": ${DCGM_METRICS_AVAILABLE},
    "metricsCount": ${DCGM_METRICS_COUNT}
  },
  "gpuMetricsExporter": {
    "installed": ${GPU_METRICS_EXPORTER_INSTALLED},
    "vendor": "${GPU_METRICS_VENDOR}",
    "amdDeviceMetricsExporter": ${AMD_GPU_EXPORTER_INSTALLED},
    "amdNamespace": "${AMD_GPU_EXPORTER_NAMESPACE:-none}",
    "amdPodsRunning": ${AMD_GPU_EXPORTER_PODS_RUNNING},
    "jobAttribution": ${GPU_METRICS_JOB_ATTRIBUTION},
    "jobAttributionMethod": "${GPU_METRICS_ATTRIBUTION_METHOD}"
  },
  "prometheus": {
    "installed": ${PROMETHEUS_INSTALLED},
    "namespace": "${PROMETHEUS_NAMESPACE:-none}",
    "version": "${PROMETHEUS_VERSION:-unknown}",
    "type": "${PROMETHEUS_TYPE:-standalone}",
    "serviceMonitorCount": ${SM_COUNT:-0}
  },
  "grafana": {
    "installed": ${GRAFANA_INSTALLED},
    "namespace": "${GRAFANA_NAMESPACE:-none}",
    "version": "${GRAFANA_VERSION:-unknown}",
    "dashboardCount": ${GRAFANA_DASHBOARDS}
  },
  "alerting": {
    "alertmanagerInstalled": ${ALERTMANAGER_INSTALLED},
    "alertmanagerNamespace": "${ALERTMANAGER_NAMESPACE:-none}",
    "alertRulesCount": ${ALERT_RULES_COUNT}
  },
  "components": {
    "kubeStateMetrics": ${KSM_INSTALLED},
    "amdDeviceMetricsExporter": ${AMD_GPU_EXPORTER_INSTALLED},
    "nodeExporter": ${NODE_EXPORTER_INSTALLED},
    "metricsServer": ${METRICS_SERVER_INSTALLED},
    "gpuFeatureDiscovery": ${GFD_INSTALLED},
    "nodeProblemDetector": ${NPD_INSTALLED}
  },
  "logging": {
    "stack": "${LOGGING_STACK}"
  },
  "summary": {
    "score": ${SCORE},
    "maxScore": ${TOTAL},
    "status": "${MONITORING_STATUS}"
  }
}
EOF
)

# Output JSON
if [[ "$JSON_ONLY" == "true" ]]; then
    echo "$JSON_OUTPUT" | jq .
else
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -n "$OUTPUT_DIR" ]]; then
        RESULTS_DIR="$OUTPUT_DIR"
    else
        RESULTS_DIR="${SCRIPT_DIR}/audit-results"
    fi

    mkdir -p "$RESULTS_DIR"
    OUTPUT_FILE="${RESULTS_DIR}/${AUDIT_TIMESTAMP_FILE}_${AUDIT_CLUSTER_NAME}_monitoring.json"

    echo "$JSON_OUTPUT" | jq . > "$OUTPUT_FILE"

    print_section "Output"
    print_info "JSON saved: ${OUTPUT_FILE}"
    echo ""
fi
