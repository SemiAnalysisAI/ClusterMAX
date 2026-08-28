#!/bin/bash
# Focused Kubernetes entrypoint for `cmax audit security`.
set -euo pipefail

WORKLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CLUSTERMAX_AUDIT_HARNESS=k8s
export CLUSTERMAX_AUDIT_SCOPE=security
exec bash "$WORKLOAD_DIR/cluster-audit-slurm-security.sh" "$@"
