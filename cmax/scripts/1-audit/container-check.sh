#!/bin/bash
# Container runtime inventory for a compute-node host.  This script is run by
# the Slurm and Kubernetes collectors on the node that will execute workloads;
# it must not be run on a login/operator host and its output is KEY=VALUE only.

echo "WORKER_CONTAINER_HOSTNAME=$(hostname 2>/dev/null || echo unknown)"

# A Slurm worker may itself be a provider-managed tenant container. Package
# versions inside that image are not evidence about the outer host runtime.
RUNTIME_SCOPE="${CLUSTERMAX_CONTAINER_RUNTIME_SCOPE:-}"
if [[ -z "$RUNTIME_SCOPE" ]]; then
    RUNTIME_SCOPE="nested-container"
    if [[ ! -f /.dockerenv && ! -f /run/.containerenv \
        && -x "$(command -v systemd-detect-virt 2>/dev/null)" ]] \
        && ! systemd-detect-virt --container >/dev/null 2>&1; then
        RUNTIME_SCOPE="host"
    fi
fi
echo "WORKER_CONTAINER_RUNTIME_SCOPE=$RUNTIME_SCOPE"

# Docker and the NVIDIA runtime registration.  `docker info` is intentionally
# executed as the audit user: a root-only Docker daemon is not usable by the
# benchmark workloads this audit preflights.
DOCKER_PATH=$(command -v docker 2>/dev/null || true)
DOCKER_VERSION_OUTPUT=""
if [[ -n "$DOCKER_PATH" ]]; then
    DOCKER_VERSION_OUTPUT=$("$DOCKER_PATH" --version 2>/dev/null || true)
    # Some containerd hosts provide a `docker` compatibility link to nerdctl or
    # Podman. The command name alone does not prove that Docker Engine exists.
    # Require the Docker CLI's own version signature before this block reports
    # Docker or applies the Docker Engine minimum version.
    if ! grep -qE '^Docker version[[:space:]]' <<< "$DOCKER_VERSION_OUTPUT"; then
        DOCKER_PATH=""
    fi
fi
NVIDIA_RUNTIME_CONFIGURED=false
if [[ -n "$DOCKER_PATH" ]]; then
    echo "WORKER_CONTAINER_DOCKER_INSTALLED=true"
    echo "WORKER_CONTAINER_DOCKER_PATH=$DOCKER_PATH"
    DOCKER_VERSION=$(printf '%s\n' "$DOCKER_VERSION_OUTPUT" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
    echo "WORKER_CONTAINER_DOCKER_VERSION=${DOCKER_VERSION:-unknown}"
    DOCKER_RUNTIMES=$(docker info --format '{{json .Runtimes}}' 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        echo "WORKER_CONTAINER_DOCKER_ACCESSIBLE=true"
        if grep -qi 'nvidia' <<< "$DOCKER_RUNTIMES"; then
            NVIDIA_RUNTIME_CONFIGURED=true
            echo "WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED=true"
        else
            echo "WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED=false"
        fi
    else
        echo "WORKER_CONTAINER_DOCKER_ACCESSIBLE=false"
        echo "WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED=false"
    fi
    DOCKER_SERVER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
else
    echo "WORKER_CONTAINER_DOCKER_INSTALLED=false"
    echo "WORKER_CONTAINER_DOCKER_PATH="
    echo "WORKER_CONTAINER_DOCKER_VERSION=unknown"
    echo "WORKER_CONTAINER_DOCKER_ACCESSIBLE=false"
    echo "WORKER_CONTAINER_NVIDIA_RUNTIME_CONFIGURED=false"
    DOCKER_SERVER_VERSION=""
fi
echo "WORKER_CONTAINER_DOCKER_SERVER_VERSION=${DOCKER_SERVER_VERSION:-unknown}"

# NVIDIA Container Toolkit.  Prefer the installed CLI version, then package
# managers.  The runtime binary is a valid fallback for deployments where the
# CLI package has deliberately been split from the runtime package.
NCT_VERSION=""
NCT_PATH=""
if command -v nvidia-container-toolkit >/dev/null 2>&1; then
    NCT_PATH=$(command -v nvidia-container-toolkit)
    NCT_VERSION=$(nvidia-container-toolkit --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
elif command -v nvidia-ctk >/dev/null 2>&1; then
    NCT_PATH=$(command -v nvidia-ctk)
    NCT_VERSION=$(nvidia-ctk --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
elif command -v nvidia-container-runtime >/dev/null 2>&1; then
    NCT_PATH=$(command -v nvidia-container-runtime)
    NCT_VERSION=$(nvidia-container-runtime --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
fi

if [[ -z "$NCT_VERSION" ]] && command -v dpkg-query >/dev/null 2>&1; then
    NCT_VERSION=$(dpkg-query -W -f='${Version}' nvidia-container-toolkit 2>/dev/null || true)
fi
if [[ -z "$NCT_VERSION" ]] && command -v rpm >/dev/null 2>&1; then
    if ! NCT_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' nvidia-container-toolkit 2>/dev/null); then
        NCT_VERSION=""
    fi
fi

# A configured `docker info` nvidia runtime is direct proof the toolkit works on
# this worker, so credit it even when the package/CLI checks above miss it (the
# runtime can be registered from a host path outside the audit user's PATH).
if [[ -n "$NCT_PATH" || -n "$NCT_VERSION" || "$NVIDIA_RUNTIME_CONFIGURED" == "true" ]]; then
    echo "WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED=true"
else
    echo "WORKER_CONTAINER_NVIDIA_TOOLKIT_INSTALLED=false"
fi
echo "WORKER_CONTAINER_NVIDIA_TOOLKIT_PATH=$NCT_PATH"
echo "WORKER_CONTAINER_NVIDIA_TOOLKIT_VERSION=${NCT_VERSION:-unknown}"

# Low-level OCI runtime. The version can be absent inside a nested tenant
# container even though the outer host uses runc. Preserve that distinction as
# unknown so the provider must attest the host version.
RUNC_PATH=$(command -v runc 2>/dev/null || true)
RUNC_VERSION=""
if [[ -n "$RUNC_PATH" ]]; then
    RUNC_VERSION=$(runc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+([^[:space:]]*)?' | head -1 || true)
fi
if [[ -z "$RUNC_VERSION" ]] && command -v dpkg-query >/dev/null 2>&1; then
    RUNC_VERSION=$(dpkg-query -W -f='${Version}' runc 2>/dev/null || true)
fi
if [[ -z "$RUNC_VERSION" ]] && command -v rpm >/dev/null 2>&1; then
    if ! RUNC_VERSION=$(rpm -q --qf '%{VERSION}-%{RELEASE}' runc 2>/dev/null); then
        RUNC_VERSION=""
    fi
fi
echo "WORKER_CONTAINER_RUNC_INSTALLED=$([[ -n "$RUNC_PATH" || -n "$RUNC_VERSION" ]] && echo true || echo false)"
echo "WORKER_CONTAINER_RUNC_PATH=$RUNC_PATH"
echo "WORKER_CONTAINER_RUNC_VERSION=${RUNC_VERSION:-unknown}"

SECURITY_DOCKER_VERSION="unknown"
SECURITY_NCT_VERSION="unknown"
SECURITY_RUNC_VERSION="unknown"
if [[ "$RUNTIME_SCOPE" == "host" ]]; then
    # The client binary version does not attest the Docker Engine daemon. If
    # the daemon cannot be queried, preserve unknown for provider follow-up.
    if [[ -z "$DOCKER_PATH" ]]; then
        SECURITY_DOCKER_VERSION="not-installed"
    else
        SECURITY_DOCKER_VERSION="${DOCKER_SERVER_VERSION:-unknown}"
    fi
    SECURITY_NCT_VERSION="$([[ -n "$NCT_PATH" || -n "$NCT_VERSION" \
        || "$NVIDIA_RUNTIME_CONFIGURED" == "true" ]] \
        && echo "${NCT_VERSION:-unknown}" || echo not-installed)"
    SECURITY_RUNC_VERSION="$([[ -n "$RUNC_PATH" || -n "$RUNC_VERSION" ]] \
        && echo "${RUNC_VERSION:-unknown}" || echo not-installed)"
elif [[ -n "$DOCKER_SERVER_VERSION" ]]; then
    # A daemon response is authoritative for Docker even from a client running
    # in a container. The image-local Toolkit and runc packages remain hidden.
    SECURITY_DOCKER_VERSION="$DOCKER_SERVER_VERSION"
fi
echo "WORKER_CONTAINER_SECURITY_DOCKER_VERSION=$SECURITY_DOCKER_VERSION"
echo "WORKER_CONTAINER_SECURITY_NCT_VERSION=$SECURITY_NCT_VERSION"
echo "WORKER_CONTAINER_SECURITY_RUNC_VERSION=$SECURITY_RUNC_VERSION"

# The focused security profile needs only the host-runtime version evidence
# above. Do not run Enroot registry imports or inventory unrelated launchers.
if [[ "${CLUSTERMAX_AUDIT_SCOPE:-full}" == "security" ]]; then
    exit 0
fi

# Enroot's import test runs on the worker because it verifies that the actual
# workload host can reach its registry and write its local image cache.
#
# Honor the same worker-step TMPDIR opt-in as the bench launcher
# (CLUSTERMAX_STEP_TMPDIR in bench/harnesses/slurm/default.sbatch): on workers
# whose /tmp is an overlayfs pod root, enroot cannot create OCI whiteouts there
# (mknod returns EPERM) and the import would fail for a reason the campaign,
# running with the same knob, does not share. Enroot resolves its scratch dir
# from ENROOT_TEMP_PATH, then TMPDIR; export both for direct invocations.
if [[ -n "${CLUSTERMAX_STEP_TMPDIR:-}" && -d "${CLUSTERMAX_STEP_TMPDIR:-}" ]]; then
    export ENROOT_TEMP_PATH="$CLUSTERMAX_STEP_TMPDIR"
    export TMPDIR="$CLUSTERMAX_STEP_TMPDIR"
fi
ENROOT_PATH=$(command -v enroot 2>/dev/null || true)
if [[ -n "$ENROOT_PATH" ]]; then
    ENROOT_VERSION=$(enroot version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
    echo "WORKER_CONTAINER_ENROOT_INSTALLED=true"
    echo "WORKER_CONTAINER_ENROOT_PATH=$ENROOT_PATH"
    echo "WORKER_CONTAINER_ENROOT_VERSION=${ENROOT_VERSION:-unknown}"

    ENROOT_SQSH=$(mktemp /tmp/clustermax-enroot-audit-XXXXXX.sqsh 2>/dev/null || true)
    if [[ -z "$ENROOT_SQSH" ]]; then
        echo "WORKER_CONTAINER_ENROOT_IMPORT=failed"
    else
        # Bound the import with `timeout` when it is available, but still run it
        # unbounded otherwise: a worker without the `timeout` binary must not
        # report the import as failed when it was never attempted.
        if command -v timeout >/dev/null 2>&1; then
            timeout 30 enroot import -o "$ENROOT_SQSH" docker://hello-world >/dev/null 2>&1
        else
            enroot import -o "$ENROOT_SQSH" docker://hello-world >/dev/null 2>&1
        fi
        ENROOT_IMPORT_RC=$?
        if [[ "$ENROOT_IMPORT_RC" -eq 0 ]]; then
            echo "WORKER_CONTAINER_ENROOT_IMPORT=pass"
        elif [[ "$ENROOT_IMPORT_RC" -eq 124 ]]; then
            echo "WORKER_CONTAINER_ENROOT_IMPORT=timeout"
        else
            echo "WORKER_CONTAINER_ENROOT_IMPORT=failed"
        fi
        rm -f "$ENROOT_SQSH"
    fi
else
    echo "WORKER_CONTAINER_ENROOT_INSTALLED=false"
    echo "WORKER_CONTAINER_ENROOT_PATH="
    echo "WORKER_CONTAINER_ENROOT_VERSION=unknown"
    echo "WORKER_CONTAINER_ENROOT_IMPORT=not-installed"
fi

# Singularity and Apptainer are interchangeable at this audit layer.
SINGULARITY_PATH=$(command -v singularity 2>/dev/null || command -v apptainer 2>/dev/null || true)
if [[ -n "$SINGULARITY_PATH" ]]; then
    SINGULARITY_VERSION=$($SINGULARITY_PATH --version 2>/dev/null | tr '\n' ' ' | head -c 200 || true)
    echo "WORKER_CONTAINER_SINGULARITY_INSTALLED=true"
    echo "WORKER_CONTAINER_SINGULARITY_PATH=$SINGULARITY_PATH"
    echo "WORKER_CONTAINER_SINGULARITY_VERSION=${SINGULARITY_VERSION:-unknown}"
else
    echo "WORKER_CONTAINER_SINGULARITY_INSTALLED=false"
    echo "WORKER_CONTAINER_SINGULARITY_PATH="
    echo "WORKER_CONTAINER_SINGULARITY_VERSION=unknown"
fi
