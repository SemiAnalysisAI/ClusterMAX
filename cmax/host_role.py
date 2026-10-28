"""Find the role of this host in a Slurm or Kubernetes cluster.

The audit target says what to audit. The host role says where the command
runs. A standalone audit on a cluster node covers only that node, and a Slurm
audit from a compute node starts work from a job instead of a login node. The
role lets the target confirmation stop these runs before collection starts.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

ISSUE_URL = "https://github.com/SemiAnalysisAI/ClusterMAX/issues/new?title=cmax%20host%20role%20detection%20is%20wrong"

SLURM_COMPUTE = "slurm-compute"
SLURM_LOGIN = "slurm-login"
K8S_NODE = "k8s-node"
K8S_POD = "k8s-pod"
UNKNOWN = "unknown"

LABELS = {
    SLURM_COMPUTE: "Slurm compute node",
    SLURM_LOGIN: "Slurm login node",
    K8S_NODE: "Kubernetes node",
    K8S_POD: "Kubernetes pod",
}

# Files that kubeadm, k3s, RKE2, EKS, and GKE nodes keep for the kubelet.
KUBELET_PATHS = (
    "/var/lib/kubelet/config.yaml",
    "/var/lib/kubelet/kubeconfig",
    "/etc/kubernetes/kubelet.conf",
    "/etc/rancher/k3s/k3s.yaml",
    "/etc/rancher/rke2/rke2.yaml",
)

# k3s runs the kubelet inside its own process, so its process names count too.
KUBERNETES_PROCESSES = ("kubelet", "k3s-server", "k3s-agent")
WATCHED_PROCESSES = frozenset({"slurmd", "slurmctld", *KUBERNETES_PROCESSES})


@dataclass(frozen=True)
class HostFacts:
    """The local signals that identify a cluster node."""

    environ: Mapping[str, str]
    processes: frozenset[str] = frozenset()
    paths: frozenset[str] = frozenset()
    commands: frozenset[str] = frozenset()
    slurm_node: bool | None = None


@dataclass(frozen=True)
class HostRole:
    kind: str
    evidence: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return LABELS.get(self.kind, "")

    @property
    def summary(self) -> str:
        if not self.label:
            return ""
        if not self.evidence:
            return self.label
        return f"{self.label} ({'; '.join(self.evidence)})"


@dataclass(frozen=True)
class Guard:
    """A reason to ask again before the audit starts."""

    reason: str
    instead: str
    prompt: str


def classify(facts: HostFacts) -> HostRole:
    env = facts.environ

    if "slurmctld" in facts.processes:
        # A single-node cluster runs slurmctld and slurmd on one head node.
        # That head node is the right place for the Slurm audit.
        return HostRole(SLURM_LOGIN, ("slurmctld is running",))

    slurm = []
    node_name = env.get("SLURMD_NODENAME", "").strip()
    if node_name:
        slurm.append(f"SLURMD_NODENAME={node_name}")
    if "slurmd" in facts.processes:
        slurm.append("slurmd is running")
    if facts.slurm_node:
        slurm.append("the hostname is a Slurm node")
    if slurm:
        return HostRole(SLURM_COMPUTE, tuple(slurm))

    kubernetes = [
        f"{name} is running"
        for name in KUBERNETES_PROCESSES
        if name in facts.processes
    ]
    kubernetes.extend(f"{path} exists" for path in KUBELET_PATHS if path in facts.paths)
    if kubernetes:
        return HostRole(K8S_NODE, tuple(kubernetes))

    slurm_client = sorted(facts.commands & {"sbatch", "scontrol"})
    in_pod = bool(env.get("KUBERNETES_SERVICE_HOST", "").strip())
    if slurm_client:
        # Slurm on Kubernetes runs login nodes as pods. Their Slurm client
        # tools make them login nodes, not workload pods.
        return HostRole(SLURM_LOGIN, (f"{slurm_client[0]} is in PATH",))
    if in_pod:
        return HostRole(K8S_POD, ("KUBERNETES_SERVICE_HOST is set",))
    return HostRole(UNKNOWN)


def _running_processes(proc: Path = Path("/proc")) -> frozenset[str]:
    found: set[str] = set()
    try:
        entries = list(proc.iterdir())
    except OSError:
        return frozenset()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(errors="replace").strip()
        except OSError:
            continue
        if name in WATCHED_PROCESSES:
            found.add(name)
    return frozenset(found)


def _slurm_node_lookup(scontrol: str, environ: Mapping[str, str]) -> bool | None:
    hostname = socket.gethostname().split(".", 1)[0]
    if not hostname:
        return None
    try:
        result = subprocess.run(
            [scontrol, "show", "node", "-o", hostname],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
            env=dict(environ),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return False if "not found" in result.stderr.lower() else None
    return f"NodeName={hostname} " in f"{result.stdout} "


def collect(
    environ: Mapping[str, str] | None = None,
    *,
    which: Callable[[str], str | None] = shutil.which,
    exists: Callable[[str], bool] = os.path.exists,
    processes: Iterable[str] | None = None,
) -> HostFacts:
    env = os.environ if environ is None else environ
    running = _running_processes() if processes is None else frozenset(processes)
    commands = frozenset(
        name for name in ("sbatch", "scontrol", "kubectl") if which(name)
    )
    slurm_node = None
    scontrol = which("scontrol")
    if (
        scontrol
        and not running & {"slurmd", "slurmctld"}
        and not env.get("SLURMD_NODENAME")
    ):
        # A job's PID namespace can hide slurmd. Ask the controller instead.
        slurm_node = _slurm_node_lookup(scontrol, env)
    return HostFacts(
        environ=dict(env),
        processes=running,
        paths=frozenset(path for path in KUBELET_PATHS if exists(path)),
        commands=commands,
        slurm_node=slurm_node,
    )


def detect(environ: Mapping[str, str] | None = None) -> HostRole:
    return classify(collect(environ))


def guard(harness: str, role: HostRole) -> Guard | None:
    """Return the reason to confirm again, or None when the run is expected."""
    if harness == "standalone":
        if role.kind == SLURM_COMPUTE:
            return Guard(
                reason=(
                    "This host is a Slurm compute node. A standalone audit covers "
                    "only this node and skips the cluster checks."
                ),
                instead="From a Slurm login node, run: cmax audit --slurm",
                prompt="Run a standalone audit on this compute node anyway? [y/N]: ",
            )
        if role.kind == SLURM_LOGIN:
            return Guard(
                reason=(
                    "This host is a Slurm login node. A standalone audit covers "
                    "only this login node and not the cluster."
                ),
                instead="From this login node, run: cmax audit --slurm",
                prompt="Run a standalone audit on this login node anyway? [y/N]: ",
            )
        if role.kind in {K8S_NODE, K8S_POD}:
            where = "node" if role.kind == K8S_NODE else "pod"
            return Guard(
                reason=(
                    f"This host is a Kubernetes {where}. A standalone audit covers "
                    f"only this {where} and skips the cluster checks."
                ),
                instead=(
                    "From a machine with kubectl access to the cluster, run: "
                    "cmax audit --k8s"
                ),
                prompt=f"Run a standalone audit on this {where} anyway? [y/N]: ",
            )
    if harness == "slurm" and role.kind == SLURM_COMPUTE:
        return Guard(
            reason=(
                "This host is a Slurm compute node. Run the Slurm audit from a "
                "login node so it can schedule its own jobs."
            ),
            instead="From a Slurm login node, run: cmax audit --slurm",
            prompt="Run the Slurm audit from this compute node anyway? [y/N]: ",
        )
    return None
