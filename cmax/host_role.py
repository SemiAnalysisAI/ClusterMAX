"""Find the role of this host in a Slurm or Kubernetes cluster.

The target says what a command runs against. The host role says where the
command runs. A standalone run on a cluster node covers only that node, and a
Slurm run from a compute node starts work from a job instead of a login node.
`confirm` stops these runs before any work starts.

The guard is not specific to the audit. Every cmax command that runs against
a target declares a host role policy in the CLI (see `cmax.cli`), and
`cmax.target_selection.prepare_target` calls `confirm` for it. A new command
gets the same checks, wording, and `--allow-cluster-node` option without code
of its own.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

ISSUE_URL = "https://github.com/SemiAnalysisAI/ClusterMAX/issues/new?title=cmax%20host%20role%20detection%20is%20wrong"

SLURM_COMPUTE = "slurm-compute"
SLURM_LOGIN = "slurm-login"
K8S_NODE = "k8s-node"
K8S_POD = "k8s-pod"
UNKNOWN = "unknown"

# Target flags that every target-selecting cmax command accepts.
TARGET_FLAGS = frozenset(
    {"--local", "--vm", "--container", "--standalone", "--slurm", "--k8s"}
)

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
CONTAINER_PATHS = ("/.dockerenv", "/run/.containerenv")
# Kubernetes mounts a service account token into pods by default. Slurm on
# Kubernetes (Slinky) can run login and slurmd pods without
# KUBERNETES_SERVICE_HOST (enableServiceLinks: false) and without a container
# marker file, so this path is the only sign of the pod.
POD_PATHS = ("/var/run/secrets/kubernetes.io/serviceaccount",)


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
    context: tuple[str, ...] = ()

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


class HostRoleRefused(RuntimeError):
    """The target does not fit this host, and no one can confirm the run."""


class HostRoleCancelled(RuntimeError):
    """The operator did not confirm the run on this host."""


@dataclass(frozen=True)
class Guard:
    """A reason to ask again before the command starts."""

    reason: str
    instead: str
    prompt: str


def _classify(facts: HostFacts) -> HostRole:
    env = facts.environ

    if "slurmctld" in facts.processes:
        # A single-node cluster runs slurmctld and slurmd on one head node.
        # That head node is the right place for the Slurm audit.
        return HostRole(SLURM_LOGIN, ("slurmctld is running",))

    slurm = []
    node_name = env.get("SLURMD_NODENAME", "").strip()
    if node_name:
        slurm.append("SLURMD_NODENAME is set")
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


def classify(facts: HostFacts) -> HostRole:
    """Keep the scheduler role separate from the runtime context."""
    role = _classify(facts)
    context = []
    if facts.environ.get("KUBERNETES_SERVICE_HOST", "").strip() or facts.paths & set(POD_PATHS):
        context.append("Kubernetes pod")
    elif facts.processes & set(KUBERNETES_PROCESSES) or facts.paths & set(KUBELET_PATHS):
        context.append("Kubernetes node")
    if facts.paths & set(CONTAINER_PATHS) or facts.environ.get("container"):
        context.append("container")
    return HostRole(role.kind, role.evidence, tuple(context))


def may_have_both_interfaces(role: HostRole | None) -> bool:
    """Decide whether to probe both interfaces, not whether either is usable."""
    return bool(
        (role is not None
         and role.kind in {SLURM_LOGIN, SLURM_COMPUTE}
         and any(item.startswith("Kubernetes") for item in role.context))
        or (shutil.which("scontrol") and shutil.which("kubectl"))
    )


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
        # Slurm 26.05 prints "Node <name> not found" to stdout; older
        # releases print it to stderr.
        message = f"{result.stdout}\n{result.stderr}".lower()
        return False if "not found" in message else None
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
        paths=frozenset(
            path for path in (*KUBELET_PATHS, *CONTAINER_PATHS, *POD_PATHS) if exists(path)
        ),
        commands=commands,
        slurm_node=slurm_node,
    )


def detect(environ: Mapping[str, str] | None = None) -> HostRole:
    return classify(collect(environ))


def guard(
    harness: str,
    role: HostRole,
    *,
    noun: str = "audit",
    command: str = "cmax audit",
) -> Guard | None:
    """Return the reason to confirm again, or None when the run is expected.

    noun names the work in the messages ("audit", "benchmark"). command is the
    command the operator ran, without target flags; the hint adds the target
    flag that fits this host.
    """
    if harness == "standalone":
        if role.kind == SLURM_COMPUTE:
            return Guard(
                reason=(
                    f"This host looks like a Slurm compute node. A standalone {noun} "
                    "covers only this node and skips the cluster checks."
                ),
                instead=f"From a Slurm login node, run: {command} --slurm",
                prompt=f"Run a standalone {noun} on this compute node anyway? [y/N]: ",
            )
        if role.kind == SLURM_LOGIN:
            return Guard(
                reason=(
                    f"This host looks like a Slurm login node. A standalone {noun} "
                    "covers only this login node and not the cluster."
                ),
                instead=f"From this login node, run: {command} --slurm",
                prompt=f"Run a standalone {noun} on this login node anyway? [y/N]: ",
            )
        if role.kind in {K8S_NODE, K8S_POD}:
            where = "node" if role.kind == K8S_NODE else "pod"
            return Guard(
                reason=(
                    f"This host looks like a Kubernetes {where}. A standalone {noun} "
                    f"covers only this {where} and skips the cluster checks."
                ),
                instead=(
                    "From a machine with kubectl access to the cluster, run: "
                    f"{command} --k8s"
                ),
                prompt=f"Run a standalone {noun} on this {where} anyway? [y/N]: ",
            )
    if harness == "slurm" and role.kind == SLURM_COMPUTE:
        return Guard(
            reason=(
                f"This host looks like a Slurm compute node. Run the Slurm {noun} from a "
                "login node so it can schedule its own jobs."
            ),
            instead=f"From a Slurm login node, run: {command} --slurm",
            prompt=f"Run the Slurm {noun} from this compute node anyway? [y/N]: ",
        )
    return None


def report_preview(harness: str, role: HostRole, *, stream: TextIO) -> None:
    """Print only known signal labels. Never copy raw environment or log data."""
    allowed = {
        "SLURMD_NODENAME is set", "the hostname is a Slurm node",
        "KUBERNETES_SERVICE_HOST is set", "sbatch is in PATH", "scontrol is in PATH",
        *(f"{name} is running" for name in WATCHED_PROCESSES),
        *(f"{path} exists" for path in KUBELET_PATHS),
    }
    signals = [item for item in role.evidence if item in allowed]
    context = [item for item in role.context if item in {
        "Kubernetes pod", "Kubernetes node", "container",
    }]
    print("Detection report preview (nothing has been uploaded):", file=stream)
    print(f"  Target: {harness if harness in {'slurm', 'k8s', 'standalone'} else 'unknown'}", file=stream)
    print(f"  Detected role: {role.label or 'unknown'}", file=stream)
    print(f"  Signals: {'; '.join(signals) or 'no shareable signals'}", file=stream)
    print(f"  Runtime context: {', '.join(context) or 'unknown'}", file=stream)
    print("  Describe the expected role and review these details before sharing.", file=stream)
    print("  Do not attach credentials, hostnames, cluster names, or raw logs.", file=stream)
    print(f"  File an issue: {ISSUE_URL}", file=stream)


def confirm(
    harness: str,
    role: HostRole | None,
    *,
    noun: str,
    command: str,
    reader: Callable[[str], str],
    stream: TextIO,
    terminal: bool,
    allow_cluster_node: bool,
) -> None:
    """Ask a second time when the target does not fit the role of this host.

    `--yes` does not answer this question; only `--allow-cluster-node` does.
    Raises HostRoleRefused in a non-interactive run and HostRoleCancelled when
    the operator does not confirm.
    """
    # The hint adds the target flag that fits; drop the one the operator gave.
    base = " ".join(word for word in command.split() if word not in TARGET_FLAGS)
    found = guard(harness, role, noun=noun, command=base) if role is not None else None
    if found is None:
        return
    print(f"cmax: {found.reason}", file=stream)
    if role is not None and role.evidence:
        print(f"  Evidence: {'; '.join(role.evidence)}", file=stream)
    print(f"  {found.instead}", file=stream)
    print(
        f"  If the detection is wrong, review sanitized details before filing: {ISSUE_URL}",
        file=stream,
    )
    if allow_cluster_node:
        print("  Host role check: accepted with --allow-cluster-node", file=stream)
        return
    if not terminal:
        raise HostRoleRefused(
            f"{found.reason} {found.instead}. "
            "To run here anyway, pass --allow-cluster-node."
        )
    print("  To skip this question, pass --allow-cluster-node.", file=stream)
    while True:
        try:
            answer = reader(
                "Host role mismatch: [Enter] cancel, [c] continue here, "
                "[r] detection looks wrong: "
            ).strip().lower()
            if answer in {"r", "report"}:
                report_preview(harness, role, stream=stream)
                continue
            if answer in {"c", "continue"}:
                confirmed = reader(found.prompt).strip().lower()
                if confirmed in {"y", "yes"}:
                    return
                raise HostRoleCancelled(f"{noun} canceled")
            if answer in {"", "n", "no", "q", "quit"}:
                raise HostRoleCancelled(f"{noun} canceled")
            print("Enter c or r, or press Enter to cancel.", file=stream)
        except (EOFError, KeyboardInterrupt) as exc:
            raise HostRoleCancelled(f"{noun} canceled") from exc
