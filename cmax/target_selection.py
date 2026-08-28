from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable, Mapping, MutableMapping
from pathlib import Path
from typing import TextIO

from cmax import security


class TargetSelectionError(RuntimeError):
    pass


class TargetSelectionCancelled(RuntimeError):
    pass


Reader = Callable[[str], str]
KubernetesContextChange = tuple[str, str, dict[str, str]]


def apply_kubeconfig(
    value: str | None,
    *,
    environ: MutableMapping[str, str] | None = None,
) -> str | None:
    """Apply one operator-selected kubeconfig to this process."""
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    if not path.is_file():
        raise TargetSelectionError(f"kubeconfig file not found: {path}")
    target_environ = os.environ if environ is None else environ
    target_environ["KUBECONFIG"] = str(path)
    return str(path)


def _run(
    command: list[str],
    *,
    environ: Mapping[str, str],
    timeout: float = 8.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            env=dict(environ),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TargetSelectionError(f"could not run {' '.join(command)}: {exc}") from exc


def _command_error(result: subprocess.CompletedProcess[str]) -> str:
    detail = result.stderr.strip() or result.stdout.strip()
    return detail.splitlines()[0] if detail else "the command returned an error"


def _kubeconfig_label(environ: Mapping[str, str]) -> str:
    configured = environ.get("KUBECONFIG", "").strip()
    if configured:
        return configured
    default = Path.home() / ".kube" / "config"
    return str(default) if default.is_file() else "kubectl default credentials"


def _kubernetes_details(
    environ: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        raise TargetSelectionError(
            "Kubernetes was selected, but kubectl is not installed or is not in PATH."
        )

    current = _run(
        [kubectl, "config", "current-context"],
        environ=environ,
    )
    context = current.stdout.strip() if current.returncode == 0 else ""
    if not context and environ.get("KUBERNETES_SERVICE_HOST"):
        context = "in-cluster service account"
    if not context:
        raise TargetSelectionError(
            "Kubernetes was selected, but kubectl has no current context."
        )

    access = _run(
        [kubectl, "--request-timeout=8s", "cluster-info"],
        environ=environ,
        timeout=10.0,
    )
    if access.returncode != 0:
        raise TargetSelectionError(
            f"kubectl cannot reach context '{context}': {_command_error(access)}"
        )
    return (
        ("Target", "Kubernetes cluster"),
        ("Context", context),
        ("Credentials", _kubeconfig_label(environ)),
        ("Access", "kubectl connection succeeded"),
    )


def _slurm_cluster_name(
    scontrol: str,
    environ: Mapping[str, str],
) -> str:
    configured = environ.get("SLURM_CLUSTER_NAME", "").strip()
    if configured:
        return configured
    result = _run([scontrol, "show", "config"], environ=environ)
    if result.returncode != 0:
        return "current Slurm cluster"
    for line in result.stdout.splitlines():
        if line.strip().startswith("ClusterName") and "=" in line:
            return line.split("=", 1)[1].strip() or "current Slurm cluster"
    return "current Slurm cluster"


def _slurm_details(environ: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    scontrol = shutil.which("scontrol")
    if not scontrol:
        raise TargetSelectionError(
            "Slurm was selected, but scontrol is not installed or is not in PATH."
        )
    access = _run([scontrol, "ping"], environ=environ)
    if access.returncode != 0:
        raise TargetSelectionError(
            f"the Slurm controller is not reachable: {_command_error(access)}"
        )
    return (
        ("Target", "Slurm cluster"),
        ("Cluster", _slurm_cluster_name(scontrol, environ)),
        ("Access", "current Slurm client session"),
    )


def _local_details(
    target: security.SecurityTarget,
) -> tuple[tuple[str, str], ...]:
    system = platform.system() or "unknown operating system"
    release = platform.mac_ver()[0] if system == "Darwin" else platform.release()
    system_label = "macOS" if system == "Darwin" else system
    if release:
        system_label = f"{system_label} {release}"
    environment_labels = {
        "local": "Local machine",
        "vm": "Local virtual machine",
        "container": "Local container",
        "bare-metal": "Standalone bare-metal host",
    }
    details = [
        ("Target", environment_labels.get(target.environment, "Local machine")),
        ("Host", socket.gethostname()),
        ("System", f"{system_label} ({platform.machine() or 'unknown architecture'})"),
        ("Access", "current shell; cluster credentials are not used"),
    ]
    if system == "Darwin":
        details.append(
            (
                "Compatibility",
                "limited; Linux GPU checks can report unavailable components",
            )
        )
    return tuple(details)


def target_details(
    target: security.SecurityTarget,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[tuple[str, str], ...]:
    source = os.environ if environ is None else environ
    if target.harness == "k8s":
        details = _kubernetes_details(source)
    elif target.harness == "slurm":
        details = _slurm_details(source)
    else:
        details = _local_details(target)
    selection = "operator-selected" if target.explicit else "auto-detected"
    return (*details, ("Selection", selection))


def _print_target(
    command: str,
    details: tuple[tuple[str, str], ...],
    *,
    stream: TextIO,
) -> None:
    print("# ClusterMAX audit target", file=stream)
    print(f"  Command: {command}", file=stream)
    for label, value in details:
        print(f"  {label}: {value}", file=stream)


def _read(
    reader: Reader,
    prompt: str,
) -> str:
    try:
        return reader(prompt).strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise TargetSelectionCancelled("audit canceled") from exc


def _configured_kubernetes_target(
    *,
    reader: Reader,
    stream: TextIO,
    environ: MutableMapping[str, str],
    kubeconfig_hint: str | None,
    context_changes: list[KubernetesContextChange] | None = None,
) -> security.SecurityTarget:
    kubectl = shutil.which("kubectl")
    if not kubectl:
        raise TargetSelectionError(
            "Kubernetes requires kubectl in PATH before credentials can be selected."
        )

    had_kubeconfig = "KUBECONFIG" in environ
    original_kubeconfig = environ.get("KUBECONFIG", "")
    context_change: KubernetesContextChange | None = None
    try:
        default_path = original_kubeconfig or kubeconfig_hint
        prompt_default = default_path or "kubectl default"
        entered = _read(reader, f"Kubeconfig path [{prompt_default}]: ")
        if entered:
            apply_kubeconfig(entered, environ=environ)

        listed = _run(
            [kubectl, "config", "get-contexts", "-o", "name"],
            environ=environ,
        )
        contexts = list(
            dict.fromkeys(
                line.strip() for line in listed.stdout.splitlines() if line.strip()
            )
        )
        if listed.returncode != 0 or not contexts:
            raise TargetSelectionError(
                f"the selected kubeconfig has no contexts: {_command_error(listed)}"
            )
        current_result = _run(
            [kubectl, "config", "current-context"],
            environ=environ,
        )
        current = current_result.stdout.strip() if current_result.returncode == 0 else ""

        print("Kubernetes contexts:", file=stream)
        for number, context in enumerate(contexts, start=1):
            marker = " (current)" if context == current else ""
            print(f"  {number}. {context}{marker}", file=stream)
        default_number = contexts.index(current) + 1 if current in contexts else 1
        answer = _read(
            reader,
            f"Select the Kubernetes context [default {default_number}]: ",
        )
        if answer:
            try:
                context_number = int(answer)
            except ValueError as exc:
                raise TargetSelectionError("enter a Kubernetes context number") from exc
            if not 1 <= context_number <= len(contexts):
                raise TargetSelectionError("enter a listed Kubernetes context number")
        else:
            context_number = default_number
        selected = contexts[context_number - 1]

        if selected != current:
            confirmed = _read(
                reader,
                f"Set '{selected}' as current in this kubeconfig? [y/N]: ",
            ).lower()
            if confirmed not in {"y", "yes"}:
                raise TargetSelectionError("Kubernetes context was not changed.")
            switched = _run(
                [kubectl, "config", "use-context", selected],
                environ=environ,
            )
            if switched.returncode != 0:
                raise TargetSelectionError(
                    f"kubectl could not select '{selected}': {_command_error(switched)}"
                )
            context_change = (kubectl, current, dict(environ))

        target = security.SecurityTarget("k8s", "k8s", True)
        _kubernetes_details(environ)
        if context_change is not None and context_changes is not None:
            context_changes.append(context_change)
        return target
    except (TargetSelectionError, TargetSelectionCancelled):
        try:
            if context_change is not None:
                _restore_kubernetes_context(context_change)
        finally:
            if had_kubeconfig:
                environ["KUBECONFIG"] = original_kubeconfig
            else:
                environ.pop("KUBECONFIG", None)
        raise


def _restore_kubernetes_context(change: KubernetesContextChange) -> None:
    kubectl, context, change_environ = change
    command = (
        [kubectl, "config", "use-context", context]
        if context
        else [kubectl, "config", "unset", "current-context"]
    )
    restored = _run(command, environ=change_environ)
    if restored.returncode != 0:
        context_label = context or "an unset current context"
        raise TargetSelectionError(
            f"kubectl could not restore {context_label}: {_command_error(restored)}"
        )


def _restore_kubernetes_contexts(
    changes: list[KubernetesContextChange],
) -> None:
    while changes:
        _restore_kubernetes_context(changes[-1])
        changes.pop()


def _choose_target(
    *,
    reader: Reader,
    stream: TextIO,
    environ: MutableMapping[str, str],
    kubeconfig_hint: str | None,
    context_changes: list[KubernetesContextChange],
) -> security.SecurityTarget:
    while True:
        print("Select an audit target:", file=stream)
        print("  1. This local machine", file=stream)
        print("  2. A Kubernetes cluster", file=stream)
        print("  3. A Slurm cluster", file=stream)
        print("  4. Cancel", file=stream)
        answer = _read(reader, "Target [1-4]: ")
        if answer == "1":
            return security.detect_target("local")
        if answer == "2":
            try:
                return _configured_kubernetes_target(
                    reader=reader,
                    stream=stream,
                    environ=environ,
                    kubeconfig_hint=kubeconfig_hint,
                    context_changes=context_changes,
                )
            except TargetSelectionError as exc:
                print(f"cmax: {exc}", file=stream)
                continue
        if answer == "3":
            target = security.detect_target("slurm")
            try:
                _slurm_details(environ)
            except TargetSelectionError as exc:
                print(f"cmax: {exc}", file=stream)
                continue
            return target
        if answer == "4" or answer.lower() in {"n", "no", "q", "quit"}:
            raise TargetSelectionCancelled("audit canceled")
        print("Enter a number from 1 to 4.", file=stream)


def _is_interactive(stream: TextIO) -> bool:
    try:
        return bool(sys.stdin.isatty() and stream.isatty())
    except (AttributeError, ValueError):
        return False


def prepare_audit_target(
    target: security.SecurityTarget,
    *,
    command: str,
    assume_yes: bool = False,
    kubeconfig: str | None = None,
    reader: Reader | None = None,
    stream: TextIO | None = None,
    environ: MutableMapping[str, str] | None = None,
    interactive: bool | None = None,
) -> security.SecurityTarget:
    """Show, validate, and confirm the audit target before collection."""
    output = sys.stdout if stream is None else stream
    target_environ = os.environ if environ is None else environ
    ask = input if reader is None else reader
    apply_kubeconfig(kubeconfig, environ=target_environ)
    terminal = _is_interactive(output) if interactive is None else interactive
    context_changes: list[KubernetesContextChange] = []

    selected = target
    try:
        while True:
            try:
                details = target_details(selected, environ=target_environ)
            except TargetSelectionError as exc:
                print("# ClusterMAX audit target", file=output)
                print(f"  Command: {command}", file=output)
                print(f"  Access check: failed; {exc}", file=output)
                if assume_yes or not terminal:
                    raise
                _restore_kubernetes_contexts(context_changes)
                selected = _choose_target(
                    reader=ask,
                    stream=output,
                    environ=target_environ,
                    kubeconfig_hint=kubeconfig,
                    context_changes=context_changes,
                )
                continue

            _print_target(command, details, stream=output)
            if assume_yes:
                print("  Confirmation: accepted with --yes", file=output)
                return selected
            if not terminal:
                if selected.explicit:
                    print("  Confirmation: accepted from the explicit target", file=output)
                    return selected
                raise TargetSelectionError(
                    "target confirmation requires an interactive terminal. "
                    "Pass an explicit target option or --yes for automation."
                )

            answer = _read(
                ask,
                "Run this audit? [y]es, [c]hange target or access, [N]o: ",
            ).lower()
            if answer in {"y", "yes"}:
                return selected
            if answer in {"c", "change", "e", "edit"}:
                _restore_kubernetes_contexts(context_changes)
                selected = _choose_target(
                    reader=ask,
                    stream=output,
                    environ=target_environ,
                    kubeconfig_hint=kubeconfig,
                    context_changes=context_changes,
                )
                continue
            if answer in {"", "n", "no", "q", "quit"}:
                raise TargetSelectionCancelled("audit canceled")
            print("Enter y, c, or n.", file=output)
    except (TargetSelectionError, TargetSelectionCancelled):
        _restore_kubernetes_contexts(context_changes)
        raise
