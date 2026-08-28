import io
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from cmax import security, target_selection


def answers(*values: str):
    remaining = iter(values)
    return lambda _prompt: next(remaining)


def completed(
    args: list[str],
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, returncode, stdout, stderr)


def test_macos_target_is_reported_before_confirmation() -> None:
    target = security.SecurityTarget("standalone", "local")
    output = io.StringIO()
    with mock.patch.object(
        target_selection.platform, "system", return_value="Darwin"
    ), mock.patch.object(
        target_selection.platform, "mac_ver", return_value=("26.5", (), "")
    ), mock.patch.object(
        target_selection.platform, "machine", return_value="arm64"
    ), mock.patch.object(
        target_selection.socket, "gethostname", return_value="eagle.local"
    ):
        selected = target_selection.prepare_audit_target(
            target,
            command="cmax audit security",
            reader=answers("y"),
            stream=output,
            interactive=True,
            environ={},
        )

    assert selected == target
    rendered = output.getvalue()
    assert "Command: cmax audit security" in rendered
    assert "Target: Local machine" in rendered
    assert "Host: eagle.local" in rendered
    assert "System: macOS 26.5 (arm64)" in rendered
    assert "Linux GPU checks can report unavailable components" in rendered


def test_operator_can_change_an_auto_detected_target_to_local() -> None:
    detected = security.SecurityTarget("k8s", "k8s")
    local = security.SecurityTarget("standalone", "local", True)
    output = io.StringIO()
    with mock.patch.object(
        target_selection,
        "target_details",
        side_effect=[
            (("Target", "Kubernetes cluster"), ("Context", "wrong-cluster")),
            (("Target", "Local machine"), ("Host", "eagle.local")),
        ],
    ), mock.patch.object(security, "detect_target", return_value=local):
        selected = target_selection.prepare_audit_target(
            detected,
            command="cmax audit",
            reader=answers("c", "1", "y"),
            stream=output,
            interactive=True,
            environ={},
        )

    assert selected == local
    assert "Select an audit target" in output.getvalue()
    assert output.getvalue().count("# ClusterMAX audit target") == 2


def test_empty_confirmation_cancels_without_starting_work() -> None:
    target = security.SecurityTarget("standalone", "local")
    with pytest.raises(target_selection.TargetSelectionCancelled):
        target_selection.prepare_audit_target(
            target,
            command="cmax audit",
            reader=answers(""),
            stream=io.StringIO(),
            interactive=True,
            environ={},
        )


def test_noninteractive_auto_detection_requires_an_explicit_decision() -> None:
    target = security.SecurityTarget("standalone", "local")
    with pytest.raises(
        target_selection.TargetSelectionError,
        match="explicit target option or --yes",
    ):
        target_selection.prepare_audit_target(
            target,
            command="cmax audit",
            stream=io.StringIO(),
            interactive=False,
            environ={},
        )


def test_noninteractive_explicit_target_is_confirmation() -> None:
    target = security.SecurityTarget("standalone", "local", True)
    output = io.StringIO()
    selected = target_selection.prepare_audit_target(
        target,
        command="cmax audit",
        stream=output,
        interactive=False,
        environ={},
    )
    assert selected == target
    assert "accepted from the explicit target" in output.getvalue()


def test_yes_reports_and_accepts_an_auto_detected_target() -> None:
    target = security.SecurityTarget("standalone", "local")
    output = io.StringIO()
    selected = target_selection.prepare_audit_target(
        target,
        command="cmax audit",
        assume_yes=True,
        stream=output,
        interactive=False,
        environ={},
    )
    assert selected == target
    assert "accepted with --yes" in output.getvalue()


def test_kubernetes_selection_applies_kubeconfig_and_context(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("apiVersion: v1\n")
    current = {"context": "development"}

    def fake_run(command, **_kwargs):
        if command[-4:] == ["config", "get-contexts", "-o", "name"]:
            return completed(command, stdout="development\nproduction\n")
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout=current["context"] + "\n")
        if command[-3:-1] == ["config", "use-context"]:
            current["context"] = command[-1]
            return completed(command, stdout="switched\n")
        if command[-1] == "cluster-info":
            return completed(command, stdout="Kubernetes control plane is running\n")
        raise AssertionError(command)

    output = io.StringIO()
    environ: dict[str, str] = {}
    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(target_selection, "_run", side_effect=fake_run):
        target = target_selection._configured_kubernetes_target(
            reader=answers(str(kubeconfig), "2", "y"),
            stream=output,
            environ=environ,
            kubeconfig_hint=None,
        )

    assert target == security.SecurityTarget("k8s", "k8s", True)
    assert environ["KUBECONFIG"] == str(kubeconfig)
    assert current["context"] == "production"
    assert "production" in output.getvalue()


def test_failed_kubernetes_access_restores_the_original_context(
    tmp_path: Path,
) -> None:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("apiVersion: v1\n")
    current = {"context": "development"}

    def fake_run(command, **_kwargs):
        if command[-4:] == ["config", "get-contexts", "-o", "name"]:
            return completed(command, stdout="development\nproduction\n")
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout=current["context"] + "\n")
        if command[-3:-1] == ["config", "use-context"]:
            current["context"] = command[-1]
            return completed(command, stdout="switched\n")
        if command[-1] == "cluster-info":
            return completed(command, returncode=1, stderr="connection refused\n")
        raise AssertionError(command)

    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(target_selection, "_run", side_effect=fake_run), pytest.raises(
        target_selection.TargetSelectionError,
        match="connection refused",
    ):
        target_selection._configured_kubernetes_target(
            reader=answers(str(kubeconfig), "2", "y"),
            stream=io.StringIO(),
            environ={},
            kubeconfig_hint=None,
        )

    assert current["context"] == "development"


def test_kubernetes_restore_unsets_an_originally_empty_context() -> None:
    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        return completed(command, stdout="Property current-context unset.\n")

    change = ("/usr/bin/kubectl", "", {"KUBECONFIG": "/clusters/config"})
    with mock.patch.object(target_selection, "_run", side_effect=fake_run):
        target_selection._restore_kubernetes_context(change)

    assert commands == [
        ["/usr/bin/kubectl", "config", "unset", "current-context"]
    ]


def test_selecting_local_restores_the_previous_kubernetes_context(
    tmp_path: Path,
) -> None:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("apiVersion: v1\n")
    current = {"context": "development"}
    local = security.SecurityTarget("standalone", "local", True)

    def fake_run(command, **_kwargs):
        if command[-4:] == ["config", "get-contexts", "-o", "name"]:
            return completed(command, stdout="development\nproduction\n")
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout=current["context"] + "\n")
        if command[-3:-1] == ["config", "use-context"]:
            current["context"] = command[-1]
            return completed(command, stdout="switched\n")
        if command[-1] == "cluster-info":
            return completed(command, stdout="Kubernetes control plane is running\n")
        raise AssertionError(command)

    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(
        target_selection, "_run", side_effect=fake_run
    ), mock.patch.object(
        security, "detect_target", return_value=local
    ):
        selected = target_selection.prepare_audit_target(
            local,
            command="cmax audit",
            reader=answers(
                "c",
                "2",
                str(kubeconfig),
                "2",
                "y",
                "c",
                "1",
                "y",
            ),
            stream=io.StringIO(),
            interactive=True,
            environ={},
        )

    assert selected == local
    assert current["context"] == "development"


def test_kubernetes_selection_preserves_a_kubeconfig_path_list() -> None:
    configured = "/clusters/development:/clusters/production"
    prompts: list[str] = []
    responses = iter(("", ""))

    def reader(prompt: str) -> str:
        prompts.append(prompt)
        return next(responses)

    def fake_run(command, **_kwargs):
        if command[-4:] == ["config", "get-contexts", "-o", "name"]:
            return completed(command, stdout="production\n")
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout="production\n")
        if command[-1] == "cluster-info":
            return completed(command, stdout="Kubernetes control plane is running\n")
        raise AssertionError(command)

    environ = {"KUBECONFIG": configured}
    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(target_selection, "_run", side_effect=fake_run):
        target = target_selection._configured_kubernetes_target(
            reader=reader,
            stream=io.StringIO(),
            environ=environ,
            kubeconfig_hint="/clusters/original",
        )

    assert target == security.SecurityTarget("k8s", "k8s", True)
    assert environ["KUBECONFIG"] == configured
    assert prompts[0] == f"Kubeconfig path [{configured}]: "


def test_declined_context_change_returns_to_target_selection(tmp_path: Path) -> None:
    kubeconfig = tmp_path / "config"
    kubeconfig.write_text("apiVersion: v1\n")
    detected = security.SecurityTarget("standalone", "local")
    local = security.SecurityTarget("standalone", "local", True)

    def fake_run(command, **_kwargs):
        if command[-4:] == ["config", "get-contexts", "-o", "name"]:
            return completed(command, stdout="development\nproduction\n")
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout="development\n")
        raise AssertionError(command)

    output = io.StringIO()
    environ: dict[str, str] = {}
    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(
        target_selection, "_run", side_effect=fake_run
    ), mock.patch.object(
        security, "detect_target", return_value=local
    ):
        selected = target_selection.prepare_audit_target(
            detected,
            command="cmax audit",
            reader=answers("c", "2", str(kubeconfig), "2", "n", "1", "y"),
            stream=output,
            interactive=True,
            environ=environ,
        )

    assert selected == local
    rendered = output.getvalue()
    assert "Kubernetes context was not changed" in rendered
    assert rendered.count("Select an audit target") == 2
    assert "KUBECONFIG" not in environ


def test_unreachable_kubernetes_context_cannot_be_confirmed() -> None:
    target = security.SecurityTarget("k8s", "k8s", True)

    def fake_run(command, **_kwargs):
        if command[-2:] == ["config", "current-context"]:
            return completed(command, stdout="stale-context\n")
        return completed(command, returncode=1, stderr="connection refused\n")

    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/kubectl"
    ), mock.patch.object(target_selection, "_run", side_effect=fake_run), pytest.raises(
        target_selection.TargetSelectionError,
        match="connection refused",
    ):
        target_selection.prepare_audit_target(
            target,
            command="cmax audit security",
            assume_yes=True,
            stream=io.StringIO(),
            interactive=False,
            environ={},
        )


def test_slurm_summary_names_the_reachable_cluster() -> None:
    target = security.SecurityTarget("slurm", "slurm", True)

    def fake_run(command, **_kwargs):
        if command[-1] == "ping":
            return completed(command, stdout="Slurmctld is UP\n")
        return completed(command, stdout="ClusterName = gpu-prod\n")

    output = io.StringIO()
    with mock.patch.object(
        target_selection.shutil, "which", return_value="/usr/bin/scontrol"
    ), mock.patch.object(target_selection, "_run", side_effect=fake_run):
        selected = target_selection.prepare_audit_target(
            target,
            command="cmax audit",
            stream=output,
            interactive=False,
            environ={},
        )

    assert selected == target
    assert "Cluster: gpu-prod" in output.getvalue()
    assert "current Slurm client session" in output.getvalue()
