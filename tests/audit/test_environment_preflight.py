"""Synthetic regression cases for the interactive environment preflight."""

import io
from unittest import mock

import pytest

from cmax import host_role, security, target_selection


def reader(*values):
    return mock.Mock(side_effect=values)


COMPUTE = host_role.HostRole(host_role.SLURM_COMPUTE, ("slurmd is running",))
LOGIN_POD = host_role.HostRole(
    host_role.SLURM_LOGIN, ("scontrol is in PATH",), ("Kubernetes pod", "container"),
)


def prepare(target=None, **kwargs):
    options = dict(
        command="cmax audit", noun="audit", stream=io.StringIO(),
        environ={}, interactive=True, host_role=COMPUTE,
    )
    options.update(kwargs)
    with mock.patch.object(security, "local_environment", return_value="bare-metal"):
        return target_selection.prepare_target(
            target or security.SecurityTarget("standalone", "bare-metal", True),
            **options,
        )


@pytest.mark.parametrize("values", [("",), ("c", ""), ("c", "n"), (EOFError(),), ("c", KeyboardInterrupt())])
def test_guard_cancels_without_running(values):
    with pytest.raises(target_selection.TargetSelectionCancelled):
        prepare(reader=reader(*values))


def test_report_is_a_local_allowlist_and_does_not_confirm():
    output = io.StringIO()
    role = host_role.HostRole(
        host_role.SLURM_COMPUTE,
        ("slurmd is running", "SLURMD_NODENAME=private-host", "token=secret"),
        ("Kubernetes pod", "private-cluster"),
    )
    host_role.report_preview("standalone", role, stream=output)
    report = output.getvalue()
    assert "slurmd is running" in report
    assert "private-host" not in report
    assert "private-cluster" not in report
    assert "secret" not in report
    assert "nothing has been uploaded" in report
    assert host_role.ISSUE_URL in report
    output = io.StringIO()
    ask = reader("r", "",)
    with mock.patch.object(host_role.subprocess, "run") as run:
        with pytest.raises(target_selection.TargetSelectionCancelled):
            prepare(reader=ask, stream=output)
    run.assert_not_called()
    assert ask.call_count == 2
    assert "Detection report preview" in output.getvalue()


def test_unknown_menu_answer_cannot_confirm():
    ask = reader("y", "invalid", "c", "y")
    prepare(reader=ask)
    assert ask.call_count == 4


def test_automation_requires_an_override():
    with pytest.raises(target_selection.TargetSelectionError, match="--allow-cluster-node"):
        prepare(interactive=False)
    prepare(interactive=False, allow_cluster_node=True)


@pytest.mark.parametrize("interactive", [False, True])
def test_yes_accepts_the_host_role_mismatch_without_a_prompt(interactive):
    output = io.StringIO()
    ask = reader()
    prepare(interactive=interactive, assume_yes=True, reader=ask, stream=output)
    ask.assert_not_called()
    assert "Host role check: accepted with --yes" in output.getvalue()


@pytest.mark.parametrize("answer,harness", [("s", "slurm"), ("k", "k8s")])
def test_mixed_cluster_asks_for_interface_and_shows_context(answer, harness):
    output = io.StringIO()
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        selected = prepare(
            security.SecurityTarget("slurm", "slurm"), host_role=LOGIN_POD,
            reader=reader(answer, "y"), stream=output,
        )
    assert selected.harness == harness
    assert selected.explicit
    assert "Both Slurm and Kubernetes are reachable" in output.getvalue()
    assert "Host role: Slurm login node" in output.getvalue()
    assert "Runtime context: Kubernetes pod, container" in output.getvalue()


@pytest.mark.parametrize("answer", ["", EOFError(), KeyboardInterrupt()])
def test_mixed_cluster_can_cancel(answer):
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        with pytest.raises(target_selection.TargetSelectionCancelled):
            prepare(
                security.SecurityTarget("slurm", "slurm"), host_role=LOGIN_POD,
                reader=reader(answer),
            )


def test_mixed_worker_still_requires_double_confirmation_after_interface_choice():
    role = host_role.HostRole(COMPUTE.kind, COMPUTE.evidence, ("Kubernetes pod",))
    ask = reader("s", "c", "y")
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        prepare(security.SecurityTarget("slurm", "slurm"), host_role=role, reader=ask)
    assert ask.call_count == 3


def test_mixed_cluster_without_a_terminal_requires_an_interface_or_yes():
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        with pytest.raises(target_selection.TargetSelectionError, match="Select --slurm or --k8s"):
            prepare(
                security.SecurityTarget("slurm", "slurm"), host_role=LOGIN_POD,
                interactive=False, allow_cluster_node=True,
            )


@pytest.mark.parametrize("interactive", [False, True])
@pytest.mark.parametrize("harness", ["slurm", "k8s"])
def test_yes_keeps_the_auto_detected_interface(interactive, harness):
    output = io.StringIO()
    ask = reader()
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        selected = prepare(
            security.SecurityTarget(harness, harness), host_role=LOGIN_POD,
            interactive=interactive, assume_yes=True, reader=ask, stream=output,
        )
    assert selected.harness == harness
    ask.assert_not_called()
    assert f"auto-detected {harness}, accepted with --yes" in output.getvalue()


def test_yes_on_a_mixed_compute_pod_skips_every_prompt():
    role = host_role.HostRole(COMPUTE.kind, COMPUTE.evidence, ("Kubernetes pod",))
    ask = reader()
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details", return_value=()):
        selected = prepare(
            security.SecurityTarget("slurm", "slurm"), host_role=role,
            interactive=False, assume_yes=True, reader=ask,
        )
    assert selected.harness == "slurm"
    ask.assert_not_called()


def test_explicit_interface_does_not_probe_the_other_scheduler():
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(target_selection, "_kubernetes_details") as kubernetes:
        prepare(
            security.SecurityTarget("slurm", "slurm", True), host_role=LOGIN_POD,
            interactive=False,
        )
    kubernetes.assert_not_called()


def test_unreachable_kubernetes_does_not_offer_a_mixed_choice():
    ask = reader("y")
    with mock.patch.object(target_selection, "_slurm_details", return_value=()), \
         mock.patch.object(
             target_selection, "_kubernetes_details",
             side_effect=target_selection.TargetSelectionError("unreachable"),
         ):
        prepare(security.SecurityTarget("slurm", "slurm"), host_role=LOGIN_POD, reader=ask)
    assert ask.call_count == 1


def test_classification_keeps_slurm_and_runtime_context_separate():
    role = host_role.classify(host_role.HostFacts(
        environ={"SLURMD_NODENAME": "private-host", "KUBERNETES_SERVICE_HOST": "private-ip"},
        processes=frozenset({"slurmd"}), paths=frozenset({"/.dockerenv"}),
    ))
    assert role.kind == host_role.SLURM_COMPUTE
    assert role.context == ("Kubernetes pod", "container")
    assert "private-host" not in role.summary


def test_service_account_mount_marks_a_pod_without_service_links():
    # Slinky login and slurmd pods can run without KUBERNETES_SERVICE_HOST.
    facts = host_role.collect(
        {},
        which=lambda name: f"/usr/bin/{name}" if name == "sbatch" else None,
        exists=lambda path: path in host_role.POD_PATHS,
        processes=(),
    )
    role = host_role.classify(facts)
    assert role.kind == host_role.SLURM_LOGIN
    assert role.context == ("Kubernetes pod",)
    assert host_role.may_have_both_interfaces(role)


def test_container_without_a_service_account_is_not_a_pod():
    role = host_role.classify(host_role.HostFacts(
        environ={}, processes=frozenset(), paths=frozenset({"/.dockerenv"}),
    ))
    assert role.context == ("container",)
