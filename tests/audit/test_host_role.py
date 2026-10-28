import io
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from cmax import cli, host_role, security, target_selection

SLURM_CLIENT = frozenset({"sbatch", "scontrol"})


def facts(**values) -> host_role.HostFacts:
    values.setdefault("environ", {})
    return host_role.HostFacts(**values)


def answers(*values: str):
    remaining = iter(values)
    prompts: list[str] = []

    def read(prompt: str) -> str:
        prompts.append(prompt)
        return next(remaining)

    read.prompts = prompts
    return read


# Each case copies the signals of one host type seen in collected audit logs.
ROLE_CASES = {
    "slurm login node": (facts(commands=SLURM_CLIENT), host_role.SLURM_LOGIN),
    "slurm login node inside salloc": (
        facts(environ={"SLURM_JOB_ID": "1234"}, commands=SLURM_CLIENT, slurm_node=False),
        host_role.SLURM_LOGIN,
    ),
    "slurm login pod on kubernetes": (
        facts(environ={"KUBERNETES_SERVICE_HOST": "10.0.0.1"}, commands=SLURM_CLIENT),
        host_role.SLURM_LOGIN,
    ),
    "slurm compute node over ssh": (
        facts(processes=frozenset({"slurmd"}), commands=SLURM_CLIENT),
        host_role.SLURM_COMPUTE,
    ),
    "slurm job step with a private pid namespace": (
        facts(
            environ={"SLURM_JOB_ID": "1235", "SLURMD_NODENAME": "gpu-001"},
            commands=SLURM_CLIENT,
        ),
        host_role.SLURM_COMPUTE,
    ),
    "slurm node found by the controller": (
        facts(commands=SLURM_CLIENT, slurm_node=True),
        host_role.SLURM_COMPUTE,
    ),
    "slurm worker pod on kubernetes": (
        facts(
            environ={"KUBERNETES_SERVICE_HOST": "10.0.0.1"},
            processes=frozenset({"slurmd"}),
            commands=SLURM_CLIENT,
        ),
        host_role.SLURM_COMPUTE,
    ),
    "single-node slurm cluster head node": (
        facts(
            environ={"SLURM_JOB_ID": "1236", "SLURMD_NODENAME": "node-0"},
            processes=frozenset({"slurmd", "slurmctld"}),
            commands=SLURM_CLIENT,
        ),
        host_role.SLURM_LOGIN,
    ),
    "kubernetes worker host": (
        facts(
            processes=frozenset({"kubelet"}),
            paths=frozenset({"/var/lib/kubelet/config.yaml"}),
        ),
        host_role.K8S_NODE,
    ),
    "k3s agent host": (facts(processes=frozenset({"k3s-agent"})), host_role.K8S_NODE),
    "kubernetes node with a stopped kubelet": (
        facts(paths=frozenset({"/etc/kubernetes/kubelet.conf"})),
        host_role.K8S_NODE,
    ),
    "kubernetes pod": (
        facts(environ={"KUBERNETES_SERVICE_HOST": "10.0.0.1"}),
        host_role.K8S_POD,
    ),
    "operator laptop with kubectl": (
        facts(commands=frozenset({"kubectl"})),
        host_role.UNKNOWN,
    ),
    "standalone vm": (facts(), host_role.UNKNOWN),
}


@pytest.mark.parametrize("case", ROLE_CASES)
def test_host_roles_match_collected_host_types(case: str) -> None:
    observed, expected = ROLE_CASES[case]

    assert host_role.classify(observed).kind == expected


def test_role_summary_names_the_evidence() -> None:
    role = host_role.classify(
        facts(environ={"SLURMD_NODENAME": "gpu-001"}, processes=frozenset({"slurmd"}))
    )

    assert role.summary == (
        "Slurm compute node (SLURMD_NODENAME=gpu-001; slurmd is running)"
    )
    assert host_role.HostRole(host_role.UNKNOWN).summary == ""


@pytest.mark.parametrize(
    ("harness", "kind", "hint"),
    [
        ("standalone", host_role.SLURM_COMPUTE, "cmax audit --slurm"),
        ("standalone", host_role.SLURM_LOGIN, "cmax audit --slurm"),
        ("standalone", host_role.K8S_NODE, "cmax audit --k8s"),
        ("standalone", host_role.K8S_POD, "cmax audit --k8s"),
        ("slurm", host_role.SLURM_COMPUTE, "From a Slurm login node"),
    ],
)
def test_guard_names_the_command_to_run_instead(
    harness: str, kind: str, hint: str
) -> None:
    found = host_role.guard(harness, host_role.HostRole(kind))

    assert found is not None
    assert hint in found.instead


@pytest.mark.parametrize(
    ("harness", "kind"),
    [
        ("standalone", host_role.UNKNOWN),
        ("slurm", host_role.SLURM_LOGIN),
        ("k8s", host_role.K8S_POD),
        ("k8s", host_role.SLURM_COMPUTE),
    ],
)
def test_expected_runs_have_no_guard(harness: str, kind: str) -> None:
    assert host_role.guard(harness, host_role.HostRole(kind)) is None


def test_collect_reads_processes_paths_and_commands(tmp_path: Path) -> None:
    for pid, name in (("1", "systemd"), ("42", "kubelet"), ("self", "slurmd")):
        (tmp_path / pid).mkdir()
        (tmp_path / pid / "comm").write_text(f"{name}\n")

    processes = host_role._running_processes(tmp_path)
    observed = host_role.collect(
        {},
        which=lambda name: "/usr/bin/kubectl" if name == "kubectl" else None,
        exists=lambda path: path == "/var/lib/kubelet/config.yaml",
        processes=processes,
    )

    assert processes == frozenset({"kubelet"})
    assert observed.paths == frozenset({"/var/lib/kubelet/config.yaml"})
    assert observed.commands == frozenset({"kubectl"})
    assert observed.slurm_node is None
    assert host_role._running_processes(tmp_path / "missing") == frozenset()


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (subprocess.CompletedProcess([], 0, "NodeName=gpu-001 Arch=x86_64\n", ""), True),
        (subprocess.CompletedProcess([], 1, "", "Node gpu-001 not found\n"), False),
        (subprocess.CompletedProcess([], 1, "", "Unable to contact slurm controller\n"), None),
    ],
)
def test_controller_lookup_finds_a_node_hidden_by_the_pid_namespace(
    result: subprocess.CompletedProcess[str], expected: bool | None
) -> None:
    with mock.patch.object(
        host_role.socket, "gethostname", return_value="gpu-001.cluster.local"
    ), mock.patch.object(host_role.subprocess, "run", return_value=result) as run:
        observed = host_role.collect(
            {},
            which=lambda name: f"/usr/bin/{name}" if name == "scontrol" else None,
            exists=lambda _path: False,
            processes=(),
        )

    assert observed.slurm_node is expected
    assert run.call_args.args[0] == ["/usr/bin/scontrol", "show", "node", "-o", "gpu-001"]


def test_controller_lookup_is_skipped_when_slurmd_is_visible() -> None:
    with mock.patch.object(host_role.subprocess, "run") as run:
        observed = host_role.collect(
            {},
            which=lambda name: f"/usr/bin/{name}",
            exists=lambda _path: False,
            processes=("slurmd",),
        )

    run.assert_not_called()
    assert host_role.classify(observed).kind == host_role.SLURM_COMPUTE


COMPUTE = host_role.HostRole(host_role.SLURM_COMPUTE, ("slurmd is running",))
STANDALONE = security.SecurityTarget("standalone", "bare-metal", True)


def prepare(target=STANDALONE, role=COMPUTE, **options):
    output = io.StringIO()
    options.setdefault("interactive", False)
    with mock.patch.object(security, "local_environment", return_value="bare-metal"):
        selected = target_selection.prepare_audit_target(
            target,
            command="cmax audit --standalone",
            stream=output,
            environ={},
            host_role=role,
            **options,
        )
    return selected, output.getvalue()


def test_standalone_on_a_compute_node_stops_without_a_terminal() -> None:
    output = io.StringIO()
    with mock.patch.object(security, "local_environment", return_value="bare-metal"):
        with pytest.raises(target_selection.TargetSelectionError) as error:
            target_selection.prepare_audit_target(
                STANDALONE,
                command="cmax audit --standalone",
                stream=output,
                environ={},
                interactive=False,
                host_role=COMPUTE,
            )

    text = output.getvalue()
    assert "Host role: Slurm compute node (slurmd is running)" in text
    assert "From a Slurm login node, run: cmax audit --slurm" in text
    assert host_role.ISSUE_URL in text
    assert "--allow-cluster-node" in str(error.value)


def test_yes_does_not_skip_the_second_confirmation() -> None:
    output = io.StringIO()
    with mock.patch.object(security, "local_environment", return_value="bare-metal"):
        with pytest.raises(target_selection.TargetSelectionError):
            target_selection.prepare_audit_target(
                STANDALONE,
                command="cmax audit --standalone",
                assume_yes=True,
                stream=output,
                environ={},
                interactive=False,
                host_role=COMPUTE,
            )


def test_allow_cluster_node_overrides_the_guard() -> None:
    selected, text = prepare(allow_cluster_node=True)

    assert selected == STANDALONE
    assert "Host role check: accepted with --allow-cluster-node" in text


def test_interactive_run_asks_twice() -> None:
    reader = answers("y", "y")

    selected, _text = prepare(interactive=True, reader=reader)

    assert selected == STANDALONE
    assert reader.prompts == [
        "Run this audit? [y]es, [c]hange target or access, [N]o: ",
        "Run a standalone audit on this compute node anyway? [y/N]: ",
    ]


def test_interactive_second_confirmation_defaults_to_no() -> None:
    with pytest.raises(target_selection.TargetSelectionCancelled):
        prepare(interactive=True, reader=answers("y", ""))


def test_interactive_yes_still_asks_the_second_confirmation() -> None:
    reader = answers("y")

    prepare(interactive=True, reader=reader, assume_yes=True)

    assert reader.prompts == [
        "Run a standalone audit on this compute node anyway? [y/N]: ",
    ]


def test_slurm_audit_from_a_compute_node_is_guarded() -> None:
    target = security.SecurityTarget("slurm", "slurm", True)
    with mock.patch.object(
        target_selection, "_slurm_details", return_value=(("Target", "Slurm cluster"),)
    ):
        with pytest.raises(target_selection.TargetSelectionError) as error:
            prepare(target=target)

    assert "Run the Slurm audit from a login node" in str(error.value)


def test_slurm_audit_from_a_login_node_runs() -> None:
    target = security.SecurityTarget("slurm", "slurm", True)
    login = host_role.HostRole(host_role.SLURM_LOGIN, ("sbatch is in PATH",))
    with mock.patch.object(
        target_selection, "_slurm_details", return_value=(("Target", "Slurm cluster"),)
    ):
        selected, text = prepare(target=target, role=login)

    assert selected == target
    assert "Host role: Slurm login node (sbatch is in PATH)" in text
    assert "cmax:" not in text


def test_standalone_on_an_unknown_host_runs() -> None:
    selected, text = prepare(role=host_role.HostRole(host_role.UNKNOWN))

    assert selected == STANDALONE
    assert "Host role" not in text
    assert "Warning" not in text


@pytest.mark.parametrize(
    ("selected", "detected", "flag"),
    [
        ("bare-metal", "vm", "--vm"),
        ("bare-metal", "container", "--container"),
        ("vm", "bare-metal", "--standalone"),
        ("container", "vm", "--vm"),
    ],
)
def test_explicit_host_type_is_checked_against_detection(
    selected: str, detected: str, flag: str
) -> None:
    target = security.SecurityTarget("standalone", selected, True)
    with mock.patch.object(security, "local_environment", return_value=detected):
        details = dict(target_selection.target_details(target))

    assert f"(use {flag})" in details["Warning"]


def test_auto_detected_host_type_has_no_mismatch_warning() -> None:
    target = security.SecurityTarget("standalone", "vm")
    with mock.patch.object(security, "local_environment", return_value="bare-metal"):
        details = dict(target_selection.target_details(target))

    assert "Warning" not in details


def test_cli_passes_allow_cluster_node() -> None:
    target = security.SecurityTarget("standalone", "bare-metal", True)
    with mock.patch.object(security, "detect_target", return_value=target), mock.patch.object(
        target_selection, "prepare_audit_target", return_value=target
    ) as prepared, mock.patch("cmax.audit_runner.run", return_value=0):
        result = cli.main(
            ["--repo", "/runtime", "audit", "--standalone", "--allow-cluster-node"]
        )

    assert result == 0
    assert prepared.call_args.kwargs["allow_cluster_node"] is True
