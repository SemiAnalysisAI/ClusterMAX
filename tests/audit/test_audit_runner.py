from pathlib import Path
from unittest import mock

from cmax import audit_profiles, audit_report, audit_runner, runtime_paths, security


def test_default_audit_directory_uses_private_audit_storage(tmp_path: Path) -> None:
    with mock.patch.dict(audit_runner.os.environ, {}, clear=True), mock.patch.object(
        audit_runner.Path, "home", return_value=tmp_path
    ):
        audit_dir = audit_runner._audit_dir()

    assert audit_dir.parent == tmp_path / ".clustermax" / "audit"


def test_runner_renders_with_the_installed_runtime_root(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    results = tmp_path / "results"

    def finish_audit(*args, **kwargs):
        audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (audit_dir / "audit.values.json").write_text("{}")
        return 0, "collector output"

    with (
        mock.patch.object(security, "find_runtime_root", return_value=runtime),
        mock.patch.object(
            security,
            "detect_target",
            return_value=security.SecurityTarget("standalone", "bare-metal"),
        ) as detect_target,
        mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_audit
        ),
        mock.patch.object(audit_runner.audit_report, "render", return_value="report") as render,
        mock.patch.dict(
            audit_runner.os.environ,
            {"CLUSTERMAX_RUNS_ROOT": str(results), "CLUSTER_SLUG": "test-cluster"},
            clear=False,
        ),
    ):
        assert (
            audit_runner.run(
                verbosity=1, target="standalone", category="hardware"
            )
            == 0
        )
        detect_target.assert_called_once_with("standalone")

    assert render.call_args.kwargs["rules_root"] == runtime
    assert render.call_args.kwargs["category"] == "hardware"
    assert render.call_args.kwargs["environment"] == "bare-metal"


def test_runner_uses_the_target_that_the_operator_confirmed(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    results = tmp_path / "results"
    selected = security.SecurityTarget("standalone", "local", True)

    def finish_audit(*args, **kwargs):
        audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (audit_dir / "audit.values.json").write_text("{}")
        return 0, "collector output"

    with (
        mock.patch.object(security, "find_runtime_root", return_value=runtime),
        mock.patch.object(security, "detect_target") as detect_target,
        mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_audit
        ),
        mock.patch.object(audit_runner.audit_report, "render", return_value="report"),
        mock.patch.dict(
            audit_runner.os.environ,
            {"CLUSTERMAX_RUNS_ROOT": str(results), "CLUSTER_SLUG": "test-local"},
            clear=False,
        ),
    ):
        assert audit_runner.run(
            verbosity=1,
            resolved_target=selected,
        ) == 0

    detect_target.assert_not_called()


def test_runner_forces_full_scope_for_each_selected_harness(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    results = tmp_path / "results"
    collector_environments: list[dict[str, str]] = []

    def finish_audit(*args, **kwargs):
        collector_environments.append(kwargs["env"])
        audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (audit_dir / "audit.values.json").write_text("{}")
        return 0, "collector output"

    with (
        mock.patch.object(security, "find_runtime_root", return_value=runtime),
        mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_audit
        ),
        mock.patch.object(audit_runner.audit_report, "render", return_value="report"),
        mock.patch.dict(
            audit_runner.os.environ,
            {
                "CLUSTERMAX_RUNS_ROOT": str(results),
                "CLUSTER_SLUG": "test-routing",
                "CLUSTERMAX_AUDIT_HARNESS": "wrong-harness",
                "CLUSTERMAX_AUDIT_SCOPE": "security",
            },
            clear=False,
        ),
    ):
        for harness in ("slurm", "k8s", "standalone"):
            assert audit_runner.run(
                verbosity=1,
                resolved_target=security.SecurityTarget(harness, harness, True),
            ) == 0

    assert [
        (
            env["CLUSTERMAX_AUDIT_HARNESS"],
            env["CLUSTERMAX_AUDIT_ENVIRONMENT"],
            env["CLUSTERMAX_AUDIT_SCOPE"],
        )
        for env in collector_environments
    ] == [
        ("slurm", "slurm", "full"),
        ("k8s", "k8s", "full"),
        ("standalone", "standalone", "full"),
    ]


def test_each_named_profile_uses_the_shared_runner_and_scope(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    collector_environments: list[dict[str, str]] = []

    def finish_audit(*args, **kwargs):
        collector_environments.append(kwargs["env"])
        audit_dir = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (audit_dir / "audit.out").write_text("collector output\n")
        (audit_dir / "audit.values.json").write_text("{}")
        return 0, "collector output"

    with (
        mock.patch.object(security, "find_runtime_root", return_value=runtime),
        mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_audit
        ),
        mock.patch.object(
            audit_runner.audit_report, "render", return_value="report"
        ) as render,
        mock.patch.object(
            audit_runner,
            "_audit_dir",
            side_effect=lambda: tmp_path / f"run-{len(collector_environments)}",
        ),
    ):
        for profile in audit_profiles.AUDIT_PROFILE_NAMES:
            assert audit_runner.run(
                category=profile,
                resolved_target=security.SecurityTarget("standalone", "vm", True),
            ) == 0

    assert [
        environment["CLUSTERMAX_AUDIT_SCOPE"]
        for environment in collector_environments
    ] == list(audit_profiles.AUDIT_PROFILE_NAMES)
    assert all(
        environment["CLUSTERMAX_AUDIT_ENVIRONMENT"] == "vm"
        for environment in collector_environments
    )
    assert [call.kwargs["category"] for call in render.call_args_list] == list(
        audit_profiles.AUDIT_PROFILE_NAMES
    )
    for index in range(len(audit_profiles.AUDIT_PROFILE_NAMES)):
        names = {path.name for path in (tmp_path / f"run-{index}").iterdir()}
        assert names == {"audit.out", "audit.values.json"}


def test_security_profile_returns_two_when_the_standard_report_fails(
    tmp_path: Path,
) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    audit_dir = tmp_path / "audit"

    def finish_audit(*args, **kwargs):
        destination = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (destination / "audit.values.json").write_text("{}")
        return 0, "collector output"

    failed = audit_report.AuditCheck(
        "security.test", "Security test", "isolation", audit_report.FAIL, False
    )
    with (
        mock.patch.object(security, "find_runtime_root", return_value=runtime),
        mock.patch.object(audit_runner, "_audit_dir", return_value=audit_dir),
        mock.patch.object(
            audit_runner.progress, "run_with_progress", side_effect=finish_audit
        ),
        mock.patch.object(audit_runner.audit_report, "render", return_value="report"),
        mock.patch.object(
            audit_runner.audit_report, "evaluate", return_value=[failed]
        ) as evaluate,
    ):
        result = audit_runner.run(
            category="security",
            resolved_target=security.SecurityTarget("standalone", "vm", True),
            exit_on_fail=True,
        )

    assert result == 2
    assert evaluate.call_args.kwargs == {
        "category": "security",
        "harness": "standalone",
        "environment": "vm",
    }
