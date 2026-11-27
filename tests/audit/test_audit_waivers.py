"""Tests for the waiver file and for waived checks in the audit report."""

from __future__ import annotations

from datetime import date
from pathlib import Path
from unittest import mock

import pytest

from cmax import audit_report, audit_runner, audit_waivers, cli, runtime_paths, security

RUNTIME_ROOT = runtime_paths.package_runtime_root()
DOCKER = "containers.dockerOnWorkers"
TOOLKIT = "containers.nvidiaContainerToolkit"


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / audit_waivers.DEFAULT_NAME
    path.write_text(text)
    return path


def waiver_set(*waivers: audit_waivers.Waiver) -> audit_waivers.WaiverSet:
    return audit_waivers.WaiverSet(Path("waivers.yaml"), tuple(waivers))


def check(key: str, status: str) -> audit_report.AuditCheck:
    return audit_report.AuditCheck(key, key, "containers", status, False)


def test_load_reads_checks_reasons_and_both_date_spellings(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "version: 1\n"
        "waivers:\n"
        f"  - check: {DOCKER}\n"
        "    reason: >\n"
        "      No Docker on cluster hosts.\n"
        "      Podman and containerd are used.\n"
        "    expires: 2027-06-30\n"
        f"  - check: {TOOLKIT}\n"
        "    reason: Tracked in a ticket.\n"
        '    expires: "2027-01-01"\n'
        "    status: warning\n",
    )

    loaded = audit_waivers.load(path)

    assert loaded.path == path
    assert loaded.waivers == (
        audit_waivers.Waiver(
            DOCKER,
            "No Docker on cluster hosts. Podman and containerd are used.",
            date(2027, 6, 30),
        ),
        audit_waivers.Waiver(TOOLKIT, "Tracked in a ticket.", date(2027, 1, 1), "warning"),
    )
    assert loaded.get(TOOLKIT).reason == "Tracked in a ticket."
    assert loaded.get("containers.enroot") is None


@pytest.mark.parametrize(
    "text,message",
    [
        ("waivers: []\n", "not a version 1 waiver file"),
        ("version: 2\nwaivers: []\n", "not a version 1 waiver file"),
        ("version: 1\nwaivers: {}\n", "waivers must be a list"),
        ("version: 1\nwaivers:\n  - reason: r\n", "check must name an audit check"),
        (f"version: 1\nwaivers:\n  - check: {DOCKER}\n", "needs a reason"),
        (f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: '  '\n", "needs a reason"),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    owner: me\n",
            "unknown field owner",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    expires: soon\n",
            "expires must be a YYYY-MM-DD date",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: a\n"
            f"  - check: {DOCKER}\n    reason: b\n",
            "is waived twice",
        ),
        ("version: [1\n", "could not read waiver file"),
        ("version: true\nwaivers: []\n", "not a version 1 waiver file"),
        ("version: 1.0\nwaivers: []\n", "not a version 1 waiver file"),
        # An empty date must not make a permanent waiver.
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    expires:\n",
            "expires must be a YYYY-MM-DD date",
        ),
        # Python 3.11 and later read these two as dates. Python 3.10 does not.
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    expires: 20270131\n",
            "expires must be a YYYY-MM-DD date",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    expires: 2027-W05-1\n",
            "expires must be a YYYY-MM-DD date",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    expires: '2027-02-30'\n",
            "expires must be a YYYY-MM-DD date",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    status: pass\n",
            "status must be warning or fail",
        ),
        (
            f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: r\n    status:\n",
            "status must be warning or fail",
        ),
    ],
)
def test_load_rejects_an_invalid_file(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(audit_waivers.WaiverError, match=message):
        audit_waivers.load(write(tmp_path, text))


def test_find_path_prefers_the_option_then_the_variable_then_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default = write(tmp_path, "version: 1\n")
    named = tmp_path / "named.yaml"
    named.write_text("version: 1\n")
    from_env = tmp_path / "env.yaml"
    from_env.write_text("version: 1\n")
    empty = tmp_path / "empty"
    empty.mkdir()

    monkeypatch.delenv(audit_waivers.ENV_VAR, raising=False)
    assert audit_waivers.find_path(cwd=empty) is None
    assert audit_waivers.find_path(cwd=tmp_path) == default
    monkeypatch.setenv(audit_waivers.ENV_VAR, str(from_env))
    assert audit_waivers.find_path(cwd=tmp_path) == from_env
    assert audit_waivers.find_path(str(named), cwd=tmp_path) == named


def test_find_path_rejects_a_named_file_that_does_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "version: 1\n")
    monkeypatch.delenv(audit_waivers.ENV_VAR, raising=False)
    with pytest.raises(audit_waivers.WaiverError, match="waiver file not found"):
        audit_waivers.find_path(str(tmp_path / "missing.yaml"), cwd=tmp_path)
    # An empty option is a mistake. It must not select the default file.
    with pytest.raises(audit_waivers.WaiverError, match="waiver file not found"):
        audit_waivers.find_path("", cwd=tmp_path)
    monkeypatch.setenv(audit_waivers.ENV_VAR, str(tmp_path / "missing.yaml"))
    with pytest.raises(audit_waivers.WaiverError, match="waiver file not found"):
        audit_waivers.find_path(cwd=tmp_path)


def test_find_path_rejects_a_path_that_is_not_a_readable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(audit_waivers.ENV_VAR, raising=False)
    directory = tmp_path / "directory"
    (directory / audit_waivers.DEFAULT_NAME).mkdir(parents=True)
    dangling = tmp_path / "dangling"
    dangling.mkdir()
    (dangling / audit_waivers.DEFAULT_NAME).symlink_to(tmp_path / "not-mounted.yaml")

    for cwd in (directory, dangling):
        with pytest.raises(audit_waivers.WaiverError, match="is not a readable file"):
            audit_waivers.find_path(cwd=cwd)
    with pytest.raises(audit_waivers.WaiverError, match="is not a readable file"):
        audit_waivers.find_path(str(directory), cwd=tmp_path)


def test_load_reports_a_file_that_is_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / audit_waivers.DEFAULT_NAME
    path.write_bytes(
        f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: caf\xe9\n".encode("latin-1")
    )

    with pytest.raises(audit_waivers.WaiverError, match="could not read waiver file"):
        audit_waivers.load(path)


def test_a_waiver_marks_a_failure_and_a_warning_but_not_a_pass_or_a_skip() -> None:
    waivers = waiver_set(
        *(audit_waivers.Waiver(key, "accepted") for key in ("a", "b", "c", "d"))
    )
    checks = [
        check("a", audit_report.FAIL),
        check("b", audit_report.WARNING),
        check("c", audit_report.PASS),
        check("d", audit_report.SKIPPED),
        check("e", audit_report.FAIL),
    ]

    marked = audit_report.apply_waivers(checks, waivers)

    assert [
        (item.key, item.status, item.waived_status, item.waiver_state) for item in marked
    ] == [
        ("a", audit_report.WAIVED, audit_report.FAIL, audit_report.WAIVER_APPLIED),
        ("b", audit_report.WAIVED, audit_report.WARNING, audit_report.WAIVER_APPLIED),
        ("c", audit_report.PASS, "", audit_report.WAIVER_NOT_NEEDED),
        ("d", audit_report.SKIPPED, "", ""),
        ("e", audit_report.FAIL, "", ""),
    ]
    assert audit_report.apply_waivers(checks, None) is checks


def test_a_waiver_applies_through_its_expiry_date_and_not_after() -> None:
    waivers = waiver_set(audit_waivers.Waiver("a", "accepted", date(2027, 6, 30)))
    checks = [check("a", audit_report.FAIL)]

    last_day = audit_report.apply_waivers(checks, waivers, today=date(2027, 6, 30))
    next_day = audit_report.apply_waivers(checks, waivers, today=date(2027, 7, 1))

    assert last_day[0].status == audit_report.WAIVED
    assert next_day[0].status == audit_report.FAIL
    assert next_day[0].waiver_state == audit_report.WAIVER_EXPIRED
    report = audit_report.format_report(next_day)
    assert "FAIL     a  [a]" in report
    assert "Waiver expired: 2027-06-30; the check is graded again. Reason was: accepted" in report
    assert "1 failed, 0 warnings, 0 passed, 0 skipped\n" in report


def test_a_waiver_for_a_warning_does_not_accept_a_later_failure() -> None:
    warning_only = waiver_set(audit_waivers.Waiver("a", "accepted", status="warning"))
    up_to_failure = waiver_set(audit_waivers.Waiver("a", "accepted", status="fail"))
    warning = [check("a", audit_report.WARNING)]
    failure = [check("a", audit_report.FAIL)]

    assert audit_report.apply_waivers(warning, warning_only)[0].status == audit_report.WAIVED
    assert audit_report.apply_waivers(warning, up_to_failure)[0].status == audit_report.WAIVED
    assert audit_report.apply_waivers(failure, up_to_failure)[0].status == audit_report.WAIVED
    graded = audit_report.apply_waivers(failure, warning_only)

    assert graded[0].status == audit_report.FAIL
    assert graded[0].waiver_state == audit_report.WAIVER_EXCEEDED
    report = audit_report.format_report(graded)
    assert (
        "Waiver not applied: it accepts WARNING only, and the check is graded again. "
        "Reason was: accepted"
    ) in report
    assert "1 failed, 0 warnings, 0 passed, 0 skipped\n" in report


def test_the_report_names_a_waiver_for_a_check_that_passes() -> None:
    waivers = waiver_set(
        audit_waivers.Waiver("a", "accepted"),
        audit_waivers.Waiver("b", "accepted"),
        audit_waivers.Waiver("c", "accepted"),
    )
    checks = audit_report.apply_waivers(
        [
            check("a", audit_report.PASS),
            check("b", audit_report.SKIPPED),
            check("c", audit_report.FAIL),
        ],
        waivers,
    )

    report = audit_report.format_report(checks)

    assert checks[0].status == audit_report.PASS
    assert "Waiver not needed: the check passes; remove it from the waiver file." in report
    assert "0 failed, 0 warnings, 1 passed, 1 skipped, 1 waived\n" in report
    assert "1 waiver not needed, the check passes: a\n" in report


def test_the_report_shows_a_waived_check_with_its_reason_at_every_level() -> None:
    waivers = waiver_set(
        audit_waivers.Waiver("a", "No Docker by design.", date(2027, 6, 30)),
        audit_waivers.Waiver("b", "Tracked in a ticket."),
    )
    checks = audit_report.apply_waivers(
        [
            check("a", audit_report.FAIL),
            check("b", audit_report.WARNING),
            check("c", audit_report.FAIL),
        ],
        waivers,
    )

    for verbosity in (1, 2, 3):
        report = audit_report.format_report(checks, verbosity=verbosity)
        assert "WAIVED   a  [a]" in report
        assert "Waived: No Docker by design. (was FAIL; expires 2027-06-30)" in report
        assert "Waived: Tracked in a ticket. (was WARNING)" in report
        assert "Observed: false" in report
        assert "1 failed, 0 warnings, 0 passed, 0 skipped, 2 waived" in report


def test_the_summary_keeps_four_counts_without_a_waived_check() -> None:
    report = audit_report.format_report([check("a", audit_report.FAIL)])

    assert "1 failed, 0 warnings, 0 passed, 0 skipped\n" in report


def test_evaluate_waives_a_real_check_and_sorts_it_below_the_findings() -> None:
    values = {"audit_data": {"containers": {"nvidiaContainerToolkit": False}}}
    plain = {item.key: item for item in audit_report.evaluate(values, RUNTIME_ROOT)}
    assert plain[TOOLKIT].status == audit_report.FAIL

    checks = audit_report.evaluate(
        values, RUNTIME_ROOT, waivers=waiver_set(audit_waivers.Waiver(TOOLKIT, "accepted"))
    )

    by_key = {item.key: item for item in checks}
    assert by_key[TOOLKIT].status == audit_report.WAIVED
    assert by_key[TOOLKIT].observed == plain[TOOLKIT].observed
    assert len(checks) == len(plain)
    statuses = [item.status for item in checks]
    assert audit_report.FAIL not in statuses
    assert statuses.index(audit_report.WAIVED) < statuses.index(audit_report.WARNING)


def test_check_waivers_rejects_a_check_that_does_not_exist() -> None:
    audit_report.check_waivers(waiver_set(audit_waivers.Waiver(DOCKER, "r")), RUNTIME_ROOT)
    audit_report.check_waivers(waiver_set(audit_waivers.Waiver("bmc-ipmi", "r")), RUNTIME_ROOT)

    with pytest.raises(audit_waivers.WaiverError, match="unknown audit check containers.dokcer"):
        audit_report.check_waivers(
            waiver_set(audit_waivers.Waiver("containers.dokcer", "r")), RUNTIME_ROOT
        )


def test_a_waived_failure_does_not_fail_the_security_run(tmp_path: Path, capsys) -> None:
    runtime = tmp_path / "runtime"
    runner = runtime_paths.audit_runner(runtime)
    runner.parent.mkdir(parents=True)
    runner.write_text("#!/bin/sh\n")
    waivers = waiver_set(audit_waivers.Waiver(TOOLKIT, "Accepted for this test."))

    def finish_audit(*args, **kwargs):
        destination = Path(kwargs["env"]["RUN_RESULTS_DIR"])
        (destination / "audit.values.json").write_text("{}")
        return 0, "collector output"

    def run(selected):
        with (
            mock.patch.object(security, "find_runtime_root", return_value=runtime),
            mock.patch.object(security, "_inject_observability"),
            mock.patch.object(
                audit_runner.progress, "run_with_progress", side_effect=finish_audit
            ),
            # The runner grades the real report module, with one failed check.
            mock.patch.object(
                audit_runner.audit_report,
                "evaluate",
                side_effect=lambda *a, waivers=None, **kw: audit_report.apply_waivers(
                    [check(TOOLKIT, audit_report.FAIL)], waivers
                ),
            ),
        ):
            return audit_runner.run(
                category="security",
                resolved_target=security.SecurityTarget("standalone", "vm", True),
                exit_on_fail=True,
                output_dir=str(tmp_path / f"run-{selected is not None}"),
                waivers=selected,
            )

    assert run(None) == 2
    assert "FAIL" in capsys.readouterr().out
    assert run(waivers) == 0
    output = capsys.readouterr().out
    assert "Waived: Accepted for this test. (was FAIL)" in output
    assert "0 failed, 0 warnings, 0 passed, 0 skipped, 1 waived" in output


def test_the_cli_reads_the_option_and_stops_on_an_unknown_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.delenv(audit_waivers.ENV_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    parser = cli.build_parser()
    good = tmp_path / "good.yaml"
    good.write_text(f"version: 1\nwaivers:\n  - check: {DOCKER}\n    reason: By design.\n")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nwaivers:\n  - check: no.such.check\n    reason: r\n")

    args = parser.parse_args(["audit", "security", "--waivers", str(good)])
    loaded = cli._load_waivers(args, parser)
    assert [waiver.check for waiver in loaded.waivers] == [DOCKER]
    assert f"1 waiver(s) from {good}" in capsys.readouterr().err

    assert cli._load_waivers(parser.parse_args(["audit"]), parser) is None
    assert parser.parse_args(["audit", "--waivers", "a", "hardware"]).waivers == "a"
    assert parser.parse_args(["audit", "review", "--waivers", "a"]).waivers == "a"

    with pytest.raises(SystemExit) as raised:
        cli._load_waivers(parser.parse_args(["audit", "--waivers", str(bad)]), parser)
    assert raised.value.code == 2
    assert "unknown audit check no.such.check" in capsys.readouterr().err


def test_a_bad_waiver_file_stops_the_audit_before_the_target_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    monkeypatch.delenv(audit_waivers.ENV_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    write(tmp_path, f"version: 1\nwaivers:\n  - check: {DOCKER}\n")

    with (
        mock.patch.object(cli, "_resolve_audit_target") as resolve,
        mock.patch.object(audit_runner, "run") as run,
        pytest.raises(SystemExit) as raised,
    ):
        cli.main(["audit", "--standalone"])

    assert raised.value.code == 2
    assert "needs a reason" in capsys.readouterr().err
    resolve.assert_not_called()
    run.assert_not_called()
