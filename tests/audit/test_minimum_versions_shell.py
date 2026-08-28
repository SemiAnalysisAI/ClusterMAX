#!/usr/bin/env python3
"""The audit shell collectors read their CVE minimums from the generated table.

`minimum-versions.json` is regenerated daily by a workflow, so the collectors
must never carry a hardcoded minimum: a literal that the refresh has moved past
grades a vulnerable host as a pass. These tests execute the real shell code
(pattern 1 of the AGENTS.md testing doctrine) against temporary minimum tables
whose values differ from the committed ones, which is what proves the minimum is
read from the file instead of baked into the script.

They also cover the fail-safe contract. A missing reader, a missing table, a
corrupt table, or a removed key must produce an explicit unknown state and let
the audit keep running. A permissive substitute (0, an empty string, or a stale
literal) is the one outcome these checks must never produce.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

WORKLOAD = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
HOST_CHECK = WORKLOAD / "host-check.sh"
AUDIT_COMMON = WORKLOAD / "audit-common.sh"
K8S_COLLECTOR = WORKLOAD / "cluster-audit-k8s.sh"
SLURM_COLLECTOR = WORKLOAD / "cluster-audit-slurm.sh"
STANDALONE_COLLECTOR = WORKLOAD / "cluster-audit-standalone.sh"
MINIMUMS_READER = WORKLOAD / "minimum_versions.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest  # noqa: E402

# The check's Fragnesia block, executed verbatim. Anchors are the leading
# comment and the last line the block prints.
FRAGNESIA_BLOCK = bashtest.extract_block(
    HOST_CHECK,
    "# Ubuntu's CVE-2026-46300 (Fragnesia) Noble 6.8 fixed package carries a minimum",
    'echo "WORKER_FRAGNESIA_STATUS=${WORKER_FRAGNESIA_STATUS}"',
)

# The two collectors' calls into the shared advisory builder, executed verbatim
# so the convergence test compares real call sites rather than paraphrases.
K8S_ADVISORY_CALL = bashtest.extract_block(
    K8S_COLLECTOR,
    "SECURITY_ADVISORY_JSON=$(build_security_advisory_json \\",
    '--vmscape-status "${HP_VMSCAPE_STATUS:-unknown}")',
)
COMMON_ADVISORY_CALL = bashtest.extract_block(
    AUDIT_COMMON,
    "security_advisory_json=$(build_security_advisory_json \\",
    '--vmscape-status "${WORKER_VMSCAPE_STATUS:-unknown}")',
)

# Each collector's container-recommendation minimum lookup and the gate that
# consumes it. `_TAIL` closes the if-block the end anchor sits inside, because
# extract_block stops at the anchor line.
RESOLVE_END = (
    '    print_detail "Versions stay not-verified (false) rather than being '
    'graded against a guessed minimum"'
)
SLURM_RESOLVE = (
    bashtest.extract_block(
        SLURM_COLLECTOR,
        "DOCKER_RECOMMENDED_MIN=$(minimum_version components.docker.minimum)",
        RESOLVE_END,
    )
    + "fi\n"
)
STANDALONE_RESOLVE = (
    bashtest.extract_block(
        STANDALONE_COLLECTOR,
        "DOCKER_RECOMMENDED_MIN=$(minimum_version components.docker.minimum)",
        RESOLVE_END,
    )
    + "fi\n"
)
SLURM_GATE = bashtest.extract_block(
    SLURM_COLLECTOR,
    '        version_meets_minimum "$DOCKER_VERSION" "$DOCKER_RECOMMENDED_MIN"',
    'version_meets_minimum "$NVIDIA_CT_VERSION" "$NVIDIA_CT_RECOMMENDED_MIN"'
    ' && NVIDIA_CT_VERSION_OK="true"',
)
STANDALONE_DOCKER_GATE = (
    bashtest.extract_block(
        STANDALONE_COLLECTOR,
        '    if version_meets_minimum "$DOCKER_VERSION" "$DOCKER_RECOMMENDED_MIN"; then',
        'print_warn "Docker ${DOCKER_VERSION} is below recommended ${DOCKER_RECOMMENDED_MIN}"',
    )
    + "fi\n"
)
# The SECURITY_GPU_VENDOR derivation each collector feeds to
# build_security_version_audit as its 6th positional argument. `_TAIL` closes
# the if-block, because extract_block stops at the anchor line.
SLURM_VENDOR_GATE = (
    bashtest.extract_block(
        SLURM_COLLECTOR, 'SECURITY_GPU_VENDOR="nvidia"', 'SECURITY_GPU_VENDOR="amd"'
    )
    + "fi\n"
)
STANDALONE_VENDOR_GATE = (
    bashtest.extract_block(
        STANDALONE_COLLECTOR, 'SECURITY_GPU_VENDOR="nvidia"', 'SECURITY_GPU_VENDOR="amd"'
    )
    + "fi\n"
)
STANDALONE_NCT_GATE = (
    bashtest.extract_block(
        STANDALONE_COLLECTOR,
        '    if version_meets_minimum "$NCT_VERSION_CMD" "$NVIDIA_CT_RECOMMENDED_MIN"; then',
        'print_warn "nvidia-container-toolkit: ${NCT_VERSION_CMD} is below '
        'recommended ${NVIDIA_CT_RECOMMENDED_MIN}"',
    )
    + "fi\n"
)


class TempDirMixin(unittest.TestCase):
    def temp_dir(self) -> Path:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        return Path(holder.name)

    def write_minimum_table(self, table: dict | str) -> Path:
        path = self.temp_dir() / "minimum-versions.json"
        path.write_text(table if isinstance(table, str) else json.dumps(table))
        return path


def minimum_table(
    *,
    fragnesia_abi: int = 200,
    fragnesia_fixed: str = "6.8.0-200.200",
    fragnesia_status: str = "released",
    fragnesia_released: str | None = None,
    fragnesia_available: str | None = None,
    januscape_fixed: str = "6.8.0-137.137",
    januscape_status: str = "pending",
    docker_minimum: str = "40.4.3",
    nct_minimum: str = "2.19.1",
) -> dict:
    """A schema-version-1 table whose values differ from the committed ones."""
    fragnesia = {
        "abi": fragnesia_abi,
        "cve": "CVE-2026-46300",
        "fixed": fragnesia_fixed,
        "package": "linux",
        "relatedCves": ["CVE-2026-43284", "CVE-2026-43500"],
        "status": fragnesia_status,
    }
    if fragnesia_released is not None:
        fragnesia["released"] = fragnesia_released
    if fragnesia_available is not None:
        fragnesia["fixAvailability"] = {
            "status": "confirmed",
            "available": fragnesia_available,
            "feed": "ubuntu-security-notice",
        }
    return {
        "schemaVersion": 1,
        "generated": "2026-07-30T00:00:00Z",
        "gracePeriodDays": 3,
        "maxAgeDays": 10,
        "components": {
            "docker": {"kind": "minimum", "minimum": docker_minimum},
            "nvidiaContainerToolkit": {"kind": "minimum", "minimum": nct_minimum},
            "ubuntuNoble": {
                "kind": "distroPackages",
                "release": "noble",
                "packages": {
                    "linuxFragnesia": fragnesia,
                    "linuxJanuscape": {
                        "cve": "CVE-2026-53359",
                        "fixed": januscape_fixed,
                        "package": "linux",
                        "status": januscape_status,
                    },
                    "linuxVmscape": {
                        "cve": "CVE-2025-40300",
                        "fixed": "6.8.0-90.91",
                        "package": "linux",
                        "status": "released",
                    },
                    "qemu": {
                        "cve": "CVE-2024-3446",
                        "fixed": "1:8.2.2+ds-0ubuntu1.99",
                        "package": "qemu",
                        "status": "released",
                    },
                },
            }
        },
    }


class FragnesiaAbiMinimumTests(TempDirMixin):
    """host-check.sh grades the running kernel against the table's ABI minimum."""

    def check(self, kernel: str, **env: str) -> dict[str, str]:
        preamble = (
            "ID=ubuntu\n"
            "VERSION_ID=24.04\n"
            f"WORKER_GUEST_KERNEL_RUNNING={kernel}\n"
        )
        run = bashtest.run_bash(preamble + FRAGNESIA_BLOCK, env=env)
        self.assertEqual(
            run.returncode, 0, f"check block exited {run.returncode}: {run.stderr}"
        )
        facts = dict(
            line.split("=", 1) for line in run.stdout.splitlines() if "=" in line
        )
        return facts

    def write_table(self, **kwargs) -> dict[str, str]:
        """Write a temporary minimum table and return the env that selects it."""
        table = self.write_minimum_table(minimum_table(**kwargs))
        return {
            "CLUSTERMAX_MINIMUM_VERSIONS": str(table),
            "CLUSTERMAX_MINIMUM_VERSIONS_READER": str(MINIMUMS_READER),
            "CLUSTERMAX_FRAGNESIA_ABI_MINIMUM": "",
        }

    def test_kernel_at_the_table_minimum_passes(self) -> None:
        env = self.write_table(fragnesia_abi=200)

        facts = self.check("6.8.0-200-generic", **env)

        self.assertEqual(facts["WORKER_FRAGNESIA_ABI_FLOOR"], "200")
        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "pass")

    def test_kernel_one_below_the_table_minimum_fails(self) -> None:
        env = self.write_table(fragnesia_abi=200)

        facts = self.check("6.8.0-199-generic", **env)

        self.assertEqual(facts["WORKER_FRAGNESIA_ABI"], "199")
        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "fail")

    def test_minimum_moves_with_the_table_not_with_the_script(self) -> None:
        # The same kernel grades differently under two tables. A hardcoded
        # literal cannot produce this, so this is the assertion that pins the
        # minimum to the file.
        below = self.check("6.8.0-150-generic", **self.write_table(fragnesia_abi=200))
        at_or_above = self.check(
            "6.8.0-150-generic", **self.write_table(fragnesia_abi=140)
        )

        self.assertEqual(below["WORKER_FRAGNESIA_STATUS"], "fail")
        self.assertEqual(at_or_above["WORKER_FRAGNESIA_STATUS"], "pass")

    def test_collector_supplied_minimum_wins_for_stdin_delivered_checks(self) -> None:
        # The k8s collector pipes the check into a container that cannot see
        # the checkout, so it passes the minimum it already resolved.
        facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="151",
            CLUSTERMAX_MINIMUM_VERSIONS_READER="",
        )

        self.assertEqual(facts["WORKER_FRAGNESIA_ABI_FLOOR"], "151")
        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "fail")

    def test_non_noble_kernel_stays_not_applicable(self) -> None:
        env = self.write_table()

        facts = self.check("5.15.0-100-generic", **env)

        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "not-applicable")


class FragnesiaFailSafeTests(TempDirMixin):
    """An unreadable minimum must report unknown, never a pass."""

    def check(self, kernel: str, **env: str) -> tuple[bashtest.BashRun, dict[str, str]]:
        preamble = (
            "ID=ubuntu\n"
            "VERSION_ID=24.04\n"
            f"WORKER_GUEST_KERNEL_RUNNING={kernel}\n"
        )
        run = bashtest.run_bash(preamble + FRAGNESIA_BLOCK, env=env)
        facts = dict(
            line.split("=", 1) for line in run.stdout.splitlines() if "=" in line
        )
        return run, facts

    def assert_unknown_and_alive(self, run: bashtest.BashRun, facts: dict) -> None:
        self.assertEqual(run.returncode, 0, f"check crashed: {run.stderr}")
        self.assertEqual(facts["WORKER_FRAGNESIA_ABI_FLOOR"], "unknown")
        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "unknown")
        # The observed kernel is still reported, so the finding stays actionable.
        self.assertEqual(facts["WORKER_FRAGNESIA_ABI"], "150")

    def test_missing_table_yields_unknown(self) -> None:
        run, facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_MINIMUM_VERSIONS="/nonexistent/minimum-versions.json",
            CLUSTERMAX_MINIMUM_VERSIONS_READER=str(MINIMUMS_READER),
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="",
        )

        self.assert_unknown_and_alive(run, facts)

    def test_corrupt_table_yields_unknown(self) -> None:
        table = self.write_minimum_table("{ this is not json")

        run, facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_MINIMUM_VERSIONS=str(table),
            CLUSTERMAX_MINIMUM_VERSIONS_READER=str(MINIMUMS_READER),
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="",
        )

        self.assert_unknown_and_alive(run, facts)

    def test_missing_reader_yields_unknown(self) -> None:
        run, facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_MINIMUM_VERSIONS_READER="/nonexistent/minimum_versions.py",
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="",
        )

        self.assert_unknown_and_alive(run, facts)

    def test_removed_key_yields_unknown(self) -> None:
        data = minimum_table()
        del data["components"]["ubuntuNoble"]["packages"]["linuxFragnesia"]["abi"]
        table = self.write_minimum_table(data)

        run, facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_MINIMUM_VERSIONS=str(table),
            CLUSTERMAX_MINIMUM_VERSIONS_READER=str(MINIMUMS_READER),
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="",
        )

        self.assert_unknown_and_alive(run, facts)

    def test_collector_supplied_garbage_minimum_yields_unknown(self) -> None:
        run, facts = self.check(
            "6.8.0-150-generic",
            CLUSTERMAX_FRAGNESIA_ABI_MINIMUM="unknown",
            CLUSTERMAX_MINIMUM_VERSIONS_READER="/nonexistent/minimum_versions.py",
        )

        self.assert_unknown_and_alive(run, facts)


class AdvisoryBlockTests(TempDirMixin):
    """build_security_advisory_json emits the table's values, not literals."""

    def build(self, table: dict | str | None, *args: str) -> str:
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": "/nonexistent/minimum-versions.json"}
        if table is not None:
            env["CLUSTERMAX_MINIMUM_VERSIONS"] = str(self.write_minimum_table(table))
        quoted = " ".join(f"'{arg}'" for arg in args)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\nbuild_security_advisory_json {quoted}\n',
            env=env,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout

    def parse(self, fragment: str) -> dict:
        # The builder emits a run of object members with a trailing comma, so it
        # can be spliced into a "security" object that owns further members.
        # Closing it with a sentinel is how a caller's splice behaves.
        return json.loads("{" + fragment + '"sentinel": true}')

    def test_members_carry_the_table_values(self) -> None:
        table = minimum_table(fragnesia_abi=200, fragnesia_fixed="6.8.0-200.200")

        block = self.parse(self.build(table, "--fragnesia-status", "pass"))

        self.assertEqual(block["fragnesia"]["ubuntuNoblePackageMinimum"], "6.8.0-200.200")
        self.assertEqual(block["fragnesia"]["ubuntuNoblePackageMinimumAbi"], "200")
        self.assertEqual(block["fragnesia"]["cve"], "CVE-2026-46300")
        self.assertEqual(
            block["fragnesia"]["relatedCves"], ["CVE-2026-43284", "CVE-2026-43500"]
        )

    def test_check_results_and_minimums_are_reported_together(self) -> None:
        bulletin_released = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        fix_available = (datetime.now(timezone.utc) - timedelta(days=3)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        block = self.parse(
            self.build(
                minimum_table(
                    fragnesia_released=bulletin_released,
                    fragnesia_available=fix_available,
                ),
                "--fragnesia-status",
                "fail",
                "--fragnesia-compared-abi",
                "200",
                "--januscape-exposed",
                "true",
                "--januscape-status",
                "critical",
            )
        )

        self.assertEqual(block["fragnesia"]["status"], "pass")
        self.assertEqual(block["fragnesia"]["comparedAbiFloor"], "200")
        self.assertEqual(
            block["fragnesia"]["gracePeriod"]["message"],
            "(passes as fix became available within past 3 days)",
        )
        self.assertEqual(
            block["fragnesia"]["gracePeriod"]["fixAvailable"], fix_available
        )
        self.assertIs(block["januscape"]["exposed"], True)
        self.assertEqual(block["januscape"]["status"], "critical")

        unconfirmed = self.parse(
            self.build(
                minimum_table(fragnesia_released=bulletin_released),
                "--fragnesia-status",
                "fail",
            )
        )
        self.assertEqual(unconfirmed["fragnesia"]["status"], "pass")
        self.assertEqual(
            unconfirmed["fragnesia"]["gracePeriod"]["message"],
            "(passes because fixed release availability is not yet confirmed)",
        )

    def test_januscape_carries_the_tracked_ubuntu_status_and_fix(self) -> None:
        # The entry previously recorded that no vendor fix existed for Noble.
        # Both the tracker status and the tracked fix version now come from the
        # table, so a released fix propagates without a code edit.
        pending = self.parse(
            self.build(
                minimum_table(januscape_status="pending", januscape_fixed="6.8.0-137.137")
            )
        )
        released = self.parse(
            self.build(
                minimum_table(januscape_status="released", januscape_fixed="6.8.0-140.140")
            )
        )

        self.assertEqual(pending["januscape"]["ubuntuNobleFixStatus"], "pending")
        self.assertEqual(pending["januscape"]["ubuntuNobleKernelFix"], "6.8.0-137.137")
        self.assertEqual(released["januscape"]["ubuntuNobleFixStatus"], "released")
        self.assertEqual(released["januscape"]["ubuntuNobleKernelFix"], "6.8.0-140.140")

    def test_missing_table_yields_unknown_minimums_not_stale_literals(self) -> None:
        block = self.parse(self.build(None, "--fragnesia-status", "unknown"))

        self.assertEqual(block["fragnesia"]["ubuntuNoblePackageMinimum"], "unknown")
        self.assertEqual(block["fragnesia"]["ubuntuNoblePackageMinimumAbi"], "unknown")
        self.assertEqual(block["fragnesia"]["cve"], "unknown")
        self.assertEqual(block["fragnesia"]["relatedCves"], [])
        self.assertEqual(block["januscape"]["ubuntuNobleKernelFix"], "unknown")
        self.assertEqual(block["januscape"]["ubuntuNobleFixStatus"], "unknown")

    def test_corrupt_table_still_emits_spliceable_json(self) -> None:
        block = self.parse(self.build("{ this is not json"))

        self.assertEqual(block["fragnesia"]["ubuntuNoblePackageMinimum"], "unknown")
        self.assertTrue(block["sentinel"])


class CollectorConvergenceTests(TempDirMixin):
    """The k8s collector and the shared builder must not drift apart again."""

    def test_both_collectors_emit_the_same_advisory_members(self) -> None:
        table = self.write_minimum_table(minimum_table(fragnesia_abi=200))
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": str(table)}

        # Identical check evidence under each collector's own variable names.
        k8s_facts = {
            "HP_FRAGNESIA_STATUS": "fail",
            "HP_FRAGNESIA_ABI_MINIMUM": "200",
            "HP_NESTED_CPU": "true",
            "HP_KVM_DEVICE": "true",
            "HP_NESTED_MODULE": "kvm_amd",
            "HP_NESTED_ENABLED": "1",
            "HP_JANUSCAPE_EXPOSED_JSON": "true",
            "HP_JANUSCAPE_STATUS": "critical",
        }
        shared_facts = {
            "WORKER_FRAGNESIA_STATUS": "fail",
            "WORKER_FRAGNESIA_ABI_FLOOR": "200",
            "WORKER_NESTED_CPU_EXPOSED": "true",
            "WORKER_KVM_DEVICE": "true",
            "WORKER_NESTED_MODULE": "kvm_amd",
            "WORKER_NESTED_ENABLED": "1",
            "januscape_exposed_json": "true",
            "WORKER_JANUSCAPE_STATUS": "critical",
        }

        def assignments(facts: dict[str, str]) -> str:
            return "".join(f"{key}={value}\n" for key, value in facts.items())

        k8s = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            + assignments(k8s_facts)
            + K8S_ADVISORY_CALL
            + '\nprintf "%s\\n" "$SECURITY_ADVISORY_JSON"\n',
            env=env,
        )
        shared = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            + assignments(shared_facts)
            + COMMON_ADVISORY_CALL
            + '\nprintf "%s\\n" "$security_advisory_json"\n',
            env=env,
        )

        self.assertEqual(k8s.returncode, 0, k8s.stderr)
        self.assertEqual(shared.returncode, 0, shared.stderr)
        self.assertEqual(k8s.stdout, shared.stdout)
        members = json.loads("{" + k8s.stdout + '"sentinel": true}')
        self.assertEqual(members["fragnesia"]["ubuntuNoblePackageMinimumAbi"], "200")
        self.assertEqual(members["fragnesia"]["comparedAbiFloor"], "200")
        self.assertEqual(members["januscape"]["ubuntuNobleFixStatus"], "pending")


class K8sCheckDeliveryTests(TempDirMixin):
    """host_check_stdin ships the resolved minimum with the check source."""

    def deliver(self, table: dict | None) -> bashtest.BashRun:
        tmp = self.temp_dir()
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": "/nonexistent/minimum-versions.json"}
        if table is not None:
            path = tmp / "minimum-versions.json"
            path.write_text(json.dumps(table))
            env["CLUSTERMAX_MINIMUM_VERSIONS"] = str(path)

        # Stand in for host-check.sh with its real Fragnesia block, so the whole
        # k8s delivery path (collector resolves the minimum -> pipes it ahead of
        # the check -> check grades with it) executes end to end. The full check
        # is not run because it touches cluster hardware.
        (tmp / "host-check.sh").write_text(
            "ID=ubuntu\nVERSION_ID=24.04\n"
            "WORKER_GUEST_KERNEL_RUNNING=6.8.0-150-generic\n" + FRAGNESIA_BLOCK
        )
        stdin_fn = bashtest.extract_function(K8S_COLLECTOR, "host_check_stdin")
        return bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            # The check must not reach the table by itself here, so the only
            # minimum it can see is the one the collector piped in.
            "unset CLUSTERMAX_MINIMUM_VERSIONS_READER\n"
            f'WORKLOAD_DIR="{tmp}"\n' + stdin_fn + "\nhost_check_stdin | bash\n",
            env=env,
        )

    def test_piped_minimum_grades_the_worker(self) -> None:
        run = self.deliver(minimum_table(fragnesia_abi=200))

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=200", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=fail", run.stdout)

    def test_lower_piped_minimum_passes_the_same_worker(self) -> None:
        run = self.deliver(minimum_table(fragnesia_abi=140))

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=140", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=pass", run.stdout)

    def test_unresolvable_table_pipes_unknown_and_keeps_running(self) -> None:
        run = self.deliver(None)

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=unknown", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=unknown", run.stdout)
        self.assertNotIn("WORKER_FRAGNESIA_STATUS=pass", run.stdout)


class ContainerRecommendationMinimumTests(TempDirMixin):
    """The operational container recommendations come from the same table.

    Both were hardcoded, and the NVIDIA Container Toolkit literal (1.19.0) sat
    below the minimum version the June 2026 bulletin set (1.19.1,
    CVE-2026-24260), so the audit recommended a version its own security check
    fails. The recommendation and the security verdict stay separate checks;
    they now read one minimum.
    """

    RESULT_KEYS = (
        "DOCKER_RECOMMENDED_MIN",
        "DOCKER_VERSION_OK",
        "NVIDIA_CT_RECOMMENDED_MIN",
        "NVIDIA_CT_VERSION_OK",
    )

    def collector(
        self,
        resolve: str,
        gate: str,
        *,
        table: dict | None,
        setup: str,
    ) -> dict[str, str]:
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": "/nonexistent/minimum-versions.json"}
        if table is not None:
            env["CLUSTERMAX_MINIMUM_VERSIONS"] = str(self.write_minimum_table(table))
        report = "".join(f'echo "{key}=${key}"\n' for key in self.RESULT_KEYS)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            'DOCKER_VERSION_OK="false"\nNVIDIA_CT_VERSION_OK="false"\n'
            + resolve
            + setup
            + gate
            + report,
            env=env,
        )
        self.assertEqual(run.returncode, 0, f"collector exited nonzero: {run.stderr}")
        facts = {}
        for line in run.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and key in self.RESULT_KEYS:
                facts[key] = value
        return facts

    def slurm(self, docker: str, nct: str, table: dict | None) -> dict[str, str]:
        setup = f'DOCKER_VERSION="{docker}"\nNVIDIA_CT_VERSION="{nct}"\n'
        return self.collector(SLURM_RESOLVE, SLURM_GATE, table=table, setup=setup)

    def standalone(self, docker: str, nct: str, table: dict | None) -> dict[str, str]:
        setup = f'DOCKER_VERSION="{docker}"\nNCT_VERSION_CMD="{nct}"\n'
        return self.collector(
            STANDALONE_RESOLVE,
            STANDALONE_DOCKER_GATE + STANDALONE_NCT_GATE,
            table=table,
            setup=setup,
        )

    def test_slurm_grades_against_the_table_values(self) -> None:
        table = minimum_table(docker_minimum="40.4.3", nct_minimum="2.19.1")

        at_minimum = self.slurm("40.4.3", "2.19.1", table)
        below = self.slurm("40.4.2", "2.19.0", table)

        self.assertEqual(at_minimum["DOCKER_RECOMMENDED_MIN"], "40.4.3")
        self.assertEqual(at_minimum["NVIDIA_CT_RECOMMENDED_MIN"], "2.19.1")
        self.assertEqual(at_minimum["DOCKER_VERSION_OK"], "true")
        self.assertEqual(at_minimum["NVIDIA_CT_VERSION_OK"], "true")
        self.assertEqual(below["DOCKER_VERSION_OK"], "false")
        self.assertEqual(below["NVIDIA_CT_VERSION_OK"], "false")

    def test_standalone_grades_against_the_table_values(self) -> None:
        table = minimum_table(docker_minimum="40.4.3", nct_minimum="2.19.1")

        at_minimum = self.standalone("40.4.3", "2.19.1", table)
        below = self.standalone("40.4.2", "2.19.0", table)

        self.assertEqual(at_minimum["DOCKER_RECOMMENDED_MIN"], "40.4.3")
        self.assertEqual(at_minimum["NVIDIA_CT_RECOMMENDED_MIN"], "2.19.1")
        self.assertEqual(at_minimum["DOCKER_VERSION_OK"], "true")
        self.assertEqual(at_minimum["NVIDIA_CT_VERSION_OK"], "true")
        self.assertEqual(below["DOCKER_VERSION_OK"], "false")
        self.assertEqual(below["NVIDIA_CT_VERSION_OK"], "false")

    def test_recommendation_moves_with_the_table_not_with_the_script(self) -> None:
        # One observed version, two tables, two verdicts. A restated literal in
        # the test or in the collector cannot produce this.
        strict = self.slurm("29.4.3", "1.19.0", minimum_table(nct_minimum="1.19.1"))
        lenient = self.slurm("29.4.3", "1.19.0", minimum_table(nct_minimum="1.19.0"))

        self.assertEqual(strict["NVIDIA_CT_VERSION_OK"], "false")
        self.assertEqual(lenient["NVIDIA_CT_VERSION_OK"], "true")

    def test_both_collectors_resolve_the_same_recommendations(self) -> None:
        table = minimum_table(docker_minimum="31.0.0", nct_minimum="1.20.0")

        slurm = self.slurm("31.0.0", "1.20.0", table)
        standalone = self.standalone("31.0.0", "1.20.0", table)

        self.assertEqual(
            slurm["DOCKER_RECOMMENDED_MIN"], standalone["DOCKER_RECOMMENDED_MIN"]
        )
        self.assertEqual(
            slurm["NVIDIA_CT_RECOMMENDED_MIN"],
            standalone["NVIDIA_CT_RECOMMENDED_MIN"],
        )
        self.assertEqual(slurm["DOCKER_VERSION_OK"], standalone["DOCKER_VERSION_OK"])

    def test_unreadable_table_reports_unknown_and_never_passes(self) -> None:
        # A very high observed version must still not pass: version_ge() strips
        # non-numeric text, so an "unknown" minimum would otherwise collapse to
        # 0.0.0 and grade every host as meeting a recommendation nobody read.
        for name, result in (
            ("slurm", self.slurm("99.9.9", "99.9.9", None)),
            ("standalone", self.standalone("99.9.9", "99.9.9", None)),
        ):
            with self.subTest(collector=name):
                self.assertEqual(result["DOCKER_RECOMMENDED_MIN"], "unknown")
                self.assertEqual(result["NVIDIA_CT_RECOMMENDED_MIN"], "unknown")
                self.assertEqual(result["DOCKER_VERSION_OK"], "false")
                self.assertEqual(result["NVIDIA_CT_VERSION_OK"], "false")

    def test_corrupt_table_reports_unknown_and_never_passes(self) -> None:
        table = self.write_minimum_table("{ this is not json")
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": str(table)}
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            'DOCKER_VERSION_OK="false"\nNVIDIA_CT_VERSION_OK="false"\n'
            + SLURM_RESOLVE
            + 'DOCKER_VERSION="99.9.9"\nNVIDIA_CT_VERSION="99.9.9"\n'
            + SLURM_GATE
            + 'echo "RESULT=$DOCKER_RECOMMENDED_MIN/$DOCKER_VERSION_OK/'
            '$NVIDIA_CT_RECOMMENDED_MIN/$NVIDIA_CT_VERSION_OK"\n',
            env=env,
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("RESULT=unknown/false/unknown/false", run.stdout)


class DcgmVersionTests(TempDirMixin):
    """DCGM and dcgm-exporter versions (NVIDIA a_id 5857, CVE-2026-47483).

    NVIDIA tags dcgm-exporter as ``<dcgm>-<exporter>-<os>``, confirmed against
    published tags: 4.4.2-4.7.1-ubuntu22.04, 4.4.0-4.5.0-ubuntu22.04,
    4.2.3-4.1.3-ubuntu22.04, 3.3.6-3.4.2-ubuntu22.04. Both components are 4.x
    and the published tags run in both orderings by magnitude, so position is
    the only thing that distinguishes them and a transposition would look
    entirely plausible. The minimums differ (DCGM 4.5.3, exporter 4.8.2), so the
    transposition test below uses an input the two minimums disagree on.
    """

    def helper(self, snippet: str, env: dict[str, str] | None = None) -> str:
        run = bashtest.run_bash(f'source "{AUDIT_COMMON}"\n{snippet}\n', env=env or {})
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip()

    def test_published_tags_split_into_dcgm_then_exporter(self) -> None:
        for tag, expected in (
            ("4.4.2-4.7.1-ubuntu22.04", "4.4.2 4.7.1"),
            ("4.4.0-4.5.0-ubuntu22.04", "4.4.0 4.5.0"),
            ("4.2.3-4.1.3-ubuntu22.04", "4.2.3 4.1.3"),
            ("3.3.6-3.4.2-ubuntu22.04", "3.3.6 3.4.2"),
            ("nvcr.io/nvidia/k8s/dcgm-exporter:4.4.2-4.7.1-ubi9", "4.4.2 4.7.1"),
        ):
            with self.subTest(tag=tag):
                self.assertEqual(
                    self.helper(f'dcgm_versions_from_tag "{tag}"'), expected
                )

    def test_malformed_tags_yield_unknown_for_both(self) -> None:
        for tag in ("latest", "4.4.2-4.7.1", "4.4.2", "", "sha256:abcdef", "4.4-4.7-ubuntu22.04"):
            with self.subTest(tag=tag):
                self.assertEqual(
                    self.helper(f'dcgm_versions_from_tag "{tag}"'), "unknown unknown"
                )

    def evaluate_tag(self, tag: str) -> dict:
        # Runs the real collector path, so a transposition anywhere between the
        # tag and the evaluator fails this test.
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            f'DCGM_EXPORTER_IMAGE="{tag}"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n',
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_a_transposed_pair_would_fail_this_test(self) -> None:
        # DCGM minimum 4.5.3, exporter minimum 4.8.2. This tag is DCGM 4.6.0 (above
        # its minimum) and exporter 4.6.0 (below its minimum), so reading the fields
        # in the wrong order flips both verdicts.
        verdicts = self.evaluate_tag("4.6.0-4.6.0-ubuntu22.04")

        self.assertEqual(verdicts["dcgm"]["version"], "4.6.0")
        self.assertEqual(verdicts["dcgm"]["minimum"], "4.5.3")
        self.assertEqual(verdicts["dcgm"]["status"], "pass")
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.6.0")
        self.assertEqual(verdicts["dcgmExporter"]["minimum"], "4.8.2")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "fail")

    def test_distinct_versions_land_on_their_own_component(self) -> None:
        verdicts = self.evaluate_tag("4.4.2-4.9.9-ubuntu22.04")

        self.assertEqual(verdicts["dcgm"]["version"], "4.4.2")
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.9.9")

    def test_malformed_tag_grades_both_unknown(self) -> None:
        verdicts = self.evaluate_tag("latest")

        self.assertEqual(verdicts["dcgm"]["status"], "unknown")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "unknown")
        self.assertNotEqual(verdicts["dcgm"]["status"], "pass")
        self.assertNotEqual(verdicts["dcgmExporter"]["status"], "pass")

    def test_absent_exporter_is_not_applicable_not_unknown(self) -> None:
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            'DCGM_EXPORTER_IMAGE=""\nDCGM_EXPORTER_PRESENT="false"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n',
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        verdicts = json.loads(run.stdout)

        self.assertEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_undiscoverable_exporter_is_unknown_not_not_applicable(self) -> None:
        # With no DCGM_EXPORTER_PRESENT set, which is the Slurm collector's
        # state, the audit must not claim an absence it did not observe. The
        # Slurm scan reads head-node sockets and head-node systemd, while the
        # exporter normally runs on the workers, so a negative proves nothing
        # about the fleet. The standalone collector is the opposite case and is
        # covered by StandaloneExporterDiscoveryTests below.
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n',
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        verdicts = json.loads(run.stdout)

        self.assertEqual(verdicts["dcgmExporter"]["status"], "unknown")
        self.assertNotEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_dcgm_version_comes_from_the_existing_host_check_parse(self) -> None:
        # host-check.sh owns the `dcgmi --version` parse; this reads its
        # WORKER_DCGM_VERSION line rather than adding a second parser.
        self.assertEqual(
            self.helper("dcgm_version_from_check 'WORKER_DCGM_VERSION=dcgmi  version: 4.6.0'"),
            "4.6.0",
        )
        self.assertEqual(
            self.helper("dcgm_version_from_check 'WORKER_DCGM_VERSION=not-found'"),
            "not-installed",
        )
        self.assertEqual(self.helper("dcgm_version_from_check ''"), "unknown")

    def evaluate_check_and_tag(self, check_output: str, image: str = "", present: str = "") -> dict:
        env_prefix = ""
        if image:
            env_prefix += f'DCGM_EXPORTER_IMAGE="{image}"\n'
        if present:
            env_prefix += f'DCGM_EXPORTER_PRESENT="{present}"\n'
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            + env_prefix
            + f'build_security_version_audit "{check_output}" 580.159.03 1.19.1 '
            "1.3.6 29.4.3 nvidia 13.1\n"
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_gpu_operator_host_without_dcgmi_is_graded_from_the_tag(self) -> None:
        """The defect this fallback exists for.

        On a GPU Operator cluster DCGM runs in containers and the host has no
        dcgmi, so host-check.sh emits WORKER_DCGM_VERSION=not-found. Gating the
        tag fallback on "unknown" alone meant it never fired on exactly those
        hosts: a node whose exporter tag proves DCGM 4.5.0 is deployed, below
        the 4.5.3 minimum for CVE-2026-47483, graded not_applicable with a detail
        saying DCGM was not installed on the inspected host.
        """
        verdicts = self.evaluate_check_and_tag(
            "WORKER_DCGM_VERSION=not-found", image="4.5.0-4.8.2-ubuntu22.04"
        )

        self.assertEqual(verdicts["dcgm"]["version"], "4.5.0")
        self.assertEqual(verdicts["dcgm"]["status"], "fail")
        self.assertNotEqual(verdicts["dcgm"]["status"], "not_applicable")
        # The exporter half of the same tag is unaffected and still passes.
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.8.2")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "pass")

    def test_genuine_absence_stays_not_applicable(self) -> None:
        # No dcgmi and no exporter image is real absence, not missing evidence.
        # This case must not drift to unknown: most clusters have no DCGM and a
        # permanent warning on all of them would train reviewers to ignore it.
        verdicts = self.evaluate_check_and_tag(
            "WORKER_DCGM_VERSION=not-found", present="false"
        )

        self.assertEqual(verdicts["dcgm"]["status"], "not_applicable")
        self.assertEqual(verdicts["dcgm"]["version"], "not-installed")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_a_deployed_exporter_with_an_unreadable_tag_is_unknown(self) -> None:
        # The image proves DCGM is deployed here, so an unreadable version is a
        # warning. Falling back to not-installed would be a clean verdict for a
        # component we know is running.
        verdicts = self.evaluate_check_and_tag(
            "WORKER_DCGM_VERSION=not-found", image="latest"
        )

        self.assertEqual(verdicts["dcgm"]["status"], "unknown")
        self.assertNotEqual(verdicts["dcgm"]["status"], "not_applicable")
        self.assertNotEqual(verdicts["dcgm"]["status"], "pass")

    def test_host_check_dcgm_version_wins_over_the_image_tag(self) -> None:
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            'DCGM_EXPORTER_IMAGE="4.4.2-4.7.1-ubuntu22.04"\n'
            'build_security_version_audit "WORKER_DCGM_VERSION=dcgmi  version: 4.6.0" '
            '580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n',
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        verdicts = json.loads(run.stdout)

        # The running host engine, not the version the exporter was built against.
        self.assertEqual(verdicts["dcgm"]["version"], "4.6.0")
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.7.1")


class SecurityGpuVendorGateTests(unittest.TestCase):
    """The vendor handed to the minimum versions must depend on the vendor alone.

    `build_security_version_audit`'s 6th positional argument decides whether the
    NVIDIA driver minimums apply at all. Both the slurm and standalone collectors
    used to require `DRIVER_VERSION == unknown` as well as `AMD_GPUS_PRESENT`,
    which made the gate depend on the AMD driver promotion *not* existing on
    those two harnesses. cluster-audit-k8s.sh:2655 already promotes the amdgpu
    version into the vendor-neutral gpus.driverVersion field (42 committed
    records carry amdgpu 6.16.13 from oracle-mi355x that way), so porting that
    block to slurm or standalone for AMD parity would have silently flipped an
    AMD cluster back to "nvidia".

    Standalone was the worse case: it passes DRIVER_VERSION itself as the
    security driver version, so the promoted amdgpu version would have been
    graded directly against NVIDIA's driver minimums.

    This class is the coverage that was missing. test_audit_common.py never
    passed a 6th positional argument, so the derivation had no executable test
    at all and both bugs survived.
    """

    GATES = (("slurm", SLURM_VENDOR_GATE), ("standalone", STANDALONE_VENDOR_GATE))
    # The real amdgpu version on oracle-mi355x, as committed.
    AMD_DRIVER_VERSION = "6.16.13"

    def vendor(self, gate: str, **variables: str) -> str:
        assignments = "".join(f'{key}="{value}"\n' for key, value in variables.items())
        run = bashtest.run_bash(
            assignments + gate + 'printf "%s\\n" "$SECURITY_GPU_VENDOR"\n'
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip()

    def test_amd_driver_promotion_does_not_flip_the_gate_back_to_nvidia(self) -> None:
        # The regression guard. Before the fix this returned "nvidia" on both
        # collectors, because a promoted DRIVER_VERSION defeated the gate.
        for name, gate in self.GATES:
            with self.subTest(collector=name):
                self.assertEqual(
                    self.vendor(
                        gate,
                        AMD_GPUS_PRESENT="true",
                        DRIVER_VERSION=self.AMD_DRIVER_VERSION,
                    ),
                    "amd",
                )

    def test_amd_without_a_promoted_driver_still_gates_amd(self) -> None:
        for name, gate in self.GATES:
            with self.subTest(collector=name):
                self.assertEqual(
                    self.vendor(gate, AMD_GPUS_PRESENT="true", DRIVER_VERSION="unknown"),
                    "amd",
                )

    def test_amd_with_no_driver_variable_at_all_gates_amd(self) -> None:
        for name, gate in self.GATES:
            with self.subTest(collector=name):
                self.assertEqual(self.vendor(gate, AMD_GPUS_PRESENT="true"), "amd")

    def test_nvidia_host_gates_nvidia(self) -> None:
        for name, gate in self.GATES:
            with self.subTest(collector=name):
                self.assertEqual(
                    self.vendor(
                        gate, AMD_GPUS_PRESENT="false", DRIVER_VERSION="580.159.03"
                    ),
                    "nvidia",
                )

    def test_gate_defaults_to_nvidia_when_nothing_is_set(self) -> None:
        for name, gate in self.GATES:
            with self.subTest(collector=name):
                self.assertEqual(self.vendor(gate), "nvidia")

    def test_the_gate_decides_whether_nvidia_minimums_apply(self) -> None:
        """Why the gate matters: the same version grades differently by vendor.

        Executed through the real evaluator, so this fails if the vendor stops
        reaching it, and it fires for any change that stops the gate being reached.
        """
        verdicts = {}
        for name, gate in self.GATES:
            run = bashtest.run_bash(
                f'source "{AUDIT_COMMON}"\n'
                f'WORKLOAD_DIR="{WORKLOAD}"\n'
                'AMD_GPUS_PRESENT="true"\n'
                f'DRIVER_VERSION="{self.AMD_DRIVER_VERSION}"\n'
                + gate
                + 'build_security_version_audit "" "$DRIVER_VERSION" unknown unknown '
                'unknown "$SECURITY_GPU_VENDOR"\n'
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            verdicts[name] = json.loads(run.stdout)["nvidiaDriver"]

        for name, verdict in verdicts.items():
            with self.subTest(collector=name):
                self.assertEqual(verdict["status"], "not_applicable")
                self.assertIn("amd", verdict["detail"].lower())

        # The same amdgpu version under the NVIDIA vendor is not dismissed, so
        # the gate is load-bearing rather than cosmetic.
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            f'build_security_version_audit "" "{self.AMD_DRIVER_VERSION}" unknown '
            "unknown unknown nvidia\n"
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        mislabelled = json.loads(run.stdout)["nvidiaDriver"]
        self.assertNotEqual(mislabelled["status"], "not_applicable")


class VirtioNetCheckStderrTests(TempDirMixin):
    """virtio_net_check_facts must relay the check's warnings to the operator.

    The check writes one WARNING line per problem to stderr, including the
    fan-out degradation notice that says it could not reach part of the fleet.
    That notice exists nowhere else on a live run: the text survives in
    virtioNetReason in the values file, but an operator watching the audit would
    see nothing. The reviewer's critical finding was a partial fan-out reporting
    a fleet-wide clean answer, and this was the line throwing away the one
    signal that would have tipped an operator off.

    This matches run_checks.py, which relays every audit check's stderr verbatim
    and treats a non-zero exit as "no data" rather than a failed run. Two
    properties are load-bearing and are asserted separately: the relayed stderr
    must not corrupt the JSON parsed from stdout, and a noisy or failing check
    must not fail the audit.

    (Check-internal behavior is covered in test_virtio_net_check.py; this file
    covers the audit-common.sh collector wiring.)
    """

    REPORT = (
        'printf "%s|%s|%s\\n" "$VIRTIO_NET_VERSION" "$VIRTIO_NET_STATE" "$VIRTIO_NET_MODE"\n'
    )

    PAYLOAD = '{"virtioNet": "24.10.17", "state": "version", "virtioNetMode": "dpu"}'

    def collector(self, check_body: str) -> bashtest.BashRun:
        """Run the real shell function against a stand-in check.

        The stand-in is genuine Python, so the collector's real
        `python3 <check> --summary` invocation is exercised and the second
        python3 call that parses the payload is left alone.
        """
        workload = self.temp_dir()
        check_dir = workload / "checks" / "fabric"
        check_dir.mkdir(parents=True)
        check = check_dir / "virtio-net-check.py"
        check.write_text("import sys\n" + check_body)
        check.chmod(0o755)
        return bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{workload}"\n'
            "virtio_net_check_facts\n"
            'echo "RC=$?"\n' + self.REPORT,
        )

    def emit(self, *stderr_lines: str, stdout: str | None = None, exit_code: int = 0) -> str:
        body = "".join(
            f'print({line!r}, file=sys.stderr)\n' for line in stderr_lines
        )
        if stdout is not None:
            body += f"print({stdout!r})\n"
        if exit_code:
            body += f"sys.exit({exit_code})\n"
        return body

    def test_check_warnings_reach_the_operator(self) -> None:
        run = self.collector(
            self.emit(
                "  WARNING: virtio_net_bluefield: reached 2 of 9 hosts",
                stdout=self.PAYLOAD,
            )
        )

        self.assertIn("reached 2 of 9 hosts", run.stderr)

    def test_relayed_stderr_does_not_corrupt_the_parsed_json(self) -> None:
        # Command substitution captures fd 1 only. If stderr were merged into
        # stdout the payload would not parse and every value would fall back.
        run = self.collector(
            self.emit(
                "  WARNING: virtio_net_bluefield: noisy line one",
                "  WARNING: virtio_net_bluefield: noisy line two",
                stdout=self.PAYLOAD,
            )
        )

        self.assertIn("noisy line one", run.stderr)
        self.assertIn("24.10.17|version|dpu", run.stdout)

    def test_a_noisy_check_does_not_fail_the_audit(self) -> None:
        run = self.collector(
            "for i in range(200):\n"
            '    print("  WARNING: line %d" % i, file=sys.stderr)\n'
            f"print({self.PAYLOAD!r})\n"
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("RC=0", run.stdout)
        self.assertIn("24.10.17|version|dpu", run.stdout)

    def test_a_failing_check_warns_but_keeps_the_audit_running(self) -> None:
        run = self.collector(
            self.emit(
                "  WARNING: virtio_net_bluefield: check blew up", exit_code=3
            )
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("RC=0", run.stdout)
        self.assertIn("check blew up", run.stderr)
        # Fail-safe values survive: never a version, never "not-installed".
        self.assertIn("unknown|incomplete|", run.stdout)
        self.assertNotIn("not-installed", run.stdout)


class VirtioNetWorstObservedWiringTests(TempDirMixin):
    """A host proven below the minimum must not be softened by an unreadable host.

    The cluster rollup takes the worst *state*, so a fleet where one node reads
    a below-minimum controller version and another node cannot be reached rolls up
    to "unknown", which grades as a warning. The virtioNetWorstObserved* group
    and virtioNetObservedJson carry the per-host reading past that rollup so the
    proven finding grades as "fail", which is critical.

    These tests drive the real build_security_version_audit against a stand-in
    check, so they cover the whole path: check --summary output, the shell key
    read, argument construction, and the evaluator's verdict.
    """

    BELOW_MINIMUM = "24.10.17"  # LTS24 is fixed at 24.10.50.
    OBSERVED = [
        {"host": "worker-3", "version": "24.10.17", "line": "LTS24", "mode": "dpu"}
    ]

    def workload(self, summary: dict) -> Path:
        """A workload dir with the real evaluator and a stand-in check."""
        root = self.temp_dir() / "workload"
        root.mkdir()
        # Symlinks, so the evaluator resolves its own sibling minimum table
        # through __file__.resolve() and grades against the real minimums.
        for real in WORKLOAD.iterdir():
            if real.is_file():
                (root / real.name).symlink_to(real)
        check_dir = root / "checks" / "fabric"
        check_dir.mkdir(parents=True)
        check = check_dir / "virtio-net-check.py"
        check.write_text(
            "import json, sys\nprint(json.dumps(" + repr(summary) + "))\n"
        )
        check.chmod(0o755)
        return root

    def evaluate(self, summary: dict) -> dict:
        root = self.workload(summary)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{root}"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n'
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)["virtioNetBluefield"]

    def summary(self, **overrides) -> dict:
        base = {
            "virtioNet": "unknown",
            "virtioNetLine": None,
            "virtioNetMode": "dpu",
            "virtioNetSource": None,
            "virtioNetReason": "one host could not be reached",
            "dpuIsolationJson": "{}",
            "state": "unknown",
            "virtioNetWorstObserved": "",
            "virtioNetWorstObservedLine": None,
            "virtioNetWorstObservedMode": "unknown",
            "virtioNetWorstObservedHost": "",
            "virtioNetObservedJson": "[]",
        }
        base.update(overrides)
        return base

    def test_a_proven_host_makes_an_unknown_rollup_fail(self) -> None:
        """The assertion this whole wiring exists for.

        One host read 24.10.17 (below the LTS24 minimum of 24.10.50) while the
        cluster rollup is "unknown" because another host was unreachable.
        Without the wiring this reports "unknown", a warning, and a machine we
        proved is vulnerable gets softened by a machine we could not read.
        """
        verdict = self.evaluate(
            self.summary(
                virtioNetWorstObserved=self.BELOW_MINIMUM,
                virtioNetWorstObservedLine="LTS24",
                virtioNetWorstObservedMode="dpu",
                virtioNetWorstObservedHost="worker-3",
                virtioNetObservedJson=json.dumps(self.OBSERVED),
            )
        )

        self.assertEqual(verdict["status"], "fail")
        self.assertNotEqual(verdict["status"], "unknown")
        self.assertEqual(verdict["exposure"], "live")

    def test_without_a_proven_host_the_rollup_still_decides(self) -> None:
        # Absence of a worst-observed reading must leave today's behavior
        # untouched: an unresolved fleet stays unknown, never a pass.
        verdict = self.evaluate(self.summary())

        self.assertEqual(verdict["status"], "unknown")
        self.assertNotEqual(verdict["status"], "pass")

    def test_a_json_array_survives_the_shell_intact(self) -> None:
        # The readings carry spaces, quotes and brackets. If the array were
        # unquoted it would split the argument list and the readings would be
        # lost, silently dropping the proven finding.
        observed = [
            {
                "host": "worker 3 [rack A]",
                "version": self.BELOW_MINIMUM,
                "line": "LTS24",
                "mode": "dpu",
                "note": 'reading "confirmed" twice',
            }
        ]
        verdict = self.evaluate(
            self.summary(virtioNetObservedJson=json.dumps(observed))
        )

        self.assertEqual(verdict["status"], "fail")
        self.assertEqual(verdict["observedControllers"], 1)

    def test_malformed_observed_json_does_not_become_a_pass(self) -> None:
        verdict = self.evaluate(
            self.summary(virtioNetObservedJson='[{"host": "worker-3", ')
        )

        self.assertNotEqual(verdict["status"], "pass")
        self.assertEqual(verdict["status"], "unknown")

    def test_a_complete_rollup_reports_complete_coverage(self) -> None:
        # --virtio-net-state is what tells the evaluator coverage was complete.
        # Omitting it can only weaken a clean reading, never a proven failure,
        # but it must be sent so a fully-resolved fleet is not reported as
        # partially assessed.
        verdict = self.evaluate(
            self.summary(
                virtioNet="24.10.50",
                virtioNetLine="LTS24",
                state="version",
                virtioNetWorstObserved="24.10.50",
                virtioNetWorstObservedLine="LTS24",
                virtioNetWorstObservedMode="dpu",
                virtioNetWorstObservedHost="worker-1",
                virtioNetObservedJson=json.dumps(
                    [{"host": "worker-1", "version": "24.10.50", "line": "LTS24", "mode": "dpu"}]
                ),
            )
        )

        self.assertEqual(verdict["status"], "pass")


class VirtioNetEvaluatorFlagContractTests(TempDirMixin):
    """Pin the exact flag spellings the collector emits.

    The evaluator half is written by another agent, so the two halves are only
    connected by these strings. A rename on either side would otherwise show up
    as a silently ignored argument rather than a failure.
    """

    def emitted_args(self, summary: dict) -> list[str]:
        root = self.temp_dir() / "workload"
        root.mkdir()
        # A stand-in evaluator that dumps its own argv, so this records what the
        # collector actually sends rather than what it appears to send.
        (root / "security_version_audit.py").write_text(
            "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
        )
        check_dir = root / "checks" / "fabric"
        check_dir.mkdir(parents=True)
        check = check_dir / "virtio-net-check.py"
        check.write_text("import json, sys\nprint(json.dumps(" + repr(summary) + "))\n")
        check.chmod(0o755)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{root}"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n'
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)["argv"]

    def test_every_virtio_net_flag_is_emitted_with_its_value(self) -> None:
        argv = self.emitted_args(
            {
                "virtioNet": "24.10.17",
                "virtioNetLine": "LTS24",
                "virtioNetMode": "dpu",
                "virtioNetSource": "virtnet-version",
                "virtioNetReason": "one host unreachable",
                "dpuIsolationJson": '{"scanComplete": true}',
                "state": "unknown",
                "virtioNetWorstObserved": "24.10.17",
                "virtioNetWorstObservedLine": "LTS24",
                "virtioNetWorstObservedMode": "dpu",
                "virtioNetWorstObservedHost": "worker-3",
                "virtioNetObservedJson": '[{"host": "worker-3"}]',
            }
        )

        pairs = dict(zip(argv[::2], argv[1::2]))
        self.assertEqual(pairs["--virtio-net"], "24.10.17")
        self.assertEqual(pairs["--virtio-net-line"], "LTS24")
        self.assertEqual(pairs["--virtio-net-mode"], "dpu")
        self.assertEqual(pairs["--virtio-net-source"], "virtnet-version")
        self.assertEqual(pairs["--virtio-net-reason"], "one host unreachable")
        self.assertEqual(pairs["--virtio-net-state"], "unknown")
        self.assertEqual(pairs["--virtio-net-worst"], "24.10.17")
        self.assertEqual(pairs["--virtio-net-worst-line"], "LTS24")
        self.assertEqual(pairs["--virtio-net-worst-mode"], "dpu")
        self.assertEqual(pairs["--virtio-net-worst-host"], "worker-3")
        self.assertEqual(pairs["--virtio-net-observed-json"], '[{"host": "worker-3"}]')
        self.assertEqual(pairs["--dpu-isolation-json"], '{"scanComplete": true}')

    def test_the_json_array_arrives_as_one_argument(self) -> None:
        payload = '[{"host": "worker 3 [rack A]", "note": "a b c"}]'
        argv = self.emitted_args(
            {
                "virtioNet": "unknown",
                "state": "unknown",
                "virtioNetObservedJson": payload,
            }
        )

        self.assertIn(payload, argv)
        self.assertEqual(argv[argv.index("--virtio-net-observed-json") + 1], payload)

    def test_every_emitted_flag_is_one_the_evaluator_accepts(self) -> None:
        # Catches a flag renamed on either half, in either direction.
        argv = self.emitted_args(
            {
                "virtioNet": "24.10.17",
                "state": "version",
                "virtioNetWorstObserved": "24.10.17",
                "virtioNetWorstObservedLine": "LTS24",
                "virtioNetWorstObservedMode": "dpu",
                "virtioNetWorstObservedHost": "worker-3",
                "virtioNetObservedJson": "[]",
                "dpuIsolationJson": "{}",
            }
        )
        emitted = {arg for arg in argv if arg.startswith("--")}
        self.assertTrue(emitted, "the collector emitted no flags at all")

        # Hand the collector's own argv to the real evaluator. Scanning its
        # source for quoted "--flag" strings tested a copy of the interface;
        # argparse is the interface, and it rejects an unknown flag with exit 2.
        proc = subprocess.run(
            [sys.executable, str(WORKLOAD / "security_version_audit.py"), *argv],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"the evaluator rejected a flag the collector emits:\n{proc.stderr}",
        )
        # It parsed them and produced the record, rather than exiting 0 early.
        self.assertIn("virtioNetBluefield", json.loads(proc.stdout))


class DegradedSecurityAuditFallbackTests(TempDirMixin):
    """A degraded audit must report every component, not fall silent on some.

    When security_version_audit.py or python3 is unavailable,
    build_security_version_audit prints a hardcoded fallback object. Every rule
    in audit_findings.py matches on a status value and skips an absent key, so
    a component missing from that object produces no finding at all: silence,
    not an unknown. A degraded audit is exactly when an operator most needs to
    know which checks did not run.

    The fallback listed only the original six components, so dcgm, dcgmExporter,
    virtioNetBluefield, and dpuHostIsolation reported nothing on a degraded run.

    The expected set is derived from the real evaluator rather than restated
    here, so a component added to the evaluator fails this test until the
    fallback carries it too.
    """

    def evaluator_components(self) -> set[str]:
        """Component names the real evaluator emits, by their status field.

        floorsMetadata is provenance rather than a component and carries no
        status, so keying on the status field selects exactly the components
        without naming any of them.
        """
        result = subprocess.run(
            [sys.executable, str(WORKLOAD / "security_version_audit.py")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        verdicts = json.loads(result.stdout)
        components = {
            name
            for name, value in verdicts.items()
            if isinstance(value, dict) and "status" in value
        }
        self.assertTrue(components, "the evaluator emitted no components")
        return components

    def fallback(self, *, remove_policy: bool, args: str = '""') -> dict:
        """Drive the real degraded path with the policy script absent."""
        workload = self.temp_dir() / "workload"
        workload.mkdir()
        for real in WORKLOAD.iterdir():
            if real.is_file() and not (
                remove_policy and real.name == "security_version_audit.py"
            ):
                (workload / real.name).symlink_to(real)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{workload}"\n'
            f"build_security_version_audit {args}\n"
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_missing_policy_script_reports_every_component_as_unknown(self) -> None:
        verdicts = self.fallback(remove_policy=True)

        self.assertEqual(set(verdicts), self.evaluator_components())
        for name, verdict in sorted(verdicts.items()):
            with self.subTest(component=name):
                self.assertEqual(verdict["status"], "unknown")

    def test_the_degraded_fallback_is_actually_being_exercised(self) -> None:
        # Guards the test itself: if the policy script were still reachable the
        # assertions above would be checking the real evaluator, not the
        # fallback, and would pass no matter what the fallback contained.
        def statuses(verdicts: dict) -> list[tuple[str, str]]:
            return sorted(
                (name, value["status"])
                for name, value in verdicts.items()
                if isinstance(value, dict) and "status" in value
            )

        # Real versions, so the healthy evaluator grades something as pass. With
        # empty inputs it legitimately returns all-unknown too, which would make
        # the two paths indistinguishable and this guard vacuous.
        graded = '"" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1'
        degraded = self.fallback(remove_policy=True, args=graded)
        healthy = self.fallback(remove_policy=False, args=graded)

        self.assertTrue(all(v["status"] == "unknown" for v in degraded.values()))
        self.assertIn("pass", [status for _, status in statuses(healthy)])
        self.assertNotEqual(statuses(degraded), statuses(healthy))
        # The healthy run also carries provenance the fallback cannot produce.
        self.assertIn("floorsMetadata", healthy)
        self.assertNotIn("floorsMetadata", degraded)

    def test_no_component_falls_silent_on_a_degraded_audit(self) -> None:
        # The incident in one assertion: audit_findings.py skips absent keys, so
        # a component missing here reports nothing at all rather than unknown.
        verdicts = self.fallback(remove_policy=True)

        self.assertEqual(self.evaluator_components() - set(verdicts), set())


class VersionMinimumGuardTests(unittest.TestCase):
    """version_meets_minimum refuses to grade against an unresolved minimum."""

    def guard(self, observed: str, minimum: str) -> int:
        return bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'version_meets_minimum "{observed}" "{minimum}"\n'
        ).returncode

    def test_grades_normally_when_both_sides_are_known(self) -> None:
        self.assertEqual(self.guard("1.19.1", "1.19.1"), 0)
        self.assertEqual(self.guard("1.19.2", "1.19.1"), 0)
        self.assertNotEqual(self.guard("1.19.0", "1.19.1"), 0)

    def test_refuses_an_unknown_minimum(self) -> None:
        # version_ge would pass here, because it strips "unknown" to 0.0.0.
        self.assertEqual(
            bashtest.run_bash(
                f'source "{AUDIT_COMMON}"\nversion_ge "99.9.9" "unknown"\n'
            ).returncode,
            0,
        )
        self.assertNotEqual(self.guard("99.9.9", "unknown"), 0)

    def test_refuses_an_unknown_observed_version(self) -> None:
        self.assertNotEqual(self.guard("unknown", "1.19.1"), 0)
        self.assertNotEqual(self.guard("", "1.19.1"), 0)


class StandaloneExporterDiscoveryTests(unittest.TestCase):
    """The standalone host is the whole fleet, so a negative scan proves absence.

    The monitoring-stack scan reads this machine's listening sockets and its
    systemd units, and a standalone audit has no other node the exporter could
    be running on. Grading that "unknown" made every exporter-free standalone
    run raise a "requires provider attestation" finding that no operator can
    answer, because there is nothing left to attest.

    This runs the collector's own wiring line rather than asserting on its
    source, so a rename of either variable fails here.
    """

    WIRING = bashtest.extract_block(
        STANDALONE_COLLECTOR,
        "DCGM_EXPORTER_PRESENT=",
        "DCGM_EXPORTER_PRESENT=",
    )

    def evaluate(self, detected: str) -> dict:
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            f'DCGM_EXPORTER_DETECTED="{detected}"\n'
            f"{self.WIRING}\n"
            "build_security_version_audit '' 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n",
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_a_completed_scan_that_found_none_reports_absence(self) -> None:
        verdicts = self.evaluate("false")

        self.assertEqual(verdicts["dcgmExporter"]["status"], "not_applicable")
        self.assertNotEqual(verdicts["dcgmExporter"]["status"], "unknown")

    def test_a_found_exporter_does_not_become_an_absence(self) -> None:
        # "true" is not a version, so the verdict stays unknown. What it must
        # never do is claim the exporter is absent on a host that has one.
        verdicts = self.evaluate("true")

        self.assertNotEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_an_unset_detection_stays_unknown(self) -> None:
        # Defensive: if the scan never ran, the wiring must not invent absence.
        verdicts = self.evaluate("unknown")

        self.assertEqual(verdicts["dcgmExporter"]["status"], "unknown")


class StandaloneExporterProcessDetectionTests(unittest.TestCase):
    """A containerized exporter must not read as absence.

    On standalone this flag decides between "not-installed" and "unknown", so a
    detection miss is a clean grade for a host that is running an exporter. A
    compose monitoring stack puts Prometheus and dcgm-exporter on one bridge
    network: the exporter is scraped over that network, publishes no host port,
    and has no systemd unit, so the socket and systemd checks both miss it. The
    audit runs in the host PID view, so procfs sees the container process.

    This executes the collector's real detection block with stubbed `ss`,
    `systemctl`, and `pgrep`, so it fails if the fallback is removed.
    """

    BLOCK = bashtest.extract_block(
        STANDALONE_COLLECTOR,
        'DCGM_EXPORTER_DETECTED="false"',
        'if pgrep -x dcgm-exporter',
    )

    def detect(self, *, listening: str, systemd_ok: bool, pgrep_ok: bool) -> str:
        # The collector pipes this through `awk 'NR>1 {print $4}'`, so the stub
        # emits the real shape: a header row, then a row whose fourth field is
        # the local address. A bare address line is dropped as the header.
        table = (
            'echo "State Recv-Q Send-Q Local-Address Peer-Address"; '
            f'echo "LISTEN 0 4096 {listening} 0.0.0.0:*"'
        )
        stubs = {
            "ss": table,
            "netstat": table,
            "systemctl": "exit 0" if systemd_ok else "exit 1",
            "pgrep": "exit 0" if pgrep_ok else "exit 1",
        }
        run = bashtest.run_bash(
            "print_section() { :; }\nprint_info() { :; }\nprint_detail() { :; }\n"
            "collect_monitoring_evidence() { :; }\n"
            f"{self.BLOCK}\n"
            'printf "%s" "$DCGM_EXPORTER_DETECTED"\n',
            stubs=stubs,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip()

    def test_a_process_only_exporter_is_detected(self) -> None:
        # The compose shape: no host port, no unit, process visible in procfs.
        self.assertEqual(
            self.detect(listening="127.0.0.1:22", systemd_ok=False, pgrep_ok=True),
            "true",
        )

    def test_a_host_with_no_exporter_anywhere_stays_false(self) -> None:
        self.assertEqual(
            self.detect(listening="127.0.0.1:22", systemd_ok=False, pgrep_ok=False),
            "false",
        )

    def test_a_published_port_is_still_detected(self) -> None:
        self.assertEqual(
            self.detect(listening="0.0.0.0:9400", systemd_ok=False, pgrep_ok=False),
            "true",
        )


if __name__ == "__main__":
    unittest.main()
