#!/usr/bin/env python3
"""Execute real collector blocks against synthetic minimum tables and fail-safe inputs."""

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

FRAGNESIA_BLOCK = bashtest.extract_block(
    HOST_CHECK,
    "# Ubuntu's CVE-2026-46300 (Fragnesia) Noble 6.8 fixed package carries a minimum",
    'echo "WORKER_FRAGNESIA_STATUS=${WORKER_FRAGNESIA_STATUS}"',
)
UBUNTU_KERNEL_BLOCK = bashtest.extract_block(
    HOST_CHECK,
    "# The package-wide Ubuntu Noble kernel floor is derived from every matching",
    'echo "WORKER_UBUNTU_KERNEL_MINIMUM_STATUS=${WORKER_UBUNTU_KERNEL_MINIMUM_STATUS}"',
)

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

# Close the if-block because extract_block stops inside it.
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
# The gate supplies the evaluator's sixth positional argument.
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

    def virtio_workload(self, summary: dict, *, stub_evaluator: bool = False) -> Path:
        root = self.temp_dir() / "workload"
        root.mkdir()
        if stub_evaluator:
            (root / "security_version_audit.py").write_text(
                "import json, sys\nprint(json.dumps({'argv': sys.argv[1:]}))\n"
            )
        else:
            # Resolve the real evaluator's sibling reader and policy table.
            for name in (
                "security_version_audit.py",
                "minimum_versions.py",
                "minimum-versions.json",
            ):
                (root / name).symlink_to(WORKLOAD / name)
        check_dir = root / "checks" / "fabric"
        check_dir.mkdir(parents=True)
        (check_dir / "virtio-net-check.py").write_text(
            "import json\nprint(json.dumps(" + repr(summary) + "))\n"
        )
        return root


def fragnesia_check(
    kernel: str, **env: str
) -> tuple[bashtest.BashRun, dict[str, str]]:
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


def minimum_table(
    *,
    linux_abi: int = 210,
    linux_fixed: str = "6.8.0-210.210",
    linux_status: str = "released",
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
                    "linuxOpenvswitchNestedActions": {
                        "abi": 138,
                        "allowUnfixed": True,
                        "cve": "CVE-2026-64531",
                        "fixed": "6.8.0-138.138",
                        "package": "linux",
                        "status": "released",
                    },
                    "linuxCgroupWriteback": {
                        "allowUnfixed": True,
                        "cve": "CVE-2026-64378",
                        "package": "linux",
                        "status": "needed",
                    },
                    "linuxSctpSendall": {
                        "abi": 136,
                        "allowUnfixed": True,
                        "cve": "CVE-2026-46227",
                        "fixed": "6.8.0-136.136",
                        "package": "linux",
                        "status": "released",
                    },
                    # Neutral here; CVE-2026-98432 tests set their own state.
                    "linuxIpv4InetOptUaf": {
                        "allowUnfixed": True,
                        "cve": "CVE-2026-98432",
                        "package": "linux",
                        "status": "not-affected",
                    },
                    "linux": {
                        "abi": linux_abi,
                        "fixed": linux_fixed,
                        "package": "linux",
                        "status": linux_status,
                    },
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
            },
            "ubuntuJammy": {
                "kind": "distroPackages",
                "release": "jammy",
                "packages": {
                    "linuxOpenvswitchNestedActions": {
                        "abi": 190,
                        "allowUnfixed": True,
                        "cve": "CVE-2026-64531",
                        "package": "linux",
                        "status": "pending",
                    },
                    "linuxCgroupWriteback": {
                        "allowUnfixed": True,
                        "cve": "CVE-2026-64378",
                        "package": "linux",
                        "status": "needed",
                    },
                    "linuxSctpSendall": {
                        "abi": 186,
                        "allowUnfixed": True,
                        "cve": "CVE-2026-46227",
                        "fixed": "5.15.0-186.196",
                        "package": "linux",
                        "status": "released",
                    },
                    "linuxIpv4InetOptUaf": {
                        "allowUnfixed": True,
                        "cve": "CVE-2026-98432",
                        "package": "linux",
                        "status": "not-affected",
                    },
                },
            },
        },
    }


class UbuntuKernelCveTests(TempDirMixin):
    """grade_ubuntu_kernel_cves grades each GA-kernel CVE in the minimum table."""

    def grade(self, table: dict, release: str, kernel: str) -> tuple[str, ...]:
        path = self.write_minimum_table(table)
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'grade_ubuntu_kernel_cves ubuntu "{release}" "{kernel}"\n'
            'printf "%s\\n%s\\n%s\\n" "$UBUNTU_KERNEL_CVE_STATUS" '
            '"$UBUNTU_KERNEL_VULNERABLE_CVES_JSON" '
            '"$UBUNTU_KERNEL_CVE_GRACE_PERIODS_JSON"\n',
            env={"CLUSTERMAX_MINIMUM_VERSIONS": str(path)},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return tuple(run.stdout.splitlines())

    def test_jammy_kernel_fails_the_unreleased_and_the_below_minimum_cves(self) -> None:
        status, cves, grace = self.grade(minimum_table(), "22.04", "5.15.0-185-generic")
        self.assertEqual(status, "fail")
        self.assertEqual(
            json.loads(cves), ["CVE-2026-46227", "CVE-2026-64378", "CVE-2026-64531"]
        )
        self.assertEqual(json.loads(grace), [])

    def test_noble_kernel_fails_only_the_unfixed_cve_at_the_released_abi(self) -> None:
        status, cves, _ = self.grade(minimum_table(), "24.04", "6.8.0-138-generic")
        self.assertEqual(status, "fail")
        self.assertEqual(json.loads(cves), ["CVE-2026-64378"])

    def test_noble_kernel_below_the_released_abi_fails_that_cve(self) -> None:
        status, cves, _ = self.grade(minimum_table(), "24.04", "6.8.0-137-generic-64k")
        self.assertEqual(status, "fail")
        self.assertEqual(json.loads(cves), ["CVE-2026-64378", "CVE-2026-64531"])

    def test_released_fixes_pass_at_the_generated_abi(self) -> None:
        table = minimum_table()
        packages = table["components"]["ubuntuJammy"]["packages"]
        packages["linuxOpenvswitchNestedActions"].update(status="released", abi=190)
        packages["linuxCgroupWriteback"].update(status="released", abi=190)
        self.assertEqual(
            self.grade(table, "22.04", "5.15.0-190-generic"), ("pass", "[]", "[]")
        )

    def test_released_fix_observes_the_active_bulletin_grace_period(self) -> None:
        table = minimum_table()
        packages = table["components"]["ubuntuJammy"]["packages"]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        packages["linuxOpenvswitchNestedActions"].update(
            status="released",
            abi=190,
            fixed="5.15.0-190.200",
            released=now,
            fixAvailability={
                "status": "confirmed",
                "available": now,
                "bulletinReleased": now,
            },
        )
        packages["linuxCgroupWriteback"].update(status="not-affected")
        packages["linuxSctpSendall"].update(status="not-affected")

        status, cves, grace = self.grade(table, "22.04", "5.15.0-185-generic")

        self.assertEqual((status, cves), ("pass", "[]"))
        self.assertEqual(json.loads(grace)[0]["cve"], "CVE-2026-64531")
        self.assertIs(json.loads(grace)[0]["policy"]["active"], True)

    def sctp_only_table(self) -> dict:
        """Clear the other tracked CVEs so only SCTP_SENDALL decides the grade."""
        table = minimum_table()
        for component in ("ubuntuJammy", "ubuntuNoble"):
            packages = table["components"][component]["packages"]
            packages["linuxOpenvswitchNestedActions"].update(status="not-affected")
            packages["linuxCgroupWriteback"].update(status="not-affected")
        return table

    def test_sctp_sendall_boundary_is_the_published_fixed_abi(self) -> None:
        for release, kernel, expected in (
            # The internal incident kernel: jammy 5.15.0-181 is below the fix.
            ("22.04", "5.15.0-181-generic", "fail"),
            ("22.04", "5.15.0-185-generic-64k", "fail"),
            ("22.04", "5.15.0-186-generic", "pass"),
            ("22.04", "5.15.0-187-generic-64k", "pass"),
            ("24.04", "6.8.0-135-generic", "fail"),
            ("24.04", "6.8.0-136-generic-64k", "pass"),
            ("24.04", "6.8.0-137-generic", "pass"),
        ):
            with self.subTest(kernel=kernel):
                status, cves, _ = self.grade(self.sctp_only_table(), release, kernel)
                self.assertEqual(status, expected)
                self.assertEqual(
                    json.loads(cves),
                    ["CVE-2026-46227"] if expected == "fail" else [],
                )

    def test_sctp_sendall_minimum_is_read_from_the_table(self) -> None:
        # A later fixed ABI in the table moves the boundary. No floor is coded
        # in the grader.
        table = self.sctp_only_table()
        table["components"]["ubuntuJammy"]["packages"]["linuxSctpSendall"]["abi"] = 190
        status, cves, _ = self.grade(table, "22.04", "5.15.0-186-generic")
        self.assertEqual((status, json.loads(cves)), ("fail", ["CVE-2026-46227"]))
        # A tracker that withdraws the fix makes every kernel on the train fail.
        table["components"]["ubuntuJammy"]["packages"]["linuxSctpSendall"].update(
            status="needed", abi=None, fixed=""
        )
        status, cves, _ = self.grade(table, "22.04", "5.15.0-999-generic")
        self.assertEqual((status, json.loads(cves)), ("fail", ["CVE-2026-46227"]))

    def test_missing_sctp_sendall_ga_row_is_unknown(self) -> None:
        # The group still has per-kernel rows, so the GA kernel needs its own.
        table = self.sctp_only_table()
        packages = table["components"]["ubuntuNoble"]["packages"]
        del packages["linuxSctpSendall"]
        packages["linuxSctpSendallNvidia"] = self.kernel_row(
            "linux-nvidia", "6.8", "nvidia", "released", 1059)
        self.assertEqual(
            self.grade(table, "24.04", "6.8.0-140-generic"), ("unknown", "[]", "[]")
        )

    def test_release_without_tracked_cve_rows_is_unknown(self) -> None:
        """A release whose table lists no CVE row cannot be graded.

        Every tracked group is unverifiable, so the status is unknown rather
        than a pass the table cannot support.
        """
        table = minimum_table()
        table["components"]["ubuntuNoble"]["packages"] = {}
        self.assertEqual(
            self.grade(table, "24.04", "6.8.0-140-generic"),
            ("unknown", "[]", "[]"),
        )

    def test_shipped_table_grades_sctp_sendall(self) -> None:
        shipped = json.loads((WORKLOAD / "minimum-versions.json").read_text())
        for component, release, below, fixed in (
            ("ubuntuJammy", "22.04", "5.15.0-185-generic", "5.15.0-186-generic"),
            ("ubuntuNoble", "24.04", "6.8.0-135-generic", "6.8.0-136-generic"),
        ):
            with self.subTest(component=component):
                entry = shipped["components"][component]["packages"]["linuxSctpSendall"]
                self.assertEqual(entry["cve"], "CVE-2026-46227")
                self.assertEqual(entry["package"], "linux")
                self.assertEqual(entry["status"], "released")
                _, cves, _ = self.grade(shipped, release, below)
                self.assertIn("CVE-2026-46227", json.loads(cves))
                _, cves, _ = self.grade(shipped, release, fixed)
                self.assertNotIn("CVE-2026-46227", json.loads(cves))

    def test_ipv4_inet_opt_without_a_fix_fails_every_ga_abi(self) -> None:
        # CVE-2026-98432: the tracker lists the GA kernel as pending with no
        # released fix, so no running ABI on the train can pass.
        for release, component, kernel in (
            ("22.04", "ubuntuJammy", "5.15.0-999-generic"),
            ("24.04", "ubuntuNoble", "6.8.0-999-generic-64k"),
        ):
            with self.subTest(release=release):
                table = self.sctp_only_table()
                packages = table["components"][component]["packages"]
                packages["linuxSctpSendall"].update(status="not-affected")
                packages["linuxIpv4InetOptUaf"].update(
                    status="pending", fixed="", trackerNote="6.8.0-149.149"
                )
                status, cves, _ = self.grade(table, release, kernel)
                self.assertEqual((status, json.loads(cves)), ("fail", ["CVE-2026-98432"]))

    def test_missing_ipv4_inet_opt_ga_row_is_unknown(self) -> None:
        table = self.sctp_only_table()
        packages = table["components"]["ubuntuNoble"]["packages"]
        del packages["linuxIpv4InetOptUaf"]
        packages["linuxIpv4InetOptUafNvidia"] = {
            **self.kernel_row("linux-nvidia", "6.8", "nvidia", "needed"),
            "cve": "CVE-2026-98432",
            "kernelGroup": "linuxIpv4InetOptUaf",
        }
        self.assertEqual(
            self.grade(table, "24.04", "6.8.0-140-generic"), ("unknown", "[]", "[]")
        )

    def test_a_discovered_cve_group_is_graded_without_a_client_change(self) -> None:
        # The refresh adds groups for CVEs it discovers on the tracker. The
        # grader reads the groups from the table, so an unseen CVE fails the
        # kernels the tracker lists without a fix.
        table = self.sctp_only_table()
        packages = table["components"]["ubuntuNoble"]["packages"]
        packages["linuxCve2026_12345"] = {
            **self.kernel_row("linux", "6.8", "generic", "needed"),
            "cve": "CVE-2026-12345",
            "kernelGroup": "linuxCve2026_12345",
            "discovered": True,
        }
        packages["linuxCve2026_12345Nvidia"] = {
            **self.kernel_row("linux-nvidia", "6.8", "nvidia", "released", 1059),
            "cve": "CVE-2026-12345",
            "kernelGroup": "linuxCve2026_12345",
            "discovered": True,
        }
        packages["linuxSctpSendallNvidia"] = self.kernel_row(
            "linux-nvidia", "6.8", "nvidia", "released", 1059)
        packages["linuxIpv4InetOptUafNvidia"] = {
            **self.kernel_row("linux-nvidia", "6.8", "nvidia", "not-affected"),
            "cve": "CVE-2026-98432",
            "kernelGroup": "linuxIpv4InetOptUaf",
        }
        status, cves, _ = self.grade(table, "24.04", "6.8.0-140-generic")
        self.assertEqual((status, json.loads(cves)), ("fail", ["CVE-2026-12345"]))
        status, cves, _ = self.grade(table, "24.04", "6.8.0-1058-nvidia")
        self.assertEqual(
            (status, json.loads(cves)), ("fail", ["CVE-2026-12345", "CVE-2026-46227"])
        )
        status, cves, _ = self.grade(table, "24.04", "6.8.0-1059-nvidia")
        self.assertEqual((status, json.loads(cves)), ("pass", []))
        # A NVIDIA kernel with no row in the discovered group is unknown.
        del packages["linuxCve2026_12345Nvidia"]
        status, cves, _ = self.grade(table, "24.04", "6.8.0-1059-nvidia")
        self.assertEqual((status, json.loads(cves)), ("unknown", []))

    def test_shipped_table_grades_ipv4_inet_opt_on_every_tracked_kernel(self) -> None:
        # The shipped table carries the tracker state of CVE-2026-98432. No
        # Ubuntu kernel has a released fix, so a high ABI still fails.
        shipped = json.loads((WORKLOAD / "minimum-versions.json").read_text())
        for release, kernel in (
            ("22.04", "5.15.0-999-generic"),
            ("22.04", "5.15.0-9999-nvidia"),
            ("22.04", "6.8.0-999-generic"),
            ("24.04", "6.8.0-999-generic"),
            ("24.04", "6.8.0-9999-nvidia-64k"),
            ("24.04", "6.8.0-9999-aws"),
            ("24.04", "6.17.0-999-generic"),
            ("26.04", "7.0.0-999-generic"),
            ("26.04", "7.0.0-9999-nvidia"),
        ):
            with self.subTest(kernel=kernel):
                status, cves, _ = self.grade(shipped, release, kernel)
                self.assertEqual(status, "fail")
                self.assertIn("CVE-2026-98432", json.loads(cves))

    def test_missing_tracker_rows_are_unknown(self) -> None:
        table = minimum_table()
        del table["components"]["ubuntuJammy"]
        self.assertEqual(
            self.grade(table, "22.04", "5.15.0-185-generic"), ("unknown", "[]", "[]")
        )

    def kernel_row(self, package: str, family: str, flavor: str, status: str, abi=None) -> dict:
        row = {
            "allowUnfixed": True,
            "cve": "CVE-2026-46227",
            "fixed": "",
            "kernelFamily": family,
            "kernelFlavors": [flavor, f"{flavor}-64k"],
            "kernelGroup": "linuxSctpSendall",
            "package": package,
            "status": status,
        }
        if abi is not None:
            row.update(abi=abi, fixed=f"{family}.0-{abi}.{abi}")
        return row

    def all_kernels_table(self) -> dict:
        """SCTP_SENDALL rows for non-GA kernels, shaped as the refresh writes them."""
        table = self.sctp_only_table()
        jammy = table["components"]["ubuntuJammy"]["packages"]
        noble = table["components"]["ubuntuNoble"]["packages"]
        jammy["linuxSctpSendallHwe6_8"] = self.kernel_row(
            "linux-hwe-6.8", "6.8", "generic", "released", 136)
        jammy["linuxSctpSendallAws"] = self.kernel_row(
            "linux-aws", "5.15", "aws", "released", 1112)
        jammy["linuxSctpSendallLowlatency"] = self.kernel_row(
            "linux-lowlatency", "5.15", "lowlatency", "released", 184)
        noble["linuxSctpSendallNvidia"] = self.kernel_row(
            "linux-nvidia", "6.8", "nvidia", "released", 1059)
        noble["linuxSctpSendallNvidia6_17"] = self.kernel_row(
            "linux-nvidia-6.17", "6.17", "nvidia", "ignored")
        noble["linuxSctpSendallHwe6_17"] = self.kernel_row(
            "linux-hwe-6.17", "6.17", "generic", "needed")
        noble["linuxSctpSendallAzureNvidia"] = self.kernel_row(
            "linux-azure-nvidia", "6.8", "azure-nvidia", "pending")
        noble["linuxSctpSendallAws7_0"] = self.kernel_row(
            "linux-aws-7.0", "7.0", "aws", "not-affected")
        noble["linuxSctpSendallFips"] = self.kernel_row(
            "linux-fips", "6.8", "fips", "released", 136)
        table["components"]["ubuntuResolute"] = {"packages": {
            "linuxSctpSendall": self.kernel_row("linux", "7.0", "generic", "released", 28),
            "linuxIpv4InetOptUaf": {
                "allowUnfixed": True,
                "cve": "CVE-2026-98432",
                "package": "linux",
                "status": "not-affected",
            },
        }}
        return table

    def test_non_ga_kernels_use_their_own_source_package_row(self) -> None:
        for release, kernel, expected in (
            # HWE 6.8 on jammy, fixed at 6.8.0-136.136~22.04.1.
            ("22.04", "6.8.0-135-generic", "fail"),
            ("22.04", "6.8.0-136-generic-64k", "pass"),
            # linux-aws on jammy, fixed at 5.15.0-1112.119.
            ("22.04", "5.15.0-1111-aws", "fail"),
            ("22.04", "5.15.0-1112-aws", "pass"),
            ("22.04", "5.15.0-183-lowlatency", "fail"),
            ("22.04", "5.15.0-184-lowlatency-64k", "pass"),
            ("24.04", "6.8.0-1058-nvidia-64k", "fail"),
            ("24.04", "6.8.0-1059-nvidia", "pass"),
            ("24.04", "6.8.0-135-fips", "fail"),
            ("24.04", "6.8.0-136-fips", "pass"),
            # End-of-life and unfixed kernels have no fix to reach.
            ("24.04", "6.17.0-1031-nvidia", "fail"),
            ("24.04", "6.17.0-35-generic", "fail"),
            ("24.04", "6.8.0-1046-azure-nvidia", "fail"),
            ("24.04", "7.0.0-1009-aws", "pass"),
            ("26.04", "7.0.0-27-generic", "fail"),
            ("26.04", "7.0.0-28-generic-64k", "pass"),
        ):
            with self.subTest(kernel=kernel):
                status, cves, _ = self.grade(self.all_kernels_table(), release, kernel)
                self.assertEqual(status, expected)
                self.assertEqual(
                    json.loads(cves),
                    ["CVE-2026-46227"] if expected == "fail" else [],
                )

    def test_ga_kernel_ignores_the_other_kernel_rows(self) -> None:
        table = self.all_kernels_table()
        self.assertEqual(self.grade(table, "24.04", "6.8.0-136-generic"), ("pass", "[]", "[]"))
        self.assertEqual(
            self.grade(table, "22.04", "5.15.0-185-generic")[0:2],
            ("fail", '["CVE-2026-46227"]'),
        )

    def test_kernel_without_a_row_is_unknown(self) -> None:
        # The tracker lists every Ubuntu kernel package. A kernel with no row
        # is a custom, mainline, or new build that the audit cannot check.
        table = self.all_kernels_table()
        for release, kernel in (
            ("24.04", "6.8.0-1050-gcp"),
            ("22.04", "5.15.0-1090-oracle"),
            ("24.04", "6.10.3-061003-generic"),
            ("24.04", "6.8.0-136-custom"),
            ("26.04", "7.0.0-1009-aws"),
            ("24.04", "6.8.0-136-generic+"),
            ("24.04", "6.8.12"),
        ):
            with self.subTest(kernel=kernel):
                self.assertEqual(
                    self.grade(table, release, kernel), ("unknown", "[]", "[]")
                )

    def test_unknown_kernel_still_reports_a_known_failure(self) -> None:
        # A missing row in one group must not hide a failure in another.
        table = self.all_kernels_table()
        table["components"]["ubuntuNoble"]["packages"]["linuxCgroupWriteback"] = {
            "cve": "CVE-2026-64378", "package": "linux-nvidia-6.17",
            "status": "needed", "fixed": "", "allowUnfixed": True,
            "kernelGroup": "linuxCgroupWriteback", "kernelFamily": "6.17",
            "kernelFlavors": ["nvidia", "nvidia-64k"],
        }
        status, cves, _ = self.grade(table, "24.04", "6.17.0-1031-nvidia")
        self.assertEqual(status, "fail")
        self.assertEqual(json.loads(cves), ["CVE-2026-46227", "CVE-2026-64378"])

    def test_ga_only_groups_skip_other_kernels(self) -> None:
        # Groups with only the GA row check only the GA kernel. Without
        # per-kernel rows, a non-GA kernel is outside this check.
        self.assertEqual(
            self.grade(minimum_table(), "22.04", "5.15.0-1084-aws"),
            ("not-applicable", "[]", "[]"),
        )
        self.assertEqual(
            self.grade(minimum_table(), "24.04", "6.8.0-136-generic+"),
            ("unknown", "[]", "[]"),
        )

    def test_container_release_on_another_release_kernel(self) -> None:
        # A 22.04 Slurm container on a 24.04 host reports VERSION_ID 22.04,
        # but the host kernel comes from Noble. Jammy ships no 6.17 kernel,
        # so the Noble row grades it.
        table = self.all_kernels_table()
        self.assertEqual(
            self.grade(table, "22.04", "6.17.0-1021-nvidia-64k"),
            ("fail", '["CVE-2026-46227"]', "[]"),
        )
        # 7.0 aws is listed for Noble and is not in the 26.04 fixture, so the
        # one-release rule applies. With rows in two other releases, the
        # kernel stays unknown instead of picking one.
        self.assertEqual(
            self.grade(table, "22.04", "7.0.0-1009-aws"), ("pass", "[]", "[]")
        )
        table["components"]["ubuntuResolute"]["packages"]["linuxSctpSendallAws"] = (
            self.kernel_row("linux-aws", "7.0", "aws", "released", 1009)
        )
        self.assertEqual(
            self.grade(table, "22.04", "7.0.0-1009-aws"), ("unknown", "[]", "[]")
        )

    def test_two_rows_for_one_kernel_are_unknown(self) -> None:
        table = self.all_kernels_table()
        noble = table["components"]["ubuntuNoble"]["packages"]
        noble["linuxSctpSendallNvidiaCopy"] = dict(noble["linuxSctpSendallNvidia"])
        self.assertEqual(
            self.grade(table, "24.04", "6.8.0-1059-nvidia"), ("unknown", "[]", "[]")
        )

    def test_missing_grader_is_unknown(self) -> None:
        path = self.write_minimum_table(self.all_kernels_table())
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            'AUDIT_COMMON_DIR=/nonexistent\n'
            'grade_ubuntu_kernel_cves ubuntu 24.04 6.8.0-136-generic\n'
            'printf "%s\\n" "$UBUNTU_KERNEL_CVE_STATUS"\n',
            env={"CLUSTERMAX_MINIMUM_VERSIONS": str(path)},
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "unknown")

    def test_shipped_table_grades_every_listed_kernel_package(self) -> None:
        shipped = json.loads((WORKLOAD / "minimum-versions.json").read_text())
        for component, release in (
            ("ubuntuJammy", "22.04"), ("ubuntuNoble", "24.04"), ("ubuntuResolute", "26.04"),
        ):
            rows = {
                key: entry
                for key, entry in shipped["components"][component]["packages"].items()
                if entry.get("kernelGroup") == "linuxSctpSendall"
            }
            self.assertIn("linuxSctpSendall", rows, component)
            self.assertGreater(len(rows), 1, component)
            for key, entry in rows.items():
                self.assertNotIn("riscv", entry["package"])
                if entry["status"] != "released":
                    continue
                kernel = f'{entry["kernelFamily"]}.0-{entry["abi"]}-{entry["kernelFlavors"][0]}'
                with self.subTest(component=component, key=key):
                    _, cves, _ = self.grade(shipped, release, kernel)
                    self.assertNotIn("CVE-2026-46227", json.loads(cves))

    def test_other_kernel_trains_and_flavors_are_not_applicable(self) -> None:
        for release, kernel in (
            ("22.04", "5.15.0-1084-aws"),
            ("24.04", "6.8.0-1044-nvidia"),
            ("22.04", "6.8.0-60-generic"),
            ("20.04", "5.4.0-200-generic"),
        ):
            with self.subTest(kernel=kernel):
                self.assertEqual(
                    self.grade(minimum_table(), release, kernel),
                    ("not-applicable", "[]", "[]"),
                )


class FragnesiaAbiMinimumTests(TempDirMixin):
    def check(self, kernel: str, **env: str) -> dict[str, str]:
        run, facts = fragnesia_check(kernel, **env)
        self.assertEqual(
            run.returncode, 0, f"check block exited {run.returncode}: {run.stderr}"
        )
        return facts

    def write_table(self, **kwargs) -> dict[str, str]:
        table = self.write_minimum_table(minimum_table(**kwargs))
        return {
            "CLUSTERMAX_MINIMUM_VERSIONS": str(table),
            "CLUSTERMAX_MINIMUM_VERSIONS_READER": str(MINIMUMS_READER),
            "CLUSTERMAX_FRAGNESIA_ABI_MINIMUM": "",
        }

    def test_kernel_uses_the_table_minimum(self) -> None:
        for observed, floor, status in (
            (200, 200, "pass"),
            (199, 200, "fail"),
            (150, 200, "fail"),
            (150, 140, "pass"),
        ):
            with self.subTest(observed=observed, floor=floor):
                facts = self.check(
                    f"6.8.0-{observed}-generic",
                    **self.write_table(fragnesia_abi=floor),
                )
                self.assertEqual(facts["WORKER_FRAGNESIA_ABI"], str(observed))
                self.assertEqual(facts["WORKER_FRAGNESIA_ABI_FLOOR"], str(floor))
                self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], status)

    def test_collector_supplied_minimum_wins_for_stdin_delivered_checks(self) -> None:
        # Stdin-delivered checks cannot read the collector's checkout.
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


class UbuntuKernelAggregateMinimumTests(TempDirMixin):
    def check(
        self,
        kernel: str,
        *,
        distro: str = "ubuntu",
        release: str = "24.04",
        **env: str,
    ) -> dict[str, str]:
        preamble = (
            f"ID={distro}\n"
            f"VERSION_ID={release}\n"
            f"WORKER_GUEST_KERNEL_RUNNING={kernel}\n"
        )
        run = bashtest.run_bash(preamble + UBUNTU_KERNEL_BLOCK, env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        return dict(
            line.split("=", 1) for line in run.stdout.splitlines() if "=" in line
        )

    def write_table(self, **kwargs) -> dict[str, str]:
        table = self.write_minimum_table(minimum_table(**kwargs))
        return {
            "CLUSTERMAX_MINIMUM_VERSIONS": str(table),
            "CLUSTERMAX_MINIMUM_VERSIONS_READER": str(MINIMUMS_READER),
            "CLUSTERMAX_UBUNTU_KERNEL_ABI_MINIMUM": "",
        }

    def test_kernel_uses_the_table_minimum(self) -> None:
        for observed, floor, status in (
            (210, 210, "pass"),
            (209, 210, "fail"),
            (200, 210, "fail"),
            (200, 190, "pass"),
        ):
            with self.subTest(observed=observed, floor=floor):
                facts = self.check(
                    f"6.8.0-{observed}-generic",
                    **self.write_table(linux_abi=floor),
                )
                self.assertEqual(
                    facts["WORKER_UBUNTU_KERNEL_MINIMUM_STATUS"], status
                )
                self.assertEqual(
                    facts["WORKER_UBUNTU_KERNEL_ABI_FLOOR"], str(floor)
                )

    def test_missing_minimum_fails_closed(self) -> None:
        facts = self.check(
            "6.8.0-210-generic",
            CLUSTERMAX_MINIMUM_VERSIONS="/nonexistent/minimum-versions.json",
            CLUSTERMAX_MINIMUM_VERSIONS_READER=str(MINIMUMS_READER),
            CLUSTERMAX_UBUNTU_KERNEL_ABI_MINIMUM="",
        )
        self.assertEqual(facts["WORKER_UBUNTU_KERNEL_ABI_FLOOR"], "unknown")
        self.assertEqual(facts["WORKER_UBUNTU_KERNEL_MINIMUM_STATUS"], "unknown")

    def test_unassessed_noble_kernel_series_is_unknown(self) -> None:
        facts = self.check("6.11.0-20-generic", **self.write_table())
        self.assertEqual(facts["WORKER_UBUNTU_KERNEL_ABI"], "unknown")
        self.assertEqual(facts["WORKER_UBUNTU_KERNEL_MINIMUM_STATUS"], "unknown")

    def test_non_noble_is_not_applicable(self) -> None:
        facts = self.check(
            "6.8.0-210-generic", release="22.04", **self.write_table()
        )
        self.assertEqual(
            facts["WORKER_UBUNTU_KERNEL_MINIMUM_STATUS"], "not-applicable"
        )


class FragnesiaFailSafeTests(TempDirMixin):
    check = staticmethod(fragnesia_check)

    def assert_unknown_and_alive(self, run: bashtest.BashRun, facts: dict) -> None:
        self.assertEqual(run.returncode, 0, f"check crashed: {run.stderr}")
        self.assertEqual(facts["WORKER_FRAGNESIA_ABI_FLOOR"], "unknown")
        self.assertEqual(facts["WORKER_FRAGNESIA_STATUS"], "unknown")
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
        # Append a sentinel to splice the builder's trailing-comma fragment.
        return json.loads("{" + fragment + '"sentinel": true}')

    def resolute_block(self, abi: int) -> dict:
        version = f"7.0.0-{abi}.{abi}"
        table = json.loads(
            (Path(AUDIT_COMMON).parent / "minimum-versions.json").read_text()
        )
        return self.parse(self.build(
            table,
            "--bad-epoll-os", "ubuntu",
            "--bad-epoll-release", "26.04",
            "--bad-epoll-running", f"7.0.0-{abi}-generic",
            "--bad-epoll-signature", f"Ubuntu {version}-generic 7.0.14",
            "--bad-epoll-package", f"ii |linux-signed|{version}",
            "--bad-epoll-livepatch", "none",
            "--fragnesia-status", "not-applicable",
        ))

    def test_ubuntu_resolute_kernels_use_the_shipped_resolute_minimums(self) -> None:
        fixed = self.resolute_block(38)
        self.assertEqual(fixed["badEpoll"]["status"], "pass")
        self.assertEqual(fixed["badEpoll"]["minimum"], "7.0.0-28.28")
        self.assertEqual(fixed["fragnesia"]["status"], "pass")
        self.assertEqual(fixed["fragnesia"]["ubuntuNoblePackageMinimum"], "7.0.0-22.22")
        self.assertEqual(fixed["fragnesia"]["comparedAbiFloor"], "22")

        old = self.resolute_block(21)
        self.assertEqual(old["badEpoll"]["status"], "fail")
        self.assertEqual(old["fragnesia"]["status"], "fail")
        self.assertIsNone(old["fragnesia"]["gracePeriod"])

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
        released = self.parse(
            self.build(
                minimum_table(januscape_status="released", januscape_fixed="6.8.0-140.140")
            )
        )

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
    def test_both_collectors_emit_the_same_advisory_members(self) -> None:
        table = self.write_minimum_table(minimum_table(fragnesia_abi=200))
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": str(table)}

        k8s_facts = {
            "HP_FRAGNESIA_STATUS": "fail",
            "HP_FRAGNESIA_ABI_MINIMUM": "200",
            "HP_UBUNTU_KERNEL_STATUS": "pass",
            "HP_UBUNTU_KERNEL_ABI": "210",
            "HP_UBUNTU_KERNEL_ABI_MINIMUM": "210",
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
            "WORKER_UBUNTU_KERNEL_MINIMUM_STATUS": "pass",
            "WORKER_UBUNTU_KERNEL_ABI": "210",
            "WORKER_UBUNTU_KERNEL_ABI_FLOOR": "210",
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
        self.assertEqual(
            members["fragnesia"]["ubuntuNoblePackageMinimum"], "6.8.0-200.200"
        )
        self.assertEqual(members["fragnesia"]["ubuntuNoblePackageMinimumAbi"], "200")
        self.assertEqual(members["fragnesia"]["cve"], "CVE-2026-46300")
        self.assertEqual(
            members["fragnesia"]["relatedCves"],
            ["CVE-2026-43284", "CVE-2026-43500"],
        )
        self.assertEqual(members["fragnesia"]["comparedAbiFloor"], "200")
        self.assertEqual(
            members["ubuntuNobleKernelMinimum"]["ubuntuNoblePackageMinimum"],
            "6.8.0-210.210",
        )
        self.assertEqual(
            members["ubuntuNobleKernelMinimum"]["ubuntuNoblePackageMinimumAbi"], "210"
        )
        self.assertEqual(members["ubuntuNobleKernelMinimum"]["status"], "pass")
        self.assertEqual(
            members["ubuntuNobleKernelMinimum"]["comparedAbiFloor"], "210"
        )
        self.assertEqual(members["januscape"]["ubuntuNobleFixStatus"], "pending")
        self.assertEqual(members["januscape"]["ubuntuNobleKernelFix"], "6.8.0-137.137")


class K8sCheckDeliveryTests(TempDirMixin):
    def deliver(self, table: dict | None) -> bashtest.BashRun:
        tmp = self.temp_dir()
        env = {"CLUSTERMAX_MINIMUM_VERSIONS": "/nonexistent/minimum-versions.json"}
        if table is not None:
            path = tmp / "minimum-versions.json"
            path.write_text(json.dumps(table))
            env["CLUSTERMAX_MINIMUM_VERSIONS"] = str(path)

        # Run both real kernel-floor blocks without hardware collection.
        (tmp / "host-check.sh").write_text(
            "ID=ubuntu\nVERSION_ID=24.04\n"
            "WORKER_GUEST_KERNEL_RUNNING=6.8.0-150-generic\n"
            + FRAGNESIA_BLOCK
            + UBUNTU_KERNEL_BLOCK
        )
        stdin_fn = bashtest.extract_function(K8S_COLLECTOR, "host_check_stdin")
        return bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            # Force the check to use only the collector-piped minimum.
            "unset CLUSTERMAX_MINIMUM_VERSIONS_READER\n"
            f'WORKLOAD_DIR="{tmp}"\n' + stdin_fn + "\nhost_check_stdin | bash\n",
            env=env,
        )

    def test_piped_minimum_grades_the_worker(self) -> None:
        run = self.deliver(minimum_table(fragnesia_abi=200))

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=200", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=fail", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_ABI_FLOOR=210", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_MINIMUM_STATUS=fail", run.stdout)

    def test_lower_piped_minimum_passes_the_same_worker(self) -> None:
        run = self.deliver(minimum_table(fragnesia_abi=140))

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=140", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=pass", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_ABI_FLOOR=210", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_MINIMUM_STATUS=fail", run.stdout)

    def test_unresolvable_table_pipes_unknown_and_keeps_running(self) -> None:
        run = self.deliver(None)

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("WORKER_FRAGNESIA_ABI_FLOOR=unknown", run.stdout)
        self.assertIn("WORKER_FRAGNESIA_STATUS=unknown", run.stdout)
        self.assertNotIn("WORKER_FRAGNESIA_STATUS=pass", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_ABI_FLOOR=unknown", run.stdout)
        self.assertIn("WORKER_UBUNTU_KERNEL_MINIMUM_STATUS=unknown", run.stdout)


class ContainerRecommendationMinimumTests(TempDirMixin):
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

    def test_collectors_grade_against_the_table_values(self) -> None:
        table = minimum_table(docker_minimum="40.4.3", nct_minimum="2.19.1")
        for collector in (self.slurm, self.standalone):
            with self.subTest(collector=collector.__name__):
                at_minimum = collector("40.4.3", "2.19.1", table)
                below = collector("40.4.2", "2.19.0", table)
                self.assertEqual(at_minimum["DOCKER_RECOMMENDED_MIN"], "40.4.3")
                self.assertEqual(at_minimum["NVIDIA_CT_RECOMMENDED_MIN"], "2.19.1")
                self.assertEqual(at_minimum["DOCKER_VERSION_OK"], "true")
                self.assertEqual(at_minimum["NVIDIA_CT_VERSION_OK"], "true")
                self.assertEqual(below["DOCKER_VERSION_OK"], "false")
                self.assertEqual(below["NVIDIA_CT_VERSION_OK"], "false")

    def test_recommendation_moves_with_the_table_not_with_the_script(self) -> None:
        strict = self.slurm("29.4.3", "1.19.0", minimum_table(nct_minimum="1.19.1"))
        lenient = self.slurm("29.4.3", "1.19.0", minimum_table(nct_minimum="1.19.0"))

        self.assertEqual(strict["NVIDIA_CT_VERSION_OK"], "false")
        self.assertEqual(lenient["NVIDIA_CT_VERSION_OK"], "true")

    def test_unreadable_table_reports_unknown_and_never_passes(self) -> None:
        # Unknown floors must not collapse to 0.0.0 and accept every version.
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
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{WORKLOAD}"\n'
            f'DCGM_EXPORTER_IMAGE="{tag}"\n'
            'build_security_version_audit "" 580.159.03 1.19.1 1.3.6 29.4.3 nvidia 13.1\n',
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

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

    def test_undiscoverable_exporter_is_unknown_not_not_applicable(self) -> None:
        # A head-node scan cannot prove exporter absence across worker nodes.
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
        verdicts = self.evaluate_check_and_tag(
            "WORKER_DCGM_VERSION=not-found", image="4.5.0-4.8.2-ubuntu22.04"
        )

        self.assertEqual(verdicts["dcgm"]["version"], "4.5.0")
        self.assertEqual(verdicts["dcgm"]["status"], "fail")
        self.assertNotEqual(verdicts["dcgm"]["status"], "not_applicable")
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.8.2")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "pass")

    def test_genuine_absence_stays_not_applicable(self) -> None:
        verdicts = self.evaluate_check_and_tag(
            "WORKER_DCGM_VERSION=not-found", present="false"
        )

        self.assertEqual(verdicts["dcgm"]["status"], "not_applicable")
        self.assertEqual(verdicts["dcgm"]["version"], "not-installed")
        self.assertEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_a_deployed_exporter_with_an_unreadable_tag_is_unknown(self) -> None:
        # An installed image with no readable version is unknown, not absent.
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

        self.assertEqual(verdicts["dcgm"]["version"], "4.6.0")
        self.assertEqual(verdicts["dcgmExporter"]["version"], "4.7.1")


class SecurityGpuVendorGateTests(unittest.TestCase):

    GATES = (("slurm", SLURM_VENDOR_GATE), ("standalone", STANDALONE_VENDOR_GATE))
    AMD_DRIVER_VERSION = "6.1.2"

    def vendor(self, gate: str, **variables: str) -> str:
        assignments = "".join(f'{key}="{value}"\n' for key, value in variables.items())
        run = bashtest.run_bash(
            assignments + gate + 'printf "%s\\n" "$SECURITY_GPU_VENDOR"\n'
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip()

    def test_vendor_gate_uses_the_gpu_vendor(self) -> None:
        cases = (
            ("amd-promoted", {"AMD_GPUS_PRESENT": "true",
                              "DRIVER_VERSION": self.AMD_DRIVER_VERSION}, "amd"),
            ("amd-unknown", {"AMD_GPUS_PRESENT": "true",
                             "DRIVER_VERSION": "unknown"}, "amd"),
            ("amd-unset", {"AMD_GPUS_PRESENT": "true"}, "amd"),
            ("nvidia", {"AMD_GPUS_PRESENT": "false",
                        "DRIVER_VERSION": "580.159.03"}, "nvidia"),
            ("default", {}, "nvidia"),
        )
        for name, gate in self.GATES:
            for case, variables, expected in cases:
                with self.subTest(collector=name, case=case):
                    self.assertEqual(self.vendor(gate, **variables), expected)

    def test_the_gate_decides_whether_nvidia_minimums_apply(self) -> None:
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
    REPORT = (
        'printf "%s|%s|%s\\n" "$VIRTIO_NET_VERSION" "$VIRTIO_NET_STATE" "$VIRTIO_NET_MODE"\n'
    )

    PAYLOAD = '{"virtioNet": "24.10.17", "state": "version", "virtioNetMode": "dpu"}'

    def collector(self, check_body: str) -> bashtest.BashRun:
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

    def test_noisy_stderr_preserves_json_and_audit_success(self) -> None:
        run = self.collector(
            "for i in range(200):\n"
            '    print("  WARNING: line %d" % i, file=sys.stderr)\n'
            f"print({self.PAYLOAD!r})\n"
        )

        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("RC=0", run.stdout)
        self.assertIn("WARNING: line 199", run.stderr)
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
        self.assertIn("unknown|incomplete|", run.stdout)
        self.assertNotIn("not-installed", run.stdout)


class VirtioNetWorstObservedWiringTests(TempDirMixin):
    BELOW_MINIMUM = "24.10.17"  # LTS24 is fixed at 24.10.50.
    OBSERVED = [
        {"host": "worker-3", "version": "24.10.17", "line": "LTS24", "mode": "dpu"}
    ]

    def evaluate(self, summary: dict) -> dict:
        root = self.virtio_workload(summary)
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
        verdict = self.evaluate(self.summary())

        self.assertEqual(verdict["status"], "unknown")
        self.assertNotEqual(verdict["status"], "pass")

    def test_a_json_array_survives_the_shell_intact(self) -> None:
        # Preserve spaces, quotes, and brackets through shell argument construction.
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
    def emitted_args(self, summary: dict) -> list[str]:
        root = self.virtio_workload(summary, stub_evaluator=True)
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

class DegradedSecurityAuditFallbackTests(TempDirMixin):
    def evaluator_components(self) -> set[str]:
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

    def fallback(self) -> dict:
        workload = self.temp_dir() / "workload"
        workload.mkdir()
        # Omit the policy script to force the real wrapper's degraded fallback.
        run = bashtest.run_bash(
            f'source "{AUDIT_COMMON}"\n'
            f'WORKLOAD_DIR="{workload}"\n'
            'build_security_version_audit ""\n'
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_missing_policy_script_reports_every_component_as_unknown(self) -> None:
        verdicts = self.fallback()

        self.assertEqual(set(verdicts), self.evaluator_components())
        for name, verdict in sorted(verdicts.items()):
            with self.subTest(component=name):
                self.assertEqual(verdict["status"], "unknown")


class VersionMinimumGuardTests(unittest.TestCase):
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
        # version_ge strips unknown to 0.0.0; the guard must reject it first.
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
        verdicts = self.evaluate("true")

        self.assertNotEqual(verdicts["dcgmExporter"]["status"], "not_applicable")

    def test_an_unset_detection_stays_unknown(self) -> None:
        verdicts = self.evaluate("unknown")

        self.assertEqual(verdicts["dcgmExporter"]["status"], "unknown")


class StandaloneExporterProcessDetectionTests(unittest.TestCase):
    BLOCK = bashtest.extract_block(
        STANDALONE_COLLECTOR,
        'DCGM_EXPORTER_DETECTED="false"',
        'if pgrep -x dcgm-exporter',
    )

    def detect(self, *, listening: str, systemd_ok: bool, pgrep_ok: bool) -> str:
        # The socket stub needs a header and the local address in field four.
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
