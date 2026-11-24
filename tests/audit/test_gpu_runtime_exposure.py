#!/usr/bin/env python3
"""Behavior tests for the passive GPU runtime exposure check."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK = REPO_ROOT / "cmax" / "scripts" / "1-audit" / "checks" / "system" / "gpu_runtime_exposure.py"
sys.path.insert(0, str(REPO_ROOT))

from cmax import security  # noqa: E402

_spec = importlib.util.spec_from_file_location("gpu_runtime_exposure", CHECK)
exposure = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(exposure)


GPU_QUERY = "0, NVIDIA H100 80GB HBM3, Enabled, Enabled\n1, NVIDIA H100 80GB HBM3, Disabled, Enabled\n"
GPU_LISTING = """GPU 0: NVIDIA H100 80GB HBM3 (UUID: GPU-a)
  MIG 3g.40gb     Device  0: (UUID: MIG-a)
  MIG 1g.10gb     Device  1: (UUID: MIG-b)
GPU 1: NVIDIA H100 80GB HBM3 (UUID: GPU-b)
"""


def _tcp_line(address_hex: str, port: int, state: str = "0A") -> str:
    return f"   0: {address_hex}:{port:04X} 00000000:0000 {state} 0 0 0 0 0 0 0"


def fake_proc(root: Path, *, listen: str | None = None, auth: str | None = None,
              ray_site: Path | None = None, extra: dict[str, str] | None = None) -> None:
    """Write a /proc tree with one Ray dashboard and optional other processes."""
    (root / "net").mkdir(parents=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    lines = [header]
    if listen:
        lines.append(_tcp_line(listen, exposure.RAY_DASHBOARD_PORT))
    (root / "net" / "tcp").write_text("\n".join(lines) + "\n")
    (root / "net" / "tcp6").write_text(header + "\n")
    if ray_site is not None:
        pid = root / "100"
        pid.mkdir()
        script = ray_site / "ray" / "dashboard" / "dashboard.py"
        (pid / "cmdline").write_bytes(b"\0".join([b"python3", str(script).encode()]))
        (pid / "comm").write_text("python3\n")
        env = b"PATH=/usr/bin\0" + (f"RAY_AUTH_MODE={auth}".encode() if auth else b"")
        (pid / "environ").write_bytes(env)
    for number, (pid_name, comm) in enumerate((extra or {}).items(), start=200):
        pid = root / str(number)
        pid.mkdir()
        (pid / "cmdline").write_bytes(pid_name.encode())
        (pid / "comm").write_text(comm + "\n")


def ray_site(root: Path, version: str) -> Path:
    site = root / "lib" / "python3.12" / "site-packages"
    (site / "ray" / "dashboard").mkdir(parents=True)
    (site / "ray" / "dashboard" / "dashboard.py").write_text("")
    (site / f"ray-{version}.dist-info").mkdir()
    return site


class GpuFactsTests(unittest.TestCase):
    def test_query_and_listing_count_mig_instances_per_gpu(self) -> None:
        gpus = exposure.parse_gpu_query(GPU_QUERY)
        counts = exposure.count_mig_instances(GPU_LISTING)
        self.assertEqual([gpu["mig_mode"] for gpu in gpus], ["Enabled", "Disabled"])
        self.assertEqual(counts, {0: 2, 1: 0})

    def test_shared_hopper_mig_warns_and_names_the_partition(self) -> None:
        gpus = [{"host": "n1", "index": 0, "name": "NVIDIA H100 80GB HBM3",
                 "mig_mode": "Enabled", "ecc_mode": "Enabled", "mig_instances": 2}]
        verdict = exposure.grade_mig(gpus, [], True)
        self.assertEqual(verdict["status"], "warning")
        self.assertIn("n1 GPU 0", verdict["partitions"][0])

    def test_ampere_mig_passes_and_whole_gpus_are_not_applicable(self) -> None:
        ampere = [{"host": "n1", "index": 0, "name": "NVIDIA A100-SXM4-80GB",
                   "mig_mode": "Enabled", "ecc_mode": "Enabled", "mig_instances": 7}]
        whole = [{"host": "n1", "index": 0, "name": "NVIDIA H200",
                  "mig_mode": "Disabled", "ecc_mode": "Enabled", "mig_instances": 0}]
        self.assertEqual(exposure.grade_mig(ampere, [], True)["status"], "pass")
        self.assertEqual(exposure.grade_mig(whole, [], True)["status"], "not_applicable")
        self.assertEqual(exposure.grade_mig([], [], False)["status"], "unknown")

    def test_kubernetes_mig_capacity_counts_as_shared(self) -> None:
        nodes = [{"host": "k1", "gpu_model": "NVIDIA-H100-80GB-HBM3", "mig_instances": 7}]
        self.assertEqual(exposure.grade_mig([], nodes, True)["status"], "warning")

    def test_gddr_gpu_without_ecc_warns_and_hbm_is_not_applicable(self) -> None:
        gddr = [{"host": "n1", "index": 0, "name": "NVIDIA L40S", "ecc_mode": "Disabled"}]
        gddr_on = [{"host": "n1", "index": 0, "name": "NVIDIA RTX A6000", "ecc_mode": "Enabled"}]
        hbm = [{"host": "n1", "index": 0, "name": "NVIDIA H100 80GB HBM3", "ecc_mode": "Enabled"}]
        self.assertEqual(exposure.grade_ecc(gddr, True)["status"], "warning")
        self.assertEqual(exposure.grade_ecc(gddr_on, True)["status"], "pass")
        self.assertEqual(exposure.grade_ecc(hbm, True)["status"], "not_applicable")
        self.assertEqual(exposure.grade_ecc([], True)["status"], "unknown")


class CdiHookTests(unittest.TestCase):
    SPEC = {
        "cdiVersion": "0.5.0",
        "kind": "nvidia.com/gpu",
        "containerEdits": {
            "hooks": [
                {"hookName": "createContainer", "path": "/usr/bin/nvidia-cdi-hook",
                 "args": ["nvidia-cdi-hook", "update-ldcache"]},
            ]
        },
    }

    def test_json_spec_lists_the_hook_and_loader_variables(self) -> None:
        clean = exposure.cdi_hooks_in_spec(json.dumps(self.SPEC))
        self.assertEqual(clean, [{"path": "/usr/bin/nvidia-cdi-hook",
                                  "hook": "createContainer", "loader_env": []}])
        tampered = json.loads(json.dumps(self.SPEC))
        tampered["containerEdits"]["hooks"][0]["env"] = ["LD_PRELOAD=/tmp/x.so"]
        self.assertEqual(
            exposure.cdi_hooks_in_spec(json.dumps(tampered))[0]["loader_env"], ["LD_PRELOAD"]
        )

    def test_yaml_spec_is_read_without_a_yaml_library(self) -> None:
        text = "containerEdits:\n  hooks:\n  - hookName: createContainer\n    path: /usr/bin/nvidia-cdi-hook\n"
        self.assertEqual(exposure.cdi_hooks_in_spec(text)[0]["path"], "/usr/bin/nvidia-cdi-hook")

    def test_local_facts_read_cdi_dirs_and_audit_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cdi").mkdir()
            (root / "cdi" / "nvidia.json").write_text(json.dumps(self.SPEC))
            (root / "rules.d").mkdir()
            (root / "rules.d" / "gpu.rules").write_text(
                "-w /usr/bin/nvidia-cdi-hook -p x -k nvidia_cdi_hook\n"
            )
            fake_proc(root / "proc", extra={"auditd": "auditd"})
            with mock.patch.object(exposure, "CDI_SPEC_DIRS", (str(root / "cdi"),)), \
                    mock.patch.object(exposure, "AUDIT_RULE_PATHS", (str(root / "rules.d"),)):
                facts = exposure.local_cdi_facts(str(root / "proc"))
        self.assertEqual(len(facts["specs"]), 1)
        self.assertTrue(facts["audit_rules_cover_hook"])
        self.assertEqual(facts["monitors"], ["auditd"])
        self.assertEqual(exposure.grade_cdi([{"host": "n1", "cdi": facts}], None)["status"], "pass")

    def test_hook_without_monitor_warns_and_loader_env_fails(self) -> None:
        spec = {"file": "/etc/cdi/nvidia.json",
                "hooks": [{"path": "/usr/bin/nvidia-cdi-hook", "hook": "", "loader_env": []}]}
        host = {"host": "n1", "cdi": {"specs": [spec], "monitors": [], "audit_rules_cover_hook": False}}
        self.assertEqual(exposure.grade_cdi([host], None)["status"], "warning")
        auditd_only = {"host": "n1", "cdi": {**host["cdi"], "monitors": ["auditd"]}}
        self.assertEqual(exposure.grade_cdi([auditd_only], None)["status"], "warning")
        spec["hooks"][0]["loader_env"] = ["LD_AUDIT"]
        self.assertEqual(exposure.grade_cdi([host], None)["status"], "fail")
        empty = {"host": "n1", "cdi": {"specs": [], "monitors": []}}
        self.assertEqual(exposure.grade_cdi([empty], None)["status"], "not_applicable")

    def test_operator_cdi_without_a_monitor_pod_warns(self) -> None:
        k8s = {"cdi_enabled": True, "monitors": []}
        self.assertEqual(exposure.grade_cdi([], k8s)["status"], "warning")
        k8s["monitors"] = ["falco"]
        self.assertEqual(exposure.grade_cdi([], k8s)["status"], "pass")


class RayTests(unittest.TestCase):
    def test_dashboard_on_every_address_without_token_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site = ray_site(root, "2.49.1")
            fake_proc(root / "proc", listen="00000000", ray_site=site)
            facts = exposure.local_ray_facts(str(root / "proc"))
        self.assertEqual(facts["listen"], ["0.0.0.0"])
        self.assertEqual(facts["dashboards"], [{"version": "2.49.1", "auth_mode": "disabled"}])
        verdict = exposure.grade_ray([{"host": "n1", "ray": facts}], None)
        self.assertEqual(verdict["status"], "fail")
        self.assertIn("CVE-2023-48022", verdict["message"])

    def test_token_auth_or_loopback_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site = ray_site(root, "2.60.0")
            fake_proc(root / "proc", listen="00000000", auth="token", ray_site=site)
            token = exposure.local_ray_facts(str(root / "proc"))
        loopback = {"dashboards": [{"version": "2.60.0", "auth_mode": "disabled"}],
                    "listen": ["127.0.0.1"]}
        self.assertEqual(exposure.grade_ray([{"host": "n1", "ray": token}], None)["status"], "pass")
        self.assertEqual(exposure.grade_ray([{"host": "n1", "ray": loopback}], None)["status"], "pass")

    def test_loopback_dashboard_older_than_token_auth_warns(self) -> None:
        facts = {"dashboards": [{"version": "2.40.0", "auth_mode": "disabled"}], "listen": ["127.0.0.1"]}
        self.assertEqual(exposure.grade_ray([{"host": "n1", "ray": facts}], None)["status"], "warning")

    def test_no_ray_is_not_applicable(self) -> None:
        facts = {"dashboards": [], "listen": []}
        self.assertEqual(exposure.grade_ray([{"host": "n1", "ray": facts}], None)["status"], "not_applicable")


class KubernetesTests(unittest.TestCase):
    PAYLOADS = {
        "nodes": {"items": [{
            "metadata": {"name": "k1", "labels": {"nvidia.com/gpu.product": "NVIDIA-H100-80GB-HBM3"}},
            "status": {"capacity": {"nvidia.com/mig-1g.10gb": "7"}},
        }]},
        "clusterpolicies": {"items": [{"spec": {"cdi": {"enabled": True}}}]},
        "pods": {"items": [
            {"metadata": {"name": "ray-head", "namespace": "ml", "labels": {"ray.io/node-type": "head"}},
             "spec": {"containers": [{"image": "rayproject/ray:2.47.1-py311-gpu", "env": []}]},
             "status": {"phase": "Running"}},
            {"metadata": {"name": "ais-target-0", "namespace": "ais", "labels": {}},
             "spec": {"containers": [{"image": "aistorage/aisnode:v5.0"}]},
             "status": {"phase": "Running"}},
        ]},
        "services": {"items": [{
            "metadata": {"name": "ray-head-svc", "namespace": "ml"},
            "spec": {"type": "LoadBalancer", "ports": [{"port": 8265}]},
        }]},
    }

    def test_api_inventory_finds_each_topic(self) -> None:
        facts = exposure.k8s_facts(self.PAYLOADS)
        self.assertEqual(facts["nodes"][0]["mig_instances"], 7)
        self.assertTrue(facts["cdi_enabled"])
        self.assertEqual(facts["ray"][0]["version"], "2.47.1")
        self.assertEqual(facts["aistore"][0]["version"], "5.0")
        self.assertEqual(exposure.grade_ray([], facts)["status"], "fail")
        aistore = exposure.grade_aistore([], facts)
        self.assertEqual(aistore["status"], "present")
        # The shipped table publishes the AIStore minimum, so 5.0 is below it.
        self.assertTrue(aistore["minimum"])
        self.assertEqual(aistore["versionStatus"], "fail")
        self.assertEqual(aistore["deployments"][0]["status"], "fail")
        with mock.patch.object(exposure, "aistore_minimum", return_value=("", "")):
            self.assertEqual(exposure.grade_aistore([], facts)["versionStatus"], "unknown")


class PayloadTests(unittest.TestCase):
    def test_standalone_payload_has_every_topic(self) -> None:
        def runner(command, **_kwargs):
            out = GPU_QUERY if any("--query-gpu" in part for part in command) else GPU_LISTING
            return subprocess.CompletedProcess(command, 0, out, "")

        with mock.patch.object(exposure, "local_cdi_facts", return_value={"specs": [], "monitors": []}), \
                mock.patch.object(exposure, "local_ray_facts", return_value={"dashboards": [], "listen": []}), \
                mock.patch.object(exposure, "local_aistore_facts", return_value={"processes": 0}):
            payload = exposure.build_payload(
                harness="standalone", runner=runner, which=lambda name: f"/usr/bin/{name}"
            )[exposure.KEY]
        self.assertEqual(payload["mig"]["status"], "warning")
        self.assertEqual(payload["ecc"]["status"], "not_applicable")
        self.assertEqual(payload["cdiHooks"]["status"], "not_applicable")
        self.assertEqual(payload["status"], "warning")
        self.assertIn("mig", payload["message"])

    def test_worker_runs_from_standard_input(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-", "--worker"],
            input=CHECK.read_text(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
            env={**os.environ, "PATH": "/nonexistent"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        record = json.loads(proc.stdout)
        self.assertIn("host", record)
        self.assertEqual(record["gpu"]["status"], "nvidia_smi_missing")

    def test_check_is_executable_and_selected_for_security(self) -> None:
        self.assertTrue(os.access(CHECK, os.X_OK))


def audit_with(topic: str, value: dict) -> dict:
    return {"gpu_runtime_exposure": {topic: value}}


class SecurityGradeTests(unittest.TestCase):
    def _check(self, check_id: str, audit: dict) -> security.SecurityCheck:
        return next(check for check in security.evaluate_security(audit) if check.id == check_id)

    def test_topic_status_maps_to_security_status(self) -> None:
        cases = {"fail": security.CRITICAL, "warning": security.WARNING,
                 "unknown": security.WARNING, "pass": security.PASS,
                 "not_applicable": security.NOT_APPLICABLE}
        for status, expected in cases.items():
            with self.subTest(status=status):
                check = self._check("ray-dashboard-exposure", audit_with(
                    "ray", {"status": status, "message": "m", "endpoints": ["n1 listens"]}
                ))
                self.assertEqual(check.status, expected)
                self.assertIn("n1 listens", check.observed)

    def test_observed_states_the_reason_without_evidence_rows(self) -> None:
        check = self._check("mig-side-channel", audit_with(
            "mig", {"status": "not_applicable", "message": "No GPU has more than one MIG instance."}
        ))
        self.assertEqual(check.status, security.NOT_APPLICABLE)
        self.assertEqual(check.observed, "No GPU has more than one MIG instance.")

    def test_missing_evidence_warns(self) -> None:
        for check_id in ("mig-side-channel", "gpu-ecc-rowhammer",
                         "nvidia-cdi-hook-monitoring", "ray-dashboard-exposure", "aistore"):
            with self.subTest(check_id=check_id):
                self.assertEqual(self._check(check_id, {}).status, security.WARNING)

    def test_aistore_grades_each_deployment_against_the_table(self) -> None:
        present = {"status": "present", "deployments": [
            {"where": "ais/ais-target-0", "version": "5.0"},
        ]}
        block = {"minimum": "5.1", "advisory": "https://example.invalid/aistore", "cves": []}
        with mock.patch.object(security, "minimum_component",
                               side_effect=lambda name, repo=None: block if name == "aistore" else {}):
            below = self._check("aistore", audit_with("aistore", present))
            present["deployments"][0]["version"] = "5.2"
            fixed = self._check("aistore", audit_with("aistore", present))
            present["deployments"][0]["version"] = "unknown"
            unknown = self._check("aistore", audit_with("aistore", present))
        self.assertEqual(below.status, security.CRITICAL)
        self.assertIn("minimum version 5.1", below.observed)
        self.assertEqual(fixed.status, security.PASS)
        self.assertEqual(unknown.status, security.WARNING)
        absent = self._check("aistore", audit_with("aistore", {"status": "not_applicable"}))
        self.assertEqual(absent.status, security.NOT_APPLICABLE)

    def test_dcgm_exporter_is_graded_from_the_collected_verdict(self) -> None:
        audit = {"securityVersions": {"dcgmExporter": {
            "status": "fail", "version": "4.8.1", "minimum": "4.8.2",
            "detail": "Below the DCGM Exporter minimum version (4.8.2)",
        }}}
        check = self._check("dcgm-exporter", audit)
        self.assertEqual(check.status, security.CRITICAL)
        self.assertIn("observed version 4.8.1", check.observed)
        self.assertIn("--enable-pprof", check.remediation)


if __name__ == "__main__":
    unittest.main()
