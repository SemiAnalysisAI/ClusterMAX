"""Release regressions from scoped collector evidence, without contacting a cluster."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from cmax import audit_report, security

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "cmax/scripts/1-audit"
sys.path.insert(0, str(WORK))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bashtest


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


virtio = load("release_virtio", WORK / "checks/fabric/virtio-net-check.py")
kernel = load("release_kernel", WORK / "bad_epoll.py")


def test_loaded_module_driver_without_nvidia_smi(tmp_path):
    version = tmp_path / "proc/driver/nvidia"
    version.mkdir(parents=True)
    (version / "version").write_text(
        "NVRM version: NVIDIA UNIX Open Kernel Module for aarch64  580.173.02  Release Build\n"
    )
    block = bashtest.extract_block(
        WORK / "host-check.sh",
        '    module_driver=$(sed',
        '    echo "WORKER_DRIVER_VERSION=${module_driver:-unknown}"',
    )
    run = bashtest.run_bash(block, env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)})
    assert run.returncode == 0
    assert "WORKER_DRIVER_VERSION=580.173.02" in run.stdout


@pytest.mark.parametrize("selection", ["ii", "hi", "ri", "pi"])
def test_kernel_inventory_accepts_installed_selection_states(selection):
    block = bashtest.extract_block(
        WORK / "host-check.sh",
        "WORKER_GUEST_KERNEL_NEWEST_INSTALLED=unknown",
        'echo "WORKER_GUEST_REBOOT_REQUIRED=${WORKER_GUEST_REBOOT_REQUIRED}"',
    )
    run = bashtest.run_bash(
        'WORKER_GUEST_KERNEL_RUNNING=6.17.0-1021-nvidia-64k\n'
        f'dpkg-query() {{ printf "{selection} linux-image-6.17.0-1031-nvidia-64k\\n"; }}\n'
        + block
    )
    assert run.returncode == 0, run.stderr
    assert "WORKER_GUEST_KERNEL_NEWEST_INSTALLED=6.17.0-1031-nvidia-64k" in run.stdout
    assert "WORKER_GUEST_KERNEL_NEWER_INSTALLED=true" in run.stdout


@pytest.mark.parametrize("newest,newer,grade", [
    ("unknown", False, audit_report.WARNING),
    ("6.17.0-1021-nvidia-64k", False, audit_report.PASS),
    ("6.17.0-1031-nvidia-64k", True, audit_report.FAIL),
])
def test_kernel_report_uses_inventory_not_false_default(newest, newer, grade):
    values = {"audit_data": {"security": {"guestKernel": {
        "running": "6.17.0-1021-nvidia-64k", "newestInstalled": newest,
        "newerInstalled": newer,
    }}}}
    result = next(c for c in audit_report.evaluate(values, ROOT / "cmax")
                  if c.key == "security.guestKernel.newerInstalled")
    assert result.status == grade


@pytest.mark.parametrize("pci_id,complete", [("1023", True), ("a2dc", True), ("1023", False)])
def test_pci_sysfs_fallback_without_lspci(tmp_path, pci_id, complete):
    dev = tmp_path / "sys/bus/pci/devices/0000:03:00.0"
    dev.mkdir(parents=True)
    (dev / "vendor").write_text("0x15b3\n")
    (dev / "device").write_text(f"0x{pci_id}\n")
    if complete:
        (dev / "class").write_text("0x020700\n")
    # A failing lspci must use sysfs, without loading modules or installing tools.
    run = bashtest.run_bash(
        'lspci() { return 127; }\n' + virtio.K8S_COLLECTOR_SH,
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path)},
    )
    record = virtio.record_from_k8s("test-node", virtio.parse_k8s_collector(run.stdout))
    assert record["scanComplete"] is complete
    if complete:
        assert record["bluefield3Present"] is (pci_id == "a2dc")
    else:
        assert record["state"] == "incomplete"


@pytest.mark.parametrize("version,expected", [("6.17.0-1020.20", "fail"), ("6.17.0-1021.21", "pass")])
def test_fragnesia_nvidia_uses_source_minimum(version, expected, monkeypatch, tmp_path):
    table = tmp_path / "minimum.json"
    table.write_text(json.dumps({"schemaVersion": 1, "components": {"ubuntuNoble": {
        "packages": {"linuxFragnesiaNvidia617": {
            "cve": "CVE-2026-46300", "relatedCves": ["CVE-2026-43284", "CVE-2026-43500"],
            "fixed": "6.17.0-1021.21", "status": "released", "package": "linux-nvidia-6.17",
        }},
    }}}))
    monkeypatch.setenv("CLUSTERMAX_MINIMUM_VERSIONS", str(table))
    kernel.minimum_versions._CACHE = None
    abi = version.split("-")[1].split(".")[0]
    result = kernel.evaluate(
        "ubuntu", "24.04", f"6.17.0-{abi}-nvidia-64k",
        f"Ubuntu {version}-nvidia-64k 6.17.13",
        f"hi |linux-signed-nvidia-6.17|{version}", "none", advisory="fragnesia",
    )
    assert result["status"] == expected
    assert result["cve"] == "CVE-2026-46300"
    assert result["minimum"] == "6.17.0-1021.21"
    kernel.minimum_versions._CACHE = None


@pytest.mark.parametrize("guest,complete,devices,unsafe,expected", [
    (False, True, 0, 0, security.NOT_APPLICABLE),
    (False, False, 0, 0, security.WARNING),
    (True, True, 0, 0, security.WARNING),
    (False, True, 2, 1, security.CRITICAL),
    (False, True, 2, 0, security.WARNING),
    (None, True, 0, 0, security.WARNING),
])
def test_pcie_boundary_requires_physical_host_evidence(guest, complete, devices, unsafe, expected):
    audit = {"security": {
        "virtualization": {"guest": guest},
        "pciePassthrough": {"inventoryComplete": complete, "vfioDevices": devices,
                            "unsafeGroups": unsafe, "scope": "sampled-worker-host"},
    }}
    assert security._pcie_boundary(audit)[0] == expected


def test_explicit_nonexclusive_nvlink_domain_fails():
    audit = {"security": {"nvlinkBoundary": {
        "nvlinkExposed": True, "topologyChecked": True,
        "topologyCoverageComplete": True, "domainExclusive": False,
    }}}
    assert security._nvlink_boundary(audit)[0] == security.CRITICAL


def test_gpu_operator_toolkit_path_is_host_scoped():
    block = bashtest.extract_block(
        WORK / "container-check.sh",
        '# GPU Operator installs host-runtime wrappers here',
        '# Docker and the NVIDIA runtime registration.',
    )
    assert 'RUNTIME_SCOPE" == host' in block
    assert "/usr/local/nvidia/toolkit" in block


def test_security_collector_grades_resolved_driver():
    text = (WORK / "cluster-audit-slurm-security.sh").read_text()
    call = text.split("SECURITY_VERSION_AUDIT_JSON=$(build_security_version_audit", 1)[1].split(
        'print_info "Security version policy', 1
    )[0]
    assert '"${NVIDIA_DRIVER_VERSION:-unknown}"' in call
    assert '"${WORKER_DRIVER_VERSION:-unknown}"' not in call


@pytest.mark.parametrize("complete,missing,disabled,expected", [
    (True, False, False, security.PASS),
    (True, True, False, security.WARNING),
    (True, False, True, security.CRITICAL),
    (False, False, False, security.WARNING),
])
def test_ufm_complete_control_results(complete, missing, disabled, expected):
    controls = dict.fromkeys((
        "smkeyAuthentication", "mkeyAuthentication", "mkeyProtectBits",
        "forceSmAssignment", "disableHostPort0Sma", "forceDmAssignment", "limitMadQueue",
    ), True)
    if missing:
        del controls["limitMadQueue"]
    if disabled:
        controls["mkeyAuthentication"] = False
    record = {"probeComplete": complete, "controls": controls}
    assert security._ufm({"security": {"ufmSecuredBareMetalCloud": record}})[0] == expected


runtime = load("release_runtime", WORK / "k8s_runtime_software.py")


def gpu_pod(node="gpu-test"):
    return {"metadata": {"name": "workload", "namespace": "test"},
            "status": {"phase": "Running"},
            "spec": {"nodeName": node, "containers": [
                {"name": "app", "resources": {"limits": {"nvidia.com/gpu": "1"}}},
                {"name": "sidecar"},
            ]}}


@pytest.mark.parametrize("payload,rc,expected", [
    ("CUDA_TOOLKIT_VERSION=13.2.84\n", 0, "pass"),
    ("CUDA_TOOLKIT_VERSION=1.0.0\n", 0, "fail"),
    ("CUDA_TOOLKIT_VERSION=not_installed\n", 0, "not_applicable"),
    ("", 1, "unknown"),
    ('CUDA_VERSION_JSON\n{"cuda":{"version":"13.2.0"}}', 0, "pass"),
    ("CUDA_TOOLKIT_VERSION=unknown\n", 0, "unknown"),
])
def test_workload_toolkit_is_separate_from_driver_compatibility(payload, rc, expected, monkeypatch):
    def fixture_verdict(version):
        state = ("not_applicable" if version == "not_installed" else
                 "unknown" if version == "unknown" else
                 "fail" if version == "1.0.0" else "pass")
        return {"version": version, "status": state, "minimum": "13.0.0",
                "advisory": "fixture", "detail": "fixture"}
    monkeypatch.setattr(runtime, "verdict", fixture_verdict)
    calls = []
    def fake_run(argv):
        calls.append(argv)
        if argv[0] == "get":
            return 0, json.dumps({"items": [gpu_pod(), gpu_pod("different-node")]})
        return rc, payload
    before = {"securityVersions": {"cudaToolkit": fixture_verdict("not_installed")}}
    after = runtime.enrich(before, "gpu-test", runner=fake_run)
    assert after["securityVersions"]["cudaToolkit"]["status"] == expected
    assert len(calls) == 2
    assert after["runtimeSoftware"]["cudaToolkit"]["discoveredContainers"] == 1
    assert "nvidia-smi" not in runtime.PROBE


def test_runtime_node_is_original_sample_not_last_bmc_node():
    text = (WORK / "cluster-audit-slurm-security.sh").read_text()
    assert '"${WORKLOAD_DIR}/k8s_runtime_software.py" --node "$GPU_PARTITION"' in text
    assert 'SECURITY_TARGET_NODE' not in text
