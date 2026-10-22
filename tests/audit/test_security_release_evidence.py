"""Offline collector and report checks using synthetic host evidence."""
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


@pytest.mark.parametrize("status", ["fail", "pass"])
def test_generic_fragnesia_abi_result_survives_missing_package_evidence(status):
    run = bashtest.run_bash(
        f'source "{WORK}/audit-common.sh"\n'
        'build_security_advisory_json --bad-epoll-os ubuntu --bad-epoll-release 24.04 '
        '--bad-epoll-running 6.8.0-120-generic '
        f'--fragnesia-status {status} --fragnesia-compared-abi 121'
    )
    assert run.returncode == 0, run.stderr
    data = json.loads("{" + run.stdout + '"_end": null}')
    assert data["fragnesia"]["status"] == status or (
        status == "fail" and data["fragnesia"]["gracePeriod"] is not None
    )
    assert data["fragnesia"]["comparedAbiFloor"] == "121"


def test_multiple_dpus_require_per_device_mode_evidence(tmp_path):
    for bdf in ("0000:03:00.0", "0000:04:00.0"):
        dev = tmp_path / "sys/bus/pci/devices" / bdf
        dev.mkdir(parents=True)
        (dev / "vendor").write_text("0x15b3\n")
        (dev / "device").write_text("0xa2dc\n")
        (dev / "class").write_text("0x020000\n")
    called = tmp_path / "mlxconfig-called"
    run = bashtest.run_bash(
        'lspci() { return 127; }\n' + virtio.K8S_COLLECTOR_SH,
        env={"CLUSTERMAX_AUDIT_ROOT": str(tmp_path), "CALLED": str(called)},
        stubs={
            "mlxconfig": 'touch "$CALLED"; printf "Configurations: Next Boot\\nINTERNAL_CPU_OFFLOAD_ENGINE 1\\n"',
            "virtnet": 'printf "version: 99.0.0\\n"',
        },
    )
    assert run.returncode == 0, run.stderr
    assert not called.exists()
    record = virtio.record_from_k8s("fixture-node", virtio.parse_k8s_collector(run.stdout))
    assert "per-device" in record["modeError"]
    assert record["mode"] == "unknown"
    assert record["version"] is None
    assert record["state"] not in {virtio.STATE_NOT_RUNNING, virtio.STATE_VERSION}


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
    monkeypatch.setattr(kernel.minimum_versions, "_CACHE", None)
    abi = version.split("-")[1].split(".")[0]
    result = kernel.evaluate(
        "ubuntu", "24.04", f"6.17.0-{abi}-nvidia-64k",
        f"Ubuntu {version}-nvidia-64k 6.17.13",
        f"hi |linux-signed-nvidia-6.17|{version}", "none", advisory="fragnesia",
    )
    assert result["status"] == expected
    assert result["cve"] == "CVE-2026-46300"
    assert result["minimum"] == "6.17.0-1021.21"


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


@pytest.mark.parametrize("complete,missing,disabled,expected", [
    (True, False, False, security.PASS),
    (True, True, False, security.WARNING),
    (True, False, True, security.CRITICAL),
    (False, False, False, security.WARNING),
])
def test_ufm_complete_control_results(complete, missing, disabled, expected):
    controls = dict.fromkeys((
        "madKeyProtection", "guidAccessControl", "serviceAuthentication",
        "saTrustModel", "madRateLimiting", "dosProtection", "sourceRateLimiting",
    ), True)
    if missing:
        del controls["madRateLimiting"]
    if disabled:
        controls["madKeyProtection"] = False
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


@pytest.mark.parametrize("resource,expected", [
    ("nvidia.com/gpu", True), ("nvidia.com/gpu.shared", True),
    ("nvidia.com/mig-1g.10gb", True), ("other/nvidia.com/gpu", False),
    ("nvidia.com/gpu-fake", False), ("nvidia.com/rdma", False),
])
def test_gpu_resource_names_are_exact_kubernetes_keys(resource, expected):
    pod = gpu_pod()
    pod["spec"]["containers"][0]["resources"] = {"limits": {resource: "1"}}
    assert bool(runtime.targets({"items": [pod]}, "gpu-test")) is expected


def test_network_probe_prefers_verified_host_root_over_driver_image():
    pods = {"items": [
        {"metadata": {"name": "nvidia-driver-sample"},
         "status": {"phase": "Running"}, "spec": {"containers": [{"name": "driver"}]}},
        {"metadata": {"name": "nvidia-device-plugin-sample"},
         "status": {"phase": "Running"},
         "spec": {
             "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
             "containers": [{"name": "plugin", "securityContext": {"privileged": True},
                             "volumeMounts": [{"name": "host-root", "mountPath": "/host",
                                              "readOnly": True}]}],
         }},
    ]}
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, json.dumps(pods), "")
    chosen = virtio.k8s_driver_pod("operators", "worker", runner=fake_runner)
    assert chosen == {"name": "nvidia-device-plugin-sample", "container": "plugin", "hostRoot": True}


@pytest.mark.parametrize("offline", [True, False])
def test_published_table_cannot_drop_new_release_checks(tmp_path, monkeypatch, offline):
    from cmax import minimum_sync
    base = {"schemaVersion": 1, "generated": "2026-10-15T00:00:00Z", "components": {
        "ubuntuNoble": {"packages": {"linuxBadEpollNvidia617": {"fixed": "6.17.0-1031.31"}}},
    }}
    installed = tmp_path / "installed.json"
    installed.write_text(json.dumps(base))
    fetched = tmp_path / "fetched.json"
    fetched.write_text(json.dumps({
        "schemaVersion": 1, "generated": "2026-10-16T00:00:00Z",
        "components": {"ubuntuNoble": {"packages": {}}},
    }))
    monkeypatch.delenv(security.MINIMUMS_ENV, raising=False)
    monkeypatch.setattr(security, "minimum_table_path", lambda repo: installed)
    outcome = minimum_sync.SyncResult(
        not offline, not offline, None if offline else fetched,
        None if offline else "2026-10-16T00:00:00Z", "fixture",
    )
    monkeypatch.setattr(minimum_sync, "sync", lambda **kwargs: outcome)
    monkeypatch.setattr(minimum_sync, "cached_table", lambda: (fetched, "2026-10-16T00:00:00Z"))
    assert security.sync_minimum_table() is False
    assert not os.environ.get(security.MINIMUMS_ENV)


@pytest.mark.parametrize("state,expected", [
    ("pass", audit_report.PASS), ("fail", audit_report.FAIL), ("unknown", audit_report.WARNING),
])
def test_completed_dpu_isolation_failure_is_not_downgraded(state, expected):
    values = {"audit_data": {
        "securityVersions": {"dpuHostIsolation": {
            "status": state, "bluefield3Present": True, "scanComplete": True,
            "internalCpuRshim": "1" if state == "pass" else "0" if state == "fail" else "unknown",
        }},
    }}
    result = next(c for c in audit_report.evaluate(values, ROOT / "cmax")
                  if c.key == "securityVersions.dpuHostIsolation.status")
    assert result.status == expected
    assert "INTERNAL_CPU_RSHIM=" in result.observed


def test_unrestricted_configuration_does_not_claim_an_executed_dpu_escape():
    result = runtime.policy.dpu_host_isolation_result({
        "scanComplete": True, "bluefield3Present": True,
        "rshimHostAccess": {
            "rshimRestricted": False, "internalCpuRshim": "0",
            "rshimDeviceNode": False, "tmfifoNet0": False,
        },
    })
    assert result["status"] == "fail"
    assert result["findingBasis"] == "unrestricted-rshim-configuration"
    assert "no DPU login or escape was attempted" in result["detail"]


@pytest.mark.parametrize("current,next_boot", [("0", "1"), ("1", "0")])
def test_mlxconfig_uses_current_not_pending_or_default(current, next_boot):
    text = f"""
Configurations: Default Current Next Boot
  INTERNAL_CPU_MODEL EMBEDDED_CPU(1) EMBEDDED_CPU(1) EMBEDDED_CPU(1)
  INTERNAL_CPU_RSHIM DISABLED(1) {current} {next_boot}
  INTERNAL_CPU_OFFLOAD_ENGINE DISABLED(1) {current} {next_boot}
"""
    values = virtio.parse_mlxconfig(text)
    assert values["INTERNAL_CPU_RSHIM"] == current
    assert values["INTERNAL_CPU_OFFLOAD_ENGINE"] == current


@pytest.mark.parametrize("header", ["Configurations: Next Boot", ""])
def test_pending_only_or_unlabelled_mode_is_not_current_evidence(header):
    assert virtio.parse_mlxconfig(header + "\nINTERNAL_CPU_RSHIM DISABLED(1)") == {}


def shared_rdma_resource(
    is_rdma=True, array_selectors=False, namespace="nvidia-network-operator",
    shared_key=None,
):
    function = bashtest.extract_block(
        WORK / "k8s-control.sh", "k8s_detect_shared_rdma_resource() {", "# List the Multus"
    )
    selectors = {"isRdma": is_rdma}
    config = {"data": {"config.json": json.dumps({"resourceList": [
        {"resourcePrefix": "nvidia.com", "resourceName": "hostdev",
         "selectors": [selectors] if array_selectors else selectors}
    ]})}}
    nodes = {"items": [{"status": {"allocatable": {"nvidia.com/hostdev": "8"}}}]}
    if shared_key:
        nodes["items"][0]["status"]["allocatable"][shared_key] = "8"
    run = bashtest.run_bash(
        function + "\nk8s_detect_shared_rdma_resource",
        env={
            "TEST_CONFIG": json.dumps(config),
            "TEST_NODES": json.dumps(nodes),
            "TEST_NAMESPACE": namespace,
        },
        stubs={"kubectl": (
            'if [[ "$2" == configmap ]]; then [[ "$5" == "$TEST_NAMESPACE" ]] || exit 1; '
            'printf "%s" "$TEST_CONFIG"; else printf "%s" "$TEST_NODES"; fi'
        )},
    )
    assert run.returncode == 0, run.stderr
    return run.stdout.strip()


@pytest.mark.parametrize("is_rdma,expected", [(True, "nvidia.com/hostdev"), (False, "")])
@pytest.mark.parametrize("array_selectors", [False, True])
@pytest.mark.parametrize("namespace", ["nvidia-network-operator", "network-operator", "mellanox"])
def test_shared_rdma_helper_uses_sriov_configuration(
    is_rdma, expected, array_selectors, namespace,
):
    assert shared_rdma_resource(is_rdma, array_selectors, namespace) == expected


@pytest.mark.parametrize("shared_key", ["rdma/shared", "nvidia.com/rdma_shared_device_a"])
def test_explicit_shared_rdma_resource_precedes_hostdev(shared_key):
    assert shared_rdma_resource(shared_key=shared_key) == shared_key


@pytest.mark.parametrize("prefix", [None, "intel.com", "synthetic.example", "nvidia.com"])
@pytest.mark.parametrize("array_selectors", [False, True])
def test_workload_and_inventory_agree_on_hostdev_prefix(prefix, array_selectors):
    from test_k8s_collector import run_detection

    resource = {
        "resourceName": "hostdev",
        "selectors": [{"isRdma": True}] if array_selectors else {"isRdma": True},
    }
    if prefix is not None:
        resource["resourcePrefix"] = prefix
    config = {"resourceList": [resource]}
    function = bashtest.extract_block(
        WORK / "k8s-control.sh", "k8s_detect_shared_rdma_resource() {", "# List the Multus"
    )
    helper = bashtest.run_bash(
        function + "\nk8s_detect_shared_rdma_resource",
        env={
            "TEST_CONFIG": json.dumps({"data": {"config.json": json.dumps(config)}}),
            "TEST_NODES": json.dumps({"items": [{"status": {
                "allocatable": {"nvidia.com/hostdev": "3"},
            }}]}),
        },
        stubs={"kubectl": (
            'if [[ "$2" == configmap ]]; then printf "%s" "$TEST_CONFIG"; '
            'else printf "%s" "$TEST_NODES"; fi'
        )},
    )
    inventory = run_detection({"nvidia.com/hostdev": "3"}, config)
    assert helper.returncode == inventory.returncode == 0
    if prefix == "nvidia.com":
        assert helper.stdout.strip() == "nvidia.com/hostdev"
        assert "TYPE=rdma" in inventory.stdout
    else:
        assert helper.stdout.strip() == ""
        assert "TYPE=none" in inventory.stdout
