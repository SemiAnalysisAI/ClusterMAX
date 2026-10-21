"""Exercise huge-page units, neutral scoring, and bounded pool restoration."""

import importlib.util
import json
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "cmax/scripts/1-audit/checks/system/hugepages.py"
spec = importlib.util.spec_from_file_location("hugepages", CHECK)
hp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hp)


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value))


def pool(root, size, total, free, surplus=0):
    base = f"{hp.HUGETLB}/hugepages-{size}kB"
    for key, value in {"nr_hugepages": total, "free_hugepages": free,
                       "surplus_hugepages": surplus, "resv_hugepages": 0}.items():
        write(root, f"{base}/{key}", value)


@pytest.mark.parametrize("top,per_size,status", [
    ("always [madvise] never", None, "pass"),
    ("[always] madvise never", None, "neutral"),
    ("always madvise [never]", "[madvise] always inherit never", "pass"),
    ("always [madvise] never", "always madvise [inherit] never", "pass"),
    ("always [madvise] never", "always madvise inherit [never]", "neutral"),
    ("always madvise never", None, "unknown"),
])
def test_only_effective_selected_madvise_passes(tmp_path, top, per_size, status):
    write(tmp_path, f"{hp.THP}/enabled", top)
    if per_size:
        write(tmp_path, f"{hp.THP}/hugepages-2048kB/enabled", per_size)
    assert hp.thp_report(tmp_path)["status"] == status


def test_all_size_bytes_exclude_surplus_from_persistent_total(tmp_path):
    pool(tmp_path, 2048, 514, 500, surplus=2)
    pool(tmp_path, 1048576, 1, 1)
    write(tmp_path, "proc/meminfo", """HugePages_Total: 514
HugePages_Free: 500
HugePages_Rsvd: 4
HugePages_Surp: 2
Hugepagesize: 2048 kB
Hugetlb: 2101248 kB
""")
    r = hp.static_report(tmp_path)
    assert r["status"] == "neutral"
    assert r["total_bytes"] == 2 * hp.GIB + 4 * 1024 ** 2
    assert r["persistent_bytes"] == 2 * hp.GIB
    assert r["total_gb"] == r["total_bytes"] / 1e9
    assert r["total_gib"] == r["total_bytes"] / hp.GIB
    (tmp_path / "proc/meminfo").unlink()
    assert hp.static_report(tmp_path)["total_bytes"] == r["total_bytes"]
    (tmp_path / hp.HUGETLB / "hugepages-2048kB/surplus_hugepages").unlink()
    assert hp.static_report(tmp_path)["total_bytes"] is None


def test_missing_counters_are_unknown_and_zero_is_neutral(tmp_path):
    assert hp.static_report(tmp_path)["status"] == "unknown"
    assert hp.thp_report(tmp_path)["status"] == "unknown"
    write(tmp_path, "proc/meminfo", "Hugetlb: 0 kB\n")
    assert hp.static_report(tmp_path)["total_gb"] == 0
    assert hp.static_report(tmp_path)["status"] == "neutral"


@pytest.mark.parametrize("mode,expected,restored", [
    ("success", "pass", True), ("gigantic", "pass", True), ("partial", "incomplete", True),
    ("denied", "error", True), ("signal", "error", True),
    ("hangup", "error", True), ("interrupt", "error", True), ("quit", "error", True),
    ("cleanup", "error", False), ("busy", "skipped", None),
    ("low-memory", "skipped", None), ("large-size", "skipped", None),
    ("concurrent", "error", False),
])
def test_allocation_verifies_growth_and_restores_even_on_failure(monkeypatch, mode, expected, restored):
    state = {"pages": 10}
    writes = []
    def info(_):
        return {"Hugepagesize": 2097152 if mode == "large-size" else 1048576 if mode == "gigantic" else 2048,
                "HugePages_Total": state["pages"],
                "HugePages_Free": state["pages"] - (1 if mode == "busy" or (mode == "concurrent" and writes) else 0),
                "HugePages_Rsvd": 0, "HugePages_Surp": 0,
                "MemAvailable": 100 if mode == "low-memory" else 8388608}
    def writer(path, text):
        assert str(path) == "/proc/sys/vm/nr_hugepages"
        value = int(text)
        writes.append(value)
        if len(writes) == 1:
            if mode == "denied":
                raise PermissionError("denied")
            state["pages"] = 20 if mode in {"partial", "signal", "hangup", "interrupt", "quit"} else value
            sig = {
                "signal": signal.SIGTERM, "hangup": signal.SIGHUP,
                "interrupt": signal.SIGINT, "quit": signal.SIGQUIT,
            }.get(mode)
            if sig is not None:
                signal.getsignal(sig)(sig, None)
        elif mode == "cleanup":
            raise OSError("read-only")
        else:
            state["pages"] = value
        return len(text)
    monkeypatch.setattr(hp, "meminfo", info)
    monkeypatch.setattr(hp, "number", lambda _: state["pages"])
    monkeypatch.setattr(Path, "write_text", writer)
    handlers = {
        sig: signal.getsignal(sig)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
    }
    result = hp._allocation_trial(Path("/"))
    assert result["status"] == expected
    assert result["restored"] is restored
    assert {sig: signal.getsignal(sig) for sig in handlers} == handlers
    assert writes == ([] if expected == "skipped" else [522] if mode == "concurrent" else [11, 10] if mode == "gigantic" else [522, 10])
    if mode in {"success", "gigantic"}:
        assert result["allocated_bytes"] == hp.GIB


def test_real_hangup_restores_a_simulated_pool_in_an_isolated_process():
    # All pool I/O is replaced before running the trial. No host writes occur.
    script = r'''
import importlib.util
import json
import os
import signal
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("isolated_hugepages", sys.argv[1])
hp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hp)
state = {"pages": 10}
writes = []
hp.meminfo = lambda root: {
    "Hugepagesize": 2048, "HugePages_Total": state["pages"],
    "HugePages_Free": state["pages"], "HugePages_Rsvd": 0,
    "HugePages_Surp": 0, "MemAvailable": 8388608,
}
hp.number = lambda path: state["pages"]
def simulated_write(path, text):
    assert str(path) == "/proc/sys/vm/nr_hugepages"
    state["pages"] = int(text)
    writes.append(state["pages"])
    if len(writes) == 1:
        os.kill(os.getpid(), signal.SIGHUP)
    return len(text)
Path.write_text = simulated_write
signal.signal(signal.SIGHUP, signal.SIG_DFL)
result = hp._allocation_trial(Path("/"))
print(json.dumps({
    "result": result, "pages": state["pages"], "writes": writes,
    "handler_restored": signal.getsignal(signal.SIGHUP) == signal.SIG_DFL,
}))
'''
    proc = subprocess.run(
        [sys.executable, "-c", script, str(CHECK)],
        text=True, capture_output=True, timeout=10, check=True,
    )
    result = json.loads(proc.stdout)
    assert result["result"]["status"] == "error"
    assert result["result"]["restored"] is True
    assert result["pages"] == 10
    assert result["writes"] == [522, 10]
    assert result["handler_restored"] is True
    assert "received signal" in result["result"]["message"]


def test_passive_worker_runs_from_stdin_and_never_attempts_allocation(tmp_path):
    write(tmp_path, f"{hp.THP}/enabled", "always [madvise] never")
    write(tmp_path, "proc/meminfo", "Hugetlb: 0 kB\n")
    proc = subprocess.run(
        [sys.executable, "-", "--collect-host", "--root", str(tmp_path), "--harness", "k8s"],
        input=CHECK.read_text(), text=True, capture_output=True, check=True,
    )
    report = json.loads(proc.stdout)
    assert report["thp_madvise"]["status"] == "pass"
    assert report["hugepage_allocation"]["status"] == "skipped"
    assert not (tmp_path / hp.NR).exists()
    assert hp.allocation_trial(tmp_path, enabled=True)["status"] == "skipped"


def test_aggregate_and_terminal_preserve_neutral_and_unknown(tmp_path):
    from cmax import audit_report
    report = hp.collect_host(tmp_path)
    report["thp_madvise"].update(status="pass")
    report["static_hugepages"].update(status="neutral")
    data = hp.aggregate([report], [])
    checks = audit_report.evaluate({"audit_data": data}, ROOT / "cmax")
    checks = [c for c in checks if c.key.split(".")[0] in data]
    assert {c.key: c.status for c in checks} == {
        "thp_madvise.status": "pass", "static_hugepages.status": "skipped",
        "hugepage_allocation.status": "skipped",
    }
    assert "2 skipped" in audit_report.format_report(checks, color=False)
    assert data["static_hugepages"]["message"] in audit_report.format_report(checks, verbosity=3)
    assert hp.aggregate([report], ["worker missing"])["thp_madvise"]["status"] == "warning"


def test_mixed_per_size_thp_policies_do_not_pass(tmp_path):
    write(tmp_path, f"{hp.THP}/enabled", "always [madvise] never")
    write(tmp_path, f"{hp.THP}/hugepages-64kB/enabled", "[always] madvise inherit never")
    write(tmp_path, f"{hp.THP}/hugepages-2048kB/enabled", "always [madvise] inherit never")
    assert hp.thp_report(tmp_path)["status"] != "pass"


def test_partial_collection_retains_valid_evidence(tmp_path):
    write(tmp_path, f"{hp.THP}/enabled", "always [madvise] never")
    host = hp.collect_host(tmp_path)
    result = hp.aggregate([host], ["node-2 pod failed"])
    assert result["thp_madvise"]["status"] == "warning"
    assert result["thp_madvise"]["hosts"]
    assert result["thp_madvise"]["coverageComplete"] is False
    assert result["hugepage_allocation"]["status"] == "skipped"


def test_slurm_controller_ships_collector_and_marks_partial_coverage(monkeypatch, capsys):
    sys.path.insert(0, str(CHECK.parent))
    import hbm_memory_exposure as transport
    monkeypatch.setenv("SLURM_JOB_ID", "123")
    monkeypatch.setenv("SLURM_NNODES", "2")
    def run(command, **kwargs):
        assert command[:3] == ["srun", "--overlap", "--input=all"]
        assert kwargs["input_text"] == CHECK.read_text()
        report = {"host": "n1", **{
            key: {"status": "neutral", "message": "observed"}
            for key in ("thp_madvise", "static_hugepages", "hugepage_allocation")
        }}
        return subprocess.CompletedProcess(command, 0, json.dumps(report), "")
    monkeypatch.setattr(transport, "run_command", run)
    assert hp.main(["--harness", "slurm"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["thp_madvise"]["status"] == "warning"
    assert "Expected 2 workers" in data["thp_madvise"]["message"]


def test_k8s_transport_uses_read_only_host_paths_and_custom_source(monkeypatch):
    sys.path.insert(0, str(CHECK.parent))
    import hbm_memory_exposure as transport
    calls = []
    def kubectl(command, **kwargs):
        calls.append(command)
        if command[0] == "apply":
            pod = json.loads(kwargs["input_text"])
            assert all(v["readOnly"] for v in pod["spec"]["containers"][0]["volumeMounts"])
        if command[0] == "exec":
            assert kwargs["input_text"] == CHECK.read_text()
            assert "--try-allocate" not in command
            assert command[command.index("--root") + 1] == "/host"
            return subprocess.CompletedProcess(command, 0, '{"host":"n1"}', "")
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr(transport, "kubectl", kubectl)
    record, error = transport.run_k8s_host_check("default", {"name": "n1"}, "image", worker_source=CHECK.read_text())
    assert record == {"host": "n1"} and error is None
    assert calls[-1][0] == "delete"


def test_kubernetes_node_name_replaces_pod_uts_hostname(tmp_path, monkeypatch):
    # In a check pod the host-root procfs reports the pod's UTS hostname.
    write(tmp_path, "proc/sys/kernel/hostname", "clustermax-hbm-9447461b\n")
    monkeypatch.setenv("NODE_NAME", "g144462")
    assert hp.collect_host(tmp_path)["host"] == "g144462"
    monkeypatch.delenv("NODE_NAME")
    assert hp.collect_host(tmp_path)["host"] == "clustermax-hbm-9447461b"
