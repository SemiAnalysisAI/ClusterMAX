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
            state["pages"] = 20 if mode in {"partial", "signal"} else value
            if mode == "signal":
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        elif mode == "cleanup":
            raise OSError("read-only")
        else:
            state["pages"] = value
        return len(text)
    monkeypatch.setattr(hp, "meminfo", info)
    monkeypatch.setattr(hp, "number", lambda _: state["pages"])
    monkeypatch.setattr(Path, "write_text", writer)
    handler = signal.getsignal(signal.SIGTERM)
    result = hp._allocation_trial(Path("/"))
    assert result["status"] == expected
    assert result["restored"] is restored
    assert signal.getsignal(signal.SIGTERM) == handler
    assert writes == ([] if expected == "skipped" else [522] if mode == "concurrent" else [11, 10] if mode == "gigantic" else [522, 10])
    if mode in {"success", "gigantic"}:
        assert result["allocated_bytes"] == hp.GIB


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
    assert hp.aggregate([report], ["worker missing"])["thp_madvise"]["status"] == "unknown"


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
    assert data["thp_madvise"]["status"] == "unknown"
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
