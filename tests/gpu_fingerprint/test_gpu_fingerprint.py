import json
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock

import numpy as np
import pytest

from cmax import cli, gpu_fingerprint as fp, host_role, security, target_selection


def options(**overrides):
    return dict(device=0, epochs=3, launches=3000, replicate=0, timeout=180) | overrides


def worker_result(epochs=3):
    return {"protocol": fp.PROTOCOL, "epochs": [{"epoch": i} for i in range(epochs)]}


def stub_worker(monkeypatch, result=None, **kwargs):
    worker = Mock(return_value=subprocess.CompletedProcess(
        [], kwargs.get("returncode", 0),
        json.dumps(worker_result() if result is None else result),
        kwargs.get("stderr", ""),
    ))
    monkeypatch.setattr(fp.subprocess, "run", worker)
    return worker


@pytest.mark.parametrize("overrides", [
    {"device": -1}, {"device": 1024}, {"epochs": 0}, {"epochs": 11},
    {"launches": 0}, {"launches": 3001}, {"replicate": -1},
    {"timeout": 0}, {"timeout": 901}, {"epochs": True},
])
def test_options_are_bounded(overrides):
    with pytest.raises(ValueError):
        fp.validate_options(**options(**overrides))


def test_private_output_and_bounded_worker(tmp_path, monkeypatch):
    worker = stub_worker(monkeypatch)
    output = tmp_path / "sample.json"
    fp.run_to_file(output, **options(device=2))
    assert json.loads(output.read_text()) == worker_result()
    assert output.stat().st_mode & 0o777 == 0o600
    command = worker.call_args.args[0]
    assert command[-4:] == ["2", "3", "3000", "0"]
    assert worker.call_args.kwargs["timeout"] == 180
    assert worker.call_args.kwargs["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("symlink", [False, True])
def test_existing_output_is_never_replaced(tmp_path, monkeypatch, symlink):
    worker = stub_worker(monkeypatch)
    existing = tmp_path / "existing"
    existing.write_text("keep")
    output = tmp_path / "sample"
    if symlink:
        output.symlink_to(existing)
    else:
        output.write_text("keep")
    with pytest.raises(FileExistsError):
        fp.run_to_file(output, **options())
    worker.assert_not_called()
    assert existing.read_text() == output.read_text() == "keep"


@pytest.mark.parametrize("failure", [
    subprocess.TimeoutExpired(["worker"], 1), KeyboardInterrupt(),
    OSError("cannot spawn"),
])
def test_worker_failures_remove_output(tmp_path, monkeypatch, failure):
    worker = stub_worker(monkeypatch)
    worker.side_effect = failure
    output = tmp_path / "sample"
    with pytest.raises((RuntimeError, KeyboardInterrupt, OSError)):
        fp.run_to_file(output, **options())
    assert not output.exists()


def test_cuda_failure_is_not_an_assessment(tmp_path, monkeypatch):
    stub_worker(monkeypatch, returncode=1, stderr="traceback\nRuntimeError: no CUDA")
    output = tmp_path / "sample"
    with pytest.raises(RuntimeError, match="no CUDA"):
        fp.run_to_file(output, **options())
    assert not output.exists()


@pytest.mark.parametrize("result", [[], {}, {"protocol": fp.PROTOCOL, "epochs": []}])
def test_invalid_worker_output_is_not_saved(tmp_path, monkeypatch, result):
    stub_worker(monkeypatch, result)
    output = tmp_path / "sample"
    with pytest.raises(ValueError):
        fp.run_to_file(output, **options())
    assert not output.exists()


def test_missing_cupy_has_actionable_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "cupy", None)
    with pytest.raises(RuntimeError, match="separately installed CuPy"):
        fp.collect(0, 1, 1, 0)


def fake_cupy(monkeypatch, *, hip=False, corrupt=False):
    monkeypatch.setattr(fp, "BLOCKS", 4)
    selected = []
    properties_requested = []
    stream = SimpleNamespace(synchronize=Mock())
    launched = []

    def kernel(grid, block, args):
        launched.append((grid, block))
        assert args[1][0] == 0
        args[1][0] = 4
        args[2][:] = [0, 0, 0, 0] if corrupt else [2, 0, 3, 1]

    def device(ordinal):
        selected.append(ordinal)
        return nullcontext()

    def props(ordinal):
        properties_requested.append(ordinal)
        return dict(name=b"test GPU", major=8, minor=0, multiProcessorCount=108)

    cp = SimpleNamespace(
        __version__="test", int32=np.int32, float32=np.float32,
        zeros=np.zeros, empty=np.empty, asnumpy=np.copy,
        RawKernel=Mock(return_value=kernel),
        cuda=SimpleNamespace(
            Device=device, get_current_stream=lambda: stream,
            runtime=SimpleNamespace(
                is_hip=hip, getDeviceCount=lambda: 3, getDeviceProperties=props,
                driverGetVersion=lambda: 12080, runtimeGetVersion=lambda: 12080,
            ),
        ),
    )
    monkeypatch.setitem(sys.modules, "cupy", cp)
    return cp, selected, properties_requested, launched


def test_collect_selected_device_and_normalized_ranks(monkeypatch):
    cp, selected, properties, launched = fake_cupy(monkeypatch)
    result = fp.collect(2, 2, 3, 7)
    assert selected == properties == [2]
    assert len(launched) == 7  # One warmup plus six measured launches.
    assert result["device"]["visible_ordinal"] == 2
    assert result["replicate"] == 7
    assert result["assessment"] == "not_assessed"
    assert len(result["epochs"]) == 2
    assert result["epochs"][0]["block_mean_rank"] == pytest.approx([2 / 3, 0, 1, 1 / 3])
    assert not {"uuid", "serial", "hostname"} & result["device"].keys()
    assert "%smid" not in fp.KERNEL
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize("hip,device,corrupt,message", [
    (True, 0, False, "NVIDIA CUDA only"),
    (False, 3, False, "unavailable"),
    (False, 0, True, "invalid arrival ranks"),
])
def test_unsupported_or_invalid_collection(monkeypatch, hip, device, corrupt, message):
    fake_cupy(monkeypatch, hip=hip, corrupt=corrupt)
    with pytest.raises((RuntimeError, ValueError), match=message):
        fp.collect(device, 1, 1, 0)


def cli_args(tmp_path):
    return ["gpu-fingerprint", "--acknowledge-gpu-work", "--output", str(tmp_path / "sample")]


def test_acknowledgment_required_even_with_yes(tmp_path, monkeypatch):
    run = Mock()
    monkeypatch.setattr(fp, "run_to_file", run)
    with pytest.raises(SystemExit) as exc:
        cli.main(["gpu-fingerprint", "--yes", "--output", str(tmp_path / "sample")])
    assert exc.value.code == 2
    run.assert_not_called()


def test_cli_uses_guard_before_collection(tmp_path, monkeypatch):
    calls = []
    local = security.SecurityTarget("standalone", "local", True)
    prepare = Mock(side_effect=lambda *a, **kw: (calls.append("guard") or local))
    monkeypatch.setattr(target_selection, "prepare_target", prepare)
    monkeypatch.setattr(fp, "run_to_file", lambda *a, **kw: calls.append("collect"))
    assert cli.main(cli_args(tmp_path)) == 0
    assert calls == ["guard", "collect"]
    assert prepare.call_args.kwargs["noun"] == "GPU fingerprint probe"
    assert prepare.call_args.kwargs["stream"] is sys.stderr
    assert cli.host_role_unguarded_commands(cli.build_parser()) == []


def test_cluster_host_is_refused_without_override(tmp_path, monkeypatch):
    monkeypatch.setattr(host_role, "detect",
                        lambda *a, **kw: host_role.HostRole(host_role.SLURM_COMPUTE))
    run = Mock()
    monkeypatch.setattr(fp, "run_to_file", run)
    assert cli.main(cli_args(tmp_path)) == 1
    run.assert_not_called()


@pytest.mark.parametrize("target", ["slurm", "k8s"])
def test_changed_cluster_target_is_rejected(tmp_path, monkeypatch, target):
    monkeypatch.setattr(target_selection, "prepare_target",
                        lambda *a, **kw: security.SecurityTarget(target, target, True))
    run = Mock()
    monkeypatch.setattr(fp, "run_to_file", run)
    assert cli.main(cli_args(tmp_path)) == 1
    run.assert_not_called()


def test_cancellation_does_not_collect(tmp_path, monkeypatch):
    monkeypatch.setattr(target_selection, "prepare_target",
                        Mock(side_effect=target_selection.TargetSelectionCancelled()))
    run = Mock()
    monkeypatch.setattr(fp, "run_to_file", run)
    assert cli.main(cli_args(tmp_path)) == 130
    run.assert_not_called()


@pytest.mark.parametrize("flag,value", [
    ("--epochs", "0"), ("--launches", "3001"), ("--timeout", "901"),
])
def test_cli_invalid_options_do_not_touch_target(tmp_path, monkeypatch, flag, value):
    prepare = Mock()
    monkeypatch.setattr(target_selection, "prepare_target", prepare)
    assert cli.main(cli_args(tmp_path) + [flag, value]) == 1
    prepare.assert_not_called()


def test_unknown_flags_do_not_touch_target(tmp_path, monkeypatch):
    prepare = Mock()
    monkeypatch.setattr(target_selection, "prepare_target", prepare)
    with pytest.raises(SystemExit):
        cli.main(cli_args(tmp_path) + ["--slurm"])
    prepare.assert_not_called()


def test_guard_override_is_forwarded(tmp_path, monkeypatch):
    local = security.SecurityTarget("standalone", "local", True)
    prepare = Mock(return_value=local)
    monkeypatch.setattr(target_selection, "prepare_target", prepare)
    monkeypatch.setattr(fp, "run_to_file", Mock())
    assert cli.main(cli_args(tmp_path) + ["--allow-cluster-node"]) == 0
    assert prepare.call_args.kwargs["allow_cluster_node"] is True


def test_real_worker_without_cupy_leaves_no_file(tmp_path, monkeypatch):
    # A stub import fails in the subprocess without requiring a GPU or CuPy.
    (tmp_path / "cupy.py").write_text("raise ImportError('test missing CuPy')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    output = tmp_path / "sample.json"
    with pytest.raises(RuntimeError, match="separately installed CuPy"):
        fp.run_to_file(output, **options())
    assert not output.exists()


def test_help_does_not_import_cupy():
    # Separate interpreter: this check does not depend on test module imports.
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; from cmax.cli import build_parser; build_parser(); "
         "assert 'cupy' not in sys.modules; assert 'numpy' not in sys.modules"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
