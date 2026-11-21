"""Opt-in numerical GPU signature collection, separate from security grading."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cmax import __version__

UPSTREAM_COMMIT = "9a3af5177a24a233423d15fbad7eea2df7d680a1"
UPSTREAM_URL = "https://github.com/divagr18/gpu-instance-fingerprint"
BLOCKS, THREADS, BURN = 4096, 128, 15000
PROTOCOL = "cmax-p3-order-v1"

# Adapted from probes/probe_puf.py at UPSTREAM_COMMIT. P3 only: no SM ID,
# timers, serials or UUIDs enter the signature. This is a distinct protocol.
#
# MIT License
# Copyright (c) 2026 divagr18
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
KERNEL = r'''
extern "C" __global__
void order_probe(int burn, int* counter, int* slots, float* sink) {
    float acc = 1.0f + (float)(threadIdx.x & 7);
    for (int k = 0; k < burn; k++) acc = fmaf(acc, 1.0000001f, 1e-6f);
    if (threadIdx.x == 0) {
        slots[blockIdx.x] = atomicAdd(counter, 1);
        sink[blockIdx.x] = acc;
    }
}
'''


def validate_options(device: int, epochs: int, launches: int,
                     replicate: int, timeout: int) -> None:
    for name, value, low, high in (
        ("device", device, 0, 1023), ("epochs", epochs, 1, 10),
        ("launches", launches, 1, 3000), ("replicate", replicate, 0, 999999),
        ("timeout", timeout, 1, 900),
    ):
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{name} must be an integer in [{low}, {high}]")


def collect(device: int, epochs: int, launches: int, replicate: int) -> dict:
    """Collect only from the selected CUDA-visible device; import CUDA lazily."""
    validate_options(device, epochs, launches, replicate, 180)
    try:
        import cupy as cp
        import numpy as np
    except ImportError as exc:
        raise RuntimeError(
            "GPU fingerprinting needs a separately installed CuPy build for "
            "your CUDA runtime; see docs/gpu-fingerprint.md"
        ) from exc
    if getattr(cp.cuda.runtime, "is_hip", False):
        raise RuntimeError("this experimental protocol supports NVIDIA CUDA only")
    if device >= cp.cuda.runtime.getDeviceCount():
        raise ValueError(f"CUDA-visible device {device} is unavailable")

    with cp.cuda.Device(device):
        props = cp.cuda.runtime.getDeviceProperties(device)
        name = props["name"]
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        result = {
            "schema_version": 1,
            "protocol": PROTOCOL,
            "experimental": True,
            "assessment": "not_assessed",
            "clustermax_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "upstream": {"url": UPSTREAM_URL, "commit": UPSTREAM_COMMIT},
            "kernel_sha256": hashlib.sha256(KERNEL.encode()).hexdigest(),
            "config": {"blocks": BLOCKS, "threads": THREADS, "burn": BURN,
                       "launches": launches, "epochs": epochs,
                       "compiler_options": ["-std=c++11"], "warmup_launches": 1},
            "device": {"visible_ordinal": device, "name": name,
                       "compute_capability": [props["major"], props["minor"]],
                       "sm_count": props["multiProcessorCount"],
                       "driver_api": cp.cuda.runtime.driverGetVersion(),
                       "runtime": cp.cuda.runtime.runtimeGetVersion(),
                       "cupy": cp.__version__},
            "replicate": replicate,
            "epochs": [],
        }
        kernel = cp.RawKernel(KERNEL, "order_probe", options=("-std=c++11",))
        counter = cp.zeros(1, dtype=cp.int32)
        slots = cp.empty(BLOCKS, dtype=cp.int32)
        sink = cp.empty(BLOCKS, dtype=cp.float32)
        stream = cp.cuda.get_current_stream()

        def launch():
            counter.fill(0)
            kernel((BLOCKS,), (THREADS,), (np.int32(BURN), counter, slots, sink))
            stream.synchronize()

        launch()  # Compile and warm up outside the recorded epochs.
        expected = np.arange(BLOCKS)
        for epoch in range(epochs):
            started = time.monotonic()
            total = np.zeros(BLOCKS, dtype=np.float64)
            for _ in range(launches):
                launch()
                values = cp.asnumpy(slots)
                # An incomplete or invalid kernel result must not become evidence.
                if not np.array_equal(np.sort(values), expected):
                    raise RuntimeError("GPU probe returned invalid arrival ranks")
                total += values
            result["epochs"].append({
                "epoch": epoch, "seconds": time.monotonic() - started,
                "block_mean_rank": (total / (launches * (BLOCKS - 1))).tolist(),
            })
    return result


def run_to_file(output: Path, *, device: int, epochs: int, launches: int,
                replicate: int, timeout: int) -> None:
    """Run CUDA in a bounded worker and retain a private file only on success."""
    validate_options(device, epochs, launches, replicate, timeout)
    output = Path(output)
    # O_EXCL rejects existing files and symlinks. Create before any GPU work.
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    complete = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            code = (
                "import json,sys; from cmax.gpu_fingerprint import collect; "
                "print(json.dumps(collect(*map(int, sys.argv[1:])), allow_nan=False))"
            )
            try:
                worker = subprocess.run(
                    [sys.executable, "-c", code, str(device), str(epochs),
                     str(launches), str(replicate)],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    timeout=timeout, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(
                    f"GPU fingerprint worker exceeded {timeout}s; no result saved"
                ) from exc
            if worker.returncode:
                detail = worker.stderr.strip().splitlines()
                raise RuntimeError(
                    "GPU fingerprint worker failed: "
                    + (detail[-1] if detail else f"exit {worker.returncode}")
                )
            result = json.loads(worker.stdout)
            if (not isinstance(result, dict)
                    or result.get("protocol") != PROTOCOL
                    or len(result.get("epochs", [])) != epochs):
                raise ValueError("GPU fingerprint worker returned an invalid result")
            json.dump(result, handle, allow_nan=False)
            handle.write("\n")
        complete = True
    finally:
        if not complete:
            output.unlink(missing_ok=True)
