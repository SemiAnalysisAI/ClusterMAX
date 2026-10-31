# Experimental GPU instance fingerprints

`cmax gpu-fingerprint` collects the mean atomic-arrival rank for each CUDA
thread block on one local GPU. It is an active workload, outside `cmax audit`
and `cmax audit security`. It does not assign a security grade, identify a
physical GPU, or establish cross-tenant access.

The implementation adapts the P3 channel from
[gpu-instance-fingerprint at commit 9a3af51](https://github.com/divagr18/gpu-instance-fingerprint/tree/9a3af5177a24a233423d15fbad7eea2df7d680a1).
It omits P1 reductions and P2 SM-ID collection. The changed kernel, warmup and
workload sequence have their own `cmax-p3-order-v1` protocol and kernel hash.
Upstream accuracy does not transfer to this implementation.

## Run on an allocated GPU

Install a CuPy build that matches the CUDA runtime in a separate environment.
For CUDA 12, for example:

```bash
python -m pip install cupy-cuda12x
cmax gpu-fingerprint --acknowledge-gpu-work \
  --device 0 --replicate 0 --output gpu-a-r0.json
cmax gpu-fingerprint --acknowledge-gpu-work \
  --device 0 --replicate 1 --output gpu-a-r1.json
```

CuPy is optional; ClusterMAX does not install it or download probe code at
runtime. This command supports NVIDIA CUDA only. It does not implement the
PyTorch `index_add_` experiment.

Use only GPUs allocated to you, with permission to collect identifying data.
The workload competes with other GPU work. Default collection uses three
epochs of 3,000 launches, with 4,096 blocks, 128 threads and 15,000 FMA
iterations per launch. A separate worker has a 180-second timeout, including
CUDA initialization and compilation. `--timeout` accepts up to 900 seconds;
`--epochs` accepts 1–10 and `--launches` accepts 1–3,000. Lower counts are
useful for smoke tests but do not establish a stable signature.

`--device` is a CUDA-visible ordinal, so `CUDA_VISIBLE_DEVICES` remapping
applies. Metadata comes from that device's CUDA properties, not the first
`nvidia-smi` row. The command does not change device visibility, clocks,
power limits, MIG configuration or framework determinism settings.

There is no SSH, Kubernetes or Slurm fanout. Enter the allocated shell or job
first. The normal host-role guard applies; use `--allow-cluster-node` only
when local execution on that allocated worker is intended. `--yes` skips
target confirmation but cannot replace `--acknowledge-gpu-work`. A target
changed to Slurm or Kubernetes is rejected before CUDA work starts.

## Evidence and privacy

The JSON records the protocol, kernel hash, launch settings, visible device
ordinal, model, compute capability, SM count, CUDA versions, CuPy version and
each epoch's normalized per-block mean ranks. Rank vectors come only from
atomic-order outputs. Device UUIDs, serials, hostnames and SM IDs are not
collected. UUID omission does not anonymize a fingerprint.

Output is a new mode-0600 file. Existing files and symlinks are rejected before
work starts. Worker failure, timeout or interruption removes incomplete
output. Successful output is local only; the command does not upload it.
CuPy can create its normal local compilation cache. Keep results in a private
directory and do not add raw signatures to public issues or this repository.

An exit code of zero means collection completed, not that identity or security
was verified. Missing dependencies, unsupported hardware and CUDA failures
return a nonzero exit and do not produce a passing audit result.

## Validation required before identity matching

This PR adds collection only. No enrollment database, classifier, matching
threshold or provider score is included. Do not use the result as a billing
identity, cryptographic attestation or proof that two tenants share a GPU.

The [upstream README](https://github.com/divagr18/gpu-instance-fingerprint/blob/9a3af5177a24a233423d15fbad7eea2df7d680a1/README.md)
reports 111/112 leave-one-out classifications across 19 A40s. Its restart
experiment describes container restarts, which do not establish survival of
a physical host reboot. Its forgery experiment tests a finite launch-parameter
sweep, not arbitrary software replay or a hostile provider's control of output.

Hardware validation for this adaptation must:

- Collect multiple independent replicates on multiple GPUs of the same model.
  Keep operator-verified device labels separately from the signature features.
- Match protocol, kernel hash, launch counts, driver and runtime versions.
  Track clocks, temperatures, contention, MIG/MPS state and allocation changes
  in the private experiment log; this collector does not measure those states.
- Fit any cross-device centering and enrollment centroids on training data
  only. Hold out entire collection sessions rather than correlated epochs.
- Measure genuine and impostor distributions, false accepts, false rejects
  and unknown-device rejection. Test driver changes, load, container restart
  and physical reboot separately.
- Validate modern accelerator models independently. A40 results do not qualify
  H100, H200, B200, B300, MIG partitions or vGPU configurations.

CPU-only tests cover orchestration, failure handling and mocked rank collection.
They do not validate the CUDA kernel, signature stability or identification
accuracy. Hardware qualification remains required before this experiment can
be considered for a production check.
