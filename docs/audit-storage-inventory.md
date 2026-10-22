# All-node storage inventory

The full and storage profiles collect `df -hT` from each Slurm worker or GPU
Kubernetes node. Standalone mode collects the local inventory. Kubernetes probes
enter the host mount namespace through the existing host-check transport.

The collector compares mount presence, filesystem types, capacity, and utilization.
It reports unreachable nodes and command failures separately from mismatches.
Collection does not create files on the tested mounts.
Transport errors appear in the aggregate message and findings. No reports means
an unknown verdict with the collection error. Usable reports plus a transport
error produce a warning, unless a confirmed mount mismatch requires failure.

The `storage_config` JSON preserves the per-node evidence. The terminal report
includes the aggregate status and directs the operator to the affected nodes.
Tests use mock worker responses for inconsistent mounts, capacity, failures,
Slurm transport, and Kubernetes transport.
