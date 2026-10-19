# RDMA resources and fabric evidence

The full, networking, and security profiles retain per-host NIC topology and add
`nic_plane_evidence`. Read-only queries collect port width, rate, physical
presentation, and available neighbor evidence. Missing tools, permission denials,
and timeouts remain explicit. They do not prove a single-plane topology.

GPU Operator access supports privileged AMD system pods as well as NVIDIA pods.
The public host-root and container-selection behavior is retained.
NVIDIA-only vBoost and virtio checks remain scoped to NVIDIA nodes.
Namespace discovery also checks custom GPU Operator namespace names.
Mixed-vendor collection selects a compatible system pod per node across all
discovered operator namespaces. An explicit namespace override remains scoped
to that namespace.
AMD system-pod collection reads host network devices without running
`nvidia-smi`. NVIDIA affinity and NVLink readings are not applicable on those
nodes. This does not count as a failed collection or prove an NVLink boundary.

Configured `nvidia.com/hostdev` resources count as RDMA only when the SR-IOV device
plugin configuration declares `isRdma`. Failed fabric rails remain visible.
Down InfiniBand ports retain candidate evidence until peer-based role recovery
finishes. Final fabric ports always have an evidence record. Missing readings
remain explicitly not determined.
Slurm collection requires a worker allocation and does not replace missing
worker output with login-node results.

The public NVLink boundary evidence remains separate. Missing plane evidence
does not invalidate an otherwise complete NVLink topology reading.
Tests cover parser fixtures, configured resources, mixed vendor access, missing
tools, failed rails, and existing NVLink behavior.
