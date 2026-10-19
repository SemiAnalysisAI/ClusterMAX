# Hypervisor report parity

The full and security reports now include the existing QEMU virtio-serial and
VMSCAPE collector verdicts. The same evaluators serve both reports.

A recorded vulnerable status fails. Missing evidence and required physical-host
attestation remain warnings. A completed not-applicable verdict is skipped.
The report does not infer a host patch from the guest kernel version.

Tests cover pass, fail, unknown, missing, not-applicable, and host-evidence-required
states through both report paths. This change adds no exploit or active probe.
