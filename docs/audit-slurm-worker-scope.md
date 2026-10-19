# Slurm worker evidence

The full Slurm audit now uses compute-node evidence for slurmd, CUDA home,
geolocation, NHC, monitoring placement, and InfiniBand control-plane access.
SSH checks run from one compute node to another.

Reports record the collection scope. A successful worker step proves that
slurmd launched work even when the task PID namespace hides the daemon.
NHC evidence from a login-node fallback is labeled. Remote subnet-manager key
state remains unverified unless the relevant configuration was actually read.
Geolocation reports worker egress, not a physical rack location.

Supplemental vBoost, virtio, and platform checks stream their source over Slurm.
Missing worker output does not become a successful local-node check.
The public hardware/networking flags and security-only collectors are retained.

Tests execute shell collector blocks with stub commands, then inspect their
output. Regression tests retain the public driver, kernel, and NVLink behavior.
No live cluster was contacted during validation.
