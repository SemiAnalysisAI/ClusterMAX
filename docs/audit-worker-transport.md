# Audit worker transport

Slurm checks send Python source to each worker through standard input. Workers
need `python3`, but do not need the controller checkout or its virtual environment.
An unavailable worker produces missing evidence. The collector does not substitute
login-node observations for worker observations.

GPU node discovery accepts NVIDIA scalar resources, NVIDIA DRA labels, and AMD
GPU resources. Kubernetes fan-out retains the public CLI's bounded concurrency.

The HBM transport also accepts an explicit worker source. Other passive host
collectors can reuse its pod creation, host mount, timeout, and cleanup paths.
This does not change the public rule that CPU Manager applies only to Kubernetes.

The fan-out and HBM tests cover command construction, vendor labels, errors,
missing worker output, and the existing Kubernetes behavior. Live cluster
validation remains necessary before release.
