# Huge-page evidence

The full and hardware profiles inspect THP madvise policy and static HugeTLB
pools on workers. Routine audit collection does not change host memory settings.
Slurm uses streamed source. Kubernetes mounts host paths read-only.

The collector also supports a separate `--collect-host --try-allocate` trial.
This requires root on an explicitly approved idle host. It temporarily grows the
default HugeTLB pool by 1 GiB and attempts to restore the original pool on normal
completion, errors, SIGINT, SIGTERM, SIGHUP, and SIGQUIT. No program can
guarantee cleanup after SIGKILL or host failure. Do not run it on a production
host without a maintenance plan.

The regular audit never supplies `--try-allocate`. An unrun trial is neutral,
not a successful allocation test. Missing or partial worker evidence stays unknown.
Tests cover pool restoration, interruption, disabled trials, and read-only
Kubernetes transport.
