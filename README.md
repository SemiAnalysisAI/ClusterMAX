# ClusterMAX

This repo is for `cmax`, a CLI tool that we use to audit GPU clusters and standalone machines during research for ClusterMAX. 

The initial release is a small subset of our full test suite. It supports our recent article on neocloud security that precedes ClusterMAX 3.0.

This version of the `cmax` CLI provides the following commands:

| Command | Function |
|---|---|
| `cmax audit security` | This command runs a focused, read-only security audit. |
| `cmax audit` | This command runs a full cluster audit covering more than just security. |
| `cmax audit review` | This command reviews a saved audit output without running new checks. |

## Install ClusterMAX

ClusterMAX requires Python 3.10 or later. Install the current release:
```
uv venv
source .venv/bin/activate
uv pip install clustermax
cmax -v
```

You can also use the `--pre` option to install the latest nightly release:
```
uv pip install --pre -U clustermax
```

Use `-h` to see available options when using the CLI:
```
cmax -h
cmax audit -h
cmax audit security -h
```

Nightly releases use the `0.3.0.devYYYYMMDDNN` format until the stable 0.3.0
release. This version is newer than stable 0.2.1 when `--pre` is enabled.

## Public documentation

The [ClusterMAX website](https://clustermax.semianalysis.com/) explains the rating system. The [evaluation criteria](https://www.clustermax.ai/criteria) list our full checklist, while the [expectations page](https://www.clustermax.ai/expectations) lists or clearest expectations for Slurm, Kubernetes, standalone machines, monitoring dashboards, and health checks.

## Run a security audit

The current [minimum-version table](https://www.clustermax.ai/minimum-versions) lists the software and firmware versions used for grading, with vendor advisories behind each value. Its [machine-readable form](https://www.clustermax.ai/minimum-versions.json) is the table `cmax audit security` fetches on startup (skip with `--no-fetch-minimums`).

The security profile selects the version and isolation checks from the complete audit. Use `-s` or `--show` to list the applicable checks before the audit runs:

```console
$ cmax audit security --show
[versions] Minimum versions
  securityVersions.nvidiaDriver.status: Security Versions / NVIDIA Driver
  ...

[isolation] Security isolation
  security.januscape.status: Security / Januscape
  ...
```

Use `--dry-run -o yaml` to show the resolved plan. This will be useful for future releases of the clustermax CLI. The following example selects a standalone virtual machine:

```console
$ cmax audit security --vm --dry-run -o yaml
# Only audit security manifest is enabled, unrelated tests are not
version: 4
manifest_selection:
  enabled:
  - audit.audit
  disabled_count: 0
  disabled_by_phase:
    audit: 0
audit_profile:
  name: security
  dry_run: true
  command: cmax audit security
  target:
    selection: explicit
    environment: vm
    harness: standalone
  scope:
    core_collector: true
    checks:
      fabric: true
      gpu: false
      system: false
    general_findings_report: false
    standard_report: true
  artifacts:
  - audit.out
  - audit.values.json
  checks:
  - securityVersions.nvidiaDriver.status
  - securityVersions.nvidiaContainerToolkit.status
  - securityVersions.cudaToolkit.status
  - securityVersions.runc.status
  - securityVersions.docker.status
  - securityVersions.connectxFirmware.status
  - securityVersions.dcgm.status
  - securityVersions.dcgmExporter.status
  - securityVersions.virtioNetBluefield.status
  - securityVersions.virtioNetBluefield.exposure
  - securityVersions.dpuHostIsolation.status
  - security.januscape.status
  - security.guestKernel.newerInstalled
  - security.fragnesia.status
  - bmc-ipmi
  - ufm-profile
  - pcie-passthrough
  - nvlink-boundary
```

The resolved plan enables only `audit.audit`. It uses the standard artifact
files, progress wrapper, and report formatter. On Slurm, the security profile
uses a focused collector that runs the worker security inventory, container
version inventory, and backend fabric checks that its report needs.

Every live audit reports its target before it collects data. An interactive
run requires confirmation. The default answer cancels the audit with exit code
130:

```text
# ClusterMAX audit target
  Command: cmax audit security
  Target: Local machine
  Host: <hostname>
  System: macOS <version> (<architecture>)
  Access: current shell; cluster credentials are not used
  Compatibility: limited; Linux GPU checks can report unavailable components
  Selection: auto-detected
Run this audit? [y]es, [c]hange target or access, [N]o:
```

Enter `c` to select the local machine, a Kubernetes cluster, or a Slurm
cluster. Kubernetes selection accepts a kubeconfig path and a context. It
validates the connection before the audit starts. Slurm selection validates
the current Slurm client session.

Run the security audit after you confirm that the target is correct. The command
uses `-v` detail by default.
```bash
cmax audit security
```

Use `-vvv` for the most detail.
```bash
cmax audit security -vvv
```

## Notes on usage

The command detects Slurm, Kubernetes, containers, virtual machines, macOS, and standalone hosts automatically, and confirms the selection interactively with the user. To skip this confirmation and force the CLI to use a certain approach, use `--local`, `--slurm`, `--k8s`, `--container`, `--vm`, or `--standalone`. Use `--kubeconfig PATH` to select Kubernetes credentials. An explicit target option confirms the target in a non-interactive run. Use `--yes` to accept an auto-detected target without a prompt.

Users can run the command multiple times. Each run writes timestamped artifacts
under `~/.clustermax/audit/` by default.

A failed security check produces exit code 2. Use `--exit-zero` when the caller
requires exit code 0.

See [the security audit section](#run-a-security-audit) for the criteria,
report format, and evidence limits.

## Run a cluster audit

Version 0.2.1 runs the core audit. Use `-s` or `--show` to list every check without collecting data:

```bash
cmax audit --show
```

The preview groups the full audit checks into these profiles:

| Profile | Scope |
|---|---|
| `versions` | This profile shows component versions and required minimums. |
| `isolation` | This profile shows kernel, virtualization, and tenant isolation. |
| `hardware` | This profile shows GPU, memory, and input-output virtualization. |
| `software` | This profile shows GPU development and diagnostic tools. |
| `containers` | This profile shows the container runtime and its GPU integration. |
| `orchestration` | This profile shows Slurm workers, Pyxis, and Kubernetes kubelets. |
| `networking` | This profile shows fabric topology, adapter naming, and NCCL configuration. |
| `storage` | This profile shows binary storage installation and configuration checks. |
| `health` | This profile shows node health and GPU telemetry checks. |

Use a profile as an audit subcommand to select its checks:

```bash
cmax audit hardware --show
cmax audit hardware
cmax audit networking --slurm
```

Every named profile uses the same core collector wrapper, progress display,
artifact directory, and report formatter. A profile limits the supplemental
checks and the terminal report to its selected audit checks. The shared
collector still records the inventory that the selected checks need. The Slurm
security profile also omits complete-audit sections that do not supply security
evidence.

The complete audit reads seven days of retained kernel history for GPU errors.
It checks every node in an active Slurm allocation and every Kubernetes GPU
node. It uses the current-boot `dmesg` buffer when the journal is not readable.

Each live profile saves `audit.out` and `audit.values.json`. The security
profile returns exit code 2 when its standard report contains a failed check.
Use `--exit-zero` when an automation system requires exit code 0.

Every audit report uses the same status blocks. `PASS` is green, `WARNING` is
yellow, `FAIL` is red, and `SKIPPED` is dim when output goes to a terminal.
Redirected output stays plain text. The default `-v` output shows every passed,
warning, failed, and skipped check. It also shows each observed version, its
minimum version, and a link to that component in the published
[minimum-version table](https://www.clustermax.ai/minimum-versions), such as
[`runc`](https://www.clustermax.ai/minimum-versions#runc). The `-vv` output adds
labeled CVE and vendor documentation links. The `-vvv` output adds the issue
description and recommended remediation. The CLI does not provide an output
level below `-v`.

Target aliases select an environment for the complete audit:

```bash
cmax audit slurm
cmax audit k8s
cmax audit standalone
cmax audit vm
cmax audit container
```

These commands are equivalent to the matching `--slurm`, `--k8s`,
`--standalone`, `--vm`, and `--container` options.

The Slurm audit checks Pyxis through the container options that Pyxis adds to
`srun --help`. It records the installed package version when package metadata
is available. The check does not start a container or wait for a GPU allocation.
If the options are unavailable, the audit links to the
[NVIDIA Pyxis installation instructions](https://github.com/NVIDIA/pyxis#installation).

The full audit also evaluates the published criteria that have binary results
from a cluster target. These checks verify scheduler CUDA device assignment,
Lmod, Kubernetes ReadWriteMany storage, and Nsight Compute profiling permission.
The audit omits criteria that require commercial, contractual, performance,
reliability, provider-side, or scale-out network evidence.

After target selection, the audit runs only checks that apply to that target.
A standalone container, virtual machine, or bare-metal host omits every check
that applies only to Slurm or Kubernetes. These checks include GRES, Pyxis,
scheduler topology, multi-node NCCL, health programs, prologs, NHC,
auto-remediation, and kubelet CPU Manager.

A Kubernetes audit discovers provider components across all namespaces, because
managed services can use provider-specific namespaces and current Kubernetes
application labels. The audit also distinguishes a container runtime binary
from a compatibility link whose command name is `docker`. When the audit finds
Promtail with Loki or Elasticsearch, it reports the aggregation system as the
logging stack and reports Promtail only as a detected log shipper.

The Kubernetes BMC and IPMI check uses the confirmed Kubernetes identity to
create a privileged pod that mounts each worker host root. The report names
each checked node and states the fleet coverage. This evidence proves what that
administrative identity can reach. It does not prove that an ordinary workload
pod can reach the same local management interface. The check examines up to 32
worker nodes by default. Set `CLUSTERMAX_AUDIT_K8S_BMC_NODE_LIMIT` to a larger
positive integer when a larger fleet requires complete coverage.

The standalone audit also omits scale-out network checks. It does not inspect
InfiniBand, RoCE, RDMA, HCA naming, PKeys, UFM, SHARP, fabric topology, or
GPUDirect RDMA. The report marks their criteria as `SKIPPED`. Slurm and
Kubernetes audits keep their scale-out checks.

The standalone audit still reads the local PCI device list to determine
whether the NVIDIA GPU driver security criterion applies to the host.

The platform configuration checks have separate entry points. The hardware
profile runs `vm-iommu-check.py` and `arm-smmu-virtualization-check.py`. The
networking profile runs `nccl-topology-file-check.py` on Slurm and
`nccl-ib-qps-check.py` on Slurm or Kubernetes. The entry points reuse one host
collection during an audit run.

The core audit collects cluster, host, GPU, storage, network, health, and
security data. It does not run the planned performance or reliability tests.

Each audit command sets its execution profile and selected harness explicitly.
An inherited `CLUSTERMAX_AUDIT_SCOPE` or `CLUSTERMAX_AUDIT_HARNESS` value cannot
change the confirmed selection. `cmax audit` uses the complete profile. Each
named subcommand uses its matching focused profile.

Run or review the core audit with these commands:

```bash
cmax audit
cmax audit review
```

ClusterMAX detects Slurm, Kubernetes, or a standalone machine. Use `--slurm`,
`--k8s`, `--local`, or `--standalone` when detection is incorrect. The command
uses the same target report and confirmation as the security audit.

Each audit saves its results in `~/.clustermax/audit/<timestamp>/`. Set
`CLUSTERMAX_RUNS_ROOT` when you need the ingest-compatible
`<root>/<cluster>/<timestamp>/audit/` layout.

The audit is read-only. This section gives the requirements, checks, and output
files.

Use `cmax audit review` to open the newest saved audit. You can also specify an
audit directory, an `audit.values.json` file, or an `audit.out` file:

```bash
cmax audit review runs/<cluster>/<timestamp>/audit/audit.out
cmax audit review --command 'find runc'
cmax audit review --command 'show securityVersions.runc.status'
```

Use `-v` to include passing and skipped checks. Use `-vv` to include observed
evidence. Use `-vvv` to include recommended remediation and labeled reference
URLs. Use `--command raw` to print the saved collector log. Use
`--no-interactive` to print the review and exit.

## Repository contents

| Path | Contents |
|---|---|
| `cmax/` | This directory contains the command code and `cmax.yaml` configuration. |
| `cmax/scripts/1-audit/` | This directory contains the scripts that run an audit. |
| `tests/audit/` | This directory contains all audit tests, fixtures, and test helpers. |

This release excludes provider results, internal notes, the private dashboard,
benchmark implementations, bundled data, and database code.

## License

All published ClusterMAX source code uses the Apache License 2.0. See
[LICENSE](LICENSE).
