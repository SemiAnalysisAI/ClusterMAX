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

The [security release preparation checklist](docs/security-release-preparation.md)
describes the added checks and publication gates. PR validation does not publish
a stable package.

Stable publication uses a manually dispatched, approved workflow. It verifies
the PyPI upload before creating the matching GitHub tag and Release from the
same commit and artifacts. Nightly publication does not create GitHub Releases.

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

The prepared stable release is `0.3.0`. Subsequent nightly releases use the
`0.3.1.devYYYYMMDDNN` format, which sorts after `0.3.0` when `--pre` is enabled.
The version change in this branch does not publish either channel.

## Public documentation

The [ClusterMAX website](https://clustermax.semianalysis.com/) explains the rating system. The [evaluation criteria](https://www.clustermax.ai/criteria) list our full checklist, while the [expectations page](https://www.clustermax.ai/expectations) lists or clearest expectations for Slurm, Kubernetes, standalone machines, monitoring dashboards, and health checks.

## Run a security audit

The current [minimum-version table](https://www.clustermax.ai/minimum-versions) lists the software and firmware versions used for grading, with vendor advisories behind each value. Its [machine-readable form](https://semianalysisai.github.io/ClusterMAX/minimum-versions.json) is the table `cmax audit security` fetches on startup (skip with `--no-fetch-minimums`). The `minimum-versions-publish` workflow deploys that one file to the GitHub Pages site of this repository. Its `refreshed` stamp moves every day after a successful refresh, and its `changed` stamp moves only when a minimum value changes. The command line keeps the last fetched table in `~/.cache/clustermax/`, so an offline run grades against that copy instead of the older table inside the package. When the fetch fails and the table in use was last refreshed more than 7 days ago, the audit gives a warning.

The read-only Bad Epoll check, `security.badEpoll.status`, checks the running
kernel against [CVE-2026-46242](https://ubuntu.com/security/CVE-2026-46242).
It maps Ubuntu 24.04 GA 6.8 generic, Ubuntu 22.04 HWE 6.8 generic, Ubuntu
24.04 NVIDIA 6.17 (`nvidia` and `nvidia-64k`), and Ubuntu 26.04 GA 7.0 generic
packages. Each source package uses
its own fixed-version minimum. It requires matching running-kernel signature and installed-package
evidence. A newer installed kernel does not clear a failure until it is running.
Unsupported flavors, missing evidence, and active or unreadable livepatch state
produce an unknown result that requires provider patch evidence. The check does
not run an exploit or attest that a provider's kernel is genuine. An explicitly
pinned minimum table without the mapping produces an unknown result.

Security collection distinguishes the host, GPU Operator containers, and active
GPU workloads on the sampled worker. Driver detection can read the loaded
kernel module when `nvidia-smi` is outside the host search path. Toolkit
detection also checks the GPU Operator installation directory. CUDA Toolkit
versions come from `nvcc` or toolkit metadata, never the driver compatibility
version or an image tag.

The network probe prefers a verified privileged host-root mount when available.
It can enumerate PCI devices through sysfs if `lspci` is missing. It uses
read-only `mlxconfig -e` queries and grades only the Current column. Defaults
and next-boot settings do not establish current isolation. It does not install
tools or start `mst`.
Missing permissions, incomplete scans, and unassessed firmware trains remain
unknown. A completed topology scan alone does not prove exclusive ownership
of the physical NVLink domain.

Held installed kernels participate in the reboot check. Missing installed-kernel
inventory cannot produce a PASS. The NVIDIA 6.17 and Ubuntu 26.04 mappings also
check [Fragnesia and Dirty Frag](https://ubuntu.com/security/CVE-2026-46300)
against the source-package minimum. A newer downloaded table cannot silently remove
the kernel mappings shipped with this client. If it lacks those mappings,
the client reports the mismatch and retains its installed table.

On Ubuntu 22.04 and 24.04, the `generic` and `generic-64k` kernels built from
the GA `linux` source package (5.15 and 6.8) are also graded per CVE against
the Ubuntu tracker for
[CVE-2026-64531](https://ubuntu.com/security/CVE-2026-64531) and
[CVE-2026-64378](https://ubuntu.com/security/CVE-2026-64378).
[CVE-2026-46227](https://ubuntu.com/security/CVE-2026-46227) (SCTP
`SCTP_SENDALL` container escape) and
[CVE-2026-98432](https://ubuntu.com/security/CVE-2026-98432) (IPv4
`inet_opt` use-after-free in `ip_options_build()`) are graded on Ubuntu 22.04,
24.04, and 26.04 for every kernel source package that the tracker lists on
that release: GA, HWE, cloud (AWS, Azure, GCP, Oracle, IBM, GKE), NVIDIA, lowlatency, FIPS,
realtime, and the others. The minimum table has one row per source package.
The kernel family and the flavor in the running release string select the
row. A `needed`, `pending`, `deferred`, or `ignored` (for example, end of life)
tracker state fails because Ubuntu has not released a fix for that kernel. A
`released` state compares the running ABI with the published fixed ABI after
the standard bulletin grace period. A kernel with no row is unknown, because the
audit cannot check it: for example a custom or mainline build, a package newer
than the table, or a release string the audit cannot read. A kernel that
matches more than one row is also unknown. riscv64 kernels have no row of
their own, because their `generic` flavor name cannot be told apart from the
amd64 and arm64 kernels. The two CVEs above check only the GA kernel, so they
do not make other kernels unknown.

The daily refresh also discovers Ubuntu kernel CVEs before a fix exists. It
reads the Ubuntu CVE search for `linux` CVEs published since 2026-10-01 and
within the last 30 days. It adds each CVE that Ubuntu rates `critical`, or
`high` with a CVSS v3 score of 9.0 or more, and that the tracker lists for the
GA `linux` package on 22.04, 24.04, or 26.04. A discovered CVE gets the same
per-kernel rows as the CVEs above, under the key `linuxCve<year>_<number>`, and
each row carries `"discovered": true`. The audit reads the kernel CVE groups
from the minimum table, so it grades a discovered CVE without a client change.
A discovered CVE stays in the table after it leaves the 30-day window, so a
later fix is still graded. A `needs-triage` row of a discovered CVE makes that
kernel unknown. The refresh pull request lists each new discovered CVE for
review. A fetched table that lacks a kernel CVE group of the installed table
is rejected, and the client keeps its installed table. The refresh fails if
the table grows above 3 MiB, so it stays below the 4 MiB client fetch limit.

An absent host Docker installation or an absent CUDA Toolkit in the inspected
scope remains not applicable. This differs from an unreadable tool or failed
probe, which remains unknown. A complete bare-metal PCI scan with no VFIO
assignment makes that sampled host's passthrough check not applicable. UFM
control settings require provider evidence. The tenant profile skips this
provider-side check until a control record is supplied. A skip does not certify
the fabric. Shared InfiniBand fabrics still need the provider's security review.

The following results have explicit assessment scopes:

- **BMC/IPMI:** A PASS means the completed local read commands returned no
  usable management data. A generic IPMI error response remains recorded as
  `error-response`, not an access-denied response. Missing tools, timeouts and
  incomplete node coverage remain unknown. Network BMC interfaces are not tested.
- **NVLink:** A complete topology scan plus an operator ownership attestation
  can pass. Set `CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED=true` only when the
  entire observed physical domain belongs to the allocation. GPU counts alone
  do not establish ownership. The evidence records the attestation source.
- **ConnectX firmware:** The parser preserves NVIDIA's explicit GA
  ["46.3008 or newer" range](https://raw.githubusercontent.com/NVIDIA/product-security/main/2026/5699/5699.json).
  Later trains can pass for the mapped ConnectX-8 and BlueField-3 firmware
  families. Older LTS floors remain separate. Unknown products do not inherit
  that range merely because their version is higher.
- **Virtio-Net:** Verified current NIC mode passes the current-exposure check.
  Stored firmware remains unassessed when unreadable. Recheck it before enabling
  DPU mode. A NIC-mode sample cannot clear missing or mixed fleet evidence.
- **DPU host policy:** An enabled RShim path can fail the configured restriction
  policy without proving DPU login or an exploit. Runtime locks, permissions and
  ownership need separate checks. The audit does not start RShim or change modes.
  On BlueField-3, the Arm OS does not boot in NIC mode
  ([NVIDIA mode documentation](https://docs.nvidia.com/doca/archive/2-9-4/bluefield-modes-of-operation/index.html)).

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

Interactive audits print a short cluster prayer below the startup logo.
The prayer is decorative and does not change GPU settings or audit results.
It is omitted from piped output, help, version output, and inspection commands
such as `--show` or `--dry-run`. Set `CLUSTERMAX_PROGRESS=0` to hide the startup
logo, prayer, and progress display.

The command detects Slurm, Kubernetes, containers, virtual machines, macOS, and standalone hosts automatically, and confirms the selection interactively with the user. To skip this confirmation and force the CLI to use a certain approach, use `--local`, `--slurm`, `--k8s`, `--container`, `--vm`, or `--standalone`. Use `--kubeconfig PATH` to select Kubernetes credentials. An explicit target option confirms the target in a non-interactive run. Use `--yes` to accept an auto-detected target without a prompt.

Run Slurm audits from a login node and Kubernetes audits from a machine with `kubectl` access. When a standalone audit starts on a Slurm or Kubernetes node, or a Slurm audit starts on a Slurm compute node, the CLI shows the detected host role and the command to run instead, and asks a second time. `--yes` does not skip this question. Use `--allow-cluster-node` to run there anyway. If the host role is wrong, [open an issue](https://github.com/SemiAnalysisAI/ClusterMAX/issues/new) with the `Host role` line.

Users can run the command multiple times. Each run writes timestamped artifacts
under `~/.clustermax/audit/` by default.

A failed security check produces exit code 2. Use `--exit-zero` when the caller
requires exit code 0.

See [the security audit section](#run-a-security-audit) for the criteria,
report format, and evidence limits.

## Run a cluster audit

Version 0.3.0 runs the core audit. Use `-s` or `--show` to list every check without collecting data:

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
Because the probe runs as root on the host, an exposed BMC on Kubernetes is a
WARNING, not a CRITICAL: root on a bare-metal host can usually reach the
in-band BMC. Verify that tenants cannot schedule privileged pods or mount host
IPMI devices. On Slurm and standalone hosts the probe runs as the tenant user,
so an exposed BMC stays CRITICAL.

The focused security audit (`cmax audit security`) grades host-level minimums
on every GPU host, not only the sampled worker: the GPU driver, NVIDIA
Container Toolkit, runc, Docker, ConnectX firmware, DCGM, and the kernel
advisories. Each check reports the worst host, names it, and lists every host's
result. ConnectX devices are listed as `host/device`. A GPU host the audit
cannot read leaves a passing check unknown. Kubernetes reuses the BMC host-root
pod on each node; Slurm runs a short one-GPU step on each GPU node with
`--immediate=30`, so a busy node is reported as unread instead of waiting. Up
to 32 GPU hosts are read by default; set `CLUSTERMAX_AUDIT_SECURITY_HOST_LIMIT`
for larger fleets.

Kubernetes full, security, and isolation audits also inspect ClusterRoles and
ClusterRoleBindings for `get` permission on `nodes/proxy`. The report identifies
the subjects, roles, bindings, and node-name restrictions, including wildcard
grants. A matching grant produces `FAIL`. Administrative grants can be intentional
and are included for review. An incomplete inventory produces `WARNING` unless
the audit has already found a grant. This check reads RBAC configuration. It does
not connect to kubelets or execute commands in pods. See the
[Kubernetes kubelet authorization documentation](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
and [Graham Helton's nodes/proxy writeup](https://grahamhelton.com/blog/nodes-proxy-rce).

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
