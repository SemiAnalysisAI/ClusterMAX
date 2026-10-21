# Audit parity PR stack for cmax 0.3.0

This stack adds the full audit scope identified for public release.
The 0.3.0 release scope is #41 and every PR in the table below.
Each user-facing PR adds its own entry to `docs/releases/0.3.0.md`.
#70 changes only tests, so it has no release-note entry.
It follows the existing [0.3.0 release PR #41](https://github.com/SemiAnalysisAI/ClusterMAX/pull/41).
Each PR targets the preceding branch so its diff contains one feature.
Review and merge dependencies in the order below, retargeting each PR after its
base lands. Do not merge the final branch wholesale to bypass the individual reviews.

| PR | Scope |
|---|---|
| [#42](https://github.com/SemiAnalysisAI/ClusterMAX/pull/42) | Streamed worker transport, vendor-scoped GPU discovery, CI for the stack |
| [#43](https://github.com/SemiAnalysisAI/ClusterMAX/pull/43) | Tenant GPU pod defaults and admission |
| [#44](https://github.com/SemiAnalysisAI/ClusterMAX/pull/44) | Kubernetes scheduling policy inventory |
| [#45](https://github.com/SemiAnalysisAI/ClusterMAX/pull/45) | All-node storage consistency |
| [#46](https://github.com/SemiAnalysisAI/ClusterMAX/pull/46) | THP policy, HugeTLB inventory, explicit allocation-trial interface |
| [#47](https://github.com/SemiAnalysisAI/ClusterMAX/pull/47) | RDMA resource configuration and per-rail evidence |
| [#48](https://github.com/SemiAnalysisAI/ClusterMAX/pull/48) | Compute-worker Slurm evidence and SSH probe scope |
| [#49](https://github.com/SemiAnalysisAI/ClusterMAX/pull/49) | Bounded observability discovery and isolation checks |
| [#50](https://github.com/SemiAnalysisAI/ClusterMAX/pull/50) | QEMU and VMSCAPE report parity |
| [#65](https://github.com/SemiAnalysisAI/ClusterMAX/pull/65) | PwnEscape coverage of every worker and control-plane host (based on #50) |
| [#69](https://github.com/SemiAnalysisAI/ClusterMAX/pull/69) | NVIDIA GA firmware ranges for every listed NIC and DPU family (based on #50) |
| [#70](https://github.com/SemiAnalysisAI/ClusterMAX/pull/70) | Test consolidation only, not user facing (based on #69) |

## Validation

The combined code at `3ada9a9255adbbf7999d202544706b1bf5964fd5` passed:

- 1,926 Python tests and 868 subtests under Python 3.12.
- Wheel and source-archive construction with the installed build backend.
- Twine metadata checks for both artifacts using the pinned release toolchain.
- A clean wheel install under Python 3.14, CLI version and help, and the full
  and security check inventories.
- Import checks for the installed observability and new host collectors.

The packaged inventory contains 75 full-audit checks and 20 security checks.
RDMA plane records remain structured evidence rather than an additional scored
check. CI results and review findings remain on each PR.

## Release boundaries

Live Slurm and Kubernetes audits ran on the PR branch heads. Their results stay
private. The stable gate still requires a smoke test on the final master commit.

Routine huge-page collection is read-only. The separate allocation trial requires
explicit opt-in and an approved idle host. Tenant pod admission checks create
temporary test pods only in the full and orchestration profiles.

The stack preserves public security-only collectors, PwnEscape, Bad Epoll, cache
validation, Ready-node selection, and the stable publication workflow.
It does not export private provider results, credentials, dashboards, benchmark
campaigns, draft security runners, or private Git history.

These PRs neither merge the existing public contributor PRs nor fix their
previously reported release blockers. They do not dispatch publication, create
release tags, or upload to PyPI.
