# Security release preparation

This PR prepares the public `cmax` CLI for its next release. It does not change
the stable version, create a tag, or publish a distribution.

## Included changes

- The PwnEscape check reports passive evidence for
  [CVE-2026-99999](https://nvd.nist.gov/vuln/detail/CVE-2026-99999).
  The shared collector feeds the standalone, full Slurm, security-only Slurm,
  and Kubernetes paths.
- The cache validator rejects an unusable cached table after an HTTP 304
  response. It clears the cache validators so the next run requests a full
  response.
- Kubernetes probes select Ready, schedulable workers in the primary GPU
  profile. A fallback worker must match the model and GPU count.
  Inventory counts still include workers that are not Ready.
- The PR also contains the Bad Epoll check and the existing repairs to security
  evidence collection. The review fixes preserve generic Fragnesia grading
  when package evidence is missing, reject single-device mode conclusions for
  multiple DPUs, and distinguish BMC command failures from denied access.

## PwnEscape evidence limits

The [kernel CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/99xxx/CVE-2026-99999.json)
provides these upstream fixed releases: 5.10.272, 5.15.223, 6.1.190, 6.6.159,
6.12.113, 6.18.57, and 7.2.11. The check compares exact upstream release
strings within a listed branch.

Distribution suffixes, custom builds, release candidates, unlisted branches,
and active or unreadable livepatch state require further evidence.
An absent livepatch interface on readable kernel sysfs does not suppress the
version comparison. Missing or unreadable kernel sysfs remains unknown.

A VM, container, or unresolved virtualization model cannot certify the hidden
physical host. The report retains the observed worker verdict and requests
provider evidence for the physical host. A newer installed kernel does not
change the running-kernel verdict.

The collector observes visible TUN and virtio-net devices, the user namespace
limit, and livepatch state. It does not open devices, send crafted traffic,
change network settings, or run an exploit. Missing devices and disabled
nested virtualization do not exempt a host.

The check does not verify checksum-offload controls, TAP-ingress rules,
fleet coverage, or cryptographic build identity.
[The Ubuntu tracker](https://ubuntu.com/security/CVE-2026-99999) required further
evaluation on October 17, 2026, so this check does not infer Ubuntu package
floors from upstream release numbers.

## Validation before merge

- Run the affected tests under `tests/audit/`. CI runs the full suite.
- Confirm that the final PR commit passes automated review.
- Build the wheel and source distribution. Check both with `twine check`.
- Check the wheel contents and install it outside the checkout.
- Confirm that `cmax audit security --show` and `cmax audit --show` include
  `security.pwnescape.status` and `security.badEpoll.status`.
- Confirm that the installed PwnEscape grader matches the reviewed source.
- Run the packaged standalone dry run without contacting a provider.
- Keep provider audit output, credentials, and internal campaign data out of
  the public commit and distribution archives.

The offline tests use synthetic fixtures. They cover upstream version
boundaries, hidden hosts, absent and active livepatch support, collector
execution, full-report parity, cache validation, and mixed GPU pools.
They do not establish the security status of a provider.

## Stable publication gate

The current source version remains `0.2.1`, which is already released.
Do not dispatch the stable workflow with that version.

After the maintainer selects the next stable version:

- Update `cmax/_version.py` and the default in `setup.py` to the same new
  version. Set the next nightly base in `.github/workflows/python-nightly.yml`
  so future nightly versions sort after that stable release.
- Rerun the package checks on that commit, obtain review, and merge the PR.
- Confirm that the website minimum table includes the new Bad Epoll and
  NVIDIA Fragnesia mappings. Coordinate the feed correction with
  [PR #38](https://github.com/SemiAnalysisAI/ClusterMAX/pull/38).
  If publication lags, the CLI must retain its shipped mappings.
- Confirm the `pypi` environment approval and Trusted Publisher configuration.
  The existing workflow publishes only from public `master`.
- Obtain explicit release approval before dispatching the `python-publish`
  workflow with `channel=stable` from `master`.
- Verify the published package version and perform a fresh installation from
  PyPI. Create the matching GitHub tag and release notes only with approval.

The workflow and its credentials are unchanged by this PR. No PyPI readiness
claim substitutes for checking those publication gates at release time.
