# Security release preparation

This PR prepares the public `cmax` CLI for release `0.3.0`. It sets the source
and build defaults to `0.3.0` and the next nightly base to `0.3.1`.
It also adds the stable publication workflow described below.
Adding this code does not merge the PR, dispatch that workflow, create a tag,
or publish a distribution.

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
- Confirm that wheel metadata, source-distribution metadata, and installed
  `cmax --version` all report `0.3.0`.
- Rebuild a wheel from the source distribution and verify the same version.
- Verify that the configured nightly version sorts after stable `0.3.0`.
- Run `tests/test_stable_release.py`. Its synthetic files and fake services
  test the publication guards without network access or publication.
- Lint the workflow with `actionlint`.
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

The source and build defaults are prepared for `0.3.0`. The nightly base is
`0.3.1`, so later development releases sort after stable `0.3.0`.
These changes do not publish a package.

Before publication:

- Rerun the package checks on that commit, obtain review, and merge the PR.
- Confirm that `0.3.0` has not already been published to PyPI before dispatch.
- Confirm that the website minimum table includes the new Bad Epoll and
  NVIDIA Fragnesia mappings. Coordinate the feed correction with
  [PR #38](https://github.com/SemiAnalysisAI/ClusterMAX/pull/38).
  If publication lags, the CLI must retain its shipped mappings.
- Confirm the `pypi` environment approval and Trusted Publisher configuration.
  The existing workflow publishes only from public `master`.
- Obtain explicit release approval before dispatching the `python-publish`
  workflow with `channel=stable` from `master`. Set `expected_version` to
  `0.3.0` and `smoke_tested_commit` to the full master SHA tested on a cluster.
  Both inputs must match the checked-out commit and version.
- Review the committed `docs/releases/0.3.0.md` notes before approving the
  stable `pypi` environment. That approval covers the PyPI upload and the
  subsequent matching GitHub tag and Release.

## Stable workflow

The workflow has four jobs. Each checks out the full commit SHA selected by
the dispatch rather than resolving a moving branch again.

- **Build:** Reject non-master or non-manual stable runs, mismatched inputs,
  existing PyPI versions, conflicting tags, and existing visible releases.
  Run the full tests, then build and smoke-test the wheel once.
  Bundle the distributions, committed notes, a version/commit manifest, and
  `SHA256SUMS` as one immutable Actions artifact.
- **Publish:** Wait for the existing `pypi` environment approval.
  Verify the downloaded bundle and recheck version/tag collisions after
  approval. Use Trusted Publishing to upload only the wheel and source
  distribution. Do not skip existing PyPI files.
- **Verify PyPI:** Poll for both files with up to 18 checks at 10-second intervals.
  Check their recorded hashes and reject yanked or unexpected files.
  Fetch the wheel from the PyPI file host, verify its bytes, and install it
  outside the checkout. Check the version, audit inventory, and dry-run plan.
- **GitHub Release:** Run only after successful PyPI verification and the
  clean-install checks. Create `v0.3.0` at the original full commit SHA.
  Create a draft, attach the original distributions, notes, manifest, and
  checksums, and verify the attachments before publishing the draft.

Only the final stable job has `contents: write`. The upload job retains
`id-token: write` for PyPI and gets no tag/release write permission.
Nightlies retain their schedule and separate environment. They verify the
same bundle format but do not create tags or GitHub Releases.
Stable artifacts are retained for 90 days and nightly artifacts for 14 days.

## Recovery

If PyPI succeeds and a later job fails, rerun the failed job and its dependents
in the original Actions run. Do not dispatch a new run or rerun all jobs,
because that rebuilds an already-published version.

The GitHub job finds interrupted drafts through the paginated releases API.
It checks the existing tag, notes, and asset bytes before resuming an upload.
It does not move tags, replace notes, clobber files, or delete releases.
A matching complete release is a no-op on retry.

If an existing tag, release, or asset differs, the job stops for inspection.
Permission errors also stop the job. If a PyPI upload only partly completes,
inspect the registry before any further action. This workflow does not
automatically repair or replace an existing PyPI version.

If the original Actions artifact has expired, stop and plan an explicit
recovery. Do not rebuild files and assume they match the published bytes.
Repository tag rules and PyPI environment restrictions remain in force.
