# AMD host-driver security evidence

The audit treats AMD Linux GPU Driver releases separately from ROCm releases.
[AMD-SB-6034](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6034.html)
specifies driver 31.40 for CVE-2026-43603 on nine Instinct models. The daily
generator reads the affected models, minimums, CVEs, and dates into `amdDriver`.
Existing ROCm requirements are unchanged.

## Evidence and grading

The host check reads the loaded module version and source fingerprint from
`/sys/module/amdgpu`. It compares them with `modinfo` for the installed module.
An installed update does not pass while an older module remains loaded.

Automatic grading currently supports Debian/Ubuntu vendor packages:

- Prebuilt modules must belong to an installed package.
- DKMS modules must match the built module for the running kernel. Their source
  `dkms.conf` must belong to the installed `amdgpu-dkms` package.
- The installed package version must have exactly one repository origin in the
  local APT metadata, under `https://repo.radeon.com/amdgpu/<release>/ubuntu`.
  Candidate versions and installer package versions are not evidence.
- The loaded and installed module versions and source fingerprints must match.

The evaluator compares that vendor release with the minimum for the affected GPU.
Missing or conflicting evidence reports `unknown`, with a provider-evidence
finding. This includes RPM installations, inaccessible host package metadata,
custom builds, unlisted hardware, and distribution backports. A provider must
supply evidence that identifies the affected host, loaded build, and applicable
vendor or distribution fix. This change adds no automatic attestation override.

The audit does not compare raw 6.x module versions or ROCm versions against
31.40. It does not run exploit code, install packages, or reload modules.
The result covers the inspected host, not every worker in a cluster.
Package metadata and source fingerprints are operational evidence, not
cryptographic attestation against a compromised host.

## Validation limits

Tests use synthetic package and host evidence plus a trimmed AMD bulletin
fixture. The parser was also checked against the live bulletin. No AMD GPU host
was available for a hardware integration test.
