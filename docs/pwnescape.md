# PwnEscape kernel evidence

The PwnEscape check is passive. It reads kernel and package facts and does not
send probe traffic, open devices, or execute an exploit.

## Upstream kernels

The [Linux CNA record](https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/99xxx/CVE-2026-99999.json)
lists fixed stable releases for 5.10, 5.15, 6.1, 6.6, 6.12, 6.18, and 7.2,
and the mainline fix in 7.3. Exact upstream release strings are compared only
within their stable branch. Exact releases from 7.3.0 onward include the mainline
fix. Other exact upstream releases from 2.6.27 through 7.2 use the CNA's default
affected status unless their own branch has a listed fixed release.

For example, an upstream `6.8.12` is affected. An Ubuntu version signature that
ends in `6.8.12` does not establish the Ubuntu package's patch status.
Distribution suffixes and release candidates never use the upstream comparison.

## Ubuntu kernels

The check supports these image and source-package pairs:

| Ubuntu release | Running image | Source package |
|---|---|---|
| 24.04 | `6.8.0-<ABI>-generic` | `linux` or `linux-signed` |
| 26.04 | `7.0.0-<ABI>-generic` | `linux` or `linux-signed` |
| 22.04 HWE | `6.8.0-<ABI>-generic` | `linux-hwe-6.8` or `linux-signed-hwe-6.8` |

The collector reads `/etc/os-release`, `/proc/version_signature`, and the
installed source-package identity for `linux-image-$(uname -r)`. The package
version must agree with the running image's ABI and version signature. A newer
installed image, another source package, or a cloud-flavor ABI is not a match.
Held packages are accepted when their installation state is valid.

The daily minimum refresh now tracks `linuxPwnescape` for these Ubuntu releases.
The grader reads those CVE-specific entries from `minimum-versions.json` through
the existing minimum-table reader. It can use a future released fix without
changing the grader, provided that the fix stays in the mapped package train.
It does not make per-host network requests.

On 23 October 2026, the
[Ubuntu tracker](https://ubuntu.com/security/CVE-2026-99999)
records pending fixes `6.8.0-149.149i1` for Noble and `7.0.0-43.43i1` for Resolute.
Jammy's `linux-hwe-6.8` needs a fix. These are affected states, not released
security minimums.

- `needed` and `pending` report a local failure for a verified running image.
  A pending build is never used as a passing minimum.
- `released` compares the complete source-package version within the mapped
  train. The ABI, upload revision, and HWE suffix are not discarded.
- Missing identity evidence, unknown vendor states, malformed records, custom
  builds, and unmapped flavors remain unknown.

The refresh rejects an unknown PwnEscape state or the loss of a previously
released PwnEscape fix. The shipped table includes the reviewed affected states;
future refreshes follow the existing reviewed minimum-table publication path.

## Host and livepatch limits

A VM or unresolved virtualization model still requires evidence for the hidden
physical host, even when the visible Ubuntu kernel's local verdict is known.
Active or unreadable livepatch state requires CVE-specific evidence and never
silently changes an affected image into a pass.

Every reachable worker and control-plane host is graded. An affected host fails
the fleet; an unreadable host or undiscovered control plane blocks a fleet pass.
Each host record retains its Ubuntu identity evidence and vendor state.

This check is advisory-based version evidence, not cryptographic verification
of the running binary. A provider with a private backport must supply
CVE-specific evidence. Device absence and disabled user namespaces do not prove
that this CVE is fixed.
