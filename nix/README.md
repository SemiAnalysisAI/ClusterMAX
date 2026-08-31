# Nix flake: dev shell, package, containers, and analysis

This flake gives you a reproducible development environment, a hermetic build
of the `cmax` CLI, OCI container images, and a set of report-only static
analysers — pinned so you get the same tools and results on any machine. The
design is modular: a slim top-level `flake.nix` wires together small
single-purpose modules under `nix/`.

## New to Nix?

[Nix](https://nixos.org) is a package manager that builds software in isolation
from pinned inputs. In practice that means `nix develop` drops you into a shell
with the exact Python and tools this project needs — nothing installed
system-wide, nothing to conflict with your distro — and `nix build` produces the
same result on any machine.

**Install Nix** (multi-user, recommended):

```
sh <(curl -L https://nixos.org/nix/install) --daemon
```

Single-user (no root, e.g. in a container): use `--no-daemon` instead. Full
instructions: <https://nix.dev/install-nix>.

**Enable flakes** (once). Either add this line to `/etc/nix/nix.conf` (or
`~/.config/nix/nix.conf`):

```
experimental-features = nix-command flakes
```

…or prefix each command with
`--extra-experimental-features 'nix-command flakes'`.

**Two commands to get started**, from the repo root:

```
nix develop            # enter the dev shell; type 'cmax-help'
nix build .#cmax       # build the CLI -> ./result/bin/cmax
```

Video walkthroughs of the install:
[Ubuntu](https://youtu.be/cb7BBZLhuUY) ·
[Fedora](https://youtu.be/RvaTxMa4IiY). Handy references: the
[flakes wiki](https://nixos.wiki/wiki/flakes) and
[search.nixos.org](https://search.nixos.org) to find any package.

> Flakes only see git-tracked files. After adding or editing files under
> `nix/`, `git add` them before `nix build` / `nix develop`.

## Dev shell

```
nix develop            # dev shell (Python 3.12, ruff, mypy, bandit, shellcheck)
```

Type `cmax-help` for the menu. The shell defines helper functions that call the
same tool binaries the flake uses, so the shell and CI cannot drift:

| Command | Action |
|---|---|
| `cmax [args]` | Run the CLI from the working tree (your edits apply at once). |
| `cmax-test [paths]` | Run pytest (default: `tests`). |
| `cmax-lint` | `ruff check cmax` |
| `cmax-fmt` | `ruff format cmax` (rewrites files) |
| `cmax-fmt-check` | `ruff format --check cmax` |
| `cmax-types` | `mypy cmax` |
| `cmax-sec` | `bandit -r cmax` |
| `cmax-shellcheck` | shellcheck the audit `.sh` scripts |
| `cmax-analysis` | run every analyser (report-only) |

`cmax` is also on `PATH` as the built program, so `nix develop -c cmax ...` works
too; the shell function shadows it interactively to run your working tree.

## Build & run

```
nix build .#cmax           # -> ./result/bin/cmax
./result/bin/cmax --version
nix run .#cmax -- --help    # build and run in one step
```

The build runs an install check: it confirms `cmax --version` works and that the
bundled resources (`cmax.yaml`, `scripts/1-audit/run.sh`) shipped in the wheel.

## Static analysis (report-only)

Each analyser is a build target. The targets **always succeed** and write their
findings to `$out/report.txt` — they generate reports, they do not gate.

```
nix build .#analysis            # run all analysers; writes result/summary.txt
cat result/summary.txt

nix build .#analysis-ruff        # ruff lint
nix build .#analysis-ruff-format # ruff format --check
nix build .#analysis-mypy        # mypy (non-strict)
nix build .#analysis-bandit      # bandit security scan
nix build .#analysis-shellcheck  # shellcheck for the audit .sh scripts
```

Each per-tool result holds `report.txt` (the findings), `exit-code.txt` (the
tool's real exit status), and `count.txt` (a rough finding-line count). Tool
configuration lives in the repo's `pyproject.toml` (`[tool.ruff]`,
`[tool.mypy]`, `[tool.bandit]`), so the same rules apply inside and outside Nix.

## Tests

```
nix run .#test              # run the pytest suite in the host environment
nix run .#test -- tests/audit/test_security.py    # a subset
```

The suite runs through `nix run .#test`, **not** `nix flake check`. Its command
stubs write helper scripts that hard-code `/bin/bash` and `/bin/cat`; those paths
exist on a real host but not inside Nix's hermetic build sandbox, so the tests
must run in the host. Inside the dev shell, `cmax-test` does the same thing.

## Container images (OCI)

```
nix build .#oci-cmax        # OCI image for the host architecture
docker load < result        # -> loads cmax:latest
docker run --rm cmax:latest --version
```

The image is built with `dockerTools.buildLayeredImage` over the `cmax` package
plus `bash` and `coreutils` (the audit scripts are shell scripts that call
`python3`; cluster tools such as `kubectl`/`srun` are provided by the
environment, not baked in). The entrypoint is `/bin/cmax`, and the image
timestamp is fixed for reproducibility.

**amd64 and aarch64.** Images are native per-system: build `.#oci-cmax` on an
x86_64 host for the amd64 image and on an aarch64 host for the arm64 image. On a
single host you can build the other architecture through binfmt/QEMU emulation.
The package and image derivations evaluate for both `x86_64-linux` and
`aarch64-linux`.

## Gates: `nix flake check`

```
nix flake check            # package build + CLI smoke check + nix formatting
nix fmt                    # format the .nix files
```

Only sandbox-safe gates run here: the package build (whose install check
smoke-tests the CLI and the bundled resources) and a `nixfmt` formatting check.
Static analysis is report-only (above) and the test suite runs in the host
(above), so neither gates this command.

## Module layout

| Path | Role |
|---|---|
| `flake.nix` | Thin orchestrator; the target list lives in its header comment. |
| `nix/default.nix` | Per-system aggregator: assembles packages, devShells, checks, apps. |
| `nix/versions.nix` | Single source of truth for the Python interpreter and tool versions. |
| `nix/packages.nix` | Dependency lists fed to the dev shell. |
| `nix/clustermax.nix` | The `cmax` package (`buildPythonApplication`). |
| `nix/devshell.nix` | The `nix develop` environment and its helper functions. |
| `nix/lib/mkOciImage.nix` | OCI image factory. |
| `nix/containers/` | The `oci-cmax` image for the current system. |
| `nix/analysis/` | Report-only analysers (`ruff`, `mypy`, `bandit`, `shellcheck`) + combined report. |
| `nix/checks/` | The `nix flake check` gates (package build + nixfmt). |
| `nix/overlays.nix` | Exposes `cmax` and `cmax-oci` to downstream flakes. |

Every module is a function that takes an explicit attribute set and returns a
derivation (or a set of them). Tool versions come from `nix/versions.nix` alone,
so there is one place to change them.
