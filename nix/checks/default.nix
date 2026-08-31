#
# nix/checks/default.nix — the `nix flake check` gates.
#
# These must run inside Nix's hermetic build sandbox, so only sandbox-safe gates
# live here: nix formatting, plus the package build (its installCheck smoke-tests
# the CLI and asserts the bundled resources shipped — see ../clustermax.nix).
#
# The pytest suite is NOT a check: it stubs external tools with scripts that
# hard-code /bin/bash and /bin/cat, which do not exist in the sandbox. It runs in
# the host environment instead, via `nix run .#test` or `cmax-test` in the shell.
#
{
  pkgs,
  lib,
  versions,
  cmax,
  src,
}:
{
  # Building the package runs its installCheckPhase: `cmax --version` plus the
  # cmax.yaml / scripts/1-audit/run.sh resource assertions.
  cmax = cmax;

  nixfmt = import ./nixfmt.nix { inherit pkgs versions src; };
}
