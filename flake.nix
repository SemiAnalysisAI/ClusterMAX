#
# flake.nix — ClusterMAX
#
# Thin orchestrator. Every concern lives under ./nix/ and is wired up here.
# See ./nix/default.nix for the per-system aggregator.
#
# Targets:
#   nix develop                        # dev shell (ruff, mypy, bandit, shellcheck, pytest)
#   nix build   .#cmax                 # build the cmax CLI
#   nix run     .#cmax -- --help       # run the CLI
#   nix build   .#oci-cmax             # OCI image for the host arch (amd64 or aarch64)
#   nix build   .#analysis             # run ALL static-analysis reports (report-only)
#   nix build   .#analysis-ruff        # ruff lint report
#   nix build   .#analysis-ruff-format # ruff format --check report
#   nix build   .#analysis-mypy        # mypy type report
#   nix build   .#analysis-bandit      # bandit security report
#   nix build   .#analysis-shellcheck  # shellcheck report for the audit .sh scripts
#   nix run     .#test                 # run the pytest suite (uses the host toolchain)
#   nix flake check                    # package build + CLI smoke + nix formatting (gates)
#   nix fmt                            # format the .nix files
#
# Static analysis is report-only: the analysis-* targets always succeed and write
# their findings to $out/report.txt.
#
# The pytest suite runs via `nix run .#test`, not `nix flake check`: its command
# stubs hard-code /bin/bash and /bin/cat, which do not exist in the hermetic Nix
# build sandbox. The gates that DO run under `nix flake check` are the package
# build (its installCheck smoke-tests the CLI + resources) and nix formatting.
#
# Containers are native per-system: build .#oci-cmax on an x86_64 host for the
# amd64 image, and on an aarch64 host (or through binfmt/qemu) for the arm64 image.
#
{
  description = "ClusterMAX — GPU cluster audit and security CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = nixpkgs.lib;

        aggregator = import ./nix {
          inherit pkgs lib;
          src = ./.;
        };
      in
      {
        inherit (aggregator)
          packages
          devShells
          checks
          apps
          formatter
          ;
      }
    )
    // {
      overlays.default = import ./nix/overlays.nix { inherit self; };
    };
}
