#
# nix/default.nix — per-system aggregator.
#
# Imports every sub-module and assembles the flake outputs for one system:
# packages, devShells, checks, apps, and the formatter. flake.nix re-exports
# these under flake-utils.lib.eachSystem.
#
{
  pkgs,
  lib,
  src,
}:
let
  versions = import ./versions.nix { inherit pkgs; };
  packages = import ./packages.nix { inherit pkgs versions; };

  cmax = import ./clustermax.nix {
    inherit
      pkgs
      lib
      versions
      src
      ;
  };
  containers = import ./containers { inherit pkgs lib cmax; };
  analysis = import ./analysis {
    inherit
      pkgs
      lib
      versions
      src
      ;
  };

  devshell = import ./devshell.nix {
    inherit
      pkgs
      lib
      packages
      cmax
      ;
  };
  checks = import ./checks {
    inherit
      pkgs
      lib
      versions
      cmax
      src
      ;
  };

  # The test suite runs in the host environment (not the hermetic sandbox),
  # because its command stubs hard-code /bin/bash and /bin/cat.
  testApp = pkgs.writeShellApplication {
    name = "clustermax-test";
    runtimeInputs = [ versions.pythonEnv ];
    text = ''
      python -m pytest -q "''${@:-tests}"
    '';
  };
in
{
  packages = {
    default = cmax;
    inherit cmax;
    oci-cmax = containers.oci;
  }
  // analysis; # analysis-ruff, analysis-mypy, ..., and combined `analysis`

  devShells.default = devshell;

  checks = checks;

  apps = {
    cmax = {
      type = "app";
      program = "${lib.getExe cmax}";
      meta.description = "Run the cmax CLI";
    };
    analysis = {
      type = "app";
      program = "${lib.getExe (
        pkgs.writeShellApplication {
          name = "clustermax-analysis";
          text = ''
            cat ${analysis.analysis}/summary.txt
          '';
        }
      )}";
      meta.description = "Print the combined static-analysis summary";
    };
    test = {
      type = "app";
      program = "${lib.getExe testApp}";
      meta.description = "Run the pytest suite in the host environment";
    };
  };

  formatter = versions.nixfmt;
}
