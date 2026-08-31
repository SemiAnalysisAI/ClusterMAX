#
# nix/packages.nix — dependency lists fed to the dev shell.
#
# Splits packages by role so the dev shell can pull them all in one place while
# each concern (checks, containers) imports only what it needs from versions.nix.
#
{ pkgs, versions }:
let
  # The Python interpreter plus runtime deps and pytest, importable as `cmax`.
  inherit (versions) pythonEnv;

  # Static-analysis tools exposed both as report packages and in the shell.
  analysisTools = [
    versions.ruff
    versions.mypy
    versions.bandit
    versions.shellcheck
  ];

  # General development conveniences.
  devTools = [
    versions.nixfmt
    pkgs.git
  ];
in
{
  inherit analysisTools devTools;

  # Everything the `nix develop` shell should put on PATH.
  allDevPackages = [ pythonEnv ] ++ analysisTools ++ devTools;
}
