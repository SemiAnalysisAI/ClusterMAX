#
# nix/versions.nix — single source of truth for tool and dependency versions.
#
# Every other module imports this so shell, checks, package, and container all
# agree on the same Python interpreter and tool set — no drift.
#
{ pkgs }:
let
  # CI runs on Python 3.12; pin to match (pyproject requires >= 3.10).
  python = pkgs.python312;

  # Runtime dependencies of the cmax package (pyproject `dependencies`).
  runtimeDeps = ps: [
    ps.prompt-toolkit
    ps.pyyaml
  ];

  # A Python environment that can import cmax and run the test suite.
  # Used by the pytest check and the dev shell.
  pythonEnv = python.withPackages (ps: (runtimeDeps ps) ++ [ ps.pytest ]);
in
{
  inherit python runtimeDeps pythonEnv;

  # Build-time tools for producing the wheel / package.
  setuptools = python.pkgs.setuptools;

  # Static-analysis tools (report-only) and the Nix formatter.
  ruff = pkgs.ruff;
  mypy = pkgs.mypy;
  bandit = pkgs.bandit;
  shellcheck = pkgs.shellcheck;
  nixfmt = pkgs.nixfmt;
}
