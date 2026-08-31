#
# nix/devshell.nix — the `nix develop` environment.
#
# Plain pkgs.mkShell. The shellHook prints a menu and defines helper functions
# that call the SAME tool binaries the flake checks and analysis reports use, so
# the shell and CI cannot drift.
#
{
  pkgs,
  lib,
  packages,
  cmax,
}:
pkgs.mkShell {
  name = "clustermax-dev";
  # The built cmax is on PATH so `cmax` works in any invocation (incl.
  # `nix develop -c cmax ...`); the shell function below shadows it
  # interactively to run the working tree instead.
  packages = packages.allDevPackages ++ [ cmax ];

  shellHook = ''
    # Interactively, run the working-tree source so `cmax` reflects local edits.
    cmax() {            python3 -m cmax.cli "$@" ; }
    cmax-test() {       python3 -m pytest -q "''${@:-tests}" ; }
    cmax-lint() {       ruff check cmax ; }
    cmax-fmt() {        ruff format cmax ; }
    cmax-fmt-check() {  ruff format --check cmax ; }
    cmax-types() {      mypy cmax ; }
    cmax-sec() {        bandit -r cmax ; }
    cmax-shellcheck() { find cmax/scripts -name '*.sh' -print0 | xargs -0 shellcheck ; }
    cmax-analysis() {
      echo "== ruff =="        ; cmax-lint       || true
      echo "== ruff format ==" ; cmax-fmt-check  || true
      echo "== mypy =="        ; cmax-types      || true
      echo "== bandit =="      ; cmax-sec        || true
      echo "== shellcheck =="  ; cmax-shellcheck || true
    }
    cmax-help() {
      cat <<'EOF'
    ClusterMAX dev shell
      cmax [args]         run the CLI from the working tree (live edits)
      cmax-test [paths]   run pytest (default: tests)
      cmax-lint           ruff check cmax
      cmax-fmt            ruff format cmax (rewrites files)
      cmax-fmt-check      ruff format --check cmax
      cmax-types          mypy cmax
      cmax-sec            bandit -r cmax
      cmax-shellcheck     shellcheck the audit .sh scripts
      cmax-analysis       run every analyzer (report-only)
    EOF
    }

    cmax-help
  '';
}
