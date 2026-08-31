#
# nix/analysis/ruff-format.nix — ruff format --check report (report-only).
#
{
  pkgs,
  versions,
  mkReport,
}:
mkReport {
  name = "ruff-format";
  nativeBuildInputs = [ versions.ruff ];
  text = ''
    ruff format --check --diff cmax
  '';
}
