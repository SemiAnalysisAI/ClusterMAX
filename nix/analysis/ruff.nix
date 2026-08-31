#
# nix/analysis/ruff.nix — ruff lint report (report-only).
#
{
  pkgs,
  versions,
  mkReport,
}:
mkReport {
  name = "ruff";
  nativeBuildInputs = [ versions.ruff ];
  text = ''
    ruff check --output-format=full cmax
  '';
}
