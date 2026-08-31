#
# nix/analysis/bandit.nix — bandit security report (report-only).
#
{
  pkgs,
  versions,
  mkReport,
}:
mkReport {
  name = "bandit";
  nativeBuildInputs = [ versions.bandit ];
  text = ''
    bandit -r cmax
  '';
}
