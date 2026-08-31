#
# nix/analysis/shellcheck.nix — shellcheck report for the audit .sh scripts.
#
# -x follows `source`d files (e.g. audit-common.sh). Report-only.
#
{
  pkgs,
  versions,
  mkReport,
}:
mkReport {
  name = "shellcheck";
  nativeBuildInputs = [ versions.shellcheck ];
  text = ''
    find cmax/scripts -name '*.sh' -print0 | sort -z | xargs -0 shellcheck -x
  '';
}
