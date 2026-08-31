#
# nix/analysis/mypy.nix — mypy type report (report-only, non-strict).
#
# The codebase has no type annotations yet; --ignore-missing-imports keeps the
# report focused on real errors rather than un-annotated third-party stubs.
#
{
  pkgs,
  versions,
  mkReport,
}:
mkReport {
  name = "mypy";
  nativeBuildInputs = [ versions.mypy ];
  text = ''
    mypy --ignore-missing-imports --no-error-summary cmax
  '';
}
