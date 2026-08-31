#
# nix/analysis/mk-report.nix — uniform report-only analysis runner.
#
# Copies the source into a writable tree, runs one tool, and tees everything to
# $out/report.txt. It NEVER fails the build: static analysis here produces
# reports, it does not gate. $out/exit-code.txt records the tool's real exit
# status and $out/count.txt a crude finding-line count.
#
{
  pkgs,
  lib,
  src,
}:
{
  name,
  nativeBuildInputs ? [ ],
  # Shell snippet that runs the tool. cwd is a writable copy of the repo.
  text,
}:
pkgs.runCommand "clustermax-analysis-${name}"
  {
    inherit nativeBuildInputs;
    passthru.reportName = name;
  }
  ''
    cp -r ${src} ./source
    chmod -R +w ./source
    cd ./source

    mkdir -p "$out"
    report="$out/report.txt"

    set +e
    {
      ${text}
    } >"$report" 2>&1
    status=$?
    set -e

    echo "$status" >"$out/exit-code.txt"
    grep -c . "$report" >"$out/count.txt" 2>/dev/null || echo 0 >"$out/count.txt"
    echo "clustermax analysis ${name}: tool exit=$status, $(cat "$out/count.txt") report lines"
  ''
