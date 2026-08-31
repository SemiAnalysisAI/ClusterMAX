#
# nix/analysis/default.nix — report-only static-analysis aggregator.
#
# Report-only model: analyzers are exposed as *packages*, never as
# `nix flake check` gates. Each per-tool package writes $out/report.txt; the
# combined `analysis` package gathers them under one tree with a summary.txt.
#
{
  pkgs,
  lib,
  versions,
  src,
}:
let
  mkReport = import ./mk-report.nix { inherit pkgs lib src; };

  tools = {
    "analysis-ruff" = import ./ruff.nix { inherit pkgs versions mkReport; };
    "analysis-ruff-format" = import ./ruff-format.nix { inherit pkgs versions mkReport; };
    "analysis-mypy" = import ./mypy.nix { inherit pkgs versions mkReport; };
    "analysis-bandit" = import ./bandit.nix { inherit pkgs versions mkReport; };
    "analysis-shellcheck" = import ./shellcheck.nix { inherit pkgs versions mkReport; };
  };

  # Combined report: one subdirectory per tool plus a top-level summary.
  combined = pkgs.runCommand "clustermax-analysis" { } (
    ''
      mkdir -p "$out"
      summary="$out/summary.txt"
      echo "ClusterMAX static-analysis summary (report-only)" >"$summary"
      echo "" >>"$summary"
    ''
    + lib.concatStringsSep "\n" (
      lib.mapAttrsToList (name: drv: ''
        cp -r ${drv} "$out/${name}"
        printf '%-22s exit=%s lines=%s\n' \
          "${name}" "$(cat ${drv}/exit-code.txt)" "$(cat ${drv}/count.txt)" >>"$summary"
      '') tools
    )
    + ''

      echo "" >>"$summary"
      cat "$summary"
    ''
  );
in
tools // { analysis = combined; }
