#
# nix/checks/nixfmt.nix — assert every .nix file is nixfmt-formatted (a gate).
#
{
  pkgs,
  versions,
  src,
}:
pkgs.runCommand "clustermax-nixfmt-check"
  {
    nativeBuildInputs = [ versions.nixfmt ];
  }
  ''
    cd ${src}
    find . -name '*.nix' -print0 | xargs -0 nixfmt --check
    touch "$out"
  ''
