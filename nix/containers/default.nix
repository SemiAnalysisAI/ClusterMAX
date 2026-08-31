#
# nix/containers/default.nix — OCI images for the current system.
#
# Native per-system: `nix build .#oci-cmax` produces the amd64 image on an
# x86_64 host and the arm64 image on an aarch64 host.
#
{
  pkgs,
  lib,
  cmax,
}:
let
  mkOciImage = import ../lib/mkOciImage.nix { inherit pkgs lib; };
in
{
  oci = mkOciImage {
    name = "cmax";
    inherit cmax;
  };
}
