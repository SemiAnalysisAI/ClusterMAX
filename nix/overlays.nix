#
# nix/overlays.nix — expose the package and image to downstream flakes.
#
{ self }:
final: _prev: {
  cmax = self.packages.${final.system}.cmax or null;
  cmax-oci = self.packages.${final.system}.oci-cmax or null;
}
