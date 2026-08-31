#
# nix/lib/mkOciImage.nix — OCI image factory.
#
# Wraps dockerTools.buildLayeredImage over the cmax package plus bash/coreutils
# (the audit scripts are .sh files that shell out to python3; external cluster
# tools like kubectl/slurm are environment-provided, not baked in).
#
# The image architecture follows pkgs.stdenv.hostPlatform, so building on an
# x86_64 host yields the amd64 image and building on aarch64 yields the arm64
# image — native per-system, no cross plumbing.
#
{ pkgs, lib }:
{
  name,
  cmax,
  tag ? "latest",
}:
pkgs.dockerTools.buildLayeredImage {
  inherit name tag;

  # Reproducible: a fixed epoch instead of "now".
  created = "1970-01-01T00:00:00Z";

  contents = [
    cmax
    pkgs.bashInteractive
    pkgs.coreutils
    pkgs.dockerTools.caCertificates
  ];

  config = {
    Entrypoint = [ "/bin/cmax" ];
    Env = [ "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt" ];
    Labels = {
      "org.opencontainers.image.title" = "clustermax";
      "org.opencontainers.image.description" = "ClusterMAX GPU cluster audit and security CLI";
      "org.opencontainers.image.licenses" = "Apache-2.0";
      "org.opencontainers.image.source" = "https://github.com/SemiAnalysisAI/ClusterMAX";
    };
  };
}
