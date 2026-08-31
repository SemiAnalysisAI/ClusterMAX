#
# nix/clustermax.nix — the cmax CLI package.
#
# buildPythonApplication over the repo's pyproject (setuptools backend). The
# dynamic version resolves through setup.py; with no CLUSTERMAX_BUILD_VERSION set
# it falls back to cmax/_version.py (0.2.1), which setup.py rewrites into the wheel.
#
{
  pkgs,
  lib,
  versions,
  src,
}:
let
  inherit (versions) python;
in
python.pkgs.buildPythonApplication {
  pname = "clustermax";
  version = "0.2.1";
  pyproject = true;

  inherit src;

  build-system = [ versions.setuptools ];

  # pyproject pins `requires = ["setuptools==84.0.0"]`; nixpkgs ships a nearby
  # setuptools that the backend builds fine with. Skip the frontend's exact-pin
  # check (build isolation is already off) rather than chase the pinned version.
  pypaBuildFlags = [ "--skip-dependency-check" ];

  dependencies = versions.runtimeDeps python.pkgs;

  # Tests run as a dedicated flake check (see nix/checks/pytest.nix), not here.
  doCheck = false;

  pythonImportsCheck = [ "cmax" ];

  # Assert the CLI runs and that the bundled resources shipped in the wheel —
  # the same invariants the CI wheel smoke-test guards.
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    echo "checking cmax --version"
    "$out/bin/cmax" --version

    siteDir=$(echo "$out/lib/"python*"/site-packages")
    test -f "$siteDir/cmax/cmax.yaml" \
      || (echo "missing cmax/cmax.yaml in $siteDir" && exit 1)
    test -f "$siteDir/cmax/scripts/1-audit/run.sh" \
      || (echo "missing scripts/1-audit/run.sh in $siteDir" && exit 1)

    runHook postInstallCheck
  '';

  meta = {
    description = "ClusterMAX GPU cluster audit and security CLI";
    homepage = "https://clustermax.semianalysis.com/";
    license = lib.licenses.asl20;
    mainProgram = "cmax";
  };
}
