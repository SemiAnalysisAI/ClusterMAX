import os
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


ROOT = Path(__file__).parent


def package_version() -> str:
    configured = os.environ.get("CLUSTERMAX_BUILD_VERSION")
    if configured:
        return configured
    package_info = ROOT / "PKG-INFO"
    if package_info.is_file():
        for line in package_info.read_text(encoding="utf-8").splitlines():
            if line.startswith("Version: "):
                return line.removeprefix("Version: ").strip()
    return "0.2.1"


class PublicBuildPy(build_py):
    """Write the selected release version into the public wheel."""

    def run(self) -> None:
        super().run()
        version_file = Path(self.build_lib) / "cmax" / "_version.py"
        version_file.write_text(
            f'"""Version embedded in this built distribution."""\n\n'
            f'__version__ = "{self.distribution.get_version()}"\n',
            encoding="utf-8",
        )


setup(
    version=package_version(),
    cmdclass={"build_py": PublicBuildPy},
)
