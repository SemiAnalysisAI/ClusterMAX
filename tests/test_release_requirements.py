from pathlib import Path
import unittest


REQUIREMENTS_DIR = Path(__file__).parents[1] / ".github" / "requirements"


class ReleaseRequirementsTests(unittest.TestCase):
    def test_direct_release_dependencies_are_hash_locked(self) -> None:
        declared = [
            line.strip()
            for line in (REQUIREMENTS_DIR / "release.in").read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        locked = {
            line.split()[0]: line
            for line in (REQUIREMENTS_DIR / "release.txt")
            .read_text()
            .replace("\\\n", " ")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        self.assertTrue(declared, "release.in must declare release dependencies")
        for requirement in declared:
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, locked.keys())
                self.assertRegex(
                    locked[requirement],
                    r"--hash=sha256:[0-9a-f]{64}(?:\s|$)",
                )


if __name__ == "__main__":
    unittest.main()
