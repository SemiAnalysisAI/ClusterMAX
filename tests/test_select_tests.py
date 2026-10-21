import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "select_tests.py"
spec = importlib.util.spec_from_file_location("select_tests", SCRIPT)
select_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select_tests)


class MappingGuardTests(unittest.TestCase):
    def test_every_test_file_is_selected_by_some_source(self):
        _, tested_by = select_tests._graph()
        reached = set().union(*tested_by.values())
        unreached = sorted(set(select_tests.test_files()) - reached)
        self.assertEqual(unreached, [], "name or import the code these tests cover")

    def test_every_source_file_selects_some_test_or_the_full_suite(self):
        unmapped = [
            source
            for source in select_tests.source_files()
            if not select_tests._matches(source, select_tests.FULL_SUITE)
            and not select_tests.tests_for_source(source)
        ]
        self.assertEqual(unmapped, [], "add a test or list the file in FULL_SUITE")


class SelectTests(unittest.TestCase):
    def test_docs_only_selects_nothing(self):
        self.assertEqual(select_tests.select(["docs/x.md", "README.md", "LICENSE"]), [])

    def test_unknown_and_suite_wide_paths_select_everything(self):
        for path in ("Makefile", "pyproject.toml", "tests/audit/bashtest.py"):
            with self.subTest(path=path):
                self.assertIsNone(select_tests.select([path]))

    def test_a_changed_test_file_selects_itself(self):
        self.assertIn(
            "tests/audit/test_minimum_links.py",
            select_tests.select(["tests/audit/test_minimum_links.py"]),
        )

    def test_a_source_selects_its_tests_and_the_tests_of_its_users(self):
        selected = select_tests.select(["cmax/scripts/1-audit/minimum_versions.py"])
        self.assertIn("tests/audit/test_minimum_versions.py", selected)
        # security_version_audit.py imports minimum_versions.
        self.assertIn("tests/audit/test_security_version_audit.py", selected)
        self.assertNotIn("tests/audit/test_banner.py", selected)

    def test_tests_that_import_a_selected_test_are_selected(self):
        selected = select_tests.select(["tests/audit/test_security_version_audit.py"])
        self.assertIn("tests/audit/test_amd_driver_security.py", selected)


if __name__ == "__main__":
    unittest.main()
