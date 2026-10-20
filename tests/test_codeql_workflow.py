from pathlib import Path
import unittest

import yaml


WORKFLOW_PATH = Path(__file__).parents[1] / ".github/workflows/codeql.yml"


class CodeqlWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # BaseLoader preserves the GitHub Actions "on" key as text.
        cls.text = WORKFLOW_PATH.read_text()
        cls.workflow = yaml.load(cls.text, Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["analyze"]

    def test_fork_pull_requests_have_unfiltered_required_jobs(self):
        triggers = self.workflow["on"]
        self.assertEqual(
            set(triggers), {"pull_request", "push", "schedule", "workflow_dispatch"}
        )
        for event in ("pull_request", "push"):
            self.assertEqual(
                triggers[event], {"branches": ["master", "release/**"]}
            )
        self.assertNotIn("if", self.job)
        self.assertNotIn("continue-on-error", self.job)
        self.assertEqual(self.job["strategy"]["fail-fast"], "false")

    def test_required_check_names_match_branch_protection(self):
        languages = self.job["strategy"]["matrix"]["language"]
        names = {
            self.job["name"].replace("${{ matrix.language }}", language)
            for language in languages
        }
        self.assertEqual(names, {"Analyze (actions)", "Analyze (python)"})

    def test_permissions_do_not_grant_repository_or_token_writes(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(
            self.job["permissions"],
            {"contents": "read", "actions": "read", "security-events": "write"},
        )
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("secrets:", self.text)

    def test_actions_are_pinned_and_no_repository_build_is_executed(self):
        steps = self.job["steps"]
        self.assertEqual(len(steps), 3)
        for step in steps:
            self.assertRegex(step["uses"], r"^[\w/-]+@[0-9a-f]{40}$")
            self.assertNotIn("run", step)
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)
        self.assertTrue(steps[1]["uses"].startswith("github/codeql-action/init@"))
        self.assertEqual(steps[1]["with"]["languages"], "${{ matrix.language }}")
        self.assertEqual(steps[1]["with"]["build-mode"], "none")

    def test_checkout_uses_event_commit_without_persisted_credentials(self):
        checkout = self.job["steps"][0]
        self.assertTrue(checkout["uses"].startswith("actions/checkout@"))
        self.assertEqual(
            checkout["with"],
            {"ref": "${{ github.sha }}", "persist-credentials": "false"},
        )

    def test_results_are_uploaded_and_processed_without_suppressing_errors(self):
        analyze = self.job["steps"][-1]
        self.assertTrue(analyze["uses"].startswith("github/codeql-action/analyze@"))
        self.assertEqual(
            analyze["with"],
            {
                "category": "/language:${{ matrix.language }}",
                "upload": "always",
                "wait-for-processing": "true",
            },
        )


if __name__ == "__main__":
    unittest.main()
