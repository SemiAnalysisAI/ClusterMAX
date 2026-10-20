# CodeQL checks for fork pull requests

## Problem

The protected `master` branch requires `test`, `Analyze (actions)`, and
`Analyze (python)`. GitHub's CodeQL default setup excludes pull requests from
forks, so external contributor PRs can pass the test job but wait indefinitely
for the two analysis checks.

See [GitHub's default-setup trigger documentation](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/code-scanning/setup-types).

## Workflow

`.github/workflows/codeql.yml` defines the `CodeQL advanced` workflow:

- Run on pull requests to `master` and `release/**`, including forks.
- Run on pushes to those branches, weekly, and on manual dispatch.
- Keep the required names `Analyze (actions)` and `Analyze (python)`.
- Do not use path filters, author filters, or conditional skips.
- Scan the event's exact commit. On `pull_request`, this is the test merge
  commit, not the contributor's head in a privileged base-repository context.
- Pin checkout and CodeQL actions to full commit SHAs.
- Do not persist checkout credentials, run a project build, or pass secrets.
- Use `pull_request`, never `pull_request_target`.
- Grant only repository and Actions read access plus the CodeQL upload scope.
- Upload both languages' results and wait for processing. Do not suppress
  upload errors or replace scanning with a successful placeholder check.

GitHub documents `pull_request` as the supported upload path for untrusted
Dependabot runs with read-only tokens:
[CodeQL upload permissions](https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/resource-not-accessible).
The workflow uses the same event for fork PRs. Contributor workflow approval
can still be required; this change does not disable that safeguard.

## Migration requires separate approval

Adding this workflow does not change repository settings or branch protection.
Do not remove required checks, fabricate statuses, or use an admin merge
bypass to make the migration pass.

GitHub rejects advanced CodeQL SARIF uploads while default setup remains
enabled. A failed upload before the settings change is not evidence that the
fork-compatible trigger is broken:
[default-setup upload conflict](https://docs.github.com/en/code-security/code-scanning/troubleshooting-sarif-uploads/default-setup-enabled).

1. Review this PR and its workflow tests. Obtain explicit approval for the
   default-to-advanced repository setting change. This is distinct from PR
   preparation and does not authorize a merge.
2. A repository administrator selects **Settings > Advanced Security >
   CodeQL analysis > Switch to advanced**, then disables default setup in the
   confirmation dialog. Use the reviewed workflow in this PR; do not create a
   second generated workflow. Follow
   [GitHub's migration instructions](https://docs.github.com/en/code-security/how-tos/scan-code-for-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).
3. Rerun this PR's `CodeQL advanced` workflow after the switch. Confirm both
   language jobs complete, upload results, and finish processing. Inspect
   the workflow identity, not just the job names: old default-setup runs may
   have the same names. Do not merge based only on those old runs.
4. Confirm `test` also passes on the current PR commit. Obtain merge approval
   and merge through normal protection rules. Verify advanced analysis on
   the resulting `master` commit.
5. Update each affected external PR from `master` so its merge contains the
   workflow. Approve the contributor Actions run if GitHub requests approval.
   Confirm that the two language analyses and `test` report on that PR's
   current commit before making a merge decision.
6. Verify uploaded analysis and the code-scanning result on a real fork PR
   such as #34. Local workflow tests alone do not establish end-to-end fork
   upload behavior.

Keep the existing required check names and GitHub Actions app association.
The workflow does not change the query suite from CodeQL's default selection.

## Validation

Run:

```sh
python -m pytest -q tests/test_codeql_workflow.py
python -m pytest -q
actionlint .github/workflows/codeql.yml
git diff --check
```

The regression tests cover event configuration, required job names, token
permissions, immutable action pins, checkout identity, and mandatory uploads.
They do not run CodeQL or change repository settings.

## Recovery

If the advanced workflow cannot upload after the switch, keep merges blocked
and inspect its logs. Do not disable upload or loosen protection to hide the
failure.

If the migration must be abandoned, obtain approval to restore default setup
and remove or disable this advanced workflow. Do not leave two competing
configurations. Restoring default setup also restores the fork-PR limitation;
it is recovery, not a fix for external PRs.
