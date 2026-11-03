# ClusterMAX

This repository contains the ClusterMAX command-line interface.

## UX, DX and AX

- Cut taglines, helper text and secondary labels. If a screen needs them to make sense, fix the layout.
- Make the best decision that will elevate all three: the user experience (UX), developer experience (DX), and agent experience (AX) always, without breaking anything.

## Repository layout

- `cmax/` contains the Python runtime code.
- `cmax/scripts/1-audit/` contains the audit scripts.
- `tests/audit/` contains the automated audit tests, fixtures, and test helpers.

## New and ported commands

Every command that runs against a cluster or host target gets the host role
guard (`cmax/host_role.py`). The guard stops a standalone run on a cluster
node and a Slurm run from a compute node, and `--yes` or `--allow-cluster-node`
skips it.

- Add the target options with `_add_target_confirmation_options(parser, noun=...)`
  in `cmax/cli.py`. `noun` names the work in the messages, for example `"benchmark"`.
- Select the target with `target_selection.prepare_target(..., noun=...)`.
- A command that runs nothing on a target (for example, it reads saved files)
  goes in `HOST_ROLE_EXEMPT_COMMANDS` with a comment that says why.

`test_every_cli_command_has_the_host_role_guard` walks the whole parser tree
and fails for a command that does neither.

## Tests on cluster hosts

`tests/conftest.py` applies to every test directory. It hides the host's Slurm,
Kubernetes, container, GPU, and fabric tools from PATH, removes `SLURM_*`,
`SLURMD_*`, and `KUBERNETES_*` variables, and makes host role detection return
unknown. The suite then runs the same on a laptop, a CI runner, a login node,
a compute node under `srun`, and a pod. Stub a tool or set a variable in the
test that needs it. Put tests for a new module in a new `tests/<module>/`
directory; they get the same isolation.

## Audit tests

Put audit tests, fixtures, and test helpers in `tests/audit/`.

Install `pytest` and `pytest-xdist`; `pyproject.toml` runs pytest with `-n auto`.

Run the full suite with:

```bash
python3 -m pytest -q
```

List the test files that cover a change with:

```bash
python3 .github/scripts/select_tests.py --base origin/master
```

Pull requests run only the selected tests. Pushes to `master`, the nightly run,
and pull requests with the `full-tests` label run the full suite.
Run `git diff --check` before submitting changes.

After you complete all work, write the final user summary in accordance with [ASD-STE100 Simplified Technical English](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf).
