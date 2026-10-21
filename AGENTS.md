# ClusterMAX

This repository contains the ClusterMAX command-line interface.

## Repository layout

- `cmax/` contains the Python runtime code.
- `cmax/scripts/1-audit/` contains the audit scripts.
- `tests/audit/` contains the automated audit tests, fixtures, and test helpers.

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
