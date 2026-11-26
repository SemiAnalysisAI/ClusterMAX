"""Behavioral tests for the monitoring collector's scrape-freshness check.

The guarded incident: a monitoring stack can be fully "installed" and still
have stopped scraping. Every installer check passes, the pods are Running, the
dashboards load, and the graphs are flat at the moment of the outage. The
collector previously reported only whether Prometheus existed, so a cluster
that had not ingested a sample for hours scored the same as a healthy one.

`check_prometheus_freshness` asks the running server for the age of its newest
sample and grades it fresh / delayed / stale. These tests execute the real
function with a stubbed `kubectl`, so the grading boundaries are pinned
without a live cluster.

The age must come from `max(timestamp(...))`. A count of series stays high
long after scrapes stop, so a count cannot distinguish a live server from a
dead one.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPT_DIR = Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"

AUDIT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(AUDIT_DIR))
import bashtest

COLLECTOR = SCRIPT_DIR / "monitoring-k8s.sh"

# print_* are shell functions in the full collector; stub them as executables
# so the extracted function runs standalone.
PRINT_STUBS = {
    "print_section": "",
    "print_info": 'printf "INFO %s\\n" "$*"',
    "print_warn": 'printf "WARN %s\\n" "$*"',
    "print_detail": "",
}

PROM_POD = "prometheus-kube-prometheus-stack-prometheus-0"


def _run(monkeypatch, prom_response: str | None, *, now: int = 1_800_000_000,
         fallback: str | None = None) -> bashtest.BashRun:
    """Execute check_prometheus_freshness with a stubbed kubectl.

    prom_response None makes the exec return nothing, which is what an
    unreachable server looks like.
    """
    body = bashtest.extract_function(COLLECTOR, "check_prometheus_freshness")

    # kubectl dispatches on argv: the pod lookup returns the pod name, the
    # exec returns the canned Prometheus JSON.
    kubectl_body = f"""
case "$1" in
  get)  printf '%s' '{PROM_POD}' ;;
  exec) case "$*" in
          *max_over_time*) printf '%s' '{fallback if fallback is not None else prom_response or ""}' ;;
          *) printf '%s' '{prom_response or ""}' ;;
        esac ;;
esac
"""
    # Freeze the clock so the arithmetic is reproducible.
    date_body = f'#!/bin/bash\nprintf "{now}"\n'
    snippet = (
        "set -u\n"
        f'PROMETHEUS_NAMESPACE="monitoring"\n'
        f'PROMETHEUS_SCRAPE_AGE_SECONDS=""\n'
        f'PROMETHEUS_FRESHNESS="unknown"\n'
        f"{body}\n"
        "check_prometheus_freshness\n"
        'printf "AGE=%s\\n" "$PROMETHEUS_SCRAPE_AGE_SECONDS"\n'
        'printf "FRESHNESS=%s\\n" "$PROMETHEUS_FRESHNESS"\n'
    )

    with _stub_dir(monkeypatch, {"kubectl": kubectl_body, "date": date_body}):
        return bashtest.run_bash(snippet, stubs=PRINT_STUBS)


class _stub_dir:
    """Temporarily prepend a directory holding the named executables.

    bashtest.run_bash creates its own stub dir; date needs a fixed output, so
    it gets a real shim ahead of it on PATH.
    """

    def __init__(self, monkeypatch, scripts: dict[str, str]):
        self.monkeypatch = monkeypatch
        self.scripts = scripts
        self.tmp = None

    def __enter__(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory(prefix="freshness-")
        for name, body in self.scripts.items():
            p = Path(self.tmp.name) / name
            if name == "date":
                p.write_text(body)
            else:
                p.write_text(f'#!/bin/bash\n{body}\n')
            p.chmod(0o755)
        self.monkeypatch.setenv(
            "PATH", f"{self.tmp.name}:{Path('/usr/bin')}:{Path('/bin')}"
        )
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()
        return False


def _prom_json(ts: float) -> str:
    return json.dumps(
        {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {}, "value": [ts, f"{ts}"]}],
            },
        }
    )


NOW = 1_800_000_000


def test_fresh_sample_is_graded_fresh(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW - 10), now=NOW)
    assert run.returncode == 0, run.stderr
    assert "FRESHNESS=fresh" in run.stdout
    assert "AGE=10" in run.stdout


def test_boundary_300s_is_still_fresh(monkeypatch):
    # 300 seconds is the last fresh value; the next second is delayed.
    run = _run(monkeypatch, _prom_json(NOW - 300), now=NOW)
    assert "FRESHNESS=fresh" in run.stdout
    assert "AGE=300" in run.stdout


def test_301s_is_delayed(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW - 301), now=NOW)
    assert "FRESHNESS=delayed" in run.stdout


def test_boundary_3600s_is_delayed(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW - 3600), now=NOW)
    assert "FRESHNESS=delayed" in run.stdout


def test_3601s_is_stale(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW - 3601), now=NOW)
    assert "FRESHNESS=stale" in run.stdout
    assert "WARN" in run.stdout


def test_a_day_old_sample_is_stale(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW - 86400), now=NOW)
    assert "FRESHNESS=stale" in run.stdout
    assert "AGE=86400" in run.stdout


def test_unreachable_server_is_not_assessed(monkeypatch):
    # No response at all must not be reported as stale: a server we cannot
    # query tells us nothing about how old its data is.
    run = _run(monkeypatch, None, now=NOW)
    assert run.returncode == 0, run.stderr
    assert "FRESHNESS=unknown" in run.stdout
    assert "AGE=\n" in run.stdout or run.stdout.endswith("AGE=\n")


def test_malformed_response_is_not_assessed(monkeypatch):
    run = _run(monkeypatch, "not json at all", now=NOW)
    assert run.returncode == 0, run.stderr
    assert "FRESHNESS=unknown" in run.stdout


def test_empty_result_is_not_assessed(monkeypatch):
    # An empty result set means the query found no series. That is not the
    # same as stale data, so the check must decline to grade it.
    run = _run(
        monkeypatch,
        json.dumps({"status": "success", "data": {"resultType": "vector", "result": []}}),
        now=NOW,
    )
    assert "FRESHNESS=unknown" in run.stdout


def test_negative_age_is_clamped_to_zero(monkeypatch):
    # A sample timestamp a fraction ahead of the local clock is a small clock
    # disagreement, not data from the future. Reporting -1 seconds would be
    # nonsense in the JSON.
    run = _run(monkeypatch, _prom_json(NOW + 2), now=NOW)
    assert "FRESHNESS=fresh" in run.stdout
    assert "AGE=0" in run.stdout


def test_old_scrapes_are_found_after_instant_selector_goes_empty(monkeypatch):
    empty = json.dumps({"status": "success", "data": {"resultType": "vector", "result": []}})
    run = _run(monkeypatch, empty, now=NOW, fallback=_prom_json(NOW - 7200))
    assert "FRESHNESS=stale" in run.stdout
    assert "AGE=7200" in run.stdout


def test_a_large_future_timestamp_is_unknown_not_fresh(monkeypatch):
    run = _run(monkeypatch, _prom_json(NOW + 86400), now=NOW)
    assert "FRESHNESS=unknown" in run.stdout
    assert "AGE=\n" in run.stdout


@pytest.mark.parametrize("timestamp", ["NaN", "+Inf", "bad"])
def test_nonfinite_or_invalid_timestamp_is_unknown(monkeypatch, timestamp):
    response = json.loads(_prom_json(NOW))
    response["data"]["result"][0]["value"][1] = timestamp
    run = _run(monkeypatch, json.dumps(response), now=NOW)
    assert "FRESHNESS=unknown" in run.stdout


@pytest.mark.parametrize("freshness,production", [
    ("fresh", True), ("stale", False), ("delayed", False), ("unknown", False),
])
def test_installation_score_cannot_clear_unreadable_or_dead_scrapes(freshness, production):
    text = COLLECTOR.read_text()
    start = text.index('if [[ "$SCORE" -ge 9')
    end = text.index("\nfi", start) + len("\nfi")
    snippet = (
        f'SCORE=10; PROMETHEUS_FRESHNESS="{freshness}"; GREEN=; YELLOW=; RED=; NC=; '
        + text[start:end] + '\nprintf "STATUS=%s\\n" "$MONITORING_STATUS"'
    )
    result = bashtest.run_bash(snippet)
    assert result.returncode == 0, result.stderr
    assert ("STATUS=production" in result.stdout) is production


def test_query_uses_max_timestamp_not_a_series_count(monkeypatch):
    # The query text is what distinguishes a real liveness probe from a count
    # that stays high while scrapes are stopped.
    source = bashtest.extract_function(COLLECTOR, "check_prometheus_freshness")
    assert "max(timestamp(" in source
    assert "count(" not in source


def test_freshness_is_reported_in_json_output(monkeypatch):
    # The field must reach the JSON, otherwise the collector knows the answer
    # and no consumer can read it.
    text = COLLECTOR.read_text()
    assert '"scrapeAgeSeconds"' in text
    assert '"freshness"' in text


def test_collector_still_parses():
    # The added function and JSON fields must not break the script.
    import subprocess

    result = subprocess.run(
        ["bash", "-n", str(COLLECTOR)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
