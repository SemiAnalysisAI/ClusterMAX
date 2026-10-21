#!/usr/bin/env python3
"""Keep CLI coverage and public links aligned with the criteria catalog."""

from __future__ import annotations

import bashtest
import json
import sys
import unittest
from pathlib import Path


AUDIT_SCRIPTS = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit"
)
CATALOG_PATH = AUDIT_SCRIPTS / "criteria-checks.json"

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cmax import audit_profiles, audit_report, criteria_links, security  # noqa: E402


audit_findings = bashtest.load_python_script(AUDIT_SCRIPTS / "audit_findings.py", "audit_findings_criteria_parity")


KNOWN_GAPS = frozenset(
    {
        "mpi-srun-pmix",  # software.mpi.srunPmixAvailable is collected
        "prolog-fast",  # healthChecks.prologFast is collected
        "resource-limits",  # resourceLimits.* is collected
        "security-vmscape",  # security.vmscape.status is collected
        "security-qemu-virtio-serial",  # security.virtualization.virtioSerialExposed
        "idle-thermals",
        "ib-tenant-isolation",
        "fabric-class",
        "helm-access",
        "security-observability-isolation",
        "gpu-drivers",
        "cpu-power-governor",
        "gang-scheduling",
        "bin-packing",
        "default-storage-class",
        "gpu-operator",
        "network-operator",
        "vcluster-tenancy",
        "mpi-operator",
        "workload-schedulers",
        "ingress-controller",
        "load-balancer",
        "rbac-access",
    }
)


class CriteriaParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(CATALOG_PATH.read_text())
        cls.criteria = {entry["id"]: entry for entry in cls.catalog["criteria"]}

    def test_catalog_shape(self) -> None:
        for entry in self.catalog["criteria"]:
            self.assertIn(entry["coverage"], {"audit", "partial"})
            self.assertTrue(
                set(entry["harnesses"]) <= {"slurm", "k8s", "standalone"},
                entry["id"],
            )

    def test_every_check_key_maps_to_a_known_criterion(self) -> None:
        mapping = audit_findings.CHECK_CRITERIA
        rule_keys = {rule.key for rule in audit_findings.RULES}
        extension_ids = {
            "bmc-ipmi",
            "kubernetes-nodes-proxy",
            "nvlink-boundary",
            "pcie-passthrough",
            "ufm-profile",
        }

        self.assertEqual(set(mapping), rule_keys | extension_ids)
        for key, criterion_id in mapping.items():
            if criterion_id is None:
                continue  # CLI-only check; rationale lives next to the mapping.
            self.assertIn(criterion_id, self.criteria, f"{key} -> {criterion_id}")

    def test_every_audit_coverage_criterion_is_served_or_allowlisted(self) -> None:
        served = {cid for cid in audit_findings.CHECK_CRITERIA.values() if cid}
        audit_ids = {
            cid for cid, entry in self.criteria.items() if entry["coverage"] == "audit"
        }

        uncovered = audit_ids - served - KNOWN_GAPS
        self.assertEqual(uncovered, set(), f"unserved audit criteria: {sorted(uncovered)}")

        stale = KNOWN_GAPS - audit_ids
        self.assertEqual(stale, set(), f"KNOWN_GAPS not in catalog: {sorted(stale)}")

        covered_gaps = KNOWN_GAPS & served
        self.assertEqual(
            covered_gaps, set(), f"remove covered ids from KNOWN_GAPS: {sorted(covered_gaps)}"
        )

    def test_k8s_and_slurm_criteria_have_an_applicable_check(self) -> None:
        rules_by_criterion: dict[str, set[str]] = {}
        for rule in audit_findings.RULES:
            criterion_id = audit_findings.CHECK_CRITERIA.get(rule.key)
            if criterion_id is not None:
                rules_by_criterion.setdefault(criterion_id, set()).update(
                    rule.harnesses
                )
        for check_id in audit_report._SECURITY_EXTENSION_IDS:
            criterion_id = audit_findings.CHECK_CRITERIA[check_id]
            harnesses = audit_report._SECURITY_EXTENSION_HARNESSES.get(
                check_id, frozenset({"k8s", "slurm", "standalone"})
            )
            rules_by_criterion.setdefault(criterion_id, set()).update(harnesses)

        for harness in ("k8s", "slurm"):
            expected = {
                criterion_id
                for criterion_id, entry in self.criteria.items()
                if entry["coverage"] == "audit"
                and criterion_id not in KNOWN_GAPS
                and harness in entry["harnesses"]
            }
            served = {
                criterion_id
                for criterion_id, harnesses in rules_by_criterion.items()
                if harness in harnesses
            }
            self.assertEqual(
                expected - served,
                set(),
                f"{harness} criteria without an applicable check",
            )

    def test_rule_harness_scope_matches_the_dashboard(self) -> None:
        for rule in audit_findings.RULES:
            criterion_id = audit_findings.CHECK_CRITERIA[rule.key]
            if criterion_id is None:
                continue
            entry = self.criteria[criterion_id]
            self.assertTrue(
                set(rule.harnesses) <= set(entry["harnesses"]),
                f"{rule.key}: rule harnesses {sorted(rule.harnesses)} exceed "
                f"dashboard {entry['harnesses']} for {criterion_id}",
            )

    def test_every_mapped_rule_key_resolves_to_one_category(self) -> None:
        for rule in audit_findings.RULES:
            category = audit_profiles.category_for_key(rule.key)
            self.assertIsNotNone(category, rule.key)


class CriteriaLinkTests(unittest.TestCase):
    def test_every_reportable_check_has_a_non_generic_permalink(self) -> None:
        runtime_root = security.find_runtime_root()
        for spec in audit_report.list_check_specs(runtime_root):
            with self.subTest(check=spec.key):
                url = criteria_links.audit_check_url(spec.key)
                self.assertIsNotNone(url)
                self.assertTrue(url.startswith(f"{criteria_links.CRITERIA_URL}#"))
                self.assertNotEqual(url, criteria_links.CRITERIA_URL)

    def test_unknown_check_has_no_misleading_fallback(self) -> None:
        self.assertIsNone(criteria_links.audit_check_url("unknown.check"))


if __name__ == "__main__":
    unittest.main()
