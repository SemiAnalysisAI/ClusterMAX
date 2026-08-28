#!/usr/bin/env python3
"""Public criteria permalinks used by the audit CLI."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cmax import audit_report, criteria_links, security  # noqa: E402


class CriteriaLinkTests(unittest.TestCase):
    def test_representative_checks_use_specific_public_anchors(self) -> None:
        self.assertEqual(
            criteria_links.audit_check_url("securityVersions.nvidiaDriver.status"),
            "https://www.clustermax.ai/criteria#security-every-component-patched-"
            "to-at-least-the-published-clustermax-minimum-version-covering-the-gpu-"
            "driver-container-runtime-nic-and-dpu-firmware-and-host-packages",
        )
        self.assertEqual(
            criteria_links.audit_check_url("storage.rwxStatus"),
            "https://www.clustermax.ai/criteria#storage-storage-integration-with-"
            "kubernetes-for-pvcs-storage-class-including-readwritemany-rwx-pvcs",
        )
        self.assertEqual(
            criteria_links.audit_check_url("ufm-profile"),
            "https://www.clustermax.ai/criteria#security-infiniband-csps-enable-"
            "the-ufm-secured-bare-metal-cloud-profile-providing-a-comprehensive-"
            "set-of-security-features-required-for-secure-multi-tenant-cloud-"
            "environments",
        )

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
