#!/usr/bin/env python3
"""Tests for links from audit results to published minimum-version rows."""

from __future__ import annotations

import unittest

from cmax import minimum_links


class MinimumLinksTests(unittest.TestCase):
    def test_focused_security_checks_link_to_their_component_rows(self) -> None:
        self.assertEqual(
            minimum_links.security_check_url("runc"),
            "https://www.clustermax.ai/minimum-versions#runc",
        )
        self.assertEqual(
            minimum_links.security_check_url("nvidia-driver"),
            "https://www.clustermax.ai/minimum-versions#nvidiaDriver",
        )
        self.assertEqual(
            minimum_links.security_check_url("fragnesia"),
            "https://www.clustermax.ai/minimum-versions#ubuntuNoble",
        )

    def test_full_audit_version_checks_link_to_their_component_rows(self) -> None:
        self.assertEqual(
            minimum_links.audit_check_url("securityVersions.dcgm.status"),
            "https://www.clustermax.ai/minimum-versions#dcgm",
        )
        self.assertEqual(
            minimum_links.audit_check_url("containers.dockerVersionOk"),
            "https://www.clustermax.ai/minimum-versions#docker",
        )
        self.assertIsNone(
            minimum_links.audit_check_url("security.guestKernel.newerInstalled")
        )

    def test_unknown_components_do_not_produce_broken_links(self) -> None:
        self.assertIsNone(
            minimum_links.audit_check_url("securityVersions.notPublished.status")
        )
        self.assertIsNone(minimum_links.security_check_url("not-a-check"))

    def test_website_row_replaces_upstream_references(self) -> None:
        website = (
            minimum_links.REFERENCE_LABEL,
            "https://www.clustermax.ai/minimum-versions#runc",
        )
        upstream = (
            "runc release",
            "https://github.com/opencontainers/runc/releases/tag/v1.3.6",
        )

        self.assertEqual(
            minimum_links.canonical_references((website, upstream)),
            (website,),
        )
        self.assertEqual(
            minimum_links.canonical_references((upstream,)),
            (upstream,),
        )


if __name__ == "__main__":
    unittest.main()
