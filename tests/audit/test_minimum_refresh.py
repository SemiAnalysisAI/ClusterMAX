"""Offline generator tests use frozen feeds, never the daily-refreshed live table."""

from __future__ import annotations

import copy
import io
import json
import os
import re
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cmax import minimum_refresh as fr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "minimum_refresh"

GENERATED = "2026-07-30T00:00:00Z"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def baseline() -> dict:
    """Return an isolated copy of the frozen fixture baseline."""
    return json.loads(_BASELINE_JSON)


def write_baseline(directory) -> Path:
    path = Path(directory) / "minimum-versions.json"
    path.write_text(_BASELINE_JSON)
    return path


def affects(vuln: dict, version: str) -> bool:
    target = fr.version_key(version)
    for entry in vuln.get("affected", []):
        for rng in entry.get("ranges", []):
            introduced = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                elif "fixed" in event and introduced is not None:
                    low = fr.version_key(introduced)
                    if low <= target < fr.version_key(event["fixed"]):
                        return True
                    introduced = None
    return False


class StubFetcher(fr.Fetcher):
    def __init__(self, *, toolkit: str = "nvidia-container-toolkit-5850.json") -> None:
        self.calls: list[str] = []
        self.post_bodies: list[dict] = []
        self.json_by_url: dict[str, object] = {
            fr.NVIDIA_CSAF_TREE: fixture("nvidia-csaf-tree.json"),
            fr.bulletin_url(2026, 5821): fixture("nvidia-driver-5821.json"),
            fr.bulletin_url(2026, 5747): fixture("nvidia-driver-5747.json"),
            fr.bulletin_url(2026, 5861): fixture("nvidia-driver-5861.json"),
            fr.bulletin_url(2026, 9999): fixture("nvidia-driver-lexical-trap.json"),
            fr.bulletin_url(2026, 5699): fixture("nvidia-connectx-5699.json"),
            fr.bulletin_url(2026, 5847): fixture("nvidia-connectx-5847.json"),
            fr.bulletin_url(2026, 5755): fixture("nvidia-cuda-5755.json"),
            fr.bulletin_url(2026, 5850): fixture(toolkit),
            fr.bulletin_url(2026, 5815): fixture("nvidia-virtio-net-5815.json"),
            fr.bulletin_url(2026, 5857): fixture("nvidia-dcgm-5857.json"),
            fr.GITHUB_CONTENTS.format(year=2026): fixture("github-contents-2026.json"),
        }
        for bulletin in (5821, 5747, 5861):
            driver = self.json_by_url[fr.bulletin_url(2026, bulletin)]
            for version, release in driver.get("_releases", {}).items():
                self.json_by_url[
                    fr.github_release_url(fr.NVIDIA_DRIVER_RELEASE_REPO, version)
                ] = release
        toolkit_doc = self.json_by_url[fr.bulletin_url(2026, 5850)]
        if toolkit_doc.get("_release"):
            self.json_by_url[
                fr.github_release_url(
                    fr.NVIDIA_CONTAINER_TOOLKIT_RELEASE_REPO, "v1.19.1"
                )
            ] = toolkit_doc["_release"]
        dcgm_doc = self.json_by_url[fr.bulletin_url(2026, 5857)]
        self.json_by_url[
            fr.github_release_url(fr.DCGM_EXPORTER_RELEASE_REPO, "4.5.3-4.8.2")
        ] = dcgm_doc["_release"]
        ubuntu_fixture = fixture("ubuntu-security-api.json")
        ubuntu = ubuntu_fixture["responses"]
        for spec in fr.UBUNTU_PACKAGES:
            cve = spec["cve"]
            if cve not in ubuntu:
                raise AssertionError(
                    f"ubuntu-security-api.json has no response for {cve}, which "
                    f"UBUNTU_PACKAGES asks the generator to fetch"
                )
            self.json_by_url[f"{fr.UBUNTU_CVE_URL}{cve}.json"] = ubuntu[cve]
        for notice_id, notice in ubuntu_fixture["notices"].items():
            self.json_by_url[fr.ubuntu_notice_url(notice_id)] = notice
        # The API supplies pending fixes that OSV cannot represent.
        ubuntu_osv = fixture("ubuntu-osv.json")
        for spec in fr.UBUNTU_PACKAGES:
            cve = spec["cve"]
            if cve not in ubuntu_osv["cves"]:
                raise AssertionError(
                    f"ubuntu-osv.json has no record for {cve}, which "
                    f"UBUNTU_PACKAGES asks the generator to fetch"
                )
            self.json_by_url[fr.ubuntu_osv_urls(cve)[0]] = ubuntu_osv["cves"][cve]
        for notice_id, notice in ubuntu_osv["notices"].items():
            self.json_by_url[f"{fr.UBUNTU_OSV_VULN_URL}{notice_id}"] = notice
        self.json_by_url[
            fr.ubuntu_notices_query_url("linux", fr.UBUNTU_RELEASE)
        ] = fixture("ubuntu-notices-linux.json")
        self.json_by_url[
            fr.ubuntu_notices_query_url("qemu", fr.UBUNTU_RELEASE)
        ] = fixture("ubuntu-notices-qemu.json")
        self.osv = fixture("osv-runc.json")
        for version, release in self.osv.get("_releases", {}).items():
            self.json_by_url[
                fr.github_release_url(fr.RUNC_RELEASE_REPO, f"v{version}")
            ] = release
        self.md_heads = fixture("nvidia-bulletin-md-heads.json")
        self.json_by_url[fr.DOCKER_DOCS_CONTENTS] = fixture(
            "docker-docs-release-notes-listing.json"
        )
        self.text_by_url: dict[str, str] = {
            fr.NVHPC_RELEASES_PAGE: (
                FIXTURES / "nvhpc-releases.html"
            ).read_text(),
            fr.docker_release_notes_url(29): (
                FIXTURES / "docker-release-notes-29.txt"
            ).read_text(),
            fr.AMD_SECURITY_INDEX: (
                FIXTURES / "amd-product-security-index.html"
            ).read_text(),
        }
        for sb_id in (
            "amd-sb-6018",
            "amd-sb-6024",
            "amd-sb-6027",
            "amd-sb-6033",
            "amd-sb-6034",
        ):
            self.text_by_url[fr.amd_bulletin_page(sb_id)] = (
                FIXTURES / f"{sb_id}.html"
            ).read_text()
        amd_non_instinct = (FIXTURES / "amd-non-instinct.html").read_text()
        for sb_id in (
            "amd-sb-6025",
            "amd-sb-6026",
            "amd-sb-6031",
            "amd-sb-6032",
        ):
            self.text_by_url[fr.amd_bulletin_page(sb_id)] = amd_non_instinct

    def get_json(self, url: str):
        self.calls.append(url)
        if url not in self.json_by_url:
            raise fr.MinimumRefreshError(f"cannot read {url}: no fixture")
        return copy.deepcopy(self.json_by_url[url])

    def get_optional_json(self, url: str):
        self.calls.append(url)
        value = self.json_by_url.get(url)
        return copy.deepcopy(value) if value is not None else None

    def post_json(self, url: str, body: dict):
        self.calls.append(url)
        self.post_bodies.append(copy.deepcopy(body))
        if url != fr.OSV_QUERY_URL:
            raise fr.MinimumRefreshError(f"cannot query {url}: no fixture")
        vulns = copy.deepcopy(self.osv).get("vulns", [])
        version = body.get("version")
        if version:
            # Version-scoped OSV queries omit advisories for other releases.
            vulns = [vuln for vuln in vulns if affects(vuln, version)]
        return {"vulns": vulns}

    def get_text_head(self, url: str, max_bytes: int = 1200) -> str | None:
        self.calls.append(url)
        for a_id, text in self.md_heads.items():
            if url.endswith(f"/{a_id}/{a_id}.md"):
                return text[:max_bytes]
        return None

    def get_text(self, url: str) -> str:
        self.calls.append(url)
        if url not in self.text_by_url:
            raise fr.MinimumRefreshError(f"cannot read {url}: no fixture")
        return self.text_by_url[url]


# Build before tests patch source fixtures to avoid an order-dependent baseline.
_BASELINE_JSON = fr.serialize(
    fr.build_minimums(generated=GENERATED, existing={}, fetch=StubFetcher())
)


def arch_kids(doc: dict, arch_name: str) -> list[dict]:
    for arch, kids in fr.csaf_arch_branches(doc):
        if arch == arch_name:
            return kids
    raise AssertionError(f"no architecture branch named {arch_name!r}")


class ExtractorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = StubFetcher()

    def test_driver_branches_take_the_highest_version_across_bulletins(self) -> None:
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        self.assertEqual(
            block["branches"],
            {
                "535": "535.309.01",
                "570": "570.211.01",
                "580": "580.178.04",
                "590": "590.48.01",
                "595": "595.91.07",
                "610": "610.57.04",
                "615": "615.71.09",
            },
        )

    def test_driver_merge_does_not_depend_on_bulletin_order(self) -> None:
        newest_first = fr.nvidia_driver_minimums(
            refs=[{"year": 2026, "aId": 5821}, {"year": 2026, "aId": 5747}],
            fetch=self.stub,
        )
        oldest_first = fr.nvidia_driver_minimums(
            refs=[{"year": 2026, "aId": 5747}, {"year": 2026, "aId": 5821}],
            fetch=self.stub,
        )
        self.assertEqual(newest_first["branches"], oldest_first["branches"])
        self.assertEqual(newest_first["branchSources"], oldest_first["branchSources"])
        self.assertEqual(
            newest_first["floorAvailability"], oldest_first["floorAvailability"]
        )
        self.assertEqual(newest_first["sources"], oldest_first["sources"])

    def test_the_merge_compares_branch_versions_numerically(self) -> None:
        for refs in (
            [{"year": 2026, "aId": 5821}, {"year": 2026, "aId": 9999}],
            [{"year": 2026, "aId": 9999}, {"year": 2026, "aId": 5821}],
        ):
            with self.subTest(order=[ref["aId"] for ref in refs]):
                block = fr.nvidia_driver_minimums(refs=refs, fetch=self.stub)
                self.assertEqual(block["branches"]["580"], "580.159.03")
                self.assertEqual(block["branchSources"]["580"], 5821)

    def test_driver_records_which_bulletin_produced_each_branch(self) -> None:
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        self.assertEqual(
            block["branchSources"],
            {
                "535": 5821,
                "570": 5747,
                "580": 5861,
                "590": 5747,
                "595": 5861,
                "610": 5861,
                "615": 5861,
            },
        )
        self.assertEqual([item["aId"] for item in block["sources"]], [5747, 5821, 5861])
        self.assertEqual(block["source"]["aId"], 5861)

    def test_connectx_trains_come_from_the_bulletin(self) -> None:
        block = fr.connectx_minimums(fetch=self.stub)
        self.assertEqual(
            [str(train) for train in block["trains"]],
            ["28", "32", "35", "39", "43", "46"],
        )
        self.assertEqual(block["trains"]["35"], 8002)
        self.assertEqual([item["aId"] for item in block["sources"]], [5699])
        self.assertTrue(
            all(
                item["status"] == "confirmed"
                for item in block["floorAvailability"].values()
            )
        )

    def test_multiple_connectx_bulletins_keep_the_highest_matching_ga_floor(self) -> None:
        older = fixture("nvidia-connectx-5699.json")
        newer = copy.deepcopy(older)
        baseline_ranges = fr.connectx_minimums(
            documents=[({"year": 2026, "aId": 5699}, older)], fetch=self.stub
        )["gaRanges"]
        selected = baseline_ranges[0]
        for architecture, products in fr.csaf_arch_branches(newer):
            if architecture != selected["architectures"]:
                continue
            for product in products:
                if (
                    product["name"] == selected["product"]
                    and product["product"]["name"].endswith(" or newer")
                ):
                    product["product"]["name"] = "99.9999 or newer"
        combined = fr.connectx_minimums(
            documents=[
                ({"year": 2026, "aId": 5700}, newer),
                ({"year": 2026, "aId": 5699}, older),
            ],
            fetch=self.stub,
        )["gaRanges"]
        expected = copy.deepcopy(baseline_ranges)
        expected[0]["minimum"] = "99.9999"
        self.assertEqual(combined, expected)

    def test_network_bulletin_for_legacy_products_is_not_applied(self) -> None:
        doc = fixture("nvidia-connectx-5847.json")
        self.assertEqual(fr.connectx_trains_in(doc), {})

    def test_a_truncated_nvidia_tree_fails_closed(self) -> None:
        self.stub.json_by_url[fr.NVIDIA_CSAF_TREE]["truncated"] = True
        with self.assertRaisesRegex(fr.MinimumRefreshError, "truncated"):
            fr.nvidia_csaf_documents(fetch=self.stub)

    def test_an_unreadable_enumerated_csaf_document_fails_closed(self) -> None:
        del self.stub.json_by_url[fr.bulletin_url(2026, 5861)]
        with self.assertRaisesRegex(fr.MinimumRefreshError, "5861"):
            fr.nvidia_csaf_documents(fetch=self.stub)

    def test_cuda_toolkit_minimum_and_cves(self) -> None:
        block = fr.simple_product_minimum(2026, 5755, fetch=self.stub)
        self.assertEqual(block["minimum"], "13.1")
        self.assertEqual(block["fixAvailability"]["status"], "confirmed")

    def test_container_toolkit_picks_its_own_product(self) -> None:
        block = fr.simple_product_minimum(
            2026, 5850, product="NVIDIA Container Toolkit", fetch=self.stub
        )
        self.assertEqual(block["minimum"], "1.19.1")
        self.assertEqual(block["cves"], ["CVE-2026-24260"])
        self.assertEqual(
            block["fixAvailability"]["available"], "2026-05-21T23:32:36Z"
        )

    def test_catalog_routes_every_graded_nvidia_product_without_an_id_allowlist(
        self,
    ) -> None:
        documents = fr.nvidia_csaf_documents(fetch=self.stub)
        simple = fr.nvidia_simple_product_minimums(documents, fetch=self.stub)
        dcgm = fr.nvidia_dcgm_minimums(documents, fetch=self.stub)
        virtio = fr.nvidia_virtio_net_minimums(documents)
        self.assertEqual(simple["cudaToolkit"]["source"]["aId"], 5755)
        self.assertEqual(simple["nvidiaContainerToolkit"]["source"]["aId"], 5850)
        self.assertEqual(dcgm["dcgm"]["source"]["aId"], 5857)
        self.assertEqual(dcgm["dcgmExporter"]["source"]["aId"], 5857)
        self.assertEqual(virtio["source"]["aId"], 5815)

    def test_new_cuda_bulletin_raises_the_floor_without_a_code_change(self) -> None:
        original = copy.deepcopy(self.stub.json_by_url[fr.bulletin_url(2026, 5755)])
        newer = copy.deepcopy(original)
        for _arch, kids in fr.csaf_arch_branches(newer):
            for kid in kids:
                kid["product"]["name"] = kid["product"]["name"].replace("13.1", "13.2")
        blocks = fr.nvidia_simple_product_minimums(
            [
                ({"year": 2026, "aId": 5755}, original),
                ({"year": 2026, "aId": 5904}, newer),
            ],
            fetch=self.stub,
        )
        self.assertEqual(blocks["cudaToolkit"]["minimum"], "13.2")
        self.assertEqual(blocks["cudaToolkit"]["source"]["aId"], 5904)
        self.assertEqual(
            [item["aId"] for item in blocks["cudaToolkit"]["sources"]],
            [5755, 5904],
        )

    def test_applicable_cuda_document_with_unknown_grammar_fails_closed(self) -> None:
        doc = copy.deepcopy(self.stub.json_by_url[fr.bulletin_url(2026, 5755)])
        for _arch, kids in fr.csaf_arch_branches(doc):
            for kid in kids:
                kid["product"]["name"] = "All affected versions"
        with self.assertRaisesRegex(fr.MinimumRefreshError, "cudaToolkit"):
            fr.nvidia_simple_product_minimums(
                [({"year": 2026, "aId": 5904}, doc)], fetch=self.stub
            )

    def test_runc_ladder_and_advisories(self) -> None:
        block = fr.runc_ladder(fetch=self.stub)
        self.assertEqual(
            block["ladder"],
            {
                "0.1": "0.1.0",
                "1.0": "1.0.3",
                "1.1": "1.1.14",
                "1.2": "1.2.8",
                "1.3": "1.3.6",
                "1.4": "1.4.3",
                "1.5": "1.5.0-rc.3",
            },
        )

    def test_runc_advisory_ranges_carry_each_advisorys_affected_ranges(self) -> None:
        block = fr.runc_ladder(fetch=self.stub)
        self.assertIn(
            {"introduced": "0", "fixed": "1.3.6"},
            block["advisoryRanges"]["GHSA-xjvp-4fhw-gc47"],
        )
        self.assertIn(
            {"introduced": "1.3.0-rc.1", "fixed": "1.3.3"},
            block["advisoryRanges"]["GHSA-9493-h29p-rfm2"],
        )

    def test_a_withdrawn_advisory_holds_no_minimum(self) -> None:
        stub = StubFetcher()
        for vuln in stub.osv["vulns"]:
            if vuln["id"] == "GHSA-xjvp-4fhw-gc47":
                vuln["withdrawn"] = "2026-08-01T00:00:00Z"
        block = fr.runc_ladder(fetch=stub)
        self.assertNotIn("GHSA-xjvp-4fhw-gc47", block["advisories"])
        self.assertNotIn("GHSA-xjvp-4fhw-gc47", block["advisoryRanges"])
        self.assertEqual(block["ladder"]["1.3"], "1.3.3")

    def test_a_git_range_cannot_poison_the_ladder(self) -> None:
        stub = StubFetcher()
        stub.osv["vulns"].append(
            {
                "id": "GHSA-git0-0000-0000",
                "published": "2026-01-01T00:00:00Z",
                "affected": [
                    {
                        "package": {
                            "name": "github.com/opencontainers/runc",
                            "ecosystem": "Go",
                        },
                        "ranges": [
                            {
                                "type": "GIT",
                                "repo": "https://github.com/opencontainers/runc",
                                "events": [
                                    {"introduced": "0"},
                                    {"fixed": "aad4c8ec8155c8a72808d7da062d6f9b9e5d8438"},
                                ],
                            }
                        ],
                    }
                ],
            }
        )
        block = fr.runc_ladder(fetch=stub)
        self.assertNotIn("GHSA-git0-0000-0000", block["advisoryRanges"])

    def test_the_osv_query_is_not_version_scoped(self) -> None:
        fr.runc_ladder(fetch=self.stub)
        self.assertEqual(len(self.stub.post_bodies), 1)
        body = self.stub.post_bodies[0]
        self.assertNotIn("version", body)
        self.assertEqual(
            body["package"], {"name": fr.RUNC_PACKAGE, "ecosystem": fr.RUNC_ECOSYSTEM}
        )

    def test_an_advisory_that_misses_1_2_7_still_reaches_the_ladder(self) -> None:
        block = fr.runc_ladder(fetch=self.stub)
        self.assertIn("GHSA-jfvp-7x6p-h2pv", block["advisories"])
        self.assertEqual(block["ladder"]["1.1"], "1.1.14")

    def test_a_stable_release_outranks_its_own_release_candidate(self) -> None:
        stub = StubFetcher()
        stub.osv = fixture("osv-runc-rc-vs-stable.json")
        self.assertEqual(fr.runc_ladder(fetch=stub)["ladder"], {"1.5": "1.5.0"})

    def test_the_ladder_follows_every_osv_page(self) -> None:
        first, second = {"vulns": [], "next_page_token": "page-2"}, fixture("osv-runc.json")
        pages = [first, second]

        class PagedStub(StubFetcher):
            def post_json(self, url: str, body: dict):
                self.post_bodies.append(copy.deepcopy(body))
                return copy.deepcopy(pages[len(self.post_bodies) - 1])

        stub = PagedStub()
        block = fr.runc_ladder(fetch=stub)
        self.assertEqual(len(stub.post_bodies), 2)
        self.assertEqual(stub.post_bodies[1]["page_token"], "page-2")
        self.assertEqual(block["ladder"], fr.runc_ladder(fetch=StubFetcher())["ladder"])

    def test_runc_ignores_go_duplicates_and_other_packages(self) -> None:
        block = fr.runc_ladder(fetch=self.stub)
        self.assertFalse([item for item in block["advisories"] if item.startswith("GO-")])
        self.assertNotIn("1.13", block["ladder"])

    def test_virtio_net_release_lines_come_from_the_bulletin(self) -> None:
        block = fr.virtio_net_minimums(2026, 5815, fetch=self.stub)
        self.assertEqual(block["cves"], ["CVE-2026-65094"])
        self.assertEqual(
            block["lines"],
            {
                "GA": {"fixed": "25.10.6"},
                "LTS23": {"fixed": "23.10.23", "legacyAffectedThrough": "1.7.21"},
                "LTS24": {"fixed": "24.10.50"},
                "LTS25": {"fixed": "25.10.2"},
            },
        )

    def test_one_bulletin_yields_both_dcgm_components(self) -> None:
        blocks = fr.bulletin_product_minimums(2026, 5857, fr.DCGM_PRODUCTS, fetch=self.stub)
        self.assertEqual(sorted(blocks), ["dcgm", "dcgmExporter"])
        self.assertEqual(blocks["dcgm"]["minimum"], "4.5.3")
        self.assertEqual(blocks["dcgmExporter"]["minimum"], "4.8.2")
        for key in ("dcgm", "dcgmExporter"):
            self.assertEqual(
                blocks[key]["fixAvailability"]["available"],
                "2026-05-07T00:28:58Z",
            )

    def test_dcgm_products_share_one_cve_and_one_source(self) -> None:
        blocks = fr.bulletin_product_minimums(2026, 5857, fr.DCGM_PRODUCTS, fetch=self.stub)
        self.assertEqual(blocks["dcgm"]["cves"], ["CVE-2026-47483"])
        self.assertEqual(blocks["dcgm"]["cves"], blocks["dcgmExporter"]["cves"])
        self.assertEqual(blocks["dcgm"]["source"], blocks["dcgmExporter"]["source"])
        self.assertEqual(blocks["dcgm"]["source"]["aId"], 5857)

    def test_bad_epoll_uses_release_and_source_package_specific_fixes(self) -> None:
        noble = fr.ubuntu_minimums(fetch=self.stub)
        self.assertEqual(
            noble["packages"]["linuxBadEpollNvidia617"]["fixed"], "6.17.0-1031.31"
        )
        self.assertEqual(
            noble["packages"]["linuxBadEpollNvidia617"]["package"], "linux-nvidia-6.17"
        )
        self.assertEqual(
            noble["packages"]["linuxBadEpoll"]["fixed"], "6.8.0-137.137"
        )
        jammy = fr.ubuntu_minimums(
            codename="jammy",
            specs=({"key": "linuxBadEpoll", "cve": "CVE-2026-46242",
                    "package": "linux-hwe-6.8"},),
            package_policy=(),
            fetch=self.stub,
        )
        self.assertEqual(
            jammy["packages"]["linuxBadEpoll"]["fixed"], "6.8.0-138.138~22.04.1"
        )
        resolute = fr.ubuntu_minimums(
            codename="resolute", specs=fr.UBUNTU_RESOLUTE_PACKAGES,
            package_policy=(), fetch=self.stub,
        )
        self.assertEqual(resolute["release"], "resolute")
        bad_epoll = resolute["packages"]["linuxBadEpoll"]
        self.assertEqual(bad_epoll["fixed"], "7.0.0-28.28")
        self.assertEqual(bad_epoll["package"], "linux")
        self.assertEqual(bad_epoll["source"]["id"], "USN-8566-1")
        fragnesia = resolute["packages"]["linuxFragnesia"]
        self.assertEqual(fragnesia["fixed"], "7.0.0-22.22")
        self.assertEqual(fragnesia["abi"], 22)
        self.assertEqual(fragnesia["relatedCves"], ["CVE-2026-43284", "CVE-2026-43500"])
        # The Noble and Jammy fixes for the same CVEs are untouched.
        self.assertEqual(noble["packages"]["linuxFragnesia"]["fixed"], "6.8.0-124.124")

    def test_pwnescape_refresh_preserves_pending_and_needed_vendor_states(self) -> None:
        data = fr.build_minimums(generated=GENERATED, existing={}, fetch=self.stub)
        for component, source, state, fixed in (
            ("ubuntuNoble", "linux", "pending", "6.8.0-149.149i1"),
            ("ubuntuResolute", "linux", "pending", "7.0.0-43.43i1"),
            ("ubuntuJammy", "linux-hwe-6.8", "needed", ""),
        ):
            entry = data["components"][component]["packages"]["linuxPwnescape"]
            self.assertEqual(entry["cve"], "CVE-2026-99999")
            self.assertEqual(entry["package"], source)
            self.assertEqual(entry["status"], state)
            self.assertEqual(entry["fixed"], fixed)
            if fixed:
                self.assertEqual(entry["fixAvailability"]["status"], "unconfirmed")

    def test_pwnescape_refresh_picks_up_a_released_fix(self) -> None:
        # Synthetic release event: this does not assert real fix availability.
        record = self.stub.json_by_url[fr.ubuntu_osv_urls("CVE-2026-99999")[0]]
        record["affected"][0]["ranges"][0]["events"].append({"fixed": "6.8.0-150.150"})
        entry = fr.ubuntu_entry("CVE-2026-99999", "linux", "noble", fetch=self.stub)
        self.assertEqual(entry["status"], "released")
        self.assertEqual(entry["fixed"], "6.8.0-150.150")

    def test_pwnescape_refresh_rejects_unknown_states_and_loss_of_a_released_fix(self) -> None:
        old = baseline()
        for state in ("needs-triage", "ignored", "not-found"):
            data = baseline()
            data["components"]["ubuntuJammy"]["packages"]["linuxPwnescape"]["status"] = state
            with self.subTest(state=state), self.assertRaises(fr.MinimumRefreshError):
                fr.verify(data, old)
        old_entry = old["components"]["ubuntuNoble"]["packages"]["linuxPwnescape"]
        old_entry.update(status="released", fixed="6.8.0-150.150")
        with self.assertRaisesRegex(fr.MinimumRefreshError, "released PwnEscape fix disappeared"):
            fr.verify(baseline(), old)

    def test_ga_kernel_cves_are_published_for_jammy_and_noble(self) -> None:
        data = fr.build_minimums(generated=GENERATED, existing={}, fetch=self.stub)
        for component, fixed, abi in (
            ("ubuntuNoble", "6.8.0-138.138", 138),
            ("ubuntuJammy", "5.15.0-190.200", 190),
        ):
            packages = data["components"][component]["packages"]
            ovs = packages["linuxOpenvswitchNestedActions"]
            self.assertEqual(ovs["cve"], "CVE-2026-64531")
            self.assertEqual(ovs["package"], "linux")
            self.assertEqual(ovs["status"], "released")
            self.assertEqual(ovs["fixed"], fixed)
            self.assertEqual(ovs["abi"], abi)
            self.assertIs(ovs["allowUnfixed"], True)
            cgroup = packages["linuxCgroupWriteback"]
            self.assertEqual(cgroup["cve"], "CVE-2026-64378")
            self.assertEqual(cgroup["status"], "needed")
            self.assertFalse(cgroup.get("fixed"))
            self.assertIs(cgroup["allowUnfixed"], True)
        fr.verify(data, data)

    def test_ga_kernel_cve_refresh_rejects_unknown_states_and_loss_of_a_fix(self) -> None:
        old = baseline()
        for state in ("needs-triage", "ignored", "not-found"):
            data = baseline()
            entry = data["components"]["ubuntuJammy"]["packages"]["linuxCgroupWriteback"]
            entry["status"] = state
            with self.subTest(state=state), self.assertRaisesRegex(
                fr.MinimumRefreshError, "linuxCgroupWriteback"
            ):
                fr.verify(data, old)
        data = baseline()
        entry = data["components"]["ubuntuNoble"]["packages"]["linuxOpenvswitchNestedActions"]
        entry.update(status="needed", fixed="")
        with self.assertRaisesRegex(fr.MinimumRefreshError, "released fix 6.8.0-138.138"):
            fr.verify(data, old)

    def test_ubuntu_noble_packages(self) -> None:
        osv_url = fr.ubuntu_osv_urls("CVE-2024-3446")[0]
        self.stub.json_by_url[osv_url]["related"] = [
            "USN-unreadable",
            "USN-malformed",
            *self.stub.json_by_url[osv_url]["related"],
        ]
        self.stub.json_by_url[f"{fr.UBUNTU_OSV_VULN_URL}USN-malformed"] = {
            "id": "USN-malformed",
            "published": "2025-09-01T00:00:00Z",
            "affected": "not a list",
        }
        block = fr.ubuntu_minimums(fetch=self.stub)
        qemu = block["packages"]["qemu"]
        self.assertEqual(qemu["fixed"], "1:8.2.2+ds-0ubuntu1.16")
        self.assertEqual(qemu["source"]["id"], "USN-8161-1")
        self.assertEqual(qemu["released"], "2026-04-09T14:22:10.893048")
        linux = block["packages"]["linux"]
        self.assertEqual(linux["fixed"], "6.8.0-147.147")
        self.assertEqual(linux["abi"], 147)
        self.assertEqual(linux["source"]["id"], "USN-8917-1")
        self.assertEqual(linux["coverage"]["matchedNotices"], 2)
        self.assertEqual(linux["cveCount"], 2)
        self.assertEqual(qemu["cve"], "CVE-2024-3446")
        self.assertEqual(block["packages"]["linuxVmscape"]["source"]["id"], "USN-7861-1")
        self.assertEqual(block["packages"]["linuxFragnesia"]["abi"], 124)
        self.assertEqual(block["packages"]["linuxJanuscape"]["status"], "pending")
        self.assertEqual(
            block["packages"]["linuxJanuscape"]["fixAvailability"]["status"],
            "unconfirmed",
        )
        api_calls = [url for url in self.stub.calls if url.startswith(fr.UBUNTU_CVE_URL)]
        self.assertCountEqual(api_calls, [
            f"{fr.UBUNTU_CVE_URL}CVE-2026-99999.json",
            f"{fr.UBUNTU_CVE_URL}CVE-2026-46242.json",
            f"{fr.UBUNTU_CVE_URL}CVE-2026-46242.json",
            f"{fr.UBUNTU_CVE_URL}CVE-2026-46300.json",
            f"{fr.UBUNTU_CVE_URL}CVE-2026-53359.json",
            f"{fr.UBUNTU_CVE_URL}CVE-2026-64378.json",
        ])

    def test_ubuntu_notice_discovery_fails_closed_on_incomplete_pagination(self) -> None:
        first_url = fr.ubuntu_notices_query_url("qemu", fr.UBUNTU_RELEASE)
        second_url = fr.ubuntu_notices_query_url(
            "qemu", fr.UBUNTU_RELEASE, fr.UBUNTU_NOTICE_PAGE_LIMIT
        )
        self.stub.json_by_url[first_url]["total_results"] = 21
        self.stub.json_by_url[second_url] = {
            "limit": fr.UBUNTU_NOTICE_PAGE_LIMIT,
            "offset": fr.UBUNTU_NOTICE_PAGE_LIMIT,
            "total_results": 21,
            "notices": [],
        }
        with self.assertRaisesRegex(fr.MinimumRefreshError, "unique candidates"):
            fr.ubuntu_package_notices("qemu", "qemu", fetch=self.stub)

    def test_ubuntu_notice_discovery_requires_an_exact_source_package(self) -> None:
        url = fr.ubuntu_notices_query_url("qemu", fr.UBUNTU_RELEASE)
        for notice in self.stub.json_by_url[url]["notices"]:
            notice["release_packages"]["noble"][0]["name"] = "qemu-utils"
        with self.assertRaisesRegex(fr.MinimumRefreshError, "no qemu source-package"):
            fr.ubuntu_package_notices("qemu", "qemu", fetch=self.stub)

    def test_ubuntu_reads_the_github_mirror_when_osv_dev_fails(self) -> None:
        api_url, mirror_url = fr.ubuntu_osv_urls("CVE-2024-3446")
        self.stub.json_by_url[mirror_url] = self.stub.json_by_url.pop(api_url)
        entry = fr.ubuntu_entry("CVE-2024-3446", "qemu", fetch=self.stub)
        self.assertIn(mirror_url, self.stub.calls)
        self.assertEqual(entry["fixed"], "1:8.2.2+ds-0ubuntu1.10")
        self.assertEqual(entry["source"]["id"], "USN-7744-1")
        self.assertNotIn(f"{fr.UBUNTU_CVE_URL}CVE-2024-3446.json", self.stub.calls)

    def test_ubuntu_falls_back_to_the_security_api_when_no_osv_mirror_answers(
        self,
    ) -> None:
        del self.stub.json_by_url[fr.ubuntu_osv_urls("CVE-2024-3446")[0]]
        entry = fr.ubuntu_entry("CVE-2024-3446", "qemu", fetch=self.stub)
        self.assertIn(f"{fr.UBUNTU_CVE_URL}CVE-2024-3446.json", self.stub.calls)
        self.assertEqual(entry["fixed"], "1:8.2.2+ds-0ubuntu1.10")
        self.assertEqual(entry["source"]["id"], "USN-7744-1")

    def test_ubuntu_fix_is_dated_from_osv_when_ubuntu_com_is_unreachable(
        self,
    ) -> None:
        del self.stub.json_by_url[fr.ubuntu_notice_url("USN-7744-1")]
        entry = fr.ubuntu_entry("CVE-2024-3446", "qemu", fetch=self.stub)
        self.assertEqual(entry["fixed"], "1:8.2.2+ds-0ubuntu1.10")
        self.assertEqual(entry["released"], "2025-09-11T12:41:28Z")
        self.assertEqual(entry["fixAvailability"]["status"], "confirmed")
        self.assertEqual(entry["fixAvailability"]["feed"], "ubuntu-osv")
        self.assertEqual(
            entry["fixAvailability"]["url"], f"{fr.UBUNTU_OSV_VULN_URL}USN-7744-1"
        )

    def test_ubuntu_reads_usn_records_from_the_github_mirror(self) -> None:
        api_url, mirror_url = fr.ubuntu_osv_notice_urls("USN-7744-1")
        self.assertTrue(mirror_url.endswith("/osv/usn/USN-7744-1.json"))
        self.stub.json_by_url[mirror_url] = self.stub.json_by_url.pop(api_url)
        entry = fr.ubuntu_entry("CVE-2024-3446", "qemu", fetch=self.stub)
        self.assertIn(mirror_url, self.stub.calls)
        self.assertEqual(entry["fixAvailability"]["status"], "confirmed")
        self.assertEqual(entry["source"]["id"], "USN-7744-1")

    def test_ubuntu_fix_is_dated_from_the_security_api_when_no_usn_record_reads(
        self,
    ) -> None:
        # An unreadable USN must not leave a known fix permanently unconfirmed.
        for notice_id in ("USN-7744-1", "USN-8412-1"):
            del self.stub.json_by_url[fr.ubuntu_osv_notice_urls(notice_id)[0]]
        entry = fr.ubuntu_entry("CVE-2024-3446", "qemu", fetch=self.stub)
        self.assertIn(f"{fr.UBUNTU_CVE_URL}CVE-2024-3446.json", self.stub.calls)
        self.assertEqual(entry["fixAvailability"]["status"], "confirmed")
        self.assertEqual(entry["source"]["id"], "USN-7744-1")
        self.assertEqual(entry["released"], "2025-09-11T12:41:28.262010")

    def test_ubuntu_osv_ignores_other_releases(self) -> None:
        # This fixture also includes a Jammy fix to test release filtering.
        listed, fixed = fr._osv_fixed(
            self.stub.json_by_url[fr.ubuntu_osv_urls("CVE-2024-3446")[0]],
            "qemu",
            fr.UBUNTU_OSV_ECOSYSTEMS["noble"],
        )
        self.assertTrue(listed)
        self.assertEqual(fixed, "1:8.2.2+ds-0ubuntu1.10")


class VersionPhraseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = fixture("csaf-version-phrases.json")

    def test_each_phrase_variant(self) -> None:
        cases = {
            "PriorToOnly": "4.2.1",
            "UpToAndIncludingOnly": None,  # Y itself is vulnerable.
            "OrNewer": "46.3008",
            "BareVersion": "28.4702",
            "DoubleSpaceRange": "4.5.3",
            # A fixed entry wins even when the affected range names the same release.
            "FixedEqualsAffectedUpperBound": "4.8.2",
            "DriverWording": "595.71.05",
            "TrailingComma": "24.10.50",  # "24.10.50 or newer," keeps no comma.
            "AndOlderVersionsOnly": None,  # A retired scheme is not a minimum.
            "AndOlderWithFix": "23.10.23",
            "NoVersionAtAll": None,
        }
        for arch, expected in cases.items():
            with self.subTest(arch=arch):
                self.assertEqual(fr.resolve_fixed(arch_kids(self.doc, arch)), expected)

    def test_version_key_ranks_a_release_above_its_own_prerelease(self) -> None:
        ordered = ["1.5.0-rc.2", "1.5.0-rc.3", "1.5.0", "1.5.1"]
        for lower, higher in zip(ordered, ordered[1:]):
            with self.subTest(pair=(lower, higher)):
                self.assertLess(fr.version_key(lower), fr.version_key(higher))

    def test_version_key_handles_versions_with_no_prerelease(self) -> None:
        self.assertLess(fr.version_key("580.99.01"), fr.version_key("580.126.09"))
        self.assertLess(fr.version_key("1.4.0-rc.3"), fr.version_key("1.4.3"))
        self.assertLess(fr.version_key("1.0.0-rc95"), fr.version_key("1.0.3"))

    def test_version_key_reads_debian_style_versions_without_raising(self) -> None:
        # Debian versions must remain comparable without raising.
        self.assertLess(
            fr.version_key("6.8.0-124.124"), fr.version_key("6.8.0-137.137")
        )
        self.assertLess(
            fr.version_key("1:8.2.2+ds-0ubuntu1.9"),
            fr.version_key("1:8.2.2+ds-0ubuntu1.10"),
        )

    def test_phrase_roles(self) -> None:
        cases = {
            "All versions prior to 4.2.1": ("priorTo", "4.2.1"),
            "All versions up to and including 1.19.0": ("affected", "1.19.0"),
            "0.0  to 4.5.2": ("affected", "0.0"),
            "46.3008 or newer": ("fixed", "46.3008"),
            "24.10.50 or newer,": ("fixed", "24.10.50"),
            "28.4702": ("fixed", "28.4702"),
            "1.7.21 and older versions": ("legacy", "1.7.21"),
            "All supported versions": (None, None),
        }
        for phrase, expected in cases.items():
            with self.subTest(phrase=phrase):
                self.assertEqual(fr.classify_phrase(phrase), expected)

    def test_release_line_names_are_derived_from_the_label(self) -> None:
        self.assertEqual(fr.release_line_name("VIRTIO-Net GA"), "GA")
        self.assertEqual(fr.release_line_name("VIRTIO-Net LTS25"), "LTS25")
        self.assertIsNone(fr.release_line_name("VIRTIO-Net"))
        self.assertIsNone(fr.release_line_name(""))

    def test_product_filter_selects_one_product(self) -> None:
        kids = arch_kids(self.doc, "TwoProducts")
        self.assertEqual(fr.resolve_fixed(kids, product_filter="Widget"), "1.19.1")
        self.assertEqual(fr.resolve_fixed(kids, product_filter="Gadget"), "26.3.2")
        self.assertIsNone(fr.resolve_fixed(kids, product_filter="Absent"))

    def test_csaf_name_roles_are_inverted(self) -> None:
        kids = arch_kids(fixture("nvidia-driver-5821.json"), "Linux(R595)")
        labels = {kid["name"] for kid in kids}
        phrases = {kid["product"]["name"] for kid in kids}
        self.assertIn("Tesla", labels)
        self.assertIn("All driver versions prior to 595.71.05", phrases)
        self.assertEqual(fr.resolve_fixed(kids, product_filter="Tesla"), "595.71.05")
        self.assertIsNone(fr.resolve_fixed(kids, product_filter="595.71.05"))


class BuildMinimumsTest(unittest.TestCase):
    def test_serialize_sorts_keys_so_a_rebuild_diffs_cleanly(self) -> None:
        self.assertEqual(fr.serialize({"b": 1, "a": 2}), '{\n  "a": 2,\n  "b": 1\n}\n')

    def test_nvhpc_tracks_current_and_previous_official_releases(self) -> None:
        block = fr.nvhpc_release_window(fetch=StubFetcher())

        self.assertEqual(block["current"], "26.5")
        self.assertEqual(block["minimum"], "26.3")
        self.assertEqual(block["policy"], "current-or-previous")

    def test_nvhpc_release_page_format_change_fails_closed(self) -> None:
        stub = StubFetcher()
        stub.text_by_url[fr.NVHPC_RELEASES_PAGE] = "HPC SDK 26.5"

        with self.assertRaisesRegex(fr.MinimumRefreshError, "fewer than two"):
            fr.nvhpc_release_window(fetch=stub)


class DockerMinimumTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = StubFetcher()

    def docker_page(self) -> str:
        return self.stub.text_by_url[fr.docker_release_notes_url(29)]

    def test_minimum_is_the_highest_release_with_a_security_subsection(self) -> None:
        block = fr.docker_minimums(fetch=self.stub)
        self.assertEqual(block["minimum"], "29.7.0")
        self.assertEqual(block["cves"], ["CVE-2026-17106"])
        self.assertEqual(block["advisories"], ["GHSA-hfg8-hc9c-6c3h"])
        self.assertEqual(
            block["advisory"],
            "https://docs.docker.com/engine/release-notes/29/#2970",
        )
        fix = block["fixAvailability"]
        self.assertEqual(fix["status"], "confirmed")
        self.assertEqual(fix["available"], "2026-07-30T00:00:00Z")
        self.assertEqual(fix["version"], "29.7.0")
        self.assertEqual(fix["id"], "docker-engine-29.7.0")
        self.assertEqual(fix["feed"], "docker-release-notes")
        self.assertEqual(block["source"]["feed"], "docker-release-notes")
        self.assertEqual(block["source"]["majors"], [29])

    def test_cve_ids_outside_a_security_subsection_do_not_count(self) -> None:
        releases = {
            release["version"]: release
            for release in fr.parse_docker_release_notes(self.docker_page())
        }
        self.assertFalse(releases["29.7.2"]["security"])
        self.assertEqual(releases["29.7.2"]["cves"], [])
        self.assertFalse(releases["29.7.1"]["security"])
        self.assertTrue(releases["29.7.0"]["security"])
        self.assertFalse(releases["29.0.0"]["security"])

    def test_a_security_subsection_with_only_ghsa_ids_still_counts(self) -> None:
        releases = {
            release["version"]: release
            for release in fr.parse_docker_release_notes(self.docker_page())
        }
        self.assertTrue(releases["29.6.1"]["security"])
        self.assertEqual(releases["29.6.1"]["cves"], [])
        self.assertEqual(
            releases["29.6.1"]["advisories"],
            ["GHSA-7236-3392-c5c6", "GHSA-jpcc-p29g-p8mq", "GHSA-mjcv-p78q-w5fw"],
        )
        self.assertEqual(
            releases["29.6.2"]["cves"],
            [
                "CVE-2026-15788",
                "CVE-2026-15789",
                "CVE-2026-15791",
                "CVE-2026-15792",
                "CVE-2026-15793",
            ],
        )

    def test_a_release_candidate_never_becomes_the_minimum(self) -> None:
        page = (
            self.docker_page()
            + '\n## 29.8.0-rc.1\n\n{{< release-date date="2026-08-15" >}}\n\n'
            + "### Security\n\n- Fix [CVE-2026-15788](https://example.invalid/cve).\n"
        )
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page
        block = fr.docker_minimums(fetch=self.stub)
        self.assertEqual(block["minimum"], "29.7.0")

    def test_a_page_without_releases_fails_closed(self) -> None:
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = (
            "# Docker Engine version 29 release notes\n\nNo entries yet.\n"
        )
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.docker_minimums(fetch=self.stub)
        self.assertIn("docker", str(caught.exception))
        self.assertIn("no releases", str(caught.exception))

    def test_a_page_without_any_security_subsection_fails_closed(self) -> None:
        reworded = self.docker_page().replace("### Security", "### Fixes")
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = reworded
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.docker_minimums(fetch=self.stub)
        self.assertIn("Security subsection", str(caught.exception))

    def test_a_hardening_only_security_release_does_not_move_the_minimum(self) -> None:
        page = (
            '## 29.8.0\n\n{{< release-date date="2026-09-03" >}}\n\n'
            "### Security\n\n"
            "- Add daemon support for configuring the default container AppArmor "
            "profile template. [moby/moby#52771](https://github.com/moby/moby/pull/52771)\n"
            "- Prevent containers from using the 32-bit `socketcall(2)` path to "
            "create `AF_VSOCK` sockets by adding AppArmor and SELinux policy rules. "
            "[moby/moby#53551](https://github.com/moby/moby/pull/53551)\n\n"
            "### Networking\n\n- Fix a Swarm lookup.\n\n"
            + self.docker_page()
        )
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page
        block = fr.docker_minimums(fetch=self.stub)
        self.assertEqual(block["minimum"], "29.7.0")
        self.assertEqual(block["cves"], ["CVE-2026-17106"])

    def test_a_page_where_no_security_release_names_an_identifier_fails_closed(self) -> None:
        page = (
            '## 29.9.0\n\n{{< release-date date="2026-09-01" >}}\n\n'
            "### Security\n\n- Hardening only, identifiers withheld.\n"
        )
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.docker_minimums(fetch=self.stub)
        self.assertIn("names no CVE or GHSA identifier", str(caught.exception))
        self.assertIn("29.9.0", str(caught.exception))

    def test_a_security_release_without_a_date_fails_closed(self) -> None:
        page = (
            "## 29.9.0\n\n### Security\n\n"
            "- Fix [CVE-2026-15788](https://example.invalid/cve).\n"
        )
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.docker_minimums(fetch=self.stub)
        self.assertIn("release-date", str(caught.exception))

    def test_an_unreadable_page_fails_closed(self) -> None:
        del self.stub.text_by_url[fr.docker_release_notes_url(29)]
        with self.assertRaises(fr.MinimumRefreshError):
            fr.docker_minimums(fetch=self.stub)

    def test_a_page_that_lost_the_minimum_release_cannot_lower_the_minimum(self) -> None:
        existing = baseline()
        page = self.docker_page()
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page[
            page.index("## 29.6.2"):
        ]
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated=GENERATED, existing=existing, fetch=self.stub)
        message = str(caught.exception)
        self.assertIn("docker", message)
        self.assertIn("a minimum only moves up", message)

    def test_confirmed_availability_is_preserved_while_the_minimum_stays(self) -> None:
        existing = baseline()
        existing["components"]["docker"]["fixAvailability"].update(
            {
                "bulletinReleased": "2026-07-30T21:33:46Z",
                "commit": "34dfa2b7389ef29b28ee9147cf4bbdaf4bf765f6",
            }
        )
        doc = fr.build_minimums(generated=GENERATED, existing=existing, fetch=self.stub)
        self.assertEqual(
            doc["components"]["docker"]["fixAvailability"],
            existing["components"]["docker"]["fixAvailability"],
        )


def amd_page(
    rows: list[list[str]],
    header: tuple[str, ...] = ("Program", "CVE", "Mitigation", "Release Date"),
    revision: str | None = "2026-01-01",
    extra: str = "",
) -> str:
    head = "<tr>" + "".join(f"<th>{cell}</th>" for cell in header) + "</tr>"
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    revisions = ""
    if revision:
        revisions = (
            "<table><tr><th>Revision Date</th><th>Description</th></tr>"
            f"<tr><td>{revision}</td><td>Initial publication</td></tr></table>"
        )
    return (
        f"<html><body><table>{head}{body}</table>{extra}{revisions}"
        "</body></html>"
    )


class AmdRocmMinimumTest(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = StubFetcher()

    def set_page(self, sb_id: str, text: str) -> None:
        self.stub.text_by_url[fr.amd_bulletin_page(sb_id)] = text

    def test_each_program_keeps_the_highest_release_across_bulletins(self) -> None:
        block = fr.amd_rocm_minimums(fetch=self.stub)
        self.assertEqual(block["kind"], "programMap")
        self.assertEqual(
            block["programs"],
            {
                "MI210": "7.14",
                "MI250": "7.14",
                "MI250X": "7.14",
                "MI300A": "7.14",
                "MI300X": "7.14",
                "MI308X": "7.14",
                "MI325X": "7.14",
                "MI350X": "7.14",
                "MI355X": "7.14",
            },
        )
        self.assertEqual(
            block["programSources"],
            {
                "MI210": "AMD-SB-6033",
                "MI250": "AMD-SB-6033",
                "MI250X": "AMD-SB-6033",
                "MI300A": "AMD-SB-6033",
                "MI300X": "AMD-SB-6033",
                "MI308X": "AMD-SB-6033",
                "MI325X": "AMD-SB-6033",
                "MI350X": "AMD-SB-6033",
                "MI355X": "AMD-SB-6033",
            },
        )
        self.assertEqual(block["cves"], ["CVE-2026-43598"])
        self.assertEqual(
            [source["aId"] for source in block["sources"]],
            ["AMD-SB-6018", "AMD-SB-6024", "AMD-SB-6027", "AMD-SB-6033"],
        )
        self.assertEqual(block["source"]["aId"], "AMD-SB-6033")
        self.assertEqual(block["source"]["released"], "2026-09-30T00:00:00Z")
        self.assertEqual(
            block["advisory"],
            "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6033.html",
        )

    def test_the_minimum_availability_carries_the_mitigation_date(self) -> None:
        block = fr.amd_rocm_minimums(fetch=self.stub)
        available = {
            program: entry["available"]
            for program, entry in block["floorAvailability"].items()
        }
        self.assertEqual(
            available,
            {
                "MI210": "2026-07-15T00:00:00Z",
                "MI250": "2026-07-15T00:00:00Z",
                "MI250X": "2026-07-15T00:00:00Z",
                "MI300A": "2026-07-15T00:00:00Z",
                "MI300X": "2026-07-15T00:00:00Z",
                "MI308X": "2026-07-15T00:00:00Z",
                "MI325X": "2026-07-15T00:00:00Z",
                "MI350X": "2026-07-15T00:00:00Z",
                "MI355X": "2026-07-15T00:00:00Z",
            },
        )
        mi210 = block["floorAvailability"]["MI210"]
        self.assertEqual(mi210["status"], "confirmed")
        self.assertEqual(mi210["version"], "7.14")
        self.assertEqual(mi210["feed"], "amd-security-bulletin")
        self.assertEqual(mi210["aId"], "AMD-SB-6033")
        self.assertEqual(
            mi210["url"],
            "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6033.html",
        )

    def test_wording_variants_parse_to_one_exact_release(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [
                    [
                        "AMD Instinct\u2122 MI210 AMD Instinct\u2122 MI250",
                        "CVE-2025-11111",
                        "ROCm\u2122 6.4",
                        "2025-01-02",
                    ],
                    [
                        "AMD Instinct MI300A",
                        "CVE-2025-22222 (non-AMD)",
                        "BKC 26 (ROCm 7.0.1)",
                        "2025-03-04",
                    ],
                    ["AMD Instinct MI300X", "CVE-2025-33333", "ROC 6.3", "2025-05-06"],
                ]
            ),
        )
        block = fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertEqual(
            block["programs"],
            {"MI210": "6.4", "MI250": "6.4", "MI300A": "7.0.1", "MI300X": "6.3"},
        )
        self.assertEqual(block["programCves"]["MI300A"], ["CVE-2025-22222"])
        self.assertEqual(
            block["floorAvailability"]["MI250"]["available"],
            "2025-01-02T00:00:00Z",
        )

    def test_inline_tags_inside_cells_separate_tokens(self) -> None:
        # Keep footnote digits separate from CVE and release tokens.
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [
                    [
                        "AMD Instinct MI300X<sup>1</sup>",
                        '<a href="#footnotes">CVE-2025-11111</a><sup>2</sup>',
                        "ROCm 6.4",
                        "2025-01-02",
                    ],
                ]
            ),
        )
        block = fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertEqual(block["programs"], {"MI300X": "6.4"})
        self.assertEqual(block["programCves"]["MI300X"], ["CVE-2025-11111"])

    def test_a_footnote_marker_on_the_release_fails_closed(self) -> None:
        # A footnote must not turn release 6.4 into a fictitious 6.41.
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [
                    [
                        "AMD Instinct MI300X",
                        "CVE-2025-11111",
                        "ROCm 6.4<sup>1</sup>",
                        "2025-01-02",
                    ],
                ]
            ),
        )
        with self.assertRaisesRegex(
            fr.MinimumRefreshError, "does not parse as one exact release"
        ):
            fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)

    def test_rows_without_a_rocm_release_never_become_a_minimum(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [
                    ["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"],
                    ["AMD Instinct MI300X", "CVE-2025-22222", "GIM 8.4.0.K", "2025-01-02"],
                    ["AMD Instinct MI325X", "CVE-2025-33333", "BKC 26", "2025-01-02"],
                    ["AMD Instinct MI355X", "CVE-2025-44444", "No fix planned", ""],
                    [
                        "AMD Instinct MI250",
                        "CVE-2025-55555",
                        "Contact your AMD Customer Engineering representative",
                        "",
                    ],
                ]
            ),
        )
        block = fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertEqual(block["programs"], {"MI300X": "6.4"})

    def test_the_first_publication_of_the_minimum_release_keeps_the_date(self) -> None:
        self.set_page(
            "amd-sb-6024",
            amd_page(
                [["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "2025-06-01"]]
            ),
        )
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [["AMD Instinct MI300X", "CVE-2025-22222", "ROCm 6.4", "2025-02-01"]]
            ),
        )
        block = fr.amd_rocm_minimums(
            bulletins=["amd-sb-6024", "amd-sb-6027"], fetch=self.stub
        )
        entry = block["floorAvailability"]["MI300X"]
        self.assertEqual(entry["available"], "2025-02-01T00:00:00Z")
        self.assertEqual(entry["aId"], "AMD-SB-6027")
        self.assertEqual(
            block["programCves"]["MI300X"], ["CVE-2025-11111", "CVE-2025-22222"]
        )

    def test_every_tracked_header_wording_still_matches(self) -> None:
        for sb_id in ("amd-sb-6018", "amd-sb-6024", "amd-sb-6027"):
            with self.subTest(sb_id=sb_id):
                block = fr.amd_rocm_minimums(bulletins=[sb_id], fetch=self.stub)
                self.assertTrue(block["programs"])

    def test_a_rocm_mention_that_is_not_one_exact_release_fails_closed(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [
                    [
                        "AMD Instinct MI300X",
                        "CVE-2025-11111",
                        "Upgrade to ROCm 6.4 or later",
                        "2025-01-02",
                    ]
                ]
            ),
        )
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertIn("does not parse as one exact release", str(caught.exception))

    def test_a_page_without_a_dated_mitigation_table_fails_closed(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"]],
                header=("Product", "CVE", "Mitigation"),
            ),
        )
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertIn("outside the dated mitigation tables", str(caught.exception))

    def test_a_page_without_an_initial_publication_revision_fails_closed(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"]],
                revision=None,
            ),
        )
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertIn("found no Initial publication revision", str(caught.exception))

    def test_a_rocm_release_outside_the_dated_tables_fails_closed(self) -> None:
        self.set_page(
            "amd-sb-6027",
            amd_page(
                [["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"]],
                extra=(
                    "<table><tr><th>Product</th><th>Fix</th></tr>"
                    "<tr><td>AMD Instinct MI355X</td><td>ROCm 9.9</td></tr></table>"
                ),
            ),
        )
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
        self.assertIn(
            "outside the dated mitigation tables", str(caught.exception)
        )

    def test_malformed_rows_in_a_dated_table_fail_closed(self) -> None:
        cases = {
            "fewer than four cells": [["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4"]],
            "names no recognized MI program": [
                ["AMD Instinct accelerator", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"]
            ],
            "carries no CVE identifier": [
                ["AMD Instinct MI300X", "N/A", "ROCm 6.4", "2025-01-02"]
            ],
            "carries no release date": [
                ["AMD Instinct MI300X", "CVE-2025-11111", "ROCm 6.4", "May 2025"]
            ],
        }
        for expected, rows in cases.items():
            with self.subTest(expected=expected):
                self.set_page("amd-sb-6027", amd_page(rows))
                with self.assertRaises(fr.MinimumRefreshError) as caught:
                    fr.amd_rocm_minimums(bulletins=["amd-sb-6027"], fetch=self.stub)
                self.assertIn(expected, str(caught.exception))

    def test_an_unreadable_bulletin_fails_closed(self) -> None:
        del self.stub.text_by_url[fr.amd_bulletin_page("amd-sb-6027")]
        with self.assertRaises(fr.MinimumRefreshError):
            fr.amd_rocm_minimums(fetch=self.stub)

    def test_a_rebuild_that_lowers_a_program_minimum_is_rejected(self) -> None:
        existing = baseline()
        rocm_catalog = [
            {
                "aId": "AMD-SB-6018",
                "url": fr.amd_bulletin_page("amd-sb-6018"),
            }
        ]
        driver_catalog = [
            {
                "aId": "AMD-SB-6034",
                "url": fr.amd_bulletin_page("amd-sb-6034"),
            }
        ]
        with mock.patch.object(
            fr, "amd_bulletin_catalog", side_effect=[rocm_catalog, driver_catalog]
        ):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.build_minimums(
                    generated=GENERATED, existing=existing, fetch=self.stub
                )
        message = str(caught.exception)
        self.assertIn("rocm", message)
        self.assertIn("a minimum only moves up", message)

    def test_a_rebuild_that_drops_a_program_is_rejected(self) -> None:
        existing = baseline()
        page = amd_page(
            [
                [
                    "AMD Instinct MI210 AMD Instinct MI250 AMD Instinct MI300A "
                    "AMD Instinct MI300X AMD Instinct MI308X",
                    "CVE-2026-11111",
                    "ROCm 7.0.1",
                    "2026-01-02",
                ]
            ]
        )
        self.set_page("amd-sb-6027", page)
        rocm_catalog = [
            {
                "aId": "AMD-SB-6027",
                "url": fr.amd_bulletin_page("amd-sb-6027"),
            }
        ]
        driver_catalog = [
            {
                "aId": "AMD-SB-6034",
                "url": fr.amd_bulletin_page("amd-sb-6034"),
            }
        ]
        with mock.patch.object(
            fr, "amd_bulletin_catalog", side_effect=[rocm_catalog, driver_catalog]
        ):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.build_minimums(
                    generated=GENERATED, existing=existing, fetch=self.stub
                )
        message = str(caught.exception)
        self.assertIn("rocm.MI325X", message)
        self.assertIn("a published minimum is never removed", message)

    def test_confirmed_availability_is_preserved_while_the_minimum_stays(self) -> None:
        existing = baseline()
        existing["components"]["rocm"]["floorAvailability"]["MI210"].update(
            {"bulletinReleased": "2026-05-12T00:00:00Z", "note": "first sighting"}
        )
        doc = fr.build_minimums(generated=GENERATED, existing=existing, fetch=self.stub)
        self.assertEqual(
            doc["components"]["rocm"]["floorAvailability"]["MI210"],
            existing["components"]["rocm"]["floorAvailability"]["MI210"],
        )


class FailClosedTest(unittest.TestCase):
    def test_missing_ubuntu_fix_raises_and_names_the_package(self) -> None:
        stub = StubFetcher()
        url = f"{fr.UBUNTU_CVE_URL}CVE-2026-53359.json"
        doc = copy.deepcopy(stub.json_by_url[url])
        for package in doc["packages"]:
            package["statuses"] = [
                status
                for status in package["statuses"]
                if status["release_codename"] != "noble"
            ]
        stub.json_by_url[url] = doc
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        message = str(caught.exception)
        self.assertIn("ubuntuNoble.linuxJanuscape", message)
        self.assertIn("6.8.0-137.137", message)

    def test_virtio_net_without_any_fixed_release_raises(self) -> None:
        stub = StubFetcher()
        url = fr.bulletin_url(2026, 5815)
        doc = copy.deepcopy(stub.json_by_url[url])
        arch = doc["product_tree"]["branches"][0]["branches"][0]
        arch["branches"] = [
            kid
            for kid in arch["branches"]
            if not kid["product"]["name"].lower().startswith("all versions prior")
            and "newer" not in kid["product"]["name"]
        ]
        stub.json_by_url[url] = doc
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        self.assertIn("virtioNetBluefield", str(caught.exception))

    def test_a_dropped_virtio_net_line_raises(self) -> None:
        stub = StubFetcher()
        url = fr.bulletin_url(2026, 5815)
        doc = copy.deepcopy(stub.json_by_url[url])
        arch = doc["product_tree"]["branches"][0]["branches"][0]
        arch["branches"] = [
            kid for kid in arch["branches"] if kid["name"] != "VIRTIO-Net LTS24"
        ]
        stub.json_by_url[url] = doc
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        message = str(caught.exception)
        self.assertIn("virtioNetBluefield.LTS24", message)
        self.assertIn("24.10.50", message)

    def test_one_lost_dcgm_product_still_fails_the_whole_rebuild(self) -> None:
        stub = StubFetcher()
        url = fr.bulletin_url(2026, 5857)
        doc = copy.deepcopy(stub.json_by_url[url])
        doc["vulnerabilities"][0]["product_status"] = {
            "fixed": [
                "all4_5_dcgm_4_5_3",
                "all4_8_dcgm_exporter_4_8_2",
            ]
        }
        vendor = doc["product_tree"]["branches"][0]
        vendor["branches"] = [
            arch for arch in vendor["branches"] if arch["name"] != "All(4.8)"
        ]
        stub.json_by_url[url] = doc
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        message = str(caught.exception)
        self.assertIn("dcgmExporter", message)
        self.assertNotIn("dcgm:", message)  # The surviving product is fine.

    def test_a_reworded_dcgm_range_fails_closed(self) -> None:
        stub = StubFetcher()
        url = fr.bulletin_url(2026, 5857)
        doc = copy.deepcopy(stub.json_by_url[url])
        for arch in doc["product_tree"]["branches"][0]["branches"]:
            for kid in arch["branches"]:
                phrase = kid["product"]["name"]
                if " to " not in phrase:
                    kid["product"]["name"] = f"All versions up to and including {phrase}"
        stub.json_by_url[url] = doc
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        message = str(caught.exception)
        self.assertIn("dcgm", message)
        self.assertIn("dcgmExporter", message)

    def test_a_bulletin_set_that_would_lower_a_branch_minimum_fails(self) -> None:
        stub = StubFetcher()
        stub.json_by_url[fr.NVIDIA_CSAF_TREE]["tree"] = [
            {"path": "2026/5699/5699.json", "type": "blob"},
            {"path": "2026/5747/5747.json", "type": "blob"},
        ]
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub
            )
        message = str(caught.exception)
        self.assertIn("nvidiaDriver.580", message)
        self.assertIn("580.178.04", message)
        self.assertIn("580.126.09", message)
        self.assertIn("nvidiaDriver.595", message)

    def test_a_lowered_branch_minimum_writes_nothing(self) -> None:
        stub = StubFetcher()
        with tempfile.TemporaryDirectory() as tmp:
            target = write_baseline(tmp)
            before = target.read_text()
            err = io.StringIO()
            stub.json_by_url[fr.NVIDIA_CSAF_TREE]["tree"] = [
                {"path": "2026/5699/5699.json", "type": "blob"},
                {"path": "2026/5747/5747.json", "type": "blob"},
            ]
            with mock.patch.object(fr, "_DEFAULT_FETCHER", stub), redirect_stderr(err):
                code = fr.main(
                    ["--write", str(target), "--generated", "2026-07-30T00:00:00Z"]
                )
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(), before)
            self.assertIn("nvidiaDriver.580", err.getvalue())

    def test_a_rung_that_vanishes_from_the_rebuild_fails_closed(self) -> None:
        existing = baseline()
        existing["components"]["runc"]["ladder"]["9.9"] = "9.9.1"
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated=GENERATED, existing=existing, fetch=StubFetcher()
            )
        message = str(caught.exception)
        self.assertIn("runc.9.9", message)
        self.assertIn("disappeared", message)

    def test_a_lowered_ladder_rung_fails_closed(self) -> None:
        existing = baseline()
        existing["components"]["runc"]["ladder"]["1.3"] = "1.3.9"
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
            )
        message = str(caught.exception)
        self.assertIn("runc.1.3", message)
        self.assertIn("1.3.9", message)
        self.assertIn("1.3.6", message)

    def test_a_release_candidate_replacing_a_stable_rung_fails_closed(self) -> None:
        existing = baseline()
        existing["components"]["runc"]["ladder"]["1.5"] = "1.5.0"
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
            )
        self.assertIn("runc.1.5", str(caught.exception))

    def test_a_lowered_firmware_train_fails_closed(self) -> None:
        existing = baseline()
        existing["components"]["connectxFirmware"]["trains"]["46"] = 9999
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
            )
        self.assertIn("connectxFirmware.46", str(caught.exception))

    def test_a_lowered_minimum_fails_closed(self) -> None:
        existing = baseline()
        existing["components"]["cudaToolkit"]["minimum"] = "14.0"
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(
                generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
            )
        self.assertIn("cudaToolkit", str(caught.exception))

    def test_branch_minimums_are_compared_numerically(self) -> None:
        # Lexical and numeric version ordering differ here.
        existing = baseline()
        existing["components"]["nvidiaDriver"]["branches"]["580"] = "580.99.01"
        doc = fr.build_minimums(
            generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
        )
        self.assertEqual(doc["components"]["nvidiaDriver"]["branches"]["580"], "580.178.04")

    def test_write_leaves_no_file_when_the_rebuild_fails_closed(self) -> None:
        stub = StubFetcher(toolkit="nvidia-container-toolkit-5850-reworded.json")
        with tempfile.TemporaryDirectory() as tmp:
            existing = write_baseline(tmp)
            target = Path(tmp) / "written-minimums.json"
            err = io.StringIO()
            with mock.patch.object(fr, "_DEFAULT_FETCHER", stub), redirect_stderr(err):
                code = fr.main(
                    ["--write", str(target), "--existing", str(existing),
                     "--generated", GENERATED]
                )
            self.assertEqual(code, 2)
            self.assertFalse(target.exists())
            self.assertIn("nvidiaContainerToolkit", err.getvalue())


class CliTest(unittest.TestCase):
    def run_cli(self, argv: list[str], stub: fr.Fetcher | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fr, "_DEFAULT_FETCHER", stub or StubFetcher()):
            with redirect_stdout(out), redirect_stderr(err):
                code = fr.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_check_fails_on_a_modified_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "minimum-versions.json"
            table = baseline()
            table["components"]["nvidiaDriver"]["branches"]["595"] = "1.2.3"
            target.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n")
            code, out, err = self.run_cli(["--check", str(target)])
            self.assertEqual(code, 1)
            self.assertIn("595.91.07", out)
            self.assertIn("differs", err)

    def test_print_pins_the_generated_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            existing = write_baseline(tmp)
            code, out, err = self.run_cli(
                ["--print", "--existing", str(existing),
                 "--generated", "2001-02-03T04:05:06Z"]
            )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["generated"], "2001-02-03T04:05:06Z")


class DetectNewBulletinsTest(unittest.TestCase):
    def scan(self, years: list[int] | None = None, fetch: fr.Fetcher | None = None) -> list[dict]:
        return fr.detect_new_bulletins(
            existing=baseline(), years=years or [2026], fetch=fetch or StubFetcher()
        )

    def detect_cli(self, stub: fr.Fetcher | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            existing = write_baseline(tmp)
            with mock.patch.object(fr, "_DEFAULT_FETCHER", stub or StubFetcher()):
                with redirect_stdout(out), redirect_stderr(err):
                    code = fr.main(["--detect-new-bulletins", "--existing", str(existing)])
        return code, out.getvalue(), err.getvalue()

    def test_reports_an_unknown_relevant_bulletin(self) -> None:
        new = [item for item in self.scan() if item["status"] == "new"]
        self.assertEqual([item["id"] for item in new], [5871])
        self.assertEqual(new[0]["product"], "GPU Display Driver")
        self.assertEqual(
            new[0]["title"], "Security Bulletin: GPU Display Driver - August 2026"
        )
        self.assertEqual(
            new[0]["url"],
            "https://github.com/NVIDIA/product-security/blob/main/2026/5871/5871.json",
        )

    def test_skips_known_ids_unrelated_products_and_unreadable_files(self) -> None:
        stub = StubFetcher()
        ids = {item["id"] for item in self.scan(fetch=stub)}
        self.assertNotIn(5851, ids)  # Jetson AGX Orin: not a graded product line.
        self.assertNotIn(5869, ids)  # No markdown file in the fixture set.
        for known in (5699, 5755, 5815, 5821, 5850, 5857):
            self.assertNotIn(known, ids)
            self.assertNotIn(f"/{known}/{known}.md", " ".join(stub.calls))

    def test_a_listing_that_cannot_be_read_does_not_crash_the_scan(self) -> None:
        new = [item for item in self.scan(years=[2026, 2027]) if item["status"] == "new"]
        self.assertEqual([item["id"] for item in new], [5871])

    def test_tracked_docker_majors_are_not_reported(self) -> None:
        found = self.scan()
        self.assertFalse(
            [item for item in found if item["product"] == "Docker Engine"]
        )

    def test_an_untracked_docker_major_is_reported_as_new(self) -> None:
        stub = StubFetcher()
        stub.json_by_url[fr.DOCKER_DOCS_CONTENTS] = fixture(
            "docker-docs-release-notes-listing.json"
        ) + [{"name": "30.md", "type": "file"}]
        docker = [
            item
            for item in self.scan(fetch=stub)
            if item["product"] == "Docker Engine"
        ]
        self.assertEqual([item["id"] for item in docker], [30])
        self.assertEqual(docker[0]["status"], "new")
        self.assertEqual(
            docker[0]["url"], "https://docs.docker.com/engine/release-notes/30/"
        )

    def test_an_unreadable_docker_listing_does_not_crash_the_scan(self) -> None:
        stub = StubFetcher()
        del stub.json_by_url[fr.DOCKER_DOCS_CONTENTS]
        self.assertEqual(fr.untracked_docker_majors(fetch=stub), [])
        new = [item for item in self.scan(fetch=stub) if item["status"] == "new"]
        self.assertEqual([item["id"] for item in new], [5871])

    def test_cli_exit_three_tells_the_operator_where_to_track_a_docker_major(
        self,
    ) -> None:
        stub = StubFetcher()
        stub.json_by_url[fr.DOCKER_DOCS_CONTENTS] = fixture(
            "docker-docs-release-notes-listing.json"
        ) + [{"name": "30.md", "type": "file"}]
        code, out, err = self.detect_cli(stub)
        self.assertEqual(code, 3)
        self.assertIn("Docker Engine 30 release notes", out)
        self.assertIn("DOCKER_ENGINE_MAJORS", err)

    def test_cli_exits_three_when_a_new_bulletin_exists(self) -> None:
        code, out, err = self.detect_cli()
        self.assertEqual(code, 3)
        self.assertIn("5871", out)
        self.assertIn("5744", out)
        self.assertIn("DEFERRED_BULLETINS", err)

    def test_5744_is_deferred_and_is_not_reported_as_untracked(self) -> None:
        self.assertIn("5744", fr.DEFERRED_BULLETINS)
        found = self.scan()
        snap4 = next(item for item in found if item["id"] == 5744)
        self.assertEqual(snap4["status"], "deferred")
        self.assertIn("4.5.5 LTS train", snap4["reason"])
        self.assertNotIn(5744, [item["id"] for item in found if item["status"] == "new"])

    def test_5847_is_not_applicable_to_supported_networking_products(self) -> None:
        found = self.scan()
        item = next(item for item in found if item["id"] == 5847)
        self.assertEqual(item["status"], "not_applicable")
        self.assertIn("BlueField-3", item["reason"])
        self.assertNotIn(5847, [item["id"] for item in found if item["status"] == "new"])

    def test_a_deferred_only_result_exits_zero_and_still_names_the_bulletin(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"5871": "parser work pending"}):
            code, out, err = self.detect_cli()
        self.assertEqual(code, 0)
        self.assertIn("Deferred bulletins", out)
        self.assertIn("5744", out)
        self.assertIn("drops the 4.5.5 LTS train", out)
        self.assertIn("no unknown bulletins", out)
        self.assertEqual(err, "")

    def test_a_deferred_bulletin_is_reported_even_when_the_scan_misses_it(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"4001": "retired product line"}):
            found = self.scan()
        missing = next(item for item in found if item["id"] == 4001)
        self.assertEqual(missing["status"], "deferred")
        self.assertIsNone(missing["title"])
        self.assertEqual(missing["reason"], "retired product line")

    def test_a_bulletin_that_is_tracked_and_deferred_raises(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"5755": "cannot be both"}):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                self.scan()
            self.assertIn("5755", str(caught.exception))

    def test_a_deferred_bulletin_without_a_reason_raises(self) -> None:
        for reason in ("", "   "):
            with self.subTest(reason=repr(reason)):
                with mock.patch.dict(fr.DEFERRED_BULLETINS, {"4002": reason}):
                    with self.assertRaises(fr.MinimumRefreshError) as caught:
                        fr.validate_bulletin_lists()
                    self.assertIn("4002", str(caught.exception))

    def test_a_new_amd_bulletin_automatically_changes_the_floor(self) -> None:
        stub = StubFetcher()
        row = (
            "<tr><td>AMD-SB-6099</td>"
            '<td><a href="/en/resources/product-security/bulletin/amd-sb-6099.html">'
            "AMD Instinct GPU Vulnerabilities</a></td>"
            "<td>Security Bulletin</td><td>CVE-2026-11111</td>"
            "<td>Jun 01, 2026</td><td>Jun 01, 2026</td></tr>"
        )
        stub.text_by_url[fr.AMD_SECURITY_INDEX] = stub.text_by_url[
            fr.AMD_SECURITY_INDEX
        ].replace(
            "Showing 1 to 27 of 27 entries", "Showing 1 to 28 of 28 entries"
        ).replace("</tbody>", row + "</tbody>")
        stub.text_by_url[fr.amd_bulletin_page("amd-sb-6099")] = amd_page(
            [
                [
                    "AMD Instinct MI350",
                    "CVE-2026-11111",
                    "ROCm 8.0",
                    "2026-06-01",
                ]
            ]
        )
        block = fr.amd_rocm_minimums(fetch=stub)
        self.assertEqual(block["programs"]["MI350"], "8.0")
        self.assertEqual(block["floorAvailability"]["MI350"]["aId"], "AMD-SB-6099")

    def test_non_6000_amd_bulletin_families_are_ignored(self) -> None:
        ids = {item["aId"] for item in fr.amd_bulletin_catalog(StubFetcher())}
        self.assertNotIn("AMD-SB-7064", ids)
        self.assertNotIn("AMD-SB-8015", ids)

    def test_an_unreadable_amd_index_fails_closed(self) -> None:
        stub = StubFetcher()
        del stub.text_by_url[fr.AMD_SECURITY_INDEX]
        with self.assertRaises(fr.MinimumRefreshError):
            fr.amd_bulletin_catalog(fetch=stub)

    def test_a_paginated_amd_index_fails_closed(self) -> None:
        stub = StubFetcher()
        stub.text_by_url[fr.AMD_SECURITY_INDEX] = stub.text_by_url[
            fr.AMD_SECURITY_INDEX
        ].replace("Showing 1 to 27 of 27 entries", "Showing 1 to 10 of 27 entries")
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.amd_bulletin_catalog(fetch=stub)
        self.assertIn("paginated or truncated", str(caught.exception))

class PullRequestBodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        yaml = __import__("importlib").import_module("yaml")
        path = (
            Path(__file__).resolve().parents[2]
            / ".github/workflows/minimum-versions-refresh.yml"
        )
        workflow = yaml.safe_load(path.read_text())
        (job,) = workflow["jobs"].values()
        (step,) = [
            candidate
            for candidate in job["steps"]
            if candidate.get("name") == "Write the pull request description"
        ]
        run = step["run"]
        start = run.index("<<'PY'\n") + len("<<'PY'\n")
        cls.script = run[start : run.rindex("\nPY")]

    def body(self, *, found: str | None, report: str) -> str:
        with tempfile.TemporaryDirectory() as temp:
            minimums = Path(temp) / "minimum-versions.json"
            before = {"schemaVersion": 1, "components": {"docker": {"minimum": "29.4.2"}}}
            after = {"schemaVersion": 1, "components": {"docker": {"minimum": "29.4.3"}}}
            minimums.write_text(json.dumps(after))
            (Path(temp) / "minimums-before.json").write_text(json.dumps(before))
            (Path(temp) / "new-bulletins.txt").write_text(report)
            env = {
                "MINIMUMS_PATH": str(minimums),
                "RUNNER_TEMP": temp,
                "RUN_URL": "https://example.invalid/run/1",
            }
            if found is not None:
                env["NEW_BULLETINS"] = found
            with mock.patch.dict("os.environ", env, clear=False):
                if found is None:
                    __import__("os").environ.pop("NEW_BULLETINS", None)
                with redirect_stdout(io.StringIO()):
                    exec(compile(self.script, "pr-body", "exec"), {"__name__": "__main__"})
            return (Path(temp) / "pr-body.md").read_text()

    def test_a_failed_scan_is_never_described_as_a_clean_scan(self) -> None:
        for found in (None, ""):
            with self.subTest(found=repr(found)):
                body = self.body(
                    found=found, report="Traceback: MinimumRefreshError: read timed out"
                )
                self.assertIn("failed on every attempt", body)
                self.assertNotIn("found no new relevant bulletin", body)
                self.assertNotIn("found no new bulletin", body)
                self.assertIn("minimum changes above are unaffected", body)
                self.assertIn("read timed out", body)

    def test_a_clean_scan_still_reports_a_clean_scan(self) -> None:
        body = self.body(found="false", report="no unknown bulletins for the graded product lines")
        self.assertIn("no new relevant bulletin", body)
        self.assertNotIn("failed on every attempt", body)

    def test_an_untracked_bulletin_is_still_reported(self) -> None:
        body = self.body(found="true", report="  5744  Networking SNAP4: title")
        self.assertIn("relevant bulletins that the table does not track", body)
        self.assertIn("5744  Networking SNAP4: title", body)
        self.assertNotIn("failed on every attempt", body)

    def test_a_deferred_bulletin_keeps_its_recorded_reason(self) -> None:
        report = (
            "Deferred bulletins (a recorded decision, reviewed every run):\n"
            "  5744  Networking SNAP4  https://example.invalid\n"
            "      reason: two fixed trains in one phrase"
        )
        body = self.body(found="false", report=report)
        self.assertIn("two fixed trains in one phrase", body)
        self.assertNotIn("failed on every attempt", body)


class RefreshWorkflowGatingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        yaml = __import__("importlib").import_module("yaml")
        path = (
            Path(__file__).resolve().parents[2]
            / ".github/workflows/minimum-versions-refresh.yml"
        )
        workflow = yaml.safe_load(path.read_text())
        (cls.job,) = workflow["jobs"].values()
        cls.steps = cls.job["steps"]
        cls.names = [str(step.get("name", "")) for step in cls.steps]

    def step(self, fragment: str) -> dict:
        matches = [
            step
            for step, name in zip(self.steps, self.names)
            if fragment.lower() in name.lower()
        ]
        self.assertEqual(
            len(matches), 1, f"expected exactly one step matching {fragment!r}"
        )
        return matches[0]

    def index(self, fragment: str) -> int:
        return self.steps.index(self.step(fragment))

    def test_a_failed_bulletin_scan_cannot_skip_the_pull_request(self) -> None:
        scan = self.step("Detect new upstream bulletins")
        self.assertIs(
            scan.get("continue-on-error"),
            True,
            "failed scans must not skip refreshed-table pull requests",
        )
        for fragment in ("Write the pull request", "Open or update the pull request"):
            self.assertGreater(self.index(fragment), self.index("Detect new upstream"))

    def test_the_pull_request_steps_gate_only_on_a_changed_table(self) -> None:
        for fragment in ("Write the pull request", "Open or update the pull request"):
            with self.subTest(step=fragment):
                condition = str(self.step(fragment)["if"])
                self.assertEqual(condition, "steps.compare.outputs.changed == 'true'")

    def test_a_failed_bulletin_scan_still_turns_the_run_red(self) -> None:
        gate = self.step("Fail the run when the bulletin scan")
        condition = str(gate["if"])
        self.assertIn("steps.bulletins.outcome == 'failure'", condition)
        self.assertNotIn("conclusion", condition)
        self.assertIn("cancelled()", condition)
        self.assertIn("exit 1", gate["run"])
        self.assertGreater(
            self.steps.index(gate), self.index("Open or update the pull request")
        )

    def test_the_policy_tests_still_gate_the_pull_request(self) -> None:
        for fragment in (
            "Refresh the minimum table",
            "Check that the refreshed table is complete",
            "Compare the new table",
            "Run the offline audit policy tests",
        ):
            with self.subTest(step=fragment):
                step = self.step(fragment)
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)
                self.assertLess(
                    self.steps.index(step), self.index("Open or update the pull request")
                )
        self.assertEqual(
            self.step("Refresh the minimum table").get("env", {}).get("GITHUB_TOKEN"),
            "${{ secrets.GITHUB_TOKEN }}",
        )
        with mock.patch.dict(fr.os.environ, {"GITHUB_TOKEN": "test-token"}, clear=True):
            fetcher = fr.Fetcher()
            self.assertEqual(
                fetcher._headers("https://api.github.com/repos/example/releases").get(
                    "Authorization"
                ),
                "Bearer test-token",
            )
            for url in (fr.OSV_QUERY_URL, fr.UBUNTU_CVE_URL, fr.NVIDIA_RAW):
                self.assertNotIn("Authorization", fetcher._headers(url))

    def test_github_token_does_not_cross_a_redirect_origin(self) -> None:
        request = fr.urllib.request.Request(
            "https://api.github.com/repos/example/releases",
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = fr.SameOriginAuthRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://objects.githubusercontent.com/release.json",
        )
        self.assertIsNotNone(redirected)
        self.assertNotIn("Authorization", redirected.headers)

    def test_github_token_survives_a_same_origin_redirect(self) -> None:
        request = fr.urllib.request.Request(
            "https://api.github.com/repos/example/releases",
            headers={"Authorization": "Bearer test-token"},
        )
        redirected = fr.SameOriginAuthRedirectHandler().redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://api.github.com/repositories/1/releases",
        )
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.headers["Authorization"], "Bearer test-token")


class FetchLoggingTests(unittest.TestCase):
    def test_json_fetch_logs_url_and_duration_without_credentials(self):
        url = "https://api.github.com/repos/example/releases"
        with (
            mock.patch.dict(fr.os.environ, {"GITHUB_TOKEN": "private-test-token"}),
            mock.patch.object(fr.SAFE_OPENER, "open", return_value=io.BytesIO(b"{}")),
            self.assertLogs(fr.__name__, level="INFO") as logs,
        ):
            self.assertEqual(fr.Fetcher().get_json(url), {})
        output = "\n".join(logs.output)
        self.assertIn("fetch GET " + url, output)
        self.assertIn("finished " + url + " after ", output)
        self.assertNotIn("private-test-token", output)
        self.assertNotIn("Authorization", output)

    def test_failed_request_logs_duration_and_still_raises(self):
        url = "https://example.com/feed"
        with (
            mock.patch.object(fr.SAFE_OPENER, "open", side_effect=TimeoutError("timed out")),
            self.assertLogs(fr.__name__, level="INFO") as logs,
            self.assertRaisesRegex(fr.MinimumRefreshError, "timed out"),
        ):
            fr.Fetcher().get_text(url)
        self.assertIn("finished " + url, "\n".join(logs.output))


class UbuntuConcurrencyTests(unittest.TestCase):
    def test_packages_run_concurrently_and_keep_input_order(self):
        barrier = threading.Barrier(4, timeout=5)
        specs = [
            {"key": str(n), "cve": str(n), "package": "package"}
            for n in range(4)
        ]

        def entry(cve, *args, **kwargs):
            barrier.wait()
            return {"fixed": cve}

        with mock.patch.object(fr, "ubuntu_entry", side_effect=entry):
            result = fr.ubuntu_minimums(specs=specs, package_policy=())
        self.assertEqual(list(result["packages"]), ["0", "1", "2", "3"])
        self.assertEqual(result["packages"]["2"]["fixed"], "2")

    def test_a_failed_package_still_stops_the_build(self):
        with (
            mock.patch.object(
                fr, "ubuntu_entry", side_effect=fr.MinimumRefreshError("feed unavailable")
            ),
            self.assertRaisesRegex(fr.MinimumRefreshError, "feed unavailable"),
        ):
            fr.ubuntu_minimums(
                specs=[{"key": "x", "cve": "x", "package": "x"}],
                package_policy=(),
            )


class BulletinShellTests(unittest.TestCase):
    def test_scan_exit_codes_under_github_errexit(self):
        import yaml

        path = Path(__file__).resolve().parents[2] / ".github/workflows/minimum-versions-refresh.yml"
        steps = yaml.safe_load(path.read_text())["jobs"]["refresh"]["steps"]
        script = next(s["run"] for s in steps if s.get("id") == "bulletins")
        for code, found, attempts in ((0, "false", 1), (3, "true", 1), (2, None, 3)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                stub = (
                    '(printf "attempt\\n" >> "$RUNNER_TEMP/attempts"; '
                    f'exit {code}) > "$report" 2>&1'
                )
                run, replacements = re.subn(
                    r'python3[^\n]+> "\$report" 2>&1', lambda _: stub, script
                )
                self.assertEqual(replacements, 1)
                result = subprocess.run(
                    ["bash", "-e", "-c", "sleep() { :; }\n" + run],
                    env={**os.environ, "RUNNER_TEMP": directory, "GITHUB_OUTPUT": str(output)},
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 0 if found else 1)
                self.assertEqual(
                    (Path(directory) / "attempts").read_text().splitlines(),
                    ["attempt"] * attempts,
                )
                if found:
                    self.assertEqual(output.read_text(), f"found={found}\n")
                else:
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
