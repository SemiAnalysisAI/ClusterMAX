"""Offline tests for the minimum version generator.

Every test drives `cmax.minimum_refresh` through a stub fetcher backed by trimmed
fixtures in `tests/audit/fixtures/minimum_refresh/`, so the suite never touches
the network.

No test reads the live table at
`cmax/scripts/1-audit/minimum-versions.json`. That rule is the reason
this file exists in its current shape. The workflow in
`.github/workflows/minimum-versions-refresh.yml` rewrites the live table
whenever an upstream feed publishes, so an assertion against it fails on a
correct refresh rather than on a defect. Between 2026-08-12 and 2026-08-17 that
pattern turned `python-tests` red on master and on every unrelated pull
request, twice, and each red run was a false alarm.

Every assertion here must therefore satisfy two conditions:

1. It fails when the generator is wrong.
2. It still passes when upstream publishes a new advisory or version.

A value pinned against a frozen fixture satisfies both, because the fixture
does not move. A value pinned against the live table satisfies only the first.

The live table has its own contract tests in
`tests/audit/test_minimum_versions.py`, which derives its samples from
the table itself and pin nothing.
"""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cmax import minimum_refresh as fr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "minimum_refresh"

# Every rebuild in this file pins the same stamp. The value is arbitrary,
# because no assertion reads it.
GENERATED = "2026-07-30T00:00:00Z"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


def baseline() -> dict:
    """Return a table built from the fixtures alone.

    The fail-closed tests need a published table to lower a minimum in. They
    build one here instead of reading the live table, so the guard they check
    stays the subject of the test and upstream cannot break them. Each call
    returns a fresh copy, because callers mutate the result.
    """
    return json.loads(_BASELINE_JSON)


def write_baseline(directory) -> Path:
    """Write a fixture-built table into `directory` and return its path."""
    path = Path(directory) / "minimum-versions.json"
    path.write_text(_BASELINE_JSON)
    return path


def affects(vuln: dict, version: str) -> bool:
    """Whether an OSV advisory covers one release, as the API decides it.

    The stub uses this so a version-scoped query returns the reduced advisory
    set the live API would return, instead of the whole fixture.
    """
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
    """Serve the committed fixtures instead of the live feeds."""

    def __init__(self, *, toolkit: str = "nvidia-container-toolkit-5850.json") -> None:
        self.calls: list[str] = []
        self.post_bodies: list[dict] = []
        self.json_by_url: dict[str, object] = {
            fr.bulletin_url(2026, 5821): fixture("nvidia-driver-5821.json"),
            fr.bulletin_url(2026, 5747): fixture("nvidia-driver-5747.json"),
            fr.bulletin_url(2026, 9999): fixture("nvidia-driver-lexical-trap.json"),
            fr.bulletin_url(2026, 5699): fixture("nvidia-connectx-5699.json"),
            fr.bulletin_url(2026, 5755): fixture("nvidia-cuda-5755.json"),
            fr.bulletin_url(2026, 5850): fixture(toolkit),
            fr.bulletin_url(2026, 5815): fixture("nvidia-virtio-net-5815.json"),
            fr.bulletin_url(2026, 5857): fixture("nvidia-dcgm-5857.json"),
            fr.GITHUB_CONTENTS.format(year=2026): fixture("github-contents-2026.json"),
        }
        for bulletin in (5821, 5747):
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
        # One file holds every Ubuntu response, keyed by CVE: the four share a
        # feed and a document shape, so splitting them added files without
        # adding coverage. The CSAF and OSV fixtures stay separate because their
        # shapes differ per document.
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
        for sb_id in fr.AMD_BULLETINS:
            self.text_by_url[fr.amd_bulletin_page(sb_id)] = (
                FIXTURES / f"{sb_id}.html"
            ).read_text()

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
            # OSV returns only the advisories that affect the queried release.
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


# Built once at import, and deliberately not on first use. A lazy build would
# run inside whichever test called baseline() first. Several tests patch
# fr.BULLETINS, so a first call under such a patch would record a partial table
# that every later test then read, which makes the suite order-dependent.
_BASELINE_JSON = fr.serialize(
    fr.build_minimums(generated=GENERATED, existing={}, fetch=StubFetcher())
)


def arch_kids(doc: dict, arch_name: str) -> list[dict]:
    for arch, kids in fr.csaf_arch_branches(doc):
        if arch == arch_name:
            return kids
    raise AssertionError(f"no architecture branch named {arch_name!r}")


class ExtractorTest(unittest.TestCase):
    """Each extractor must read its frozen bulletin the way the audit needs."""

    def setUp(self) -> None:
        self.stub = StubFetcher()

    def test_driver_ignores_windows_vgpu_and_cloud_gaming_branches(self) -> None:
        # Both fixtures carry Windows, vGPU guest driver, and gaming branches
        # next to the Linux data-center ones.
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        self.assertEqual(sorted(block["branches"]), ["535", "570", "580", "590", "595"])
        for windows in ("596.36", "591.59"):
            self.assertNotIn(windows, block["branches"].values())

    def test_driver_branches_take_the_highest_version_across_bulletins(self) -> None:
        # 5821 (May 2026) and 5747 (January 2026) both publish R535 and R580.
        # 5821 is higher on both, and it is the only source of R595. 5747 is
        # the only source of R570 and R590.
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        self.assertEqual(
            block["branches"],
            {
                "535": "535.309.01",
                "570": "570.211.01",
                "580": "580.159.03",
                "590": "590.48.01",
                "595": "595.71.05",
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
        """580.99.01 is lexically above 580.159.03 and numerically below it."""
        for refs in (
            [{"year": 2026, "aId": 5821}, {"year": 2026, "aId": 9999}],
            [{"year": 2026, "aId": 9999}, {"year": 2026, "aId": 5821}],
        ):
            with self.subTest(order=[ref["aId"] for ref in refs]):
                block = fr.nvidia_driver_minimums(refs=refs, fetch=self.stub)
                self.assertEqual(block["branches"]["580"], "580.159.03")
                self.assertEqual(block["branchSources"]["580"], 5821)

    def test_a_branch_from_a_single_bulletin_still_appears(self) -> None:
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        # R595 comes only from 5821, R590 only from 5747.
        self.assertEqual(block["branches"]["595"], "595.71.05")
        self.assertEqual(block["branches"]["590"], "590.48.01")

    def test_driver_records_which_bulletin_produced_each_branch(self) -> None:
        block = fr.nvidia_driver_minimums(fetch=self.stub)
        self.assertEqual(
            block["branchSources"],
            {"535": 5821, "570": 5747, "580": 5821, "590": 5747, "595": 5821},
        )
        self.assertEqual([item["aId"] for item in block["sources"]], [5747, 5821])
        # `source` stays the newest bulletin, so the single-source shape holds.
        self.assertEqual(block["source"]["aId"], 5821)

    def test_connectx_trains_come_from_the_bulletin(self) -> None:
        block = fr.connectx_minimums(fetch=self.stub)
        self.assertEqual(
            [str(train) for train in block["trains"]],
            ["28", "32", "35", "39", "43", "46"],
        )
        self.assertTrue(
            all(
                item["status"] == "confirmed"
                for item in block["floorAvailability"].values()
            )
        )

    def test_cuda_toolkit_minimum_and_cves(self) -> None:
        block = fr.simple_product_minimum(2026, 5755, fetch=self.stub)
        self.assertEqual(block["minimum"], "13.1")
        self.assertEqual(block["fixAvailability"]["status"], "confirmed")

    def test_container_toolkit_picks_its_own_product(self) -> None:
        block = fr.simple_product_minimum(
            2026, 5850, product="NVIDIA Container Toolkit", fetch=self.stub
        )
        # The same architecture branch also carries NVIDIA GPU Operator 26.3.2.
        self.assertEqual(block["minimum"], "1.19.1")
        self.assertEqual(block["cves"], ["CVE-2026-24260"])
        self.assertEqual(
            block["fixAvailability"]["available"], "2026-05-21T23:32:36Z"
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
        """The audit is offline, so the table must carry applicability evidence.

        Without per-advisory ranges the audit could only list the package's
        whole advisory history on a fail. runc 1.3.3 was reported with all
        seventeen advisories when exactly one (the 1.3.6 fix) affected it.
        """
        block = fr.runc_ladder(fetch=self.stub)
        # The advisory that set the 1.3 minimum affects everything below 1.3.6.
        self.assertIn(
            {"introduced": "0", "fixed": "1.3.6"},
            block["advisoryRanges"]["GHSA-xjvp-4fhw-gc47"],
        )
        # An advisory fixed at 1.3.3 stops holding 1.3.3 itself.
        self.assertIn(
            {"introduced": "1.3.0-rc.1", "fixed": "1.3.3"},
            block["advisoryRanges"]["GHSA-9493-h29p-rfm2"],
        )

    def test_a_withdrawn_advisory_holds_no_minimum(self) -> None:
        """A retracted advisory must not fail hosts the ecosystem cleared."""
        stub = StubFetcher()
        for vuln in stub.osv["vulns"]:
            if vuln["id"] == "GHSA-xjvp-4fhw-gc47":
                vuln["withdrawn"] = "2026-08-01T00:00:00Z"
        block = fr.runc_ladder(fetch=stub)
        self.assertNotIn("GHSA-xjvp-4fhw-gc47", block["advisories"])
        self.assertNotIn("GHSA-xjvp-4fhw-gc47", block["advisoryRanges"])
        # 1.3.6 was that advisory's fix, so the 1.3 minimum falls back to the
        # newest fix a live advisory published on that branch.
        self.assertEqual(block["ladder"]["1.3"], "1.3.3")

    def test_a_git_range_cannot_poison_the_ladder(self) -> None:
        """GIT events carry commit hashes, which are not versions.

        A hash split on dots becomes its own ladder key, and the audit reads a
        ladder key that is not major.minor as an unusable table. Only SEMVER
        and ECOSYSTEM ranges may feed the ladder.
        """
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
        """A version-scoped query hides every advisory that release escaped.

        Querying at 1.2.7 returned only the advisories affecting 1.2.7, so an
        advisory published later against 1.4.x or 1.5.x never arrived and those
        branches kept grading against a retired minimum.
        """
        fr.runc_ladder(fetch=self.stub)
        self.assertEqual(len(self.stub.post_bodies), 1)
        body = self.stub.post_bodies[0]
        self.assertNotIn("version", body)
        self.assertEqual(
            body["package"], {"name": fr.RUNC_PACKAGE, "ecosystem": fr.RUNC_ECOSYSTEM}
        )

    def test_an_advisory_that_misses_1_2_7_still_reaches_the_ladder(self) -> None:
        # GHSA-jfvp fixes 1.1.14, so it does not affect 1.2.7 and the old
        # version-scoped query never returned it. The stub honours a version in
        # the request body the way the live API does, so a query that goes back
        # to checking 1.2.7 loses this advisory and this assertion.
        self.assertFalse(
            affects(
                next(
                    vuln
                    for vuln in fixture("osv-runc.json")["vulns"]
                    if vuln["id"] == "GHSA-jfvp-7x6p-h2pv"
                ),
                "1.2.7",
            )
        )
        block = fr.runc_ladder(fetch=self.stub)
        self.assertIn("GHSA-jfvp-7x6p-h2pv", block["advisories"])
        self.assertEqual(block["ladder"]["1.1"], "1.1.14")

    def test_a_stable_release_outranks_its_own_release_candidate(self) -> None:
        """The defect in its real setting: two advisories, one branch.

        One advisory fixes the branch at 1.5.0-rc.3 and a later one at 1.5.0.
        Publishing the release candidate as the minimum would grade a host still
        running that candidate as a pass.
        """
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
        # Following every page must land on the same ladder as a single page.
        self.assertEqual(block["ladder"], fr.runc_ladder(fetch=StubFetcher())["ladder"])

    def test_runc_ignores_go_duplicates_and_other_packages(self) -> None:
        block = fr.runc_ladder(fetch=self.stub)
        self.assertFalse([item for item in block["advisories"] if item.startswith("GO-")])
        # github.com/opencontainers/selinux 1.13.0 shares an advisory with runc.
        self.assertNotIn("1.13", block["ladder"])

    def test_virtio_net_release_lines_come_from_the_bulletin(self) -> None:
        block = fr.virtio_net_minimums(fetch=self.stub)
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

    def test_virtio_net_line_names_come_from_the_bulletin(self) -> None:
        block = fr.virtio_net_minimums(fetch=self.stub)
        self.assertEqual(sorted(block["lines"]), ["GA", "LTS23", "LTS24", "LTS25"])

    def test_virtio_net_trailing_comma_stays_out_of_the_version(self) -> None:
        # Upstream publishes "24.10.50 or newer," for LTS24.
        block = fr.virtio_net_minimums(fetch=self.stub)
        self.assertEqual(block["lines"]["LTS24"], {"fixed": "24.10.50"})

    def test_virtio_net_records_the_retired_scheme_separately(self) -> None:
        # "1.7.21 and older versions" marks a retired 1.x scheme as affected.
        # It must never become the minimum of the LTS23 line.
        block = fr.virtio_net_minimums(fetch=self.stub)
        self.assertEqual(
            block["lines"]["LTS23"],
            {"fixed": "23.10.23", "legacyAffectedThrough": "1.7.21"},
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

    def test_dcgm_exporter_fixed_entry_wins_over_the_affected_range(self) -> None:
        """Upstream lists 4.8.2 as both the affected upper bound and the fix.

        Bulletin 5857 says DCGM Exporter is affected "0.0  to 4.8.2" and fixed
        at "4.8.2". Read literally the same release is both. The fixed entry is
        authoritative, so 4.8.2 is the minimum and a host on 4.8.2 grades pass.
        A change that let the affected range raise the minimum would grade every
        patched deployment as vulnerable.
        """
        blocks = fr.bulletin_product_minimums(2026, 5857, fr.DCGM_PRODUCTS, fetch=self.stub)
        self.assertEqual(blocks["dcgmExporter"]["minimum"], "4.8.2")

    def test_the_dcgm_bulletin_keeps_the_upstream_double_space(self) -> None:
        # The exact string upstream publishes. An editor that collapses the
        # double space would silently weaken every parser regression below.
        raw = (FIXTURES / "nvidia-dcgm-5857.json").read_text()
        self.assertIn('"0.0  to 4.5.2"', raw)
        self.assertIn('"0.0  to 4.8.2"', raw)

    def test_ubuntu_noble_packages(self) -> None:
        cve_url = f"{fr.UBUNTU_CVE_URL}CVE-2024-3446.json"
        self.stub.json_by_url[cve_url]["notices"] = [
            {"id": "USN-unreadable", "published": "2025-09-09T00:00:00Z"},
            {"id": "USN-malformed", "published": "2025-09-10T00:00:00Z"},
            *self.stub.json_by_url[cve_url]["notices"],
        ]
        self.stub.json_by_url[fr.ubuntu_notice_url("USN-malformed")] = {
            "release_packages": []
        }
        block = fr.ubuntu_minimums(fetch=self.stub)
        self.assertEqual(block["packages"]["linuxFragnesia"]["abi"], 124)
        self.assertEqual(block["packages"]["linuxJanuscape"]["status"], "pending")
        self.assertEqual(
            block["packages"]["linuxJanuscape"]["fixAvailability"]["status"],
            "unconfirmed",
        )


class VersionPhraseTest(unittest.TestCase):
    """Version phrasing is a text convention; pin every variant seen upstream."""

    def setUp(self) -> None:
        self.doc = fixture("csaf-version-phrases.json")

    def test_each_phrase_variant(self) -> None:
        cases = {
            "PriorToOnly": "4.2.1",
            "UpToAndIncludingOnly": None,  # Y itself is vulnerable.
            "OrNewer": "46.3008",
            "BareVersion": "28.4702",
            "DoubleSpaceRange": "4.5.3",
            # The affected range ends on the fixed release. The fixed entry
            # wins, whichever order the two entries appear in.
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
        # These appear in the ubuntuNoble block and must not crash a comparison.
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
            # A range phrase reports its first version. The role is what
            # matters: an affected phrase never contributes a minimum.
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
        """Regression: the branch name is the product, product.name is the version.

        Reading these two fields the intuitive way round yields nothing at all,
        which is the failure mode this test exists to catch.
        """
        kids = arch_kids(fixture("nvidia-driver-5821.json"), "Linux(R595)")
        labels = {kid["name"] for kid in kids}
        phrases = {kid["product"]["name"] for kid in kids}
        self.assertIn("Tesla", labels)
        self.assertIn("All driver versions prior to 595.71.05", phrases)
        self.assertEqual(fr.resolve_fixed(kids, product_filter="Tesla"), "595.71.05")
        # The swapped reading filters on a version phrase and finds no product.
        self.assertIsNone(fr.resolve_fixed(kids, product_filter="595.71.05"))


class BuildMinimumsTest(unittest.TestCase):
    def test_serialize_sorts_keys_so_a_rebuild_diffs_cleanly(self) -> None:
        """An unsorted rebuild rewrites the whole table as a spurious diff.

        The refresh workflow opens a pull request whenever the table changes,
        so unstable key order turns every run into a large fake change.
        """
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
    """The Docker minimum comes from the release notes Docker authors."""

    def setUp(self) -> None:
        self.stub = StubFetcher()

    def docker_page(self) -> str:
        return self.stub.text_by_url[fr.docker_release_notes_url(29)]

    def test_minimum_is_the_highest_release_with_a_security_subsection(self) -> None:
        # 29.7.1 and 29.7.2 sit above 29.7.0 on the fixture page and carry no
        # Security subsection, so the bug-fix releases do not move the minimum.
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
        # The 29.7.2 fixture section names CVE-2026-17106 in a bug-fix bullet.
        # The release carries no Security subsection, so it stays a bug-fix
        # release and the identifier does not mark it as a security release.
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
        # Docker names no CVE for the 29.6.1 fixes, only GHSA advisories.
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

    def test_a_security_release_without_identifiers_fails_closed(self) -> None:
        page = (
            '## 29.9.0\n\n{{< release-date date="2026-09-01" >}}\n\n'
            "### Security\n\n- Hardening only, identifiers withheld.\n"
        )
        self.stub.text_by_url[fr.docker_release_notes_url(29)] = page
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.docker_minimums(fetch=self.stub)
        self.assertIn("names no CVE or GHSA identifier", str(caught.exception))

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
        # The rebuilt page stops at 29.6.2, so the extractor computes a lower
        # minimum than the published 29.7.0 and the shared verify() rejects it.
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
        # The committed table keeps the first confirmation evidence, including
        # the release-note commit stamp, while the minimum does not move.
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
    """Build a minimal AMD bulletin page for one test case."""
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
    """The Instinct ROCm minimums come from the AMD security bulletins."""

    def setUp(self) -> None:
        self.stub = StubFetcher()

    def set_page(self, sb_id: str, text: str) -> None:
        self.stub.text_by_url[fr.amd_bulletin_page(sb_id)] = text

    def test_each_program_keeps_the_highest_release_across_bulletins(self) -> None:
        # amd-sb-6018 names ROCm 6.4 for every program, amd-sb-6024 moves the
        # fleet to 6.4.2, and amd-sb-6027 moves MI210, MI250, and MI300A to
        # 7.0.1 while it names only 6.3.1 for MI300X and MI325X. The merge
        # keeps the maximum per program, never the newest bulletin's value.
        block = fr.amd_rocm_minimums(fetch=self.stub)
        self.assertEqual(block["kind"], "programMap")
        self.assertEqual(
            block["programs"],
            {
                "MI210": "7.0.1",
                "MI250": "7.0.1",
                "MI300A": "7.0.1",
                "MI300X": "6.4.2",
                "MI308X": "6.4.2",
                "MI325X": "6.4.2",
            },
        )
        self.assertEqual(
            block["programSources"],
            {
                "MI210": "AMD-SB-6027",
                "MI250": "AMD-SB-6027",
                "MI300A": "AMD-SB-6027",
                "MI300X": "AMD-SB-6024",
                "MI308X": "AMD-SB-6027",
                "MI325X": "AMD-SB-6024",
            },
        )
        self.assertEqual(
            block["cves"],
            [
                "CVE-2025-21940",
                "CVE-2025-66660",
                "CVE-2025-66664",
                "CVE-2026-0428",
            ],
        )
        self.assertEqual(
            [source["aId"] for source in block["sources"]],
            ["AMD-SB-6018", "AMD-SB-6024", "AMD-SB-6027"],
        )
        self.assertEqual(block["source"]["aId"], "AMD-SB-6027")
        self.assertEqual(block["source"]["released"], "2026-05-12T00:00:00Z")
        self.assertEqual(
            block["advisory"],
            "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6027.html",
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
                "MI210": "2025-09-15T00:00:00Z",
                "MI250": "2025-09-15T00:00:00Z",
                "MI300A": "2025-10-06T00:00:00Z",
                "MI300X": "2025-07-21T00:00:00Z",
                "MI308X": "2025-06-09T00:00:00Z",
                "MI325X": "2025-07-21T00:00:00Z",
            },
        )
        mi210 = block["floorAvailability"]["MI210"]
        self.assertEqual(mi210["status"], "confirmed")
        self.assertEqual(mi210["version"], "7.0.1")
        self.assertEqual(mi210["feed"], "amd-security-bulletin")
        self.assertEqual(mi210["aId"], "AMD-SB-6027")
        self.assertEqual(
            mi210["url"],
            "https://www.amd.com/en/resources/product-security/bulletin/amd-sb-6027.html",
        )

    def test_wording_variants_parse_to_one_exact_release(self) -> None:
        # Every variant below is on a live bulletin today: the trademark glyph
        # inside the release, two programs in one cell, a CVE with an
        # annotation, a BKC wrapper around the release, and the ROC typo.
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
        # A footnote marker in a sup tag must not glue onto the preceding
        # token. Glued text would turn CVE-2025-11111 into CVE-2025-111112,
        # which still looks like a valid identifier.
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
        # "ROCm 6.4<sup>1</sup>" must not parse as release 6.41. The tag
        # separator turns the cell into "ROCm 6.4 1", which is not one exact
        # release, so the refresh stops instead of publishing a minimum that
        # never existed.
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
        # GIM releases, platform BKCs without a ROCm release inside, "No fix
        # planned", and referrals to Customer Engineering are mitigations that
        # are not ROCm releases. They are skipped, not errors.
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
        # Two bulletins name the same release for one program. The minimum keeps
        # the earliest date and the union of the CVE identifiers.
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
        # The three tracked bulletins write the mitigation header three ways.
        # Each committed fixture keeps its live wording, so a parse of each
        # single bulletin proves the header matcher covers all three.
        for sb_id in fr.AMD_BULLETINS:
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
        self.assertIn("found no dated mitigation table", str(caught.exception))

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
        # A ROCm release in any other table means the fix moved to a shape
        # this reader does not cover, so the refresh stops.
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
            "names no Instinct program": [
                ["AMD Radeon RX 7900", "CVE-2025-11111", "ROCm 6.4", "2025-01-02"]
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
        # A rebuild from amd-sb-6018 alone computes 6.4 for every program,
        # below the published minimums, and the shared verify() rejects it.
        existing = baseline()
        with mock.patch.object(fr, "AMD_BULLETINS", ("amd-sb-6018",)):
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
        with mock.patch.object(fr, "AMD_BULLETINS", ("amd-sb-6027",)):
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
    def test_reworded_bulletin_raises_and_names_the_component(self) -> None:
        stub = StubFetcher(toolkit="nvidia-container-toolkit-5850-reworded.json")
        with self.assertRaises(fr.MinimumRefreshError) as caught:
            fr.build_minimums(generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub)
        self.assertIn("nvidiaContainerToolkit", str(caught.exception))

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
        """A bulletin covering two products cannot deliver only one of them."""
        stub = StubFetcher()
        url = fr.bulletin_url(2026, 5857)
        doc = copy.deepcopy(stub.json_by_url[url])
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
        """A driver minimum only moves up. This is the point of the merge policy.

        Tracking only 5747 would take R580 from 580.159.03 down to 580.126.09
        and would drop R595 entirely, which would grade a vulnerable fleet as
        patched. The whole rebuild must fail instead.
        """
        stub = StubFetcher()
        with mock.patch.dict(
            fr.BULLETINS, {"nvidiaDriver": ({"year": 2026, "aId": 5747},)}
        ):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.build_minimums(
                    generated="2026-07-30T00:00:00Z", existing=baseline(), fetch=stub
                )
        message = str(caught.exception)
        self.assertIn("nvidiaDriver.580", message)
        self.assertIn("580.159.03", message)
        self.assertIn("580.126.09", message)
        self.assertIn("nvidiaDriver.595", message)

    def test_a_lowered_branch_minimum_writes_nothing(self) -> None:
        stub = StubFetcher()
        with tempfile.TemporaryDirectory() as tmp:
            target = write_baseline(tmp)
            before = target.read_text()
            err = io.StringIO()
            with mock.patch.dict(
                fr.BULLETINS, {"nvidiaDriver": ({"year": 2026, "aId": 5747},)}
            ):
                with mock.patch.object(fr, "_DEFAULT_FETCHER", stub), redirect_stderr(err):
                    code = fr.main(
                        ["--write", str(target), "--generated", "2026-07-30T00:00:00Z"]
                    )
            self.assertEqual(code, 2)
            self.assertEqual(target.read_text(), before)
            self.assertIn("nvidiaDriver.580", err.getvalue())

    def test_a_rung_that_vanishes_from_the_rebuild_fails_closed(self) -> None:
        """A published rung the rebuild no longer emits must stop the write.

        A silent drop is the dangerous direction, because the audit then grades
        that release line against no minimum at all rather than against a lower
        one. The lowered-minimum guard cannot see this case, since there is no
        new value to compare.
        """
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
        """The no-downgrade guard covers the runc ladder as well as branches."""
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
        """A rung may not fall back to a release candidate of the same release."""
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
        # Lexically "580.99.01" > "580.126.09"; numerically it is lower.
        existing = baseline()
        existing["components"]["nvidiaDriver"]["branches"]["580"] = "580.99.01"
        doc = fr.build_minimums(
            generated="2026-07-30T00:00:00Z", existing=existing, fetch=StubFetcher()
        )
        self.assertEqual(doc["components"]["nvidiaDriver"]["branches"]["580"], "580.159.03")

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
            self.assertIn("595.71.05", out)
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
        # The fixture listing carries 29.md and older pages only, and 29 is
        # tracked, so the scan reports no Docker item. The old-scheme names
        # such as 17.03.md never parse as a major.
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
        self.assertIn("DEFERRED_BULLETINS", err)

    def test_5744_is_deferred_and_is_not_reported_as_untracked(self) -> None:
        """Today's real case: SNAP4 matches a graded product line by title."""
        self.assertIn("5744", fr.DEFERRED_BULLETINS)
        found = self.scan()
        snap4 = next(item for item in found if item["id"] == 5744)
        self.assertEqual(snap4["status"], "deferred")
        self.assertIn("4.5.5 LTS train", snap4["reason"])
        self.assertNotIn(5744, [item["id"] for item in found if item["status"] == "new"])

    def test_a_deferred_only_result_exits_zero_and_still_names_the_bulletin(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"5871": "parser work pending"}):
            code, out, err = self.detect_cli()
        self.assertEqual(code, 0)
        self.assertIn("Deferred bulletins", out)
        self.assertIn("5744", out)
        self.assertIn("drops the 4.5.5 LTS train", out)
        self.assertIn("no unknown bulletins", out)
        self.assertEqual(err, "")

    def test_a_deferred_bulletin_does_not_mask_a_new_one(self) -> None:
        code, out, _ = self.detect_cli()
        self.assertEqual(code, 3)
        # Both groups are reported; only the new one drives the exit code.
        self.assertIn("5744", out)
        self.assertIn("5871", out)

    def test_a_deferred_bulletin_is_reported_even_when_the_scan_misses_it(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"4001": "retired product line"}):
            found = self.scan()
        missing = next(item for item in found if item["id"] == 4001)
        self.assertEqual(missing["status"], "deferred")
        self.assertIsNone(missing["title"])
        self.assertEqual(missing["reason"], "retired product line")

    def test_a_bulletin_that_is_tracked_and_deferred_raises(self) -> None:
        with mock.patch.dict(fr.DEFERRED_BULLETINS, {"5821": "cannot be both"}):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.validate_bulletin_lists()
            self.assertIn("5821", str(caught.exception))
            with self.assertRaises(fr.MinimumRefreshError):
                self.scan()

    def test_a_deferred_bulletin_without_a_reason_raises(self) -> None:
        for reason in ("", "   "):
            with self.subTest(reason=repr(reason)):
                with mock.patch.dict(fr.DEFERRED_BULLETINS, {"4002": reason}):
                    with self.assertRaises(fr.MinimumRefreshError) as caught:
                        fr.validate_bulletin_lists()
                    self.assertIn("4002", str(caught.exception))

    def test_tracked_and_deferred_amd_bulletins_are_not_reported_as_new(self) -> None:
        # The fixture index carries every tracked and every deferred GPU
        # bulletin, so a correct scan reports no new AMD item.
        found = self.scan()
        self.assertFalse(
            [
                item
                for item in found
                if item["status"] == "new" and item["product"] == "AMD Instinct GPU"
            ]
        )

    def test_an_untracked_amd_gpu_bulletin_is_reported_as_new(self) -> None:
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
        ].replace("</tbody>", row + "</tbody>")
        items = [
            item
            for item in self.scan(fetch=stub)
            if item["product"] == "AMD Instinct GPU"
        ]
        self.assertEqual([item["id"] for item in items], ["amd-sb-6099"])
        self.assertEqual(items[0]["status"], "new")
        self.assertEqual(
            items[0]["title"], "AMD Instinct GPU Vulnerabilities"
        )
        self.assertEqual(items[0]["url"], fr.amd_bulletin_page("amd-sb-6099"))

    def test_non_gpu_amd_bulletins_are_ignored(self) -> None:
        # The fixture index carries two non-GPU rows the scan must skip.
        ids = {item["id"] for item in self.scan()}
        self.assertNotIn("amd-sb-7064", ids)
        self.assertNotIn("amd-sb-8015", ids)

    def test_an_unreadable_amd_index_does_not_crash_the_scan(self) -> None:
        stub = StubFetcher()
        del stub.text_by_url[fr.AMD_SECURITY_INDEX]
        self.assertEqual(fr.untracked_amd_bulletins(fetch=stub), [])
        new = [item for item in self.scan(fetch=stub) if item["status"] == "new"]
        self.assertEqual([item["id"] for item in new], [5871])

    def test_amd_deferred_bulletins_are_reported_every_run(self) -> None:
        found = self.scan()
        item = next(entry for entry in found if entry["id"] == "amd-sb-6005")
        self.assertEqual(item["status"], "deferred")
        self.assertIn("6.3.2, below the tracked minimums", item["reason"])

    def test_cli_exit_three_tells_the_operator_where_to_track_an_amd_bulletin(
        self,
    ) -> None:
        stub = StubFetcher()
        row = (
            "<tr><td>AMD-SB-6099</td>"
            "<td>AMD Instinct GPU Vulnerabilities</td>"
            "<td>Security Bulletin</td><td>CVE-2026-11111</td>"
            "<td>Jun 01, 2026</td><td>Jun 01, 2026</td></tr>"
        )
        stub.text_by_url[fr.AMD_SECURITY_INDEX] = stub.text_by_url[
            fr.AMD_SECURITY_INDEX
        ].replace("</tbody>", row + "</tbody>")
        code, out, err = self.detect_cli(stub)
        self.assertEqual(code, 3)
        self.assertIn("amd-sb-6099", out)
        self.assertIn("AMD_BULLETINS", err)

    def test_an_amd_bulletin_that_is_tracked_and_deferred_raises(self) -> None:
        with mock.patch.dict(
            fr.AMD_DEFERRED_BULLETINS, {"amd-sb-6027": "cannot be both"}
        ):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.validate_bulletin_lists()
            self.assertIn("amd-sb-6027", str(caught.exception))

    def test_an_amd_deferred_bulletin_without_a_reason_raises(self) -> None:
        with mock.patch.dict(fr.AMD_DEFERRED_BULLETINS, {"amd-sb-9999": "   "}):
            with self.assertRaises(fr.MinimumRefreshError) as caught:
                fr.validate_bulletin_lists()
            self.assertIn("amd-sb-9999", str(caught.exception))

    def test_the_committed_lists_are_consistent(self) -> None:
        fr.validate_bulletin_lists()


class PullRequestBodyTest(unittest.TestCase):
    """The pull request body, generated by running the workflow's own script.

    The body is the artifact a human reads before approving a minimum change, so
    what it asserts has to be what the run proved. The generator is a Python
    heredoc inside the workflow, so these tests extract that exact script and
    execute it against controlled inputs rather than pinning its source.

    The failed-scan case exists because decoupling the scan from the pull
    request steps created it: before `continue-on-error`, a failed scan skipped
    this step entirely, so the body could not describe a scan that never ran.
    """

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
        """Run the real script and return the body it wrote."""
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
        """The scan raises before it prints anything, so only its error text is left.

        `found=` is written on the exit 0 and exit 3 paths only, so the step's
        output is unset. That combination used to fall through to the no-new-
        bulletin text.
        """
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
        """The fix must not turn every run into a failed-scan claim."""
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
    """The scheduled job's step gating, read from the workflow itself.

    The minimum table and the bulletin scan are two different jobs of work sharing
    one workflow. Refreshing the table is the safety-critical one: a stale table
    grades a vulnerable version as a pass, which is the whole reason this feature
    exists. Scanning upstream for bulletins the table does not track is
    informational.

    Every step carries an implicit `success()`, so a failing step skips every
    later step whose `if` does not opt out. That silently coupled the two: an
    `exit 1` in the scan skipped the pull request steps, stranding a refreshed
    table on the runner with master left on the old minimums and nothing red to
    say the table had moved. These tests pin the decoupling in both directions,
    because either half alone is a defect: without `continue-on-error` the scan
    blocks the table, and without the terminal gate a failing scan disappears.
    """

    @classmethod
    def setUpClass(cls) -> None:
        yaml = __import__("importlib").import_module("yaml")
        path = (
            Path(__file__).resolve().parents[2]
            / ".github/workflows/minimum-versions-refresh.yml"
        )
        # `on:` parses as the boolean True in YAML 1.1, which is irrelevant here
        # and left alone; only `jobs` is read.
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
        """The scan runs before the pull request steps, so it must not gate them."""
        scan = self.step("Detect new upstream bulletins")
        self.assertIs(
            scan.get("continue-on-error"),
            True,
            "the bulletin scan runs before the pull request steps and exits 1 on "
            "a transient upstream failure, so without continue-on-error its "
            "implicit success() skips them and the refreshed minimums never land",
        )
        for fragment in ("Write the pull request", "Open or update the pull request"):
            self.assertGreater(self.index(fragment), self.index("Detect new upstream"))

    def test_the_pull_request_steps_gate_only_on_a_changed_table(self) -> None:
        """Their `if` may name the compare step and nothing else.

        Naming any other step here would re-couple what continue-on-error just
        decoupled, so the condition is pinned rather than merely the ordering.
        """
        for fragment in ("Write the pull request", "Open or update the pull request"):
            with self.subTest(step=fragment):
                condition = str(self.step(fragment)["if"])
                self.assertEqual(condition, "steps.compare.outputs.changed == 'true'")

    def test_a_failed_bulletin_scan_still_turns_the_run_red(self) -> None:
        """continue-on-error must not also swallow the failure.

        `outcome` and not `conclusion`: continue-on-error rewrites the
        conclusion to success and leaves the real result in the outcome, so a
        gate reading the conclusion would never fire.
        """
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
        """The decoupling is narrow: only the scan was informational.

        A table that no longer grades correctly must never reach a pull request,
        so the steps that prove it does keep their implicit success() and must
        not acquire an opt-out of their own.
        """
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


if __name__ == "__main__":
    unittest.main()
