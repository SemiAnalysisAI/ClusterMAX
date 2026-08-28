#!/usr/bin/env python3
"""Unit tests for audit merge normalization."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


MERGE_PATH = (
    Path(__file__).resolve().parents[2] / "cmax" / "scripts" / "1-audit" / "merge_audit.py"
)


def load_merge_module():
    spec = importlib.util.spec_from_file_location("merge_audit_under_test", MERGE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


merge_audit = load_merge_module()


class MergeAuditTests(unittest.TestCase):
    def test_records_the_confirmed_target_environment(self) -> None:
        values = merge_audit.build_values(
            {}, harness="standalone", check_data={}, environment="vm"
        )

        self.assertEqual(values["cluster"]["environment"], "vm")

    def test_k8s_promotes_host_check_and_location_fields(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "location": {
                "region": "Virginia",
                "country": "US",
                "city": "Sandston",
            },
            "nodes": {
                "total": 4,
                "sampleCpu": "224",
                "sampleMemory": "3699199612Ki",
            },
            "gpus": {
                "total": 32,
                "model": "NVIDIA B300",
                "perNode": 8,
                "driverVersion": "unknown",
                "cudaVersion": "unknown",
                "memoryMB": "unknown",
            },
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {
                "WORKER_DRIVER_VERSION": "590.48.01",
                "WORKER_CUDA_VERSION": "13.1",
                "WORKER_NCCL_VERSION": "2.29.3",
                "WORKER_GPU_MEMORY": "275040",
                "WORKER_PEERMEM": "true",
            },
        }

        values = merge_audit.build_values(audit, harness="k8s", check_data={})
        cluster = values["cluster"]

        self.assertEqual(cluster["driver_version"], "590.48.01")
        self.assertEqual(cluster["cuda_version"], "13.1")
        self.assertEqual(cluster["nccl_version"], "2.29.3")
        self.assertEqual(cluster["gpu_memory_mb"], 275040)
        self.assertTrue(cluster["gpu_direct_rdma"])
        self.assertEqual(cluster["region"], "Virginia")
        self.assertEqual(cluster["total_cpus"], 896)
        self.assertEqual(cluster["total_memory_gb"], 14111)
        self.assertNotIn("slurm_version", cluster)

    def test_slurm_keeps_server_location_and_slurm_version(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-03T23:33:02Z"},
            "serverLocation": {"region": "Virginia", "country": "US"},
            "slurm": {"version": "25.11.5"},
            "nodes": {"total": 4, "totalCpus": 896, "totalMemoryGB": 14111},
            "gpus": {
                "total": 32,
                "model": "NVIDIA-B300-SXM6-AC",
                "perNode": 8,
                "memoryMB": "275040",
                "driverVersion": "590.48.01",
                "cudaVersion": "13.1",
                "gpuDirectRdma": True,
            },
            "software": {"ncclVersion": "2.29.3"},
        }

        values = merge_audit.build_values(audit, harness="slurm", check_data={})
        cluster = values["cluster"]

        self.assertEqual(cluster["region"], "Virginia")
        self.assertEqual(cluster["slurm_version"], "25.11.5")
        self.assertTrue(cluster["gpu_direct_rdma"])

    def test_slurm_promotes_gpu_nodes_from_mixed_cluster_inventory(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-10T19:49:57Z"},
            "serverLocation": {"region": "Texas", "country": "US"},
            "slurm": {"version": "25.05.3"},
            "nodes": {"total": 31, "totalCpus": 4032, "totalMemoryGB": 41259},
            "gpus": {
                "total": 40,
                "nodeCount": 5,
                "perNode": 8,
                "totalCpus": 960,
                "totalMemoryGB": 20160,
                "model": "NVIDIA-B300-SXM6-PC",
            },
            "software": {"ncclVersion": "2.29.2"},
        }

        values = merge_audit.build_values(audit, harness="slurm", check_data={})
        cluster = values["cluster"]

        self.assertEqual(cluster["nodes"], 5)
        self.assertEqual(cluster["gpus_per_node"], 8)
        self.assertEqual(cluster["total_cpus"], 960)
        self.assertEqual(cluster["total_memory_gb"], 20160)
        self.assertEqual(values["audit_data"]["nodes"]["total"], 31)

    def test_slurm_module_status_requires_an_installed_gpu_or_fabric_module(self) -> None:
        base = {
            "audit": {"timestamp": "2026-08-27T12:00:00Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {
                "ncclVersion": "2.28.3",
                "lmod": {"installed": True},
            },
        }
        available = copy.deepcopy(base)
        available["lmod"] = {
            "hasCudaModule": True,
            "hasHpcxModule": False,
            "hasNcclModule": False,
        }
        absent = copy.deepcopy(base)
        absent["lmod"] = {
            "hasCudaModule": False,
            "hasHpcxModule": False,
            "hasNcclModule": False,
        }

        available_data = merge_audit.build_values(
            available, harness="slurm", check_data={}
        )["audit_data"]
        absent_data = merge_audit.build_values(
            absent, harness="slurm", check_data={}
        )["audit_data"]

        self.assertEqual(available_data["software"]["lmod"]["modulesStatus"], "pass")
        self.assertEqual(absent_data["software"]["lmod"]["modulesStatus"], "fail")

    def test_slurm_cuda_assignment_distinguishes_missing_and_unassigned_evidence(self) -> None:
        def status(cuda: str, nvidia: str) -> str:
            audit = {
                "audit": {"timestamp": "2026-08-27T12:00:00Z"},
                "nodes": {"total": 1},
                "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
                "software": {
                    "ncclVersion": "2.28.3",
                    "cudaVisibleDevices": cuda,
                    "nvidiaVisibleDevices": nvidia,
                },
            }
            data = merge_audit.build_values(
                audit, harness="slurm", check_data={}
            )["audit_data"]
            return data["software"]["cudaVisibleDevicesStatus"]

        self.assertEqual(status("GPU-0", "GPU-0"), "pass")
        self.assertEqual(status("unset", "unset"), "fail")
        self.assertEqual(status("unknown", "unknown"), "unknown")

    def test_gpu_node_count_is_used_for_per_node_fallback(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-10T19:49:57Z"},
            "nodes": {"total": 31},
            "gpus": {"total": 40, "nodeCount": 5, "model": "NVIDIA B300"},
            "software": {"ncclVersion": "unknown"},
        }

        cluster = merge_audit.build_values(audit, harness="slurm", check_data={})["cluster"]

        self.assertEqual(cluster["nodes"], 5)
        self.assertEqual(cluster["gpus_per_node"], 8)

    def test_k8s_primary_gpu_profile_drives_promoted_cluster(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-07-17T06:34:38Z"},
            "location": {
                "region": "Maharashtra",
                "cloudRegion": "ap-south-1",
                "coordinates": "19.0728,72.8826",
            },
            "nodes": {"total": 9},
            "gpus": {
                "total": 34,
                "nodeCount": 6,
                "model": "NVIDIA-A10G",
                "perNode": 1,
                "memoryMB": "23028",
                "totalCpus": 800,
                "totalMemoryGB": 8106,
                "primaryProfile": {
                    "model": "NVIDIA-B200",
                    "perNode": 8,
                    "nodeCount": 4,
                    "totalGpus": 32,
                    "totalCpus": 768,
                    "totalMemoryGB": 7984,
                    "memoryMB": "183359",
                },
            },
            "software": {"ncclVersion": "unknown"},
        }

        values = merge_audit.build_values(audit, harness="k8s", check_data={})
        cluster = values["cluster"]

        self.assertEqual(cluster["gpu_model"], "B200")
        self.assertEqual(cluster["nodes"], 4)
        self.assertEqual(cluster["gpus_per_node"], 8)
        self.assertEqual(cluster["gpu_memory_mb"], 183359)
        self.assertEqual(cluster["total_cpus"], 768)
        self.assertEqual(cluster["total_memory_gb"], 7984)
        self.assertEqual(cluster["region"], "ap-south-1")
        self.assertEqual(values["audit_data"]["gpus"]["model"], "NVIDIA-A10G")
        self.assertEqual(values["audit_data"]["location"]["region"], "Maharashtra")

    def test_coordinates_parsed_from_server_location(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-09T02:53:44Z"},
            "serverLocation": {
                "region": "Utah",
                "country": "US",
                "coordinates": "40.6097,-111.9391",
            },
            "nodes": {"total": 1},
            "gpus": {"total": 4, "model": "NVIDIA GB300", "perNode": 4},
            "software": {"ncclVersion": "unknown"},
        }

        cluster = merge_audit.build_values(audit, harness="slurm", check_data={})["cluster"]

        self.assertAlmostEqual(cluster["latitude"], 40.6097)
        self.assertAlmostEqual(cluster["longitude"], -111.9391)

    def test_coordinates_absent_or_malformed_are_omitted(self) -> None:
        for server_location in ({}, {"coordinates": ""}, {"coordinates": "not,a,number"}):
            audit = {
                "audit": {"timestamp": "2026-06-09T02:53:44Z"},
                "serverLocation": server_location,
                "nodes": {"total": 1},
                "gpus": {"total": 4, "model": "NVIDIA GB300", "perNode": 4},
                "software": {"ncclVersion": "unknown"},
            }
            cluster = merge_audit.build_values(audit, harness="slurm", check_data={})["cluster"]
            self.assertNotIn("latitude", cluster)
            self.assertNotIn("longitude", cluster)


class K8sCanonicalRemapTests(unittest.TestCase):
    def _build(self, audit: dict) -> dict:
        return merge_audit.build_values(audit, harness="k8s", check_data={})["audit_data"]

    def test_remaps_host_check_facts_onto_canonical_paths(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {
                "WORKER_NVIDIA_DMABUF": "true",
                "WORKER_NVIDIA_OPEN": "true",
                "WORKER_PEERMEM_LEGACY": "false",
                "WORKER_GDRCOPY_LIB": "/usr/lib/x86_64-linux-gnu/libgdrapi.so.2",
                "WORKER_GDRCOPY_GDRDRV": "true",
                "WORKER_GPU_IDLE_TEMP_MAX": "32",
                "WORKER_GPU_IDLE_POWER_MAX": "75",
                "WORKER_DMESG_XIDS_COUNT": "0",
                "WORKER_DMESG_XID_LAST": "none",
                "WORKER_IPMITOOL_PATH": "/usr/bin/ipmitool",
                "WORKER_IPMI_USER_ACCESS": "allowed",
                "WORKER_IPMI_SUDO_ACCESS": "blocked",
            },
        }
        data = self._build(audit)

        self.assertEqual(data["gpus"]["gpuDirectRdmaPath"]["dmaBuf"], True)
        self.assertEqual(data["gpus"]["gpuDirectRdmaPath"]["nvidiaOpen"], True)
        self.assertEqual(data["gpus"]["gpuDirectRdmaPath"]["nvidiaPeermemLegacy"], False)

        self.assertEqual(data["gpus"]["gdrcopy"]["installed"], True)
        self.assertEqual(
            data["gpus"]["gdrcopy"]["libraryPath"],
            "/usr/lib/x86_64-linux-gnu/libgdrapi.so.2",
        )
        self.assertEqual(data["gpus"]["gdrcopy"]["gdrdrvLoaded"], True)

        self.assertEqual(data["gpus"]["thermals"]["idleTempMax"], "32")
        self.assertEqual(data["gpus"]["thermals"]["idlePowerMax"], "75")

        self.assertEqual(data["gpus"]["dmesgErrors"]["xidsCount"], "0")
        self.assertEqual(data["gpus"]["dmesgErrors"]["lastXid"], "none")

        self.assertEqual(data["security"]["bmcIpmi"]["ipmitoolInstalled"], True)
        self.assertEqual(data["security"]["bmcIpmi"]["userAccess"], "allowed")
        self.assertEqual(data["security"]["bmcIpmi"]["sudoAccess"], "blocked")
        self.assertEqual(data["security"]["bmcIpmi"]["exposed"], True)

    def test_binary_local_criteria_evidence_is_normalized(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-08-27T12:00:00Z"},
            "nodes": {"total": 2},
            "gpus": {"total": 16, "model": "NVIDIA H100", "perNode": 8},
            "software": {
                "ncclVersion": "2.28.3",
                "ncu": {"profilingEnabled": True},
            },
            "storage": {"rwxCapable": True, "storageReady": True},
            "hostCheck": {
                "WORKER_CUDA_VISIBLE_DEVICES": "GPU-0,GPU-1",
            },
        }

        data = self._build(audit)

        self.assertEqual(data["software"]["cudaVisibleDevicesStatus"], "pass")
        self.assertEqual(data["storage"]["rwxStatus"], "pass")

    def test_missing_worker_evidence_stays_unknown(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-08-27T12:00:00Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "networking": {"rdmaType": "unknown"},
            "hostCheck": {},
        }

        data = self._build(audit)

        self.assertEqual(data["software"]["cudaVisibleDevicesStatus"], "unknown")
        self.assertEqual(data["storage"]["rwxStatus"], "unknown")
        for key in (
            "rdmaSupportStatus",
            "ibTenantPkeysStatus",
            "ncclIbGidIndexStatus",
        ):
            self.assertNotIn(key, data["networking"])
        self.assertNotIn("sharpAmKeyStatus", data.get("security", {}))

    def test_gdrcopy_not_found_records_absent(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {"WORKER_GDRCOPY_LIB": "not-found", "WORKER_GDRCOPY_GDRDRV": "false"},
        }
        data = self._build(audit)
        self.assertEqual(data["gpus"]["gdrcopy"]["installed"], False)
        self.assertNotIn("libraryPath", data["gpus"]["gdrcopy"])

    def test_amd_only_dmesg_count_lands_without_nvidia_xid_keys(self) -> None:
        # Bugbot #729: AMD-only hosts emit WORKER_DMESG_AMDGPU_ERRORS_COUNT with no
        # NVIDIA Xid keys; amdgpuErrorsCount must still reach gpus.dmesgErrors.
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "AMD MI300X", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {"WORKER_DMESG_AMDGPU_ERRORS_COUNT": "3"},
        }
        data = self._build(audit)
        self.assertEqual(data["gpus"]["dmesgErrors"]["amdgpuErrorsCount"], "3")

    def test_monitoring_block_bridges_into_health_checks(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "monitoring": {
                "prometheus": {"installed": True},
                "grafana": {"installed": False},
                "dcgm": {"installed": True},
                "components": {"nodeExporter": True, "nodeProblemDetector": True},
            },
        }
        stack = self._build(audit)["healthChecks"]["monitoringStack"]
        self.assertEqual(stack["prometheus"], True)
        self.assertEqual(stack["grafana"], False)
        self.assertEqual(stack["dcgmExporter"], True)
        self.assertEqual(stack["nodeExporter"], True)
        self.assertEqual(stack["nodeProblemDetector"], True)

    def test_rdma_fabric_refined_to_roce_from_ethernet_topology(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-24T17:35:30Z"},
            "nodes": {"total": 4},
            "gpus": {"total": 32, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "networking": {"rdmaType": "rdma"},
            "security": {"ufmSecuredBareMetalCloud": {"status": "unknown", "applicable": None}},
        }
        nt = {"node-01": [{"layer": "Ethernet", "name": "mlx5_0", "role": "fabric"}]}
        out = merge_audit.build_values(audit, harness="k8s", check_data={"nic_topology": nt})["audit_data"]
        self.assertEqual(out["networking"]["rdmaType"], "roce")
        self.assertEqual(out["security"]["ufmSecuredBareMetalCloud"]["status"], "not_applicable")
        self.assertEqual(out["security"]["ufmSecuredBareMetalCloud"]["applicable"], False)

    def test_rdma_fabric_refined_to_ib_from_infiniband_topology(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-24T17:35:30Z"},
            "nodes": {"total": 4},
            "gpus": {"total": 32, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "networking": {"rdmaType": "rdma"},
            "security": {"ufmSecuredBareMetalCloud": {"status": "unknown"}},
        }
        nt = {"node-01": [{"layer": "InfiniBand", "name": "mlx5_0", "role": "fabric"}]}
        out = merge_audit.build_values(audit, harness="k8s", check_data={"nic_topology": nt})["audit_data"]
        self.assertEqual(out["networking"]["rdmaType"], "infiniband")
        self.assertEqual(out["security"]["ufmSecuredBareMetalCloud"]["status"], "manual")

    def test_amd_device_metrics_exporter_bridges_as_gpu_metrics(self) -> None:
        # AMD cluster: no NVIDIA DCGM, but device-metrics-exporter present.
        audit = {
            "audit": {"timestamp": "2026-06-20T07:59:09Z"},
            "nodes": {"total": 4},
            "gpus": {"total": 32, "model": "AMD Instinct MI355X", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "monitoring": {
                "prometheus": {"installed": True},
                "grafana": {"installed": True},
                "dcgm": {"installed": False},
                "gpuMetricsExporter": {
                    "installed": True,
                    "vendor": "amd",
                    "amdDeviceMetricsExporter": True,
                },
                "components": {
                    "nodeExporter": True,
                    "nodeProblemDetector": True,
                    "amdDeviceMetricsExporter": True,
                },
            },
        }
        stack = self._build(audit)["healthChecks"]["monitoringStack"]
        self.assertEqual(stack["dcgmExporter"], False)
        self.assertEqual(stack["gpuMetricsExporter"], True)
        self.assertEqual(stack["gpuMetricsVendor"], "amd")
        self.assertEqual(stack["amdDeviceMetricsExporter"], True)
        self.assertEqual(stack["nodeExporter"], True)

    def test_gpu_metrics_job_attribution_bridges(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-23T21:31:31Z"},
            "nodes": {"total": 4},
            "gpus": {"total": 32, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "monitoring": {
                "prometheus": {"installed": True},
                "gpuMetricsExporter": {
                    "installed": True,
                    "vendor": "nvidia",
                    "jobAttribution": True,
                    "jobAttributionMethod": "dcgm-kubernetes",
                },
            },
        }
        stack = self._build(audit)["healthChecks"]["monitoringStack"]
        self.assertEqual(stack["gpuMetricsJobAttribution"], True)
        self.assertEqual(stack["gpuMetricsJobAttributionMethod"], "dcgm-kubernetes")

    def test_remap_is_additive_and_does_not_overwrite_existing(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {
                "total": 8,
                "model": "NVIDIA H100",
                "perNode": 8,
                # Richer pre-existing value must win over the check-derived one.
                "gpuDirectRdmaPath": {"dmaBuf": True},
            },
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {"WORKER_NVIDIA_DMABUF": "false"},
        }
        data = self._build(audit)
        self.assertEqual(data["gpus"]["gpuDirectRdmaPath"]["dmaBuf"], True)

    def test_slurm_harness_is_not_remapped(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-02T06:17:42Z"},
            "nodes": {"total": 1},
            "gpus": {"total": 8, "model": "NVIDIA H100", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
            "hostCheck": {"WORKER_NVIDIA_DMABUF": "true"},
        }
        data = merge_audit.build_values(audit, harness="slurm", check_data={})["audit_data"]
        # On slurm the dedicated collector owns these paths; the k8s remap must
        # not run, so no gpuDirectRdmaPath is synthesized from the check here.
        self.assertNotIn("gpuDirectRdmaPath", data["gpus"])


class NormalizeChipNameTests(unittest.TestCase):
    def test_strips_vendor_prefix_and_memory_packaging_suffixes(self) -> None:
        cases = {
            # observed in the wild today
            "NVIDIA-H100-80GB-HBM3": "H100",
            "NVIDIA H100 80GB HBM3": "H100",
            "NVIDIA-B300-SXM6-AC": "B300",
            "NVIDIA B300 SXM6 AC": "B300",
            "NVIDIA-GB300": "GB300",
            "NVIDIA-H200": "H200",
            "NVIDIA B300": "B300",
            # the clean target names should pass through unchanged
            "B300": "B300",
            "B200": "B200",
            "GB300": "GB300",
            "GB200": "GB200",
            "H100": "H100",
            # AMD: keep the variant letter attached to the model number
            "AMD-Instinct-MI300X": "MI300X",
            "AMD Instinct MI325X": "MI325X",
            "MI300X": "MI300X",
            # extra packaging tokens
            "NVIDIA-H100-PCIE-80GB": "H100",
            "NVIDIA-GH200-480GB": "GH200",
            # multi-token products keep their model number; two-letter
            # packaging codes are dropped instead of being glued to the family.
            "Intel-Gaudi-3": "Gaudi-3",
            "Intel Gaudi 3": "Gaudi-3",
            "NVIDIA RTX PRO 6000": "RTX 6000 Pro",
            "NVIDIA-RTX-PRO-6000-Blackwell-Server-Edition": "RTX 6000 Pro",
            "PRO-6000-Blackwell-Server-Edition": "RTX 6000 Pro",
            "NVIDIA-B300-SXM6-PC": "B300",
            "NVIDIA B300 SXM6 PC": "B300",
            # underscore-separated vendor prefixes are stripped.
            "NVIDIA_H100": "H100",
            "NVIDIA_B300_SXM6_AC": "B300",
        }
        for raw, expected in cases.items():
            self.assertEqual(merge_audit.normalize_chip_name(raw), expected, raw)

    def test_handles_missing_and_unknown(self) -> None:
        self.assertEqual(merge_audit.normalize_chip_name(None), "unknown")
        self.assertEqual(merge_audit.normalize_chip_name(""), "unknown")
        self.assertEqual(merge_audit.normalize_chip_name("   "), "unknown")
        self.assertEqual(merge_audit.normalize_chip_name("unknown"), "unknown")

    def test_build_values_records_clean_name_but_preserves_raw(self) -> None:
        audit = {
            "audit": {"timestamp": "2026-06-09T02:53:44Z"},
            "nodes": {"total": 2},
            "gpus": {"total": 16, "model": "NVIDIA-H100-80GB-HBM3", "perNode": 8},
            "software": {"ncclVersion": "unknown"},
        }
        values = merge_audit.build_values(audit, harness="slurm", check_data={})
        # cluster.gpu_model is the bare chip name we record + show
        self.assertEqual(values["cluster"]["gpu_model"], "H100")
        # raw string is preserved for traceability + grader branching
        self.assertEqual(values["audit_data"]["gpus"]["model"], "NVIDIA-H100-80GB-HBM3")


if __name__ == "__main__":
    unittest.main()
