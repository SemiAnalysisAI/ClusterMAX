from __future__ import annotations

import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from cmax import minimum_links, report_style, runtime_paths
from cmax.yaml_support import load_yaml_module


PASS = "pass"
WARNING = "warning"
CRITICAL = "critical"
# A criterion that cannot apply to this machine, such as a BlueField check on a
# host with no BlueField. Reporting it as a pass would credit a provider for
# hardware it does not have and inflate the passed count on every cluster
# without the device. It is neither an issue nor a pass, so it is counted and
# printed on its own.
NOT_APPLICABLE = "not_applicable"
REPO_ENV = "CLUSTERMAX_REPO_ROOT"

# The generated CVE minimum table and its reader ship with the audit workload.
MINIMUMS_READER_RELATIVE = str(runtime_paths.MINIMUMS_READER_RELATIVE)
MINIMUMS_TABLE_RELATIVE = str(runtime_paths.MINIMUMS_TABLE_RELATIVE)
# The reader and the collector scripts read the minimum table from this variable
# when it holds a path. `sync_minimum_table` sets it for the current process, so
# the CLI and the collector subprocess grade against the same fetched table.
MINIMUMS_ENV = "CLUSTERMAX_MINIMUM_VERSIONS"


class SecurityAuditError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecurityTarget:
    harness: str
    environment: str
    explicit: bool = False


@dataclass(frozen=True)
class SecurityReference:
    label: str
    url: str


@dataclass(frozen=True)
class SecurityCheck:
    id: str
    title: str
    status: str
    observed: str
    importance: str
    assessment: str
    remediation: str
    documentation: str
    references: tuple[SecurityReference, ...]
    grace_period: bool = False
    grace_note: str = ""


@dataclass(frozen=True)
class CheckSpec:
    id: str
    title: str
    importance: str
    remediation: str
    references: tuple[SecurityReference, ...]
    evaluate: Callable[[dict[str, Any]], tuple[str, str, str]]


def _references(*items: tuple[str, str]) -> tuple[SecurityReference, ...]:
    return tuple(SecurityReference(label, url) for label, url in items)


def _command_ok(command: list[str], *, timeout: float = 5.0) -> bool:
    try:
        return (
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
            ).returncode
            == 0
        )
    except (OSError, subprocess.TimeoutExpired):
        return False


def _inside_container() -> bool:
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    for path in (Path("/proc/1/cgroup"), Path("/proc/self/cgroup")):
        try:
            value = path.read_text(errors="replace").lower()
        except OSError:
            continue
        if any(
            token in value
            for token in ("docker", "containerd", "kubepods", "libpod", "lxc")
        ):
            return True
    return bool(os.environ.get("container"))


def _systemd_vm_status() -> bool | None:
    command = shutil.which("systemd-detect-virt")
    if not command:
        return None
    try:
        returncode = subprocess.run(
            [command, "--quiet", "--vm"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5.0,
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None
    if returncode == 0:
        return True
    if returncode == 1:
        return False
    return None


def _inside_vm() -> bool:
    systemd_status = _systemd_vm_status()
    if systemd_status is not None:
        return systemd_status
    dmi_paths = (
        Path("/sys/class/dmi/id/product_name"),
        Path("/sys/class/dmi/id/sys_vendor"),
        Path("/sys/class/dmi/id/board_vendor"),
    )
    markers = (
        "kvm",
        "qemu",
        "vmware",
        "virtualbox",
        "xen",
        "amazon ec2",
        "google compute engine",
        "microsoft corporation",
    )
    for path in dmi_paths:
        try:
            if any(
                marker in path.read_text(errors="replace").lower() for marker in markers
            ):
                return True
        except OSError:
            continue
    return False


def _local_target(*, explicit: bool) -> SecurityTarget:
    if _inside_container():
        return SecurityTarget("standalone", "container", explicit)
    if _inside_vm():
        return SecurityTarget("standalone", "vm", explicit)
    if platform.system() == "Darwin":
        return SecurityTarget("standalone", "local", explicit)
    return SecurityTarget("standalone", "bare-metal", explicit)


def detect_target(explicit: str | None = None) -> SecurityTarget:
    if explicit:
        if explicit in {"slurm", "k8s"}:
            return SecurityTarget(explicit, explicit, True)
        if explicit == "local":
            return _local_target(explicit=True)
        if explicit in {"vm", "container", "standalone"}:
            environment = "bare-metal" if explicit == "standalone" else explicit
            return SecurityTarget("standalone", environment, True)
        raise SecurityAuditError(f"unsupported security audit target: {explicit}")

    override = os.environ.get("CLUSTERMAX_HARNESS")
    standalone_override = False
    if override:
        override = override.strip().lower()
        if override not in {"slurm", "k8s", "standalone"}:
            raise SecurityAuditError(f"invalid harness override '{override}'")
        if override != "standalone":
            return SecurityTarget(override, override, True)
        standalone_override = True

    if not standalone_override:
        if os.environ.get("SLURM_JOB_ID"):
            return SecurityTarget("slurm", "slurm")
        if os.environ.get("KUBERNETES_SERVICE_HOST"):
            return SecurityTarget("k8s", "k8s")
        if shutil.which("sbatch"):
            return SecurityTarget("slurm", "slurm")
        if shutil.which("kubectl") and _command_ok(["kubectl", "cluster-info"]):
            return SecurityTarget("k8s", "k8s")
    return _local_target(explicit=standalone_override)


def _runtime_is_valid(root: Path) -> bool:
    return runtime_paths.audit_runner(root).is_file()


def _runtime_at(candidate: Path) -> Path | None:
    for root in (candidate, candidate / "cmax"):
        resolved = root.resolve()
        if _runtime_is_valid(resolved):
            return resolved
    return None


def find_runtime_root(explicit: str | None = None) -> Path:
    configured = explicit or os.environ.get(REPO_ENV)
    if configured:
        configured_root = Path(configured).expanduser().resolve()
        root = _runtime_at(configured_root)
        if root is not None:
            return root
        source = "--repo" if explicit else REPO_ENV
        raise SecurityAuditError(
            f"{source} does not contain the security audit runtime: {configured_root}"
        )

    candidates: list[Path] = []
    cwd = Path.cwd().resolve()
    candidates.extend((cwd, *cwd.parents))
    try:
        candidates.append(runtime_paths.package_runtime_root())
    except RuntimeError:
        pass

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        root = _runtime_at(resolved)
        if root is not None:
            return root
    raise SecurityAuditError(
        "security audit runtime not found. Reinstall clustermax or run from a ClusterMAX checkout."
    )


def build_security_plan(runtime_root: Path, target: SecurityTarget) -> dict[str, Any]:
    from cmax import audit_report

    yaml = load_yaml_module(runtime_root)
    config_path = runtime_root / "cmax.yaml"
    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except OSError as exc:
        raise SecurityAuditError(
            f"security audit configuration not found: {config_path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise SecurityAuditError(
            f"invalid security audit configuration: {config_path}: {exc}"
        ) from exc

    phases = config.get("phase")
    if config.get("version") != 4 or not isinstance(phases, dict):
        raise SecurityAuditError(
            f"security audit configuration is not a version 4 cmax.yaml: {config_path}"
        )
    disabled_by_phase: dict[str, int] = {}
    for phase_name, tests in phases.items():
        if not isinstance(tests, dict):
            raise SecurityAuditError(
                f"security audit configuration has an invalid {phase_name} phase"
            )
        enabled_count = int(phase_name == "audit" and "audit" in tests)
        disabled_by_phase[phase_name] = len(tests) - enabled_count
    checks = audit_report.list_check_specs(
        runtime_root,
        category="security",
        harness=target.harness,
    )

    return {
        "version": 4,
        "manifest_selection": {
            "enabled": ["audit.audit"],
            "disabled_count": sum(disabled_by_phase.values()),
            "disabled_by_phase": disabled_by_phase,
        },
        "audit_profile": {
            "name": "security",
            "dry_run": True,
            "command": "cmax audit security",
            "target": {
                "selection": "explicit" if target.explicit else "auto-detected",
                "environment": target.environment,
                "harness": target.harness,
            },
            "scope": {
                "core_collector": True,
                "checks": {
                    "fabric": True,
                    "gpu": False,
                    "system": False,
                },
                "general_findings_report": False,
                "standard_report": True,
            },
            "artifacts": ["audit.out", "audit.values.json"],
            "checks": [check.key for check in checks],
        },
    }


def format_security_plan_yaml(
    target: SecurityTarget, *, repo: str | None = None
) -> str:
    runtime_root = find_runtime_root(repo)
    yaml = load_yaml_module(runtime_root)
    plan = build_security_plan(runtime_root, target)
    header = (
        "# Resolved dry-run plan for cmax audit security.\n"
        "# Only the core audit manifest is enabled; unrelated tests are summarized.\n"
    )
    return header + yaml.safe_dump(plan, sort_keys=False)


def _get(data: dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _display(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "not collected"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _grace_details(value: Any) -> tuple[bool, str]:
    if not isinstance(value, dict):
        return False, ""
    grace = value.get("gracePeriod")
    if not isinstance(grace, dict) or grace.get("active") is not True:
        return False, ""
    return True, str(grace.get("message") or "").strip()


def _version_evaluator(path: str) -> Callable[[dict[str, Any]], tuple[str, str, str]]:
    def evaluate(audit: dict[str, Any]) -> tuple[str, str, str]:
        verdict = _get(audit, path)
        if not isinstance(verdict, dict):
            return (
                WARNING,
                "not collected",
                "The component version was not available, so exposure cannot be ruled out.",
            )
        status = str(verdict.get("status") or "unknown").lower()
        version = _display(verdict.get("version"))
        minimum = _display(verdict.get("minimum"))
        observed = f"observed version {version}; minimum version {minimum}"
        detail = str(verdict.get("detail") or "")
        if status in {"not_applicable", "not-applicable"}:
            return (
                NOT_APPLICABLE,
                observed,
                detail or "The component is not applicable to this host.",
            )
        if status == "pass":
            suffix = detail or (
                "The observed version meets the minimum version."
            )
            return PASS, observed, suffix
        if status == "fail":
            return (
                CRITICAL,
                observed,
                detail or "The observed version is below the published minimum version.",
            )
        return (
            WARNING,
            observed,
            detail
            or "The host version could not be verified, so exposure cannot be ruled out.",
        )

    return evaluate


def _connectx_firmware(audit: dict[str, Any]) -> tuple[str, str, str]:
    verdict = _get(audit, "securityVersions.connectxFirmware")
    if not isinstance(verdict, dict):
        return (
            WARNING,
            "not collected",
            "The NIC firmware inventory was unavailable, so exposure cannot be ruled out.",
        )

    status = str(verdict.get("status") or "unknown").lower()
    minimum = _display(verdict.get("minimum"))
    raw_devices = verdict.get("devices")
    devices = raw_devices if isinstance(raw_devices, list) else []

    def matching_devices(wanted: set[str]) -> list[str]:
        return [
            f"{_display(device.get('device'))}={_display(device.get('version'))}"
            for device in devices
            if isinstance(device, dict)
            and str(device.get("status") or "unknown").lower() in wanted
        ]

    if status in {"not_applicable", "not-applicable"}:
        return (
            NOT_APPLICABLE,
            "no applicable devices",
            "No NVIDIA ConnectX or BlueField firmware was present in the completed inventory.",
        )

    if not devices:
        return (
            WARNING,
            f"observed version not collected; minimum version {minimum}",
            "The NIC firmware inventory was unavailable, so exposure cannot be ruled out.",
        )

    failing = matching_devices({"fail"})
    unknown = matching_devices({"unknown"})
    if status == "fail":
        observed = (
            f"{len(failing)} of {len(devices)} devices below minimum: "
            f"{', '.join(failing)}; minimum version {minimum}"
        )
        return (
            CRITICAL,
            observed,
            "The named devices are below the published firmware minimum version.",
        )
    if status == "pass":
        grace_active, grace_note = _grace_details(verdict)
        if grace_active:
            grace_devices = [
                device
                for device in devices
                if isinstance(device, dict) and _grace_details(device)[0]
            ]
            listed = ", ".join(
                f"{_display(device.get('device'))}={_display(device.get('version'))}"
                for device in grace_devices
            )
            detail = str((grace_devices[0] if grace_devices else {}).get("detail") or "")
            return (
                PASS,
                f"observed version {listed or 'firmware'}; minimum version {minimum} "
                "during vendor update window",
                detail or grace_note,
            )
        return (
            PASS,
            f"observed versions for all {len(devices)} devices meet minimum version {minimum}",
            "Every detected ConnectX or BlueField device meets the published firmware minimum version.",
        )

    if unknown:
        observed = (
            f"{len(unknown)} of {len(devices)} devices unverified: "
            f"{', '.join(unknown)}; minimum version {minimum}"
        )
    else:
        device_label = "device" if len(devices) == 1 else "devices"
        observed = (
            f"inventory incomplete after {len(devices)} collected {device_label}; "
            f"minimum version {minimum}"
        )
    return (
        WARNING,
        observed,
        "One or more NIC firmware versions could not be verified, so exposure cannot be ruled out.",
    )


def _status_evaluator(
    path: str,
    *,
    critical: set[str],
    warning: set[str],
    passing: set[str],
    missing_assessment: str,
) -> Callable[[dict[str, Any]], tuple[str, str, str]]:
    def evaluate(audit: dict[str, Any]) -> tuple[str, str, str]:
        value = _get(audit, path)
        normalized = str(value).strip().lower() if value is not None else ""
        parent = _get(audit, path.rsplit(".", 1)[0])
        observed = _display(value)
        if isinstance(parent, dict):
            fields = [
                (name, item)
                for name, item in parent.items()
                if not isinstance(item, (dict, list))
            ]
            fields.sort(key=lambda item: (item[0] != "status", item[0]))
            observed = "; ".join(f"{name}={_display(item)}" for name, item in fields)
        if normalized in critical:
            return (
                CRITICAL,
                observed,
                "The audit observed a known vulnerable or unsafe state.",
            )
        if normalized in warning:
            return (
                WARNING,
                observed,
                "The audit cannot verify the physical host mitigation.",
            )
        if normalized in {"not-applicable", "not_applicable"}:
            return (
                NOT_APPLICABLE,
                observed,
                "This check does not apply to the audited target.",
            )
        if normalized in passing:
            return (
                PASS,
                observed,
                "The check passed or does not apply to this environment.",
            )
        return WARNING, observed, missing_assessment

    return evaluate


def _guest_kernel(audit: dict[str, Any]) -> tuple[str, str, str]:
    kernel = _get(audit, "security.guestKernel")
    if not isinstance(kernel, dict):
        return (
            WARNING,
            "not collected",
            "The running and installed kernel versions could not be compared.",
        )
    running_value = kernel.get("running")
    newest_value = kernel.get("newestInstalled")
    running = _display(running_value)
    newest = _display(newest_value)
    observed = (
        f"observed version {running}; minimum version not applicable; "
        f"newest installed version {newest}"
    )
    newer = kernel.get("newerInstalled")
    if newer is True or str(newer).lower() == "true":
        return (
            CRITICAL,
            observed,
            "A security-updated kernel is installed but inactive until the machine reboots.",
        )
    unknown_values = {"", "unknown", "not collected", "none", "null"}
    if (
        str(running_value or "").strip().lower() in unknown_values
        or str(newest_value or "").strip().lower() in unknown_values
    ):
        return (
            WARNING,
            observed,
            "The installed kernel inventory was unavailable, so a pending security reboot cannot be ruled out.",
        )
    if newer is False or str(newer).lower() == "false":
        return PASS, observed, "The host is running its newest detected kernel."
    return (
        WARNING,
        observed,
        "The installed kernel inventory was unavailable, so a pending security reboot cannot be ruled out.",
    )


def _fragnesia(audit: dict[str, Any]) -> tuple[str, str, str]:
    advisory = _get(audit, "security.fragnesia")
    kernel = _get(audit, "security.guestKernel")
    if not isinstance(advisory, dict):
        return (
            WARNING,
            "not collected",
            "The kernel applicability or fixed package level could not be verified.",
        )
    status = str(advisory.get("status") or "unknown").lower()
    running = _display(kernel.get("running")) if isinstance(kernel, dict) else "unknown"
    minimum = _display(advisory.get("ubuntuNoblePackageMinimum"))
    cves = [advisory.get("cve"), *(advisory.get("relatedCves") or [])]
    cve_text = ", ".join(str(cve) for cve in cves if cve)
    observed = f"observed version {running}; minimum version {minimum}"
    if cve_text:
        observed += f"; {cve_text}"
    if status == "fail":
        return (
            CRITICAL,
            observed,
            "The running kernel is below the distribution minimum for known local privilege-escalation fixes.",
        )
    if status in {"not-applicable", "not_applicable"}:
        return (
            NOT_APPLICABLE,
            observed,
            "This kernel advisory does not apply to the audited target.",
        )
    if status == "pass":
        grace_active, grace_note = _grace_details(advisory)
        if grace_active:
            detail = str(advisory.get("detail") or "").strip()
            return PASS, observed, detail or grace_note
        return PASS, observed, "The running kernel meets the applicable fixed minimum."
    return (
        WARNING,
        observed,
        "The kernel applicability or fixed package level could not be verified.",
    )


def _januscape(audit: dict[str, Any]) -> tuple[str, str, str]:
    value = _get(audit, "security.januscape")
    if not isinstance(value, dict):
        return (
            WARNING,
            "not collected",
            "Nested virtualization exposure could not be assessed.",
        )
    observed = "; ".join(
        f"{name}={_display(value.get(name))}"
        for name in (
            "cpuVirtualizationExposed",
            "kvmDeviceExposed",
            "nestedEnabled",
            "status",
        )
    )
    exposed = value.get("exposed")
    if exposed is True or str(exposed).lower() == "true":
        return (
            CRITICAL,
            observed,
            "Nested virtualization attack prerequisites are exposed to an untrusted guest.",
        )
    if exposed is False or str(exposed).lower() == "false":
        return (
            PASS,
            observed,
            "The guest does not expose the complete Januscape attack prerequisites.",
        )
    return (
        WARNING,
        observed,
        "The physical-host kernel patch state and nested virtualization boundary could not be verified.",
    )


def _ufm(audit: dict[str, Any]) -> tuple[str, str, str]:
    value = _get(audit, "security.ufmSecuredBareMetalCloud")
    if not isinstance(value, dict):
        return (
            WARNING,
            "not collected",
            "InfiniBand fabric security controls could not be assessed.",
        )
    if value.get("applicable") is False:
        # A host with no native InfiniBand fabric was never assessed against
        # this profile, so crediting it with a pass would inflate the passed
        # count on every Ethernet-only cluster (see NOT_APPLICABLE above).
        return (
            NOT_APPLICABLE,
            "no native InfiniBand fabric detected",
            "No native InfiniBand fabric requiring this UFM profile was detected.",
        )
    status = str(value.get("status") or "unknown").lower()
    observed = f"status {status}"
    if status == "pass":
        return PASS, observed, "The secured bare-metal UFM profile was verified."
    if status == "fail":
        return (
            CRITICAL,
            observed,
            "Required fabric authentication or rate-limiting controls are disabled.",
        )
    return (
        WARNING,
        observed,
        "The UFM security profile requires provider-side verification.",
    )


def _boolean_exposure(
    path: str, label: str
) -> Callable[[dict[str, Any]], tuple[str, str, str]]:
    def evaluate(audit: dict[str, Any]) -> tuple[str, str, str]:
        value = _get(audit, path)
        if value is True or str(value).lower() == "true":
            return CRITICAL, f"{label}=true", f"{label} is exposed to the tenant."
        if value is False or str(value).lower() == "false":
            return PASS, f"{label}=false", f"{label} was not exposed to the tenant."
        return (
            WARNING,
            f"{label}={_display(value)}",
            f"{label} exposure could not be verified.",
        )

    return evaluate


def _bmc_ipmi(audit: dict[str, Any]) -> tuple[str, str, str]:
    value = _get(audit, "security.bmcIpmi")
    if not isinstance(value, dict):
        return (
            WARNING,
            "not collected",
            "Local BMC and IPMI access could not be assessed.",
        )

    exposed = value.get("exposed")
    nodes_total = value.get("nodesTotal")
    nodes_checked = value.get("nodesChecked")
    exposed_nodes = value.get("exposedNodes")
    complete = value.get("nodeCoverageComplete")
    access_mode = str(value.get("accessMode") or "unknown")

    if isinstance(nodes_total, int) and isinstance(nodes_checked, int):
        names = exposed_nodes if isinstance(exposed_nodes, list) else []
        listed = ", ".join(str(name) for name in names) or "none"
        observed = (
            f"{len(names)}/{nodes_total} worker nodes exposed local BMC or IPMI access; "
            f"checked {nodes_checked}/{nodes_total}; exposed nodes {listed}; "
            f"access mode {access_mode}"
        )
        scope = (
            "The check used the Kubernetes identity to create a privileged pod "
            "that mounted each worker host root. It did not test access from an "
            "ordinary workload pod."
        )
        if exposed is True or str(exposed).lower() == "true":
            return CRITICAL, observed, scope
        if complete is True and nodes_checked == nodes_total and nodes_total > 0:
            return PASS, observed, scope
        return WARNING, observed, f"Fleet coverage was incomplete. {scope}"

    # Older audit artifacts contain only the aggregate Boolean. Keep those
    # artifacts readable, but identify the missing node and access-path scope.
    if exposed is True or str(exposed).lower() == "true":
        return (
            CRITICAL,
            "BMC/IPMI=true; node coverage and access mode were not recorded",
            "The sampled environment exposed BMC or IPMI access, but this older artifact does not show whether the check used a privileged host-root path.",
        )
    if exposed is False or str(exposed).lower() == "false":
        return (
            PASS,
            "BMC/IPMI=false; node coverage and access mode were not recorded",
            "The sampled environment did not expose BMC or IPMI access.",
        )
    return (
        WARNING,
        f"BMC/IPMI={_display(exposed)}",
        "Local BMC and IPMI access could not be verified.",
    )


def _manual_boundary(
    path: str, label: str
) -> Callable[[dict[str, Any]], tuple[str, str, str]]:
    def evaluate(audit: dict[str, Any]) -> tuple[str, str, str]:
        value = _get(audit, path)
        if value is True or str(value).lower() == "true":
            return (
                WARNING,
                f"{label}=true",
                "This isolation boundary is controlled by the physical host and needs provider verification.",
            )
        if value is False or str(value).lower() == "false":
            return (
                PASS,
                f"{label}=false",
                "No additional provider-side verification was requested by the check.",
            )
        return (
            WARNING,
            f"{label}={_display(value)}",
            "The provider-side isolation state could not be determined.",
        )

    return evaluate


def _nvlink_boundary(audit: dict[str, Any]) -> tuple[str, str, str]:
    boundary = _get(audit, "security.nvlinkBoundary")
    if not isinstance(boundary, dict):
        boundary = {}
    value = boundary.get(
        "nvlinkExposed",
        _get(audit, "security.nvidiaMay2026.nvlinkExposed"),
    )
    topology_checked = boundary.get("topologyChecked")
    coverage_complete = boundary.get("topologyCoverageComplete")
    domain_exclusive = boundary.get("domainExclusive")
    nvidia_present = boundary.get("nvidiaGpuPresent")
    guest = boundary.get("targetIsVm")
    virtualization = _get(audit, "security.virtualization")
    virt_type = "unknown"
    if isinstance(virtualization, dict):
        virt_type = str(virtualization.get("type") or "unknown").strip().lower()
        if guest is None:
            guest = virtualization.get("guest")
    if guest is None:
        if virt_type == "none":
            guest = False
        elif virt_type != "unknown":
            guest = True

    exposed = value is True or str(value).lower() == "true"
    not_exposed = value is False or str(value).lower() == "false"
    checked = topology_checked is True or str(topology_checked).lower() == "true"
    complete = coverage_complete is True or str(coverage_complete).lower() == "true"
    exclusive = domain_exclusive is True or str(domain_exclusive).lower() == "true"
    target = "VM" if guest is True else "bare metal" if guest is False else "unknown"
    observed = (
        f"tenant-visible NVLink={_display(value)}; topology checked="
        f"{_display(topology_checked)}; fleet coverage complete="
        f"{_display(coverage_complete)}; target={target}; physical domain "
        f"exclusive={_display(domain_exclusive)}"
    )

    if nvidia_present is False or str(nvidia_present).lower() == "false":
        return (
            NOT_APPLICABLE,
            observed,
            "The completed GPU inventory found no NVIDIA GPU, so NVLink and "
            "NVBleed do not apply to this target.",
        )
    if exclusive:
        return (
            PASS,
            observed,
            "Provider evidence confirms that the complete physical NVLink or "
            "NVSwitch domain is exclusive to this tenant. A whole-host VM is "
            "sufficient only when the domain is node-local; rack-scale NVLink "
            "requires a tenant-exclusive NVLink partition.",
        )
    if exposed:
        return (
            WARNING,
            observed,
            "The topology probe found NVLink between tenant-visible GPUs. This "
            "makes NVBleed relevant but does not prove a vulnerability: the "
            "provider must verify that every GPU in the complete physical "
            "NVLink or NVSwitch domain belongs to the same trust boundary. A "
            "whole-host VM clears a node-local SXM/NVSwitch domain; rack-scale "
            "NVLink requires a tenant-exclusive NVLink partition.",
        )
    if not_exposed and checked and complete and guest is False:
        return (
            NOT_APPLICABLE,
            observed,
            "The complete bare-metal host inventory contained no NVLink path, "
            "so there is no NVLink tenant boundary to verify.",
        )
    if not_exposed and guest is True:
        assessment = (
            "No NVLink appeared between GPUs visible inside the VM, but guest "
            "topology cannot rule out a physical NVLink to a GPU assigned to "
            "another VM. NVBleed demonstrated leakage across that hidden "
            "cross-VM boundary, so the provider must attest the complete "
            "physical domain."
        )
    elif not_exposed and not checked:
        assessment = (
            "The collector recorded no visible NVLink without completing the "
            "topology probe. Absence is unverified, so the physical tenant "
            "boundary still requires provider evidence."
        )
    elif not_exposed and not complete:
        assessment = (
            "The sampled host exposed no NVLink, but the topology probe did not "
            "cover every GPU host. Unsampled hosts can still contain NVLink, so "
            "the cluster boundary remains unverified."
        )
    else:
        assessment = (
            "Tenant-visible NVLink topology or the machine boundary could not "
            "be determined. The provider must attest the complete physical "
            "NVLink or NVSwitch domain."
        )
    return (
        WARNING,
        observed,
        assessment,
    )


def _virtio_net_bluefield(audit: dict[str, Any]) -> tuple[str, str, str]:
    """Grade the BlueField VIRTIO-Net controller against its release-line minimum.

    The audit already decided this. It reports `exposure` separately from
    `status` precisely so a consumer does not have to re-derive urgency from a
    grade: `live` means the controller is running, `latent` means the firmware is
    installed on a card in NIC mode that a mode change would activate, and
    `unknown` means the fleet was not cleared. Re-deriving any of that here would
    put a second opinion next to the audit's own.
    """
    verdict = _get(audit, "securityVersions.virtioNetBluefield")
    if not isinstance(verdict, dict):
        return (
            WARNING,
            "not collected",
            "The BlueField controller inventory was unavailable, so exposure cannot be ruled out.",
        )
    status = str(verdict.get("status") or "unknown").lower()
    exposure = str(verdict.get("exposure") or "unknown").lower()
    version = _display(verdict.get("version"))
    minimum = _display(verdict.get("minimum"))

    if status in {"not_applicable", "not-applicable"}:
        return (
            NOT_APPLICABLE,
            "no BlueField DPU present",
            "No BlueField DPU is present in the completed device scan.",
        )
    if status == "pass":
        grace_active, grace_note = _grace_details(verdict)
        if grace_active:
            detail = str(verdict.get("detail") or "").strip()
            return (
                PASS,
                f"observed version {version}; minimum version {minimum} "
                "during vendor update window",
                detail or grace_note,
            )
        return (
            PASS,
            f"observed version {version}; minimum version {minimum}",
            "The controller firmware is at or above its published minimum.",
        )
    if status == "fail":
        if exposure == "latent":
            return (
                WARNING,
                f"observed version {version}; minimum version {minimum}; card in NIC mode",
                "The controller firmware is below its minimum and the card is in NIC "
                "mode, so nothing is running now: a switch to DPU mode would "
                "activate it (CVE-2026-65094).",
            )
        return (
            CRITICAL,
            f"observed version {version}; minimum version {minimum}",
            "The BlueField is in DPU mode and runs controller firmware below its "
            "published minimum (CVE-2026-65094).",
        )
    if exposure == "latent":
        return (
            WARNING,
            f"{version} unproven, card in NIC mode",
            "The controller firmware could not be graded and the card is in NIC "
            "mode, so nothing is running now: a switch to DPU mode would activate "
            "firmware nothing proves is patched (CVE-2026-65094).",
        )
    return (
        WARNING,
        f"observed version {version}; minimum version {minimum}",
        "The BlueField controller version requires provider attestation.",
    )


def _dpu_host_isolation(audit: dict[str, Any]) -> tuple[str, str, str]:
    """Grade whether the host can reach the DPU control plane over RShim.

    RShim is enabled by default, because an out-of-box BlueField assumes a
    trusted host. On a multi-tenant cluster that assumption does not hold: a
    tenant with host root reaches the DPU's own Arm cores, which sit outside the
    hypervisor boundary the tenant is otherwise confined by.
    """
    verdict = _get(audit, "securityVersions.dpuHostIsolation")
    if not isinstance(verdict, dict):
        return (
            WARNING,
            "not collected",
            "The BlueField isolation check did not report, so host access to the "
            "DPU control plane cannot be ruled out.",
        )
    status = str(verdict.get("status") or "unknown").lower()
    observed = _display(verdict.get("version"))
    if status in {"not_applicable", "not-applicable"}:
        return (
            NOT_APPLICABLE,
            "no BlueField DPU present",
            "No BlueField DPU is present in the completed device scan.",
        )
    if status == "pass":
        return (
            PASS,
            f"RShim restricted ({observed})",
            "The host cannot reach the DPU control plane over RShim.",
        )
    if status == "fail":
        return (
            CRITICAL,
            f"RShim reachable from the host ({observed})",
            "The host can reach the BlueField control plane over RShim, so a "
            "tenant with host root reaches the DPU Arm cores outside the "
            "hypervisor boundary. Apply the zero-trust host profile with "
            "`mlxprivhost -d <device> r --disable_rshim`.",
        )
    return (
        WARNING,
        f"RShim posture {observed}",
        "Host access to the DPU control plane could not be determined.",
    )


_MINIMUM_READER_CACHE: dict[str, ModuleType | None] = {}


def minimum_reader(repo: str | None = None) -> ModuleType | None:
    """Return the generated minimum table reader, or None when it is unavailable.

    `minimum_versions.py` ships inside the audit workload, so it is loaded by
    path from the resolved runtime root rather than imported as a package. The
    result is cached because every audit reads the table several times.
    """
    try:
        root = find_runtime_root(repo)
    except SecurityAuditError:
        return None
    cached = _MINIMUM_READER_CACHE.get(str(root))
    if cached is not None:
        return cached
    module: ModuleType | None = None
    try:
        spec = importlib.util.spec_from_file_location(
            "cmax_minimum_versions", root / MINIMUMS_READER_RELATIVE
        )
        if spec is not None and spec.loader is not None:
            candidate = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(candidate)
            sys.modules[spec.name] = candidate
            module = candidate
    except (OSError, SyntaxError, ValueError):
        module = None
    # Only a successful load is cached, so a transient runtime-root problem
    # cannot pin every later report to "reader not found".
    if module is not None:
        _MINIMUM_READER_CACHE[str(root)] = module
    return module


def minimum_table_path(repo: str | None = None) -> Path:
    """Return the installed minimum table path, honoring the reader's override."""
    reader = minimum_reader(repo)
    if reader is not None:
        return Path(reader.minimums_path())
    return find_runtime_root(repo) / MINIMUMS_TABLE_RELATIVE


def minimum_component(name: str, repo: str | None = None) -> dict[str, Any]:
    """Return one component block of the generated minimum table, or {}.

    The minimums are read only through the shipped reader, so the CLI cannot
    drift from the collector that graded the versions.
    """
    reader = minimum_reader(repo)
    if reader is None:
        return {}
    try:
        block = reader.component(name, minimum_table_path(repo))
    except (reader.MinimumDataError, SecurityAuditError):
        return {}
    return block if isinstance(block, dict) else {}


def minimum_freshness(
    *, repo: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """Report the age of the generated minimum table this report graded against.

    Freshness is a statement about this tool rather than about the cluster, so
    it is a report notice and never a graded check: it stays out of `counts()`
    and out of the exit code, and a provider is never marked down because the
    daily refresh job stalled. `notice` is None when the table is current; the
    stale wording comes from `minimum_versions.staleness_message`, so exactly one
    copy of it exists.
    """
    state: dict[str, Any] = {
        "generated": None,
        "age_days": None,
        "max_age_days": None,
        "stale": False,
        "notice": None,
    }
    reader = minimum_reader(repo)
    if reader is None:
        state["notice"] = (
            "The minimum version table reader was not found, so the minimums used "
            "for grading cannot be confirmed. Reinstall clustermax, then run "
            "the audit again."
        )
        return state
    path = minimum_table_path(repo)
    state["path"] = str(path)
    # The action that gets the current minimums depends on the installation. The
    # reader owns that wording, so exactly one copy of it exists. A reader from
    # an older checkout has no `remedy`, so a default keeps the notice useful.
    action = getattr(reader, "remedy", None)
    fix = action(path) if callable(action) else "Update the minimum version table"
    try:
        stamp = reader.generated_at(path)
        state["age_days"] = reader.age_days(path, now=now)
        state["max_age_days"] = reader.max_age_days(path)
        reminder = reader.staleness_message(path, now=now)
    except reader.MinimumDataError as exc:
        state["notice"] = (
            f"The minimum version table could not be read ({exc}), so the minimums "
            f"used for grading cannot be confirmed. {fix}, then run the audit "
            f"again."
        )
        return state
    if stamp is not None:
        state["generated"] = stamp.strftime("%Y-%m-%d")
    if stamp is None or state["age_days"] is None:
        state["notice"] = (
            f"The minimum version table has no usable generated timestamp, so "
            f"its age cannot be confirmed. {fix}, then run the audit again."
        )
        return state
    state["age_days"] = round(state["age_days"], 2)
    state["stale"] = bool(reminder)
    state["notice"] = reminder
    return state


CHECK_SPECS: tuple[CheckSpec, ...] = (
    CheckSpec(
        "nvidia-driver",
        "NVIDIA driver minimum version",
        "GPU driver vulnerabilities can expose the host kernel through device interfaces available to workloads.",
        # The bulletin link comes from the minimum table (see MINIMUM_BOUND_CHECKS).
        # It was hardcoded here, so it kept naming May 2026 and pointing at that
        # bulletin after a refresh moved a branch minimum to a later one.
        "Install the fixed release for the deployed NVIDIA driver branch and reload the driver or reboot.",
        _references(
            ("NVIDIA product security", "https://www.nvidia.com/en-us/security/"),
        ),
        _version_evaluator("securityVersions.nvidiaDriver"),
    ),
    CheckSpec(
        "nvidia-container-toolkit",
        "NVIDIA Container Toolkit minimum version",
        "Affected container hooks can allow a crafted image to escape its container during initialization.",
        # The minimum version, its bulletin, and its CVEs come from the generated
        # minimum table at evaluation time (see MINIMUM_BOUND_CHECKS), so this text
        # cannot drift from the minimum the audit graded against.
        "Upgrade NVIDIA Container Toolkit to the published minimum version, then restart the container runtime.",
        _references(
            ("NVIDIA product security", "https://www.nvidia.com/en-us/security/"),
        ),
        _version_evaluator("securityVersions.nvidiaContainerToolkit"),
    ),
    CheckSpec(
        "cuda-toolkit",
        "CUDA Toolkit minimum version",
        "CUDA Toolkit vulnerabilities can affect compiler and runtime components used by GPU workloads.",
        # The minimum version, its bulletin, and its CVEs come from the minimum
        # table at evaluation time (see MINIMUM_BOUND_CHECKS). The superseded
        # September 2025 bulletin stays as history, because the table carries
        # only the current one.
        "Upgrade the CUDA Toolkit to the published minimum version.",
        _references(
            (
                "NVIDIA September 2025 CUDA bulletin",
                "https://nvidia.custhelp.com/app/answers/detail/a_id/5661/",
            ),
        ),
        _version_evaluator("securityVersions.cudaToolkit"),
    ),
    CheckSpec(
        "runc",
        "runc minimum version",
        "Affected OCI runtime releases contain container setup races that can bypass masked-path protections.",
        "Upgrade to the fixed release for the installed runc branch and restart the container runtime.",
        # The advisory link comes from the minimum table (see MINIMUM_BOUND_CHECKS).
        # These CVEs are the named masked-path race and stay as history; the
        # table's own advisory list moves with the ladder.
        _references(
            ("CVE-2025-31133", "https://nvd.nist.gov/vuln/detail/CVE-2025-31133"),
            ("CVE-2025-52565", "https://nvd.nist.gov/vuln/detail/CVE-2025-52565"),
            ("CVE-2025-52881", "https://nvd.nist.gov/vuln/detail/CVE-2025-52881"),
        ),
        _version_evaluator("securityVersions.runc"),
    ),
    CheckSpec(
        "docker",
        "Docker Engine minimum version",
        "An outdated container daemon increases exposure to known runtime and API vulnerabilities.",
        # The release-notes link comes from the minimum table (see
        # MINIMUM_BOUND_CHECKS), so it follows the engine major the minimum names.
        "Upgrade Docker Engine to the current supported security release and restart the daemon.",
        _references(
            (
                "Docker security announcements",
                "https://docs.docker.com/security/security-announcements/",
            ),
        ),
        _version_evaluator("securityVersions.docker"),
    ),
    CheckSpec(
        "connectx-firmware",
        "ConnectX and BlueField firmware minimum version",
        "NIC firmware handles direct memory access and fabric traffic at a privileged hardware boundary.",
        "Apply the fixed NVIDIA firmware release for every detected ConnectX or BlueField device.",
        # The bulletin link comes from the minimum table (see MINIMUM_BOUND_CHECKS),
        # so it follows the train table a refresh rebuilds.
        _references(
            ("CVE-2025-23350", "https://nvd.nist.gov/vuln/detail/CVE-2025-23350"),
            ("CVE-2025-23351", "https://nvd.nist.gov/vuln/detail/CVE-2025-23351"),
        ),
        _connectx_firmware,
    ),
    CheckSpec(
        "guest-kernel",
        "Active kernel version",
        "Installed kernel fixes provide no protection until the fixed kernel is running.",
        "Reboot into the newest installed kernel and confirm the running release after startup.",
        _references(
            (
                "Ubuntu security updates",
                "https://documentation.ubuntu.com/security/security-updates/",
            ),
            ("Ubuntu kernel update guidance", "https://ubuntu.com/security/notices"),
        ),
        _guest_kernel,
    ),
    CheckSpec(
        "fragnesia",
        "Fragnesia and Dirty Frag kernel fixes",
        "Affected kernels permit local privilege escalation and may facilitate container escape.",
        "Install the fixed distribution kernel package and reboot into it.",
        _references(
            (
                "Canonical Fragnesia disclosure",
                "https://ubuntu.com/blog/fragnesia-linux-vulnerability-fixes-available",
            ),
            (
                "Canonical Dirty Frag disclosure",
                "https://ubuntu.com/blog/dirty-frag-linux-vulnerability-fixes-available",
            ),
            ("CVE-2026-46300", "https://ubuntu.com/security/CVE-2026-46300"),
            ("CVE-2026-43284", "https://ubuntu.com/security/CVE-2026-43284"),
            ("CVE-2026-43500", "https://ubuntu.com/security/CVE-2026-43500"),
        ),
        _fragnesia,
    ),
    CheckSpec(
        "januscape",
        "Januscape nested virtualization boundary",
        "Nested virtualization exposure can let an untrusted guest attack the physical-host KVM boundary.",
        "Disable nested virtualization and remove guest access to /dev/kvm until the physical-host vendor fix is installed.",
        _references(
            (
                "Canonical Januscape disclosure",
                "https://ubuntu.com/blog/januscape-linux-vulnerability-mitigations-available",
            ),
            ("CVE-2026-53359", "https://ubuntu.com/security/CVE-2026-53359"),
        ),
        _januscape,
    ),
    CheckSpec(
        "bmc-ipmi",
        "BMC and IPMI tenant isolation",
        "Tenant access to BMC or IPMI can provide out-of-band control of the physical server.",
        "Remove tenant access to IPMI devices and commands, and isolate BMC management networks.",
        _references(
            (
                "CISA IPMI risk alert",
                "https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi",
            ),
            (
                "NIST SP 800-193 platform resilience",
                "https://csrc.nist.gov/pubs/sp/800/193/final",
            ),
        ),
        _bmc_ipmi,
    ),
    CheckSpec(
        "ufm-profile",
        "InfiniBand UFM secured profile",
        "Unauthenticated fabric management traffic can expose neighboring tenants or enable denial of service.",
        "Enable and verify the UFM Secured Bare Metal Cloud controls, including randomized management keys and rate limiting.",
        _references(
            (
                "NVIDIA UFM secured-cloud guidance",
                "https://developer.nvidia.com/blog/one-click-multi-tenant-security-with-nvidia-quantum-infiniband/",
            ),
            (
                "NVIDIA InfiniBand security guidance",
                "https://docs.nvidia.com/networking/display/nvidia-infiniband-security-overview-and-guidelines.pdf",
            ),
        ),
        _ufm,
    ),
    CheckSpec(
        "pcie-passthrough",
        "PCIe passthrough isolation",
        "Passed-through accelerators depend on host IOMMU, ACS, reset isolation, and memory sanitization.",
        "Have the provider verify dedicated host IOMMU groups, DMA remapping, ACS, reset isolation, and VRAM clearing.",
        _references(
            (
                "Linux VFIO documentation",
                "https://docs.kernel.org/driver-api/vfio.html",
            ),
            (
                "Linux IOMMU userspace API",
                "https://docs.kernel.org/6.8/userspace-api/iommu.html",
            ),
        ),
        _manual_boundary(
            "security.pciePassthrough.hostVerificationRequired",
            "host verification required",
        ),
    ),
    CheckSpec(
        "nvlink-boundary",
        "NVLink tenant boundary",
        "NVBleed showed that NVLink contention and performance counters can "
        "reveal another GPU's communication patterns, including across VMs. "
        "This check detects tenant-visible NVLink and asks who owns the complete "
        "physical fabric; it does not treat NVLink itself as a vulnerability.",
        "Have the provider prove that every GPU in the physical NVLink or "
        "NVSwitch domain belongs to one trust boundary. A whole-host VM is "
        "enough only for a node-local domain; use an exclusive NVLink partition "
        "for a rack-scale domain. After verifying it, rerun with "
        "CLUSTERMAX_NVLINK_DOMAIN_EXCLUSIVE_ATTESTED=true to record the "
        "attestation.",
        _references(
            ("NVBleed disclosure", "https://arxiv.org/abs/2503.17847"),
            (
                "NVIDIA NVLink partition management",
                "https://docs.nvidia.com/mission-control/docs/systems-administration-guide/2.3.0/nvlink-partition-management.html",
            ),
        ),
        _nvlink_boundary,
    ),
    CheckSpec(
        "virtio-net-bluefield",
        "BlueField VIRTIO-Net controller firmware",
        "A BlueField VIRTIO-Net controller below its published minimum lets a "
        "guest reach the DPU control plane through the virtio-net device "
        "(CVE-2026-65094).",
        "Update the BlueField controller firmware to the minimum for its release "
        "line. A card in NIC mode is not running the controller now, and a "
        "switch to DPU mode activates it.",
        # The bulletin link and CVE come from the minimum table (see
        # MINIMUM_BOUND_CHECKS).
        _references(
            (
                "NVIDIA product security",
                "https://www.nvidia.com/en-us/security/",
            ),
        ),
        _virtio_net_bluefield,
    ),
    CheckSpec(
        "dpu-host-isolation",
        "BlueField host isolation (RShim)",
        "RShim is enabled by default, so the host reaches the DPU Arm cores "
        "directly. On a multi-tenant cluster a tenant with host root then "
        "reaches a control plane outside the hypervisor boundary.",
        "Apply the zero-trust host profile: `mlxprivhost -d <device> r "
        "--disable_rshim --disable_tracer --disable_counter_rd "
        "--disable_port_owner`.",
        _references(
            (
                "NVIDIA mlxprivhost host restriction",
                "https://docs.nvidia.com/networking/display/mftv4290/mlxprivhost",
            ),
            (
                "BlueField modes of operation",
                "https://docs.nvidia.com/networking/display/bluefielddpuosv470/modes+of+operation",
            ),
        ),
        _dpu_host_isolation,
    ),
)


# Checks whose remediation text and advisory links are owned by the generated
# minimum table: check id -> (minimum component, remediation template). The template
# takes the minimum from the table, so no minimum version is restated here.
MINIMUM_BOUND_CHECKS: dict[str, tuple[str, str, str]] = {
    "nvidia-driver": (
        "nvidiaDriver",
        # Branch minimums, so there is no single {minimum} to name. The binding is
        # here for the bulletin link, which moves when a refresh changes the
        # branch table.
        "Install the fixed release for the deployed NVIDIA driver branch and "
        "reload the driver or reboot.",
        "NVIDIA GPU driver bulletin",
    ),
    "nvidia-container-toolkit": (
        "nvidiaContainerToolkit",
        "Upgrade NVIDIA Container Toolkit to {minimum} or newer, then restart "
        "the container runtime.",
        "NVIDIA Container Toolkit bulletin",
    ),
    "cuda-toolkit": (
        "cudaToolkit",
        "Upgrade the CUDA Toolkit to {minimum} or a newer vendor-supported "
        "release.",
        "NVIDIA CUDA Toolkit bulletin",
    ),
    "runc": (
        "runc",
        # A per-branch ladder, so the remediation names the branch and not a
        # version.
        "Upgrade to the fixed release for the installed runc branch and "
        "restart the container runtime.",
        "runc security advisory",
    ),
    "docker": (
        "docker",
        "Upgrade Docker Engine to {minimum} or newer and restart the daemon.",
        "Docker Engine release notes",
    ),
    "connectx-firmware": (
        "connectxFirmware",
        # Per firmware train, so no single minimum to name.
        "Apply the fixed NVIDIA firmware release for every detected ConnectX "
        "or BlueField device.",
        "NVIDIA networking security bulletin",
    ),
    "virtio-net-bluefield": (
        "virtioNetBluefield",
        # Per release line, and the lines interleave, so a version here would be
        # wrong for most cards even before a refresh moved it.
        "Update the BlueField controller firmware to the minimum for its release "
        "line. A card in NIC mode is not running the controller now, and a "
        "switch to DPU mode activates it.",
        "NVIDIA BlueField VIRTIO-Net bulletin",
    ),
}


def _minimum_bound_details(
    spec: CheckSpec,
) -> tuple[str, tuple[SecurityReference, ...]]:
    """Return the remediation and references the minimum table owns for a check."""
    binding = MINIMUM_BOUND_CHECKS.get(spec.id)
    if binding is None:
        return spec.remediation, spec.references
    component_name, template, bulletin_label = binding
    block = minimum_component(component_name)
    remediation = spec.remediation
    minimum = block.get("minimum")
    if isinstance(minimum, str) and minimum:
        remediation = template.format(minimum=minimum)
    references: list[SecurityReference] = []
    advisory = block.get("advisory")
    if isinstance(advisory, str) and advisory:
        references.append(SecurityReference(bulletin_label, advisory))
    for cve in block.get("cves") or ():
        references.append(
            SecurityReference(str(cve), f"https://nvd.nist.gov/vuln/detail/{cve}")
        )
    return remediation, (*references, *spec.references)


def evaluate_security(values: dict[str, Any]) -> list[SecurityCheck]:
    audit = (
        values.get("audit_data")
        if isinstance(values.get("audit_data"), dict)
        else values
    )
    checks: list[SecurityCheck] = []
    grace_paths = {
        "nvidia-driver": "securityVersions.nvidiaDriver",
        "nvidia-container-toolkit": "securityVersions.nvidiaContainerToolkit",
        "cuda-toolkit": "securityVersions.cudaToolkit",
        "runc": "securityVersions.runc",
        "docker": "securityVersions.docker",
        "connectx-firmware": "securityVersions.connectxFirmware",
        "virtio-net-bluefield": "securityVersions.virtioNetBluefield",
        "fragnesia": "security.fragnesia",
    }
    for spec in CHECK_SPECS:
        status, observed, assessment = spec.evaluate(audit)
        remediation, references = _minimum_bound_details(spec)
        minimum_url = minimum_links.security_check_url(spec.id)
        if minimum_url:
            references = (
                SecurityReference(minimum_links.REFERENCE_LABEL, minimum_url),
                *references,
            )
        grace_active, grace_note = _grace_details(
            _get(audit, grace_paths.get(spec.id, "")) if spec.id in grace_paths else None
        )
        if status != PASS:
            grace_active, grace_note = False, ""
        version_path = {
            "nvidia-driver": "securityVersions.nvidiaDriver.advisory",
            "nvidia-container-toolkit": "securityVersions.nvidiaContainerToolkit.advisory",
            "cuda-toolkit": "securityVersions.cudaToolkit.advisory",
            "runc": "securityVersions.runc.advisory",
            "docker": "securityVersions.docker.advisory",
            "connectx-firmware": "securityVersions.connectxFirmware.advisory",
        }.get(spec.id)
        if version_path:
            advisory = str(_get(audit, version_path) or "").strip()
            if advisory and advisory not in {reference.url for reference in references}:
                references = (
                    SecurityReference("Detected component advisory", advisory),
                    *references,
                )
        documentation = references[0].url if references else ""
        checks.append(
            SecurityCheck(
                spec.id,
                spec.title,
                status,
                observed,
                spec.importance,
                assessment,
                remediation,
                documentation,
                references,
                grace_active,
                grace_note,
            )
        )
    return checks


def counts(checks: list[SecurityCheck]) -> dict[str, int]:
    return {
        status: sum(check.status == status for check in checks)
        for status in (PASS, WARNING, CRITICAL, NOT_APPLICABLE)
    }


_paint = report_style.paint


def format_report(
    checks: list[SecurityCheck],
    target: SecurityTarget,
    log_dir: Path,
    *,
    verbosity: int = 1,
    color: bool = False,
    now: datetime | None = None,
) -> str:
    verbosity = min(max(verbosity, 1), 3)
    # The security profile uses the same status block as the complete audit.
    # Level one shows every check and its observed value. Level two adds links.
    # Level three adds the issue explanation and recommended remediation.
    total = counts(checks)
    detection = "explicit" if target.explicit else "auto-detected"
    lines = [
        _paint("# ClusterMAX security audit report", "bold", color=color),
        "",
        _paint(
            f"  {target.environment} · {detection} · harness={target.harness}",
            "dim",
            color=color,
        ),
    ]

    # The least severe checks come first, so an operator who reads upward from
    # the footer reaches the most important findings first. Normal passing and
    # skipped checks are always visible because level one is the minimum.
    visible_statuses = (PASS, NOT_APPLICABLE, WARNING, CRITICAL)
    for status in visible_statuses:
        for check in (c for c in checks if c.status == status):
            lines.append("")
            details = []
            assessment = check.observed
            if verbosity >= 3:
                assessment = check.assessment
                details.extend(
                    (("Observed", check.observed), ("Why", check.importance))
                )
            # Remediation is for a check that found something to fix. A pass
            # has nothing, and neither does a criterion for hardware this
            # machine does not have: printing "apply the zero-trust host
            # profile" under "no BlueField DPU present" reads as an action item.
            recommendation = ""
            if verbosity >= 3 and check.grace_period:
                suffix = f" {check.grace_note}" if check.grace_note else ""
                recommendation = f"{check.remediation}{suffix}"
            elif verbosity >= 3 and check.status not in (PASS, NOT_APPLICABLE):
                recommendation = check.remediation
            all_references = tuple(
                (reference.label, reference.url)
                for reference in check.references
            )
            references = minimum_links.canonical_references(all_references)
            if verbosity < 2 and (
                not references or references[0][0] != minimum_links.REFERENCE_LABEL
            ):
                references = ()
            lines.extend(
                report_style.format_check(
                    title=check.title,
                    check_id=check.id,
                    status=check.status,
                    assessment=assessment,
                    details=details,
                    recommendation=recommendation,
                    references=references,
                    color=color,
                )
            )

    summary = ", ".join(
        (
            report_style.count(
                f"{total[CRITICAL]} failed", CRITICAL, color=color
            ),
            report_style.count(
                f"{total[WARNING]} warning"
                f"{'' if total[WARNING] == 1 else 's'}",
                WARNING,
                color=color,
            ),
            report_style.count(f"{total[PASS]} passed", PASS, color=color),
            report_style.count(
                f"{total[NOT_APPLICABLE]} skipped",
                NOT_APPLICABLE,
                color=color,
            ),
        )
    )
    lines.extend(("", summary))

    if total[CRITICAL]:
        lines.append(
            f"{_paint('Action required:', 'red', color=color)} "
            f"{total[CRITICAL]} critical finding"
            f"{'' if total[CRITICAL] == 1 else 's'}."
        )
    elif total[WARNING]:
        lines.append(
            f"{_paint('Review required:', 'yellow', color=color)} warnings need "
            "host or provider verification."
        )
    else:
        lines.append(
            _paint("No known critical exposure detected.", "green", color=color)
        )

    # Minimum-data staleness sits next to the summary, at every verbosity level:
    # an operator who reads only the last few lines must still see that the
    # grading may be out of date. It is a notice about this tool, so it changes
    # no count and no exit code.
    notice = minimum_freshness(now=now)["notice"]
    if notice:
        lines.append(f"{_paint('Minimum data:', 'yellow', color=color)} {notice}")

    lines.append(
        _paint(f"report saved to {log_dir / 'security-report.log'}", "dim", color=color)
    )
    if verbosity < 3:
        hint = {
            1: "run with -vv for CVE and documentation links, -vvv for issue details and remediation",
            2: "run with -vvv for issue details and remediation",
        }[verbosity]
        lines.append(_paint(hint, "dim", color=color))
    return "\n".join(lines)


def write_reports(
    checks: list[SecurityCheck], target: SecurityTarget, log_dir: Path
) -> None:
    payload = {
        "schema_version": 1,
        "target": asdict(target),
        "counts": counts(checks),
        # Provenance of the minimums the checks were graded against. Recorded
        # beside the checks, never counted as one of them.
        "minimum_data": minimum_freshness(),
        "checks": [asdict(check) for check in checks],
    }
    (log_dir / "security-report.json").write_text(json.dumps(payload, indent=2) + "\n")
    (log_dir / "security-report.log").write_text(
        format_report(checks, target, log_dir, verbosity=3) + "\n"
    )


def _minimum_leaves(table: dict[str, Any]) -> dict[str, str]:
    """Flatten every component minimum to a `dotted.path -> value` mapping.

    Provenance (`source`) is skipped: it changes with every regeneration and
    says nothing about the graded minimums.
    """
    leaves: dict[str, str] = {}

    def walk(prefix: str, node: Any) -> None:
        if isinstance(node, dict):
            for key, value in sorted(node.items()):
                if key == "source":
                    continue
                walk(f"{prefix}.{key}" if prefix else key, value)
        elif isinstance(node, list):
            leaves[prefix] = ", ".join(str(item) for item in node)
        else:
            leaves[prefix] = _display(node)

    components = table.get("components") if isinstance(table, dict) else None
    walk("", components if isinstance(components, dict) else {})
    return leaves


def minimum_changes(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Return one `minimum: old -> new` line for every minimum that moved."""
    old_leaves = _minimum_leaves(before)
    new_leaves = _minimum_leaves(after)
    return [
        f"{key}: {old_leaves.get(key, 'absent')} -> {new_leaves.get(key, 'absent')}"
        for key in sorted(set(old_leaves) | set(new_leaves))
        if old_leaves.get(key) != new_leaves.get(key)
    ]


def sync_minimum_table(*, repo: str | None = None) -> bool:
    """Fetch the published minimum table and grade this run against it.

    The security audit calls this by default on startup, and
    `--no-fetch-minimums` skips it. This function needs one HTTPS GET request,
    so it also works for a pip installation, where the installed table is
    read-only and the upstream generator cannot write.

    Returns True when this run grades against a fetched table.

    This never raises. When the fetch fails, the audit grades against the
    last successfully fetched table in the cache when that copy is not older
    than the installed table, and against the installed table otherwise. The
    warning names the failure and the generated date of the table in use.
    """
    try:
        from cmax import minimum_sync
    except ImportError as exc:
        print(
            f"minimum fetch skipped: the fetch module is unavailable ({exc}). "
            "Continuing with the installed minimum table.",
            flush=True,
        )
        return False
    pinned = os.environ.get(MINIMUMS_ENV, "").strip()
    if pinned:
        # An explicit path is a deliberate pin, for example a captured table
        # that reproduces an earlier audit. The flag must not silently
        # replace it.
        print(
            f"minimum fetch skipped: {MINIMUMS_ENV} pins the minimum table to "
            f"{pinned}. Unset it to fetch the published table.",
            flush=True,
        )
        return False
    installed_generated: str | None = None
    installed_path: Path | None = None
    try:
        installed_path = minimum_table_path(repo)
        installed_generated = str(
            json.loads(installed_path.read_text()).get("generated") or ""
        )
    except (SecurityAuditError, OSError, json.JSONDecodeError, AttributeError):
        # The installed table is missing or unreadable. The fetch is then the
        # only path to a usable table, so it continues with no age minimum.
        installed_generated = None
    result = minimum_sync.sync(installed_generated=installed_generated)
    print(f"minimum fetch: {result.message}", flush=True)
    installed = minimum_sync.parse_stamp(installed_generated)
    if not result.ok or result.path is None:
        # The fetch failed. One earlier launch with a working network left the
        # published table in the cache, so grade against that copy when it is
        # not older than the installed table. The audit still runs either way;
        # the warning names the age of the table it grades against.
        # `result.generated` is set only when a valid published table was
        # deliberately rejected as older than the installed table. That is a
        # decision and not a failure, so the cache must not override it, and
        # the message above already says the installed table stays.
        cached = minimum_sync.cached_table() if result.generated is None else None
        if cached is not None:
            cache_file, cached_generated = cached
            stamp = minimum_sync.parse_stamp(cached_generated)
            if stamp is not None and (installed is None or stamp >= installed):
                os.environ[MINIMUMS_ENV] = str(cache_file)
                print(
                    f"minimum fetch warning: could not update the minimum "
                    f"table. Grading against the last fetched table "
                    f"(generated {cached_generated}) from {cache_file}.",
                    flush=True,
                )
                return True
        suffix = (
            f" (generated {installed_generated})" if installed_generated else ""
        )
        print(
            f"minimum fetch warning: could not update the minimum table. "
            f"Grading against the installed table{suffix}.",
            flush=True,
        )
        return False
    fetched = minimum_sync.parse_stamp(result.generated)
    if fetched is not None and installed is not None and fetched < installed:
        # The cached table is older than the installed table. This happens when
        # a new release ships a newer table than the last fetch.
        print(
            f"minimum fetch: the cached table (generated {result.generated}) is "
            f"older than the installed table {installed_path} "
            f"(generated {installed_generated}). Grading against the installed "
            f"table.",
            flush=True,
        )
        return False
    os.environ[MINIMUMS_ENV] = str(result.path)
    print(f"minimum table in use: {result.path}", flush=True)
    return True


def refresh_minimum_table(*, repo: str | None = None) -> bool:
    """Regenerate the installed minimum table from the upstream advisory feeds.

    Opt-in only. The default audit never reaches the network, so a host with no
    outbound access grades identically and every committed run stays
    reproducible. Returns True when the table on disk was replaced.

    This never raises. A refresh failure (no generator, no network, a parse
    error, a fail-closed generator abort, or a read-only install) prints a
    warning and leaves the committed table in place so the audit still runs.
    """
    try:
        path = minimum_table_path(repo)
    except SecurityAuditError as exc:
        print(f"minimum refresh skipped: {exc}", flush=True)
        return False
    try:
        # Imported lazily so a missing generator degrades to this message
        # instead of breaking every `cmax` import.
        from cmax import minimum_refresh
    except ImportError as exc:
        print(
            f"minimum refresh skipped: the minimum generator is unavailable ({exc}). "
            f"Continuing with the committed minimum table {path}.",
            flush=True,
        )
        return False
    writable = (
        os.access(path, os.W_OK) if path.exists() else os.access(path.parent, os.W_OK)
    )
    if not writable:
        print(
            f"minimum refresh could not write {path}: the installed minimum table is "
            "read-only, which is normal for a pip-installed wheel. Continuing "
            "with the committed minimum table. Run the refresh from a ClusterMAX "
            "checkout, or rely on the default startup fetch of the published "
            "table.",
            flush=True,
        )
        return False
    try:
        existing = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        existing = {}
    try:
        table = minimum_refresh.build_minimums(existing=existing or None)
    except (Exception, SystemExit) as exc:  # network, parse, or fail-closed abort
        print(
            f"minimum refresh failed: {exc}. Continuing with the committed minimum "
            f"table {path}.",
            flush=True,
        )
        return False
    if not isinstance(table, dict) or not table.get("components"):
        print(
            "minimum refresh failed: the generator returned no components. "
            f"Continuing with the committed minimum table {path}.",
            flush=True,
        )
        return False
    # The generator owns the committed rendering, so a refreshed table stays
    # byte-identical to what the daily pull request would land.
    serialize = getattr(minimum_refresh, "serialize", None)
    payload = (
        serialize(table)
        if callable(serialize)
        else json.dumps(table, indent=2, sort_keys=True) + "\n"
    )
    try:
        path.write_text(payload)
    except OSError as exc:
        print(
            f"minimum refresh could not write {path}: {exc}. Continuing with the "
            "committed minimum table.",
            flush=True,
        )
        return False
    changes = minimum_changes(existing, table)
    print(f"minimum table refreshed: {path}", flush=True)
    for line in changes or ["no change"]:
        print(f"  {line}", flush=True)
    return True
