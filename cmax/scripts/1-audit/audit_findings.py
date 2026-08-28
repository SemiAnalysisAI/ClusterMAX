#!/usr/bin/env python3
"""Immediate findings report for the cluster audit.

Scans the merged audit values (the `audit_data` blob produced by
`merge_audit.py` and written to `audit.values.json`) and surfaces every detected
"missing / not-installed / below-recommended / not-OK" condition as a list of
findings. Each finding carries the exact source key path, the observed value, the
source file, and a severity, so the operator can screenshot it and confront the
vendor while cluster access is still live.

Detection is data-driven: the conditions worth flagging live in `RULES` as a
declarative table, so adding a new check is one entry, not a new branch.
Detection (`detect_findings`) is a pure function kept separate from printing
(`format_report` / `print_report`) so the same findings can later feed other
outputs (a Markdown report, a CI exit code) without rework.

CLI: run standalone against an existing run output:

    python3 audit_findings.py runs/<slug>/<ts>/audit/audit.values.json

Findings are starting points for hands-on verification, not vendor-ready
conclusions on their own. Container-runtime checks are worker-scoped to avoid a
known false negative: when the worker container check could not run on a compute
node (``containers.workerCheckOk`` is false) the container.* booleans hold their
stale ``false`` defaults, which are inconclusive rather than evidence of
absence. Those checks are therefore guarded so a check that never ran downgrades
to an attestation-required note instead of a MISSING/critical finding, and a
working ``docker info`` nvidia runtime is never reported as "toolkit not
installed".
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import unquote, urlparse

# Severity / category tags. Kept as plain strings so findings serialize cleanly
# to JSON for any future Markdown / CI consumer.
MISSING = "MISSING"  # a component is absent / not installed
VERSION = "VERSION"  # present but below the recommended minimum version
CONFIG = "CONFIG"  # present but configured sub-optimally
ALL_HARNESSES = frozenset({"slurm", "k8s", "standalone"})
SCALE_OUT_HARNESSES = frozenset({"slurm", "k8s"})


@dataclass(frozen=True)
class Finding:
    """A single detected discrepancy, with the evidence to back it."""

    title: str
    severity: str
    key: str  # dotted path into audit_data, e.g. "containers.nvidiaContainerToolkit"
    value: Any  # the observed value at that key
    source: str = ""  # audit.values.json path; filled in by detect_findings
    detected: str = ""
    recommendation: str = ""
    cves: tuple[str, ...] = ()
    advisories: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "key": self.key,
            "value": self.value,
            "source": self.source,
        }


@dataclass(frozen=True)
class Rule:
    """A declarative check over the audit values.

    `key` is a dotted path into the `audit_data` blob. `failing` receives the
    value found at that path (or None when the key is absent) and returns True
    when the condition is worth flagging. A rule only fires when its key is
    present unless `flag_when_missing` is set, so an audit that simply did not
    check a component does not generate noise.

    `guard`, when set, receives the whole audit blob and must return True for the
    rule to fire. It lets a rule consult sibling facts (e.g. suppress a
    container "not installed" finding when the worker check never ran, or when a
    working nvidia runtime is already attested) without collapsing every check
    into a bespoke branch.
    """

    key: str
    title: str
    severity: str
    failing: Callable[[Any], bool]
    flag_when_missing: bool = False
    guard: Callable[[dict[str, Any]], bool] | None = None
    cves: tuple[str, ...] = ()
    harnesses: frozenset[str] = ALL_HARNESSES


def _is_false(value: Any) -> bool:
    """True when the value is a boolean-ish 'no'.

    Audit collectors emit both real booleans and stringified ones; treat the
    common 'no' spellings as false and anything else as not-failing.
    """
    if isinstance(value, bool):
        return value is False
    return str(value).strip().lower() in {"false", "0", "no"}


def _missing_string(value: Any) -> bool:
    """True when a string field signals an absent / unknown component."""
    return str(value).strip().lower() in {"", "none", "not-found", "unknown", "n/a"}


def _status_is(expected: str) -> Callable[[Any], bool]:
    return lambda value: str(value).strip().lower() == expected


def _is_true(value: Any) -> bool:
    """True when the value is a boolean-ish 'yes'."""
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() in {"true", "1", "yes"}


def _container_check_unavailable(audit: dict[str, Any]) -> bool:
    """True when the worker container check did not run on a compute node.

    The Slurm / K8s collectors emit ``containers.workerCheckOk`` = false when the
    srun / privileged-pod check could not be scheduled (no idle GPU node,
    inaccessible partition, timeout). The container.* booleans then hold their
    stale ``false`` defaults, which are inconclusive, not evidence of absence.
    """
    return _is_false(nested_get(audit, "containers", "workerCheckOk"))


def _nvidia_runtime_configured(audit: dict[str, Any]) -> bool:
    """True when ``docker info`` reports an nvidia runtime on the worker.

    This is how a working NVIDIA Container Toolkit is verified in practice, so a
    configured nvidia runtime must never be reported as "toolkit not installed".
    """
    return _is_true(nested_get(audit, "containers", "dockerNvidiaRuntimeConfigured"))


def _nvidia_toolkit_confirmed(audit: dict[str, Any]) -> bool:
    """True when the NVIDIA Container Toolkit is positively attested on a worker.

    Either the toolkit package/CLI was detected or ``docker info`` reports the
    nvidia runtime; in either case there is nothing left for the provider to
    attest, so the worker-check attestation note should stay silent.
    """
    return _is_true(nested_get(audit, "containers", "nvidiaContainerToolkit")) or _nvidia_runtime_configured(audit)


def _numeric_above(threshold: float) -> Callable[[Any], bool]:
    """Failing predicate for numeric sysctl-style fields.

    Collectors stringify numbers and record "unknown" when a value could not
    be read; a non-numeric value is not evidence of a failure, so it does not
    fire (the report's unverified path surfaces "unknown" separately).
    """

    def failing(value: Any) -> bool:
        try:
            return float(str(value).strip()) > threshold
        except ValueError:
            return False

    return failing


def _user_management_unusable(value: Any) -> bool:
    """True when useradd / groupadd were checked and either is unusable."""
    if not isinstance(value, dict):
        return False
    if "useradd" not in value and "groupadd" not in value:
        return False
    return not (_is_true(value.get("useradd")) and _is_true(value.get("groupadd")))


def _enroot_installed(audit: dict[str, Any]) -> bool:
    return _is_true(nested_get(audit, "containers", "enroot"))


def _perf_installed(audit: dict[str, Any]) -> bool:
    return _is_true(nested_get(audit, "software", "perf", "installed"))


def _dcgm_installed(audit: dict[str, Any]) -> bool:
    return _is_true(nested_get(audit, "healthChecks", "dcgmInstalled"))


def _pcie_acs_path_resolved(audit: dict[str, Any]) -> bool:
    """True when the GPU-NIC path switches were actually resolved.

    An unscoped read reports host-wide ACS state, which says nothing about the
    switches on the GPU-NIC path (and on a passthrough VM the real switch is
    hypervisor-side), so an "enabled" value only becomes a finding when the
    check scoped itself to the path.
    """
    return _is_true(nested_get(audit, "gpus", "pcieAcs", "scoped"))


def _is_amd_gpu(audit: dict[str, Any]) -> bool:
    """True when the audit positively identifies an AMD GPU.

    Slurm preserves NVIDIA-shaped compatibility fields on AMD clusters. Their
    false defaults are not evidence that an AMD system lacks its equivalent
    ROCm component, so NVIDIA-only findings must consult the positive AMD
    inventory before they fire.
    """
    return _is_true(nested_get(audit, "gpus", "amd", "present"))


def _not_amd_gpu(audit: dict[str, Any]) -> bool:
    """Guard for findings that apply only to NVIDIA or unknown GPU vendors."""
    return not _is_amd_gpu(audit)


def _ncu_install_verdict_available(audit: dict[str, Any]) -> bool:
    """True unless the NCU check ended without an installation verdict.

    Kubernetes initializes ``software.ncu.installed`` to false before it tries
    to start the GPU check pod. When admission, compilation, or the check image
    fails, that default is missing data. It must not become a provider finding.
    Older audits without a counter-access result keep their original behavior.
    """
    access = nested_get(audit, "software", "ncu", "hardwareCounterAccess")
    if access is None:
        return True
    normalized = str(access).strip().lower()
    if normalized == "no-ncu":
        return not isinstance(nested_get(audit, "kubernetes"), dict)
    inconclusive = {
        "compile-failed",
        "pod-failed",
        "resource-unavailable",
        "untested",
        "unknown",
    }
    return normalized not in inconclusive


def _vboost_check_unavailable(audit: dict[str, Any]) -> bool:
    """True when the vboost check never executed nvidia-smi anywhere.

    The check aggregates to ``gpu_controls.vboost.status`` = "unavailable" when
    every per-node result is a check failure (nvidia-smi missing, a stub /
    wrong-arch binary raising OSError, or a timeout), e.g. the GCore Soperator
    login node the audit falls back to outside an allocation. The sibling
    ``allowed`` = false is then missing data, not a provider denial, so the
    "not allowed" finding must stay silent.
    """
    status = nested_get(audit, "gpu_controls", "vboost", "status")
    return str(status).strip().lower() == "unavailable"


# GPU models with no vboost slider: B300 and GB300 (with or without a vendor
# prefix or an SXM/NVL suffix, e.g. "NVIDIA-B300-SXM6-AC", "GB300 NVL72").
_VBOOST_UNSUPPORTED_GPU_RE = re.compile(r"\bg?b300\b", re.IGNORECASE)


def _vboost_unsupported_gpu(audit: dict[str, Any]) -> bool:
    """True when the deployed GPU exposes no vboost slider at all.

    B300 and GB300 do not implement the ``nvidia-smi boost-slider --vboost``
    interface: the command returns "Invalid Argument" on every node no matter
    what the provider allows (observed on Crusoe and CoreWeave HGX B300
    workers and on Google and GMI GB300 NVL72). The resulting
    ``allowed=false`` is a hardware capability gap, not a provider policy
    block, so the "not allowed" finding must stay silent on these GPUs.
    """
    model = nested_get(audit, "gpus", "model")
    return isinstance(model, str) and bool(_VBOOST_UNSUPPORTED_GPU_RE.search(model))


# Container-check outcomes that mean "the launcher was never asked", as opposed
# to "this harness has no launcher to ask". On Slurm the audit is expected to
# read the mount, so a vantage that failed leaves a real question open and the
# operator has to get the answer from the provider while access is live.
_TOPO_CHECK_UNVERIFIED_CODES = frozenset(
    {"launch_failed", "check_incomplete", "no_allocation", "no_srun", "check_disabled"}
)


def _topo_container_check_did_not_run(audit: dict[str, Any]) -> bool:
    """True when a host topology file exists but the container arm never read it.

    The k8s and standalone harnesses have no pyxis launcher at all, so they
    report ``no_launcher_on_harness`` and are silent here: nothing is pending
    from the provider on a harness the check does not cover. A Slurm run whose
    srun step could not start is different - the mount is unverified, not
    absent - and PR #1357 established that such a gap becomes an
    attestation-required note rather than a finding against the provider.
    """
    reason_code = str(nested_get(audit, "nccl_topo_file", "container", "reason_code") or "").strip()
    return reason_code in _TOPO_CHECK_UNVERIFIED_CODES


def _missing_modern_gpudirect_path(value: Any) -> bool:
    """Flag only when neither direct dma_buf nor nvidia-open is detected.

    The Slurm audit accepts nvidia-open as the modern GPUDirect path because
    current open kernel modules expose dma_buf support even when the narrower
    sysfs-hook check does not find a path named ``dma_buf*``.
    """
    if not isinstance(value, dict):
        return False
    if "dmaBuf" not in value and "nvidiaOpen" not in value:
        return False
    return not (_is_true(value.get("dmaBuf")) or _is_true(value.get("nvidiaOpen")))


def _modern_gpudirect_path_present(audit: dict[str, Any]) -> bool:
    """True when a modern GPUDirect path (dma_buf or nvidia-open) is detected.

    Used to suppress the legacy nvidia_peermem finding when a modern path is
    also available: the two paths coexist safely, and consumers such as NCCL
    select dma_buf automatically when it is supported
    (NCCL_DMABUF_ENABLE defaults to 1; registration falls through to the
    peermem GDR path only when dma_buf is unavailable). A loaded
    nvidia_peermem module alongside dma_buf is therefore not a misconfiguration
    and may still be required by legacy verbs consumers.
    """
    path = nested_get(audit, "gpus", "gpuDirectRdmaPath")
    if not isinstance(path, dict):
        return False
    return _is_true(path.get("dmaBuf")) or _is_true(path.get("nvidiaOpen"))


def _virtio_latent_exposure(audit: dict[str, Any]) -> bool:
    """True when firmware is installed on an idle controller, in NIC mode.

    Four different outcomes reach this state, and they must not share a title.
    A below-minimum version was read; or no version could be read at all; or a
    version was read and could not be graded, because the release lines
    interleave and the collector did not report the line; or nothing was
    compared at all, because the minimum table this audit ships is unusable. In
    all four the card is in NIC mode, so the firmware is installed and idle and
    a mode change would run it. The exposure is identical, what was proven is
    not.

    `_virtio_minimums_unavailable` is the first axis: when no comparison happened,
    no other description of the reading means anything, so it is excluded from
    the other three guards rather than competing with them. Within the rest,
    `_virtio_version_proven` and `_virtio_below_minimum` split what remains. Four
    latent rules are guarded on those so exactly one fires: unusable table,
    proven below minimum, unread, and read-but-ungraded.

    The unread and read-but-ungraded rules carry the attestation ask. The
    proven below-minimum rule does not: it states a proven failure, and there is
    nothing left for the provider to attest. The unusable-table rule
    deliberately does not either: nothing was compared because of a fault on
    our side, and an attestation cannot be graded until the table is repaired.
    The plain attestation note is guarded off this whole state, and off the
    unusable-table state outside it, because each of the four already carries
    the mode-change risk that note lacks.
    """
    exposure = nested_get(audit, "securityVersions", "virtioNetBluefield", "exposure")
    return str(exposure).strip().lower() == "latent"


def _virtio_below_minimum(audit: dict[str, Any]) -> bool:
    """True when the read version was proved below its own minimum.

    `floorStatus` is the firmware's grade against its minimum, recorded before any
    coverage rule and independent of the platform mode. The verdict status is
    not a substitute: the coverage rule withdraws a clean answer to "unknown",
    so a patched controller beside an unread peer reaches the same status as an
    unproven one.
    """
    status = nested_get(audit, "securityVersions", "virtioNetBluefield", "floorStatus")
    return (
        str(status).strip().lower() == "fail"
        and not _minimum_grace_active(audit, "virtioNetBluefield")
    )


def _minimum_grace_active(audit: dict[str, Any], component: str) -> bool:
    """True when the authoritative version result records an active grace."""
    status = nested_get(audit, "securityVersions", component, "status")
    grace = nested_get(audit, "securityVersions", component, "gracePeriod")
    return (
        str(status).strip().lower() == "pass"
        and isinstance(grace, dict)
        and grace.get("active") is True
    )


def _virtio_latent_below_minimum(audit: dict[str, Any]) -> bool:
    """Idle firmware the audit proved is below its minimum. Both halves proven.

    The unusable-table exclusion is stated rather than inherited. Nothing is
    proven below a minimum that was never read, and today `floorStatus` cannot be
    "fail" in that state, but that is an invariant in another module and this
    partition should not depend on it.
    """
    return (
        not _virtio_minimums_unavailable(audit)
        and _virtio_latent_exposure(audit)
        and _virtio_version_proven(audit)
        and _virtio_below_minimum(audit)
    )


def _virtio_latent_unread(audit: dict[str, Any]) -> bool:
    """Idle firmware whose version could not be read at all.

    Excludes the unusable-table state explicitly. `_virtio_running_verdict`
    returns the minimums-unavailable verdict before it parses the version, so an
    unread version also carries the sentinel and this guard overlapped the table
    rule, firing two contradictory findings for one record.
    """
    return (
        not _virtio_minimums_unavailable(audit)
        and _virtio_latent_exposure(audit)
        and not _virtio_version_proven(audit)
    )


# The `minimum` a verdict carries when the minimum table itself could not be read.
# Mirrors MINIMUMS_UNAVAILABLE in security_version_audit.py, which travels into the
# record through `asdict(verdict)`. A Finding carries only a title, a key and an
# observed value, so the verdict's corrected detail never reaches this block and
# the state has to be recognised here from the record.
MINIMUMS_UNAVAILABLE = "unavailable"


def _virtio_minimums_unavailable(audit: dict[str, Any]) -> bool:
    """True when nothing was compared, because the minimum table is unusable."""
    minimum = nested_get(audit, "securityVersions", "virtioNetBluefield", "minimum")
    return str(minimum).strip().lower() == MINIMUMS_UNAVAILABLE


def _virtio_latent_ungraded(audit: dict[str, Any]) -> bool:
    """Idle firmware whose version was read and could not be graded upstream.

    One of the owners of the latent state. The GA and newest LTS release lines
    share a year.month prefix and are fixed at different patches, so a version
    inside that window cannot be graded unless the collector reports the line;
    `_virtio_running_verdict` reports it as unknown, which leaves `floorStatus`
    neither "fail" nor "pass". An ungraded version is exactly as unproven as an
    unread one, so this state carries the same mode-change warning, and it may
    never carry the below-minimum accusation, which only a proven minimum failure
    earns.

    An unusable minimum table produces the same triple and is excluded here: it is
    not a release-line ambiguity, and asking a provider to attest a release line
    for it points at the wrong party. `_virtio_latent_unusable_table` owns it.
    """
    return (
        not _virtio_minimums_unavailable(audit)
        and not _minimum_grace_active(audit, "virtioNetBluefield")
        and _virtio_latent_exposure(audit)
        and _virtio_version_proven(audit)
        and not _virtio_below_minimum(audit)
    )


def _virtio_version_proven(audit: dict[str, Any]) -> bool:
    """True when a controller version was actually read and graded.

    Claiming firmware is below a security minimum is a vendor-facing
    accusation, so it may only be made from a version the audit read. The
    record marks an unread version with `versionUnavailableReason`
    ("not-observed" or "dpu-hardened"), which is None once a version grades.
    """
    block = nested_get(audit, "securityVersions", "virtioNetBluefield")
    if not isinstance(block, dict):
        return False
    if block.get("versionUnavailableReason"):
        return False
    return not _missing_string(block.get("gradedVersion"))


def _bluefield_observed(audit: dict[str, Any]) -> bool:
    """True when the audit holds positive evidence of a BlueField DPU.

    Most clusters have none. An attestation-required note on every one of them
    would train readers to skip the whole block, so the DPU "could not be
    verified" rules fire only when a BlueField was actually seen. A proven
    failure is never guarded this way.
    """
    if _is_true(nested_get(audit, "securityVersions", "dpuHostIsolation", "bluefieldPresent")):
        return True
    mode = nested_get(audit, "securityVersions", "virtioNetBluefield", "platformMode")
    if str(mode).strip().lower() in {"dpu", "nic"}:
        return True
    # A controller version can only be read off a BlueField.
    return not _missing_string(
        nested_get(audit, "securityVersions", "virtioNetBluefield", "gradedVersion")
    )


def _bluefield_absence_proven(audit: dict[str, Any]) -> bool:
    """True only when a completed inventory found no BlueField device."""
    isolation = nested_get(audit, "securityVersions", "dpuHostIsolation")
    if isinstance(isolation, dict):
        if (
            isolation.get("scanComplete") is True
            and isolation.get("bluefieldPresent") is False
        ):
            return True
    controller = nested_get(audit, "securityVersions", "virtioNetBluefield")
    if isinstance(controller, dict):
        status = str(controller.get("status") or "").strip().lower()
        return status in {"not_applicable", "not-applicable"}
    return False


# Declarative rule set. To add a check, append a Rule. Keys are dotted paths into
# the audit_data blob (see runs/<slug>/<ts>/audit/audit.values.json).
RULES: tuple[Rule, ...] = (
    # --- Advisory-backed host security versions -------------------------
    Rule(
        "securityVersions.nvidiaDriver.status",
        "NVIDIA driver below security minimum",
        VERSION,
        _status_is("fail"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.nvidiaDriver.status",
        "NVIDIA driver security minimum could not be verified",
        CONFIG,
        _status_is("unknown"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.nvidiaContainerToolkit.status",
        "NVIDIA Container Toolkit below security minimum",
        VERSION,
        _status_is("fail"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.nvidiaContainerToolkit.status",
        "Host NVIDIA Container Toolkit version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.cudaToolkit.status",
        "CUDA Toolkit below security minimum",
        VERSION,
        _status_is("fail"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.cudaToolkit.status",
        "CUDA Toolkit security minimum could not be verified",
        CONFIG,
        _status_is("unknown"),
        guard=_not_amd_gpu,
    ),
    Rule(
        "securityVersions.runc.status",
        "runc below security minimum",
        VERSION,
        _status_is("fail"),
    ),
    Rule(
        "securityVersions.runc.status",
        "Host runc version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
    ),
    Rule(
        "securityVersions.docker.status",
        "Docker Engine below security minimum",
        VERSION,
        _status_is("fail"),
    ),
    Rule(
        "securityVersions.docker.status",
        "Host Docker version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
    ),
    Rule(
        "securityVersions.connectxFirmware.status",
        "ConnectX firmware below security minimum",
        VERSION,
        _status_is("fail"),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.connectxFirmware.status",
        "ConnectX firmware security minimum could not be verified",
        CONFIG,
        _status_is("unknown"),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.dcgm.status",
        "DCGM below security minimum",
        VERSION,
        _status_is("fail"),
    ),
    Rule(
        "securityVersions.dcgm.status",
        "DCGM version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
    ),
    Rule(
        "securityVersions.dcgmExporter.status",
        "DCGM Exporter below security minimum",
        VERSION,
        _status_is("fail"),
    ),
    Rule(
        "securityVersions.dcgmExporter.status",
        "DCGM Exporter version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
    ),
    # --- BlueField DPU ----------------------------------------------------
    # The controller firmware check has four reportable states, not two. A
    # below-minimum controller in DPU mode is running and fails. The same firmware
    # in NIC mode is idle, so the verdict softens to a warning, and without the
    # exposure rules below it would leave the findings block entirely. An idle
    # card whose version was unread, and one whose version was read and could
    # not be graded against a single release line, are equally unproven, so each
    # gets its own rule and both keep the mode-change warning. Only an unknown
    # outside the latent state stays a plain attestation note.
    Rule(
        "securityVersions.virtioNetBluefield.status",
        "BlueField VIRTIO-Net controller below security minimum",
        VERSION,
        _status_is("fail"),
        cves=("CVE-2026-65094",),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.exposure",
        "BlueField VIRTIO-Net controller is below its security minimum but not "
        "running (NIC mode): not immediately urgent, a switch to DPU mode would "
        "activate it (CVE-2026-65094)",
        CONFIG,
        _status_is("latent"),
        guard=_virtio_latent_below_minimum,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.exposure",
        "BlueField VIRTIO-Net controller version could not be read and the card "
        "is in NIC mode, so nothing is running now: not immediately urgent, a "
        "switch to DPU mode would activate whatever firmware is installed. "
        "Request provider attestation of the controller version (CVE-2026-65094)",
        CONFIG,
        _status_is("latent"),
        guard=_virtio_latent_unread,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.exposure",
        "BlueField VIRTIO-Net controller version was read and could not be "
        "graded against a single release line, and the card is in NIC mode, so "
        "nothing is running now: not immediately urgent, a switch to DPU mode "
        "would activate firmware nothing proves is patched. Request provider "
        "attestation of the controller release line (CVE-2026-65094)",
        CONFIG,
        _status_is("latent"),
        guard=_virtio_latent_ungraded,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.exposure",
        "BlueField VIRTIO-Net controller firmware was not compared against any "
        "minimum, because the minimum version table this audit ships is unusable, "
        "and the card is in NIC mode, so nothing is running now: not immediately "
        "urgent, a switch to DPU mode would activate firmware nothing proves is "
        "patched. Repair the minimum table and run the audit again; this is a "
        "ClusterMAX fault and needs no provider action (CVE-2026-65094)",
        CONFIG,
        _status_is("latent"),
        guard=lambda audit: _virtio_minimums_unavailable(audit)
        and _virtio_latent_exposure(audit),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.status",
        "BlueField VIRTIO-Net controller firmware was not compared against any "
        "minimum, because the minimum version table this audit ships is unusable. "
        "Repair the minimum table and run the audit again; this is a ClusterMAX "
        "fault and needs no provider action (CVE-2026-65094)",
        CONFIG,
        _status_is("unknown"),
        # The running-controller variant of the rule above. A card in DPU or
        # unknown mode with an unusable table grades exposure "unknown" rather
        # than "latent", so the latent rules do not reach it, and it fell to the
        # attestation note below: a provider asked to attest a version the audit
        # already holds, for a fault on our side. An attestation cannot be
        # graded until the table is repaired.
        guard=lambda audit: _virtio_minimums_unavailable(audit)
        and not _virtio_latent_exposure(audit)
        and not _bluefield_absence_proven(audit),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.virtioNetBluefield.status",
        "BlueField VIRTIO-Net controller version requires provider attestation",
        CONFIG,
        _status_is("unknown"),
        # Suppressed across the whole latent state, because the four latent
        # rules above partition it and each one carries the mode-change warning
        # this note lacks, and across the unusable-table state, which the rule
        # above owns and which is not a question for the provider at all. This
        # note owns every remaining unknown: an unreadable version on a DPU-mode
        # or unknown-mode card, and a fleet a coverage gap left uncleared.
        guard=lambda audit: not _virtio_latent_exposure(audit)
        and not _virtio_minimums_unavailable(audit)
        and not _bluefield_absence_proven(audit),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.dpuHostIsolation.status",
        "Host side can reach the BlueField DPU control plane: not in zero-trust "
        "mode; apply mlxprivhost r --disable_rshim --disable_tracer "
        "--disable_counter_rd --disable_port_owner",
        CONFIG,
        _status_is("fail"),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "securityVersions.dpuHostIsolation.status",
        "DPU host isolation could not be verified (mlxconfig usually needs "
        "root); requires provider attestation",
        CONFIG,
        _status_is("unknown"),
        guard=lambda audit: not _bluefield_absence_proven(audit),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    # --- Hypervisor security bulletins ----------------------------------
    Rule(
        "security.januscape.status",
        "Nested virtualization exposes Januscape prerequisites",
        CONFIG,
        _status_is("host-patch-required"),
        cves=("CVE-2026-53359",),
    ),
    Rule(
        "security.januscape.status",
        "Januscape exposure could not be verified",
        CONFIG,
        _status_is("unknown"),
        cves=("CVE-2026-53359",),
    ),
    Rule(
        "security.guestKernel.newerInstalled",
        "Newer guest/worker kernel installed but not running; reboot required",
        VERSION,
        lambda value: value is True or str(value).strip().lower() in {"true", "1", "yes"},
    ),
    Rule(
        "security.fragnesia.status",
        "Running kernel is exposed to Fragnesia and Dirty Frag",
        VERSION,
        _status_is("fail"),
        cves=("CVE-2026-46300", "CVE-2026-43284", "CVE-2026-43500"),
    ),
    # --- Containers -------------------------------------------------------
    # These checks are worker-scoped. A `false` value produced only because the
    # worker check never ran (containers.workerCheckOk == false) is inconclusive,
    # so the "not installed" / "below version" rules are guarded to fire only
    # when the check ran; the workerCheckOk rule below turns that gap into an
    # attestation-required note. A configured `docker info` nvidia runtime also
    # suppresses the "toolkit not installed" finding.
    Rule(
        "containers.nvidiaContainerToolkit",
        "NVIDIA Container Toolkit not installed",
        MISSING,
        _is_false,
        guard=lambda audit: _not_amd_gpu(audit)
        and not _container_check_unavailable(audit)
        and not _nvidia_runtime_configured(audit),
    ),
    Rule(
        "containers.workerCheckOk",
        "Worker container check could not run - container runtime unverified from this vantage; requires provider attestation (not evidence of absence)",
        CONFIG,
        _is_false,
        guard=lambda audit: not _nvidia_toolkit_confirmed(audit),
    ),
    Rule(
        "containers.pyxisRuntimeWorks",
        "Slurm does not expose the Pyxis command-line options",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    # --- Compilers / toolchains ------------------------------------------
    Rule(
        "software.nvhpc.status",
        "NVIDIA HPC SDK is incomplete or outside the supported release window",
        VERSION,
        _status_is("fail"),
        guard=_not_amd_gpu,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "software.ncu.installed",
        "Nsight Compute (ncu) not installed",
        MISSING,
        _is_false,
        guard=lambda audit: _not_amd_gpu(audit) and _ncu_install_verdict_available(audit),
    ),
    Rule(
        "software.ncu.profilingEnabled",
        "Nsight Compute profiling is not enabled for the audited user",
        CONFIG,
        _is_false,
        guard=lambda audit: _not_amd_gpu(audit)
        and _is_true(nested_get(audit, "software", "ncu", "installed")),
    ),
    Rule(
        "software.lmod.modulesStatus",
        "Slurm provides no GPU or fabric software modules through Lmod",
        CONFIG,
        _status_is("fail"),
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "software.cudaVisibleDevicesStatus",
        "CUDA_VISIBLE_DEVICES is not configured by the scheduler",
        CONFIG,
        _status_is("fail"),
        harnesses=frozenset({"slurm", "k8s"}),
    ),
    # --- GPUDirect / RDMA -------------------------------------------------
    Rule(
        "gpus.gdrcopy.installed",
        "GDRCopy not installed",
        MISSING,
        _is_false,
        guard=_not_amd_gpu,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "gpus.gpuDirectRdmaPath",
        "GPUDirect RDMA lacks a modern dma_buf-capable driver path",
        CONFIG,
        _missing_modern_gpudirect_path,
        guard=_not_amd_gpu,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy",
        "Deprecated nvidia_peermem in use instead of dma_buf",
        CONFIG,
        # This one flags when TRUE (legacy path active), so invert _is_false.
        lambda value: value is True or str(value).strip().lower() in {"true", "1", "yes"},
        # Only fire when peermem is the ONLY GPUDirect path. When dma_buf or
        # nvidia-open is also present, the driver and consumers (e.g. NCCL)
        # select dma_buf automatically, so a loaded nvidia_peermem module is
        # harmless and may still serve legacy verbs consumers.
        guard=lambda audit: _not_amd_gpu(audit)
        and not _modern_gpudirect_path_present(audit),
        harnesses=SCALE_OUT_HARNESSES,
    ),
    # --- GPU controls -----------------------------------------------------
    Rule(
        "gpu_controls.vboost.allowed",
        "Vboost not enabled / not allowed",
        CONFIG,
        _is_false,
        guard=lambda audit: _not_amd_gpu(audit)
        and not _vboost_check_unavailable(audit)
        and not _vboost_unsupported_gpu(audit),
    ),
    # --- GPU HBM memory exposure -------------------------------------------
    # The Tier-0 hbm_memory_exposure check (see tests/AUDIT-CRITERIA.md) applies
    # only to coherent NVIDIA GPU platforms. It fails when GPU HBM is handed to
    # the OS as ordinary NUMA memory or the driver is not in CDMM mode. Kubelet
    # CPU Manager policy has a separate advisory result below.
    Rule(
        "hbm_memory_exposure.status",
        "GPU HBM exposed as ordinary OS-managed system memory",
        CONFIG,
        _status_is("fail"),
    ),
    Rule(
        "hbm_memory_exposure.status",
        "HBM memory exposure check reported an advisory warning; verify hands-on",
        CONFIG,
        _status_is("warning"),
    ),
    Rule(
        "kubelet_cpu_manager_policy.status",
        "Kubelet CPU Manager policy advisory; use static for GPU workload isolation",
        CONFIG,
        _status_is("warning"),
        harnesses=frozenset({"k8s"}),
    ),
    Rule(
        "kubelet_cpu_manager_policy.status",
        "Kubelet CPU Manager policy could not be checked on any Kubernetes GPU host",
        CONFIG,
        _status_is("unknown"),
        harnesses=frozenset({"k8s"}),
    ),
    # --- NVIDIA Exemplar Cloud platform checks -----------------------------
    # The platform configuration checks report not_applicable when a check does
    # not cover the platform and unknown when the platform is not readable, so
    # only fail and warning reach this block.
    Rule(
        "vm_iommu.status",
        "GPU / RDMA devices use full IOMMU DMA translation instead of passthrough",
        CONFIG,
        _status_is("warning"),
    ),
    Rule(
        "arm_smmu_virtualization.status",
        "Arm virtual machine guest has no SMMU command queue virtualization (CMDQV / VCMDQ)",
        CONFIG,
        _status_is("warning"),
    ),
    Rule(
        "nccl_topo_file.status",
        "Host NCCL topology file does not reach the benchmark container",
        CONFIG,
        _status_is("fail"),
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "nccl_topo_file.status",
        "Host NCCL topology file is present but the container mount is unverified; requires provider attestation",
        CONFIG,
        _status_is("unknown"),
        guard=_topo_container_check_did_not_run,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "nccl_ib_qps.status",
        "NCCL_IB_QPS_PER_CONNECTION is at the default on a multi-tier Clos fabric; sweep it (advisory)",
        CONFIG,
        _status_is("warning"),
        harnesses=frozenset({"slurm", "k8s"}),
    ),
    # --- Networking -------------------------------------------------------
    Rule(
        "networking.topologyConfigured",
        "No topology-aware scheduling configuration detected",
        CONFIG,
        _is_false,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "networking.hcaNamingValid",
        "Non-standard HCA / NIC device naming",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    # --- Storage ----------------------------------------------------------
    Rule(
        "storage.rwxStatus",
        "Kubernetes has no working ReadWriteMany persistent storage",
        CONFIG,
        _status_is("fail"),
        harnesses=frozenset({"k8s"}),
    ),
    # --- Health / monitoring ---------------------------------------------
    Rule(
        "healthChecks.nhcInstalled",
        "Node Health Check (NHC) not installed",
        MISSING,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "healthChecks.monitoringStack.dcgmExporter",
        "DCGM exporter not installed",
        MISSING,
        _is_false,
        guard=_not_amd_gpu,
        harnesses=SCALE_OUT_HARNESSES,
    ),
    Rule(
        "healthChecks.dcgmInstalled",
        "DCGM not installed",
        MISSING,
        _is_false,
        guard=_not_amd_gpu,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "healthChecks.dcgmSlurm",
        "DCGM is installed but not wired into the Slurm HealthCheckProgram",
        CONFIG,
        _is_false,
        guard=lambda audit: _not_amd_gpu(audit) and _dcgm_installed(audit),
        harnesses=frozenset({"slurm"}),
    ),
    # --- Access and identity (dashboard criteria parity, PR batch 1) --------
    Rule(
        "access.sudoAvailable",
        "Passwordless sudo is not available to the audited user",
        CONFIG,
        _is_false,
    ),
    Rule(
        "access.userManagement",
        "User and group management commands are not usable (useradd / groupadd)",
        CONFIG,
        _user_management_unusable,
    ),
    Rule(
        "access.sshToComputeNodes",
        "Compute nodes are not reachable over passwordless SSH",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "access.externalIdp.detected",
        "No external identity provider (OIDC / OAuth2 SSO) integration detected",
        CONFIG,
        _is_false,
    ),
    Rule(
        "access.slurmCommandsOk",
        "Core Slurm commands (sinfo / squeue / scontrol / sbatch / srun) are not functional",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    # --- Scheduler accounting ----------------------------------------------
    Rule(
        "slurm.accounting.sacctAvailable",
        "Slurm job accounting (sacct) is not available",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
    # --- Container runtimes (worker-scoped, same guard rationale as above) --
    Rule(
        "containers.enroot",
        "Enroot not installed",
        MISSING,
        _is_false,
        guard=lambda audit: not _container_check_unavailable(audit),
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "containers.enrootImportWorks",
        "Enroot is installed but 'enroot import' did not work",
        CONFIG,
        _is_false,
        guard=_enroot_installed,
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "containers.dockerOnWorkers",
        "Docker not installed on worker nodes",
        MISSING,
        _is_false,
        guard=lambda audit: not _container_check_unavailable(audit),
        harnesses=frozenset({"slurm"}),
    ),
    Rule(
        "containers.singularity",
        "Singularity / Apptainer not installed",
        MISSING,
        _is_false,
        guard=lambda audit: not _container_check_unavailable(audit),
        harnesses=frozenset({"slurm"}),
    ),
    # --- Software stack ------------------------------------------------------
    Rule(
        "software.nccl.installed",
        "NCCL not installed",
        MISSING,
        _is_false,
        guard=_not_amd_gpu,
    ),
    Rule(
        "software.perf.installed",
        "perf (Linux performance counters) not installed",
        MISSING,
        _is_false,
    ),
    Rule(
        "software.perf.perfEventParanoid",
        "perf_event_paranoid restricts unprivileged perf profiling (expected <= 1)",
        CONFIG,
        _numeric_above(1),
        guard=_perf_installed,
    ),
    Rule(
        "software.perf.kptrRestrict",
        "kptr_restrict hides kernel symbols from perf (expected 0)",
        CONFIG,
        _numeric_above(0),
        guard=_perf_installed,
    ),
    # --- GPU stack -----------------------------------------------------------
    Rule(
        "gpus.pcieAcs.enabled",
        "PCIe ACS is enabled on the GPU-NIC path switches",
        CONFIG,
        _status_is("true"),
        guard=_pcie_acs_path_resolved,
    ),
    # --- Networking / fabric -------------------------------------------------
    # No idle-thermals, fabric-class, or ib-tenant-isolation rules yet: the
    # collectors emit only raw thermal readings (per-class idle ceilings such
    # as Blackwell's 250 W / Grace-Blackwell's 300 W live in the slurm
    # collector log, not the values JSON), only a real fabric class or
    # "unknown" (never a "none" fail sentinel), and only "pass"/"unknown" for
    # ibTenantIsolation (an ibhosts listing, not an isolation verdict). Rules
    # for those criteria would either false-fail healthy Blackwell parts or
    # never fail at all; they stay in the parity KNOWN_GAPS allowlist until
    # the collectors emit graded verdict fields.
    Rule(
        "networking.ncclAutoConfig",
        "NCCL auto-configuration is overridden in /etc/nccl.conf",
        CONFIG,
        _is_false,
        harnesses=frozenset({"slurm"}),
    ),
)


# --- Guard suppression classification ----------------------------------
# A guard that keeps a matched failing value out of the findings does so for
# one of three reasons, and a report must not present them alike: the check
# does not apply to this hardware or configuration at all; sibling evidence
# already proves the checked property, so nothing failed; or the check never
# produced a verdict, so the value is unverified. The report renders these as
# a not-applicable skip, a pass, and an unverified skip respectively.
NOT_APPLICABLE_KIND = "not_applicable"
VERIFIED_KIND = "verified_ok"
UNVERIFIED_KIND = "unverified"


@dataclass(frozen=True)
class GuardReason:
    """Names why a guard suppressed a matched failing value.

    `predicate` receives the audit blob and returns True when this reason is
    the one that held the rule back. Reasons for one key are ordered, and the
    first that holds wins, mirroring the short-circuit order of the guard the
    rule carries.
    """

    predicate: Callable[[dict[str, Any]], bool]
    kind: str
    reason: str


_AMD_HARDWARE = GuardReason(
    _is_amd_gpu,
    NOT_APPLICABLE_KIND,
    "An AMD GPU is present, so this NVIDIA-specific check does not apply to "
    "this hardware.",
)

_NO_BLUEFIELD = GuardReason(
    _bluefield_absence_proven,
    NOT_APPLICABLE_KIND,
    "No BlueField DPU was observed, so this check does not apply to this "
    "configuration.",
)

# Ordered suppression reasons for every guarded rule key. Kept beside RULES so
# a new guard lands with its classification; keys without an entry (or whose
# clauses all miss) fall back to the unverified skip.
GUARD_SUPPRESSIONS: dict[str, tuple[GuardReason, ...]] = {
    "securityVersions.nvidiaDriver.status": (_AMD_HARDWARE,),
    "securityVersions.nvidiaContainerToolkit.status": (_AMD_HARDWARE,),
    "securityVersions.cudaToolkit.status": (_AMD_HARDWARE,),
    # The four latent-exposure rules partition the latent state; the only way
    # all of them stay silent on a matched "latent" value is an active grace
    # period, which the authoritative version verdict records as a pass.
    "securityVersions.virtioNetBluefield.exposure": (
        GuardReason(
            lambda audit: _minimum_grace_active(audit, "virtioNetBluefield"),
            VERIFIED_KIND,
            "An active grace period covers the installed BlueField VIRTIO-Net "
            "firmware, so the idle exposure is within the published minimum.",
        ),
    ),
    "securityVersions.virtioNetBluefield.status": (_NO_BLUEFIELD,),
    "securityVersions.dpuHostIsolation.status": (_NO_BLUEFIELD,),
    "containers.nvidiaContainerToolkit": (
        _AMD_HARDWARE,
        GuardReason(
            _nvidia_runtime_configured,
            VERIFIED_KIND,
            "docker info reports the nvidia runtime on the worker, which "
            "verifies a working NVIDIA Container Toolkit.",
        ),
        GuardReason(
            _container_check_unavailable,
            UNVERIFIED_KIND,
            "The worker container check never ran, so this value is "
            "unverified rather than evidence of absence.",
        ),
    ),
    "containers.workerCheckOk": (
        GuardReason(
            _nvidia_toolkit_confirmed,
            VERIFIED_KIND,
            "The NVIDIA Container Toolkit is positively attested on the "
            "worker, so nothing is left for the provider to attest.",
        ),
    ),
    "software.nvhpc.status": (_AMD_HARDWARE,),
    "software.ncu.installed": (
        _AMD_HARDWARE,
        GuardReason(
            lambda audit: not _ncu_install_verdict_available(audit),
            UNVERIFIED_KIND,
            "The NCU check ended without an installation verdict, so this "
            "value is unverified rather than evidence of absence.",
        ),
    ),
    # A missing NCU install only makes the profiling check inapplicable when
    # that absence is conclusively established. The same verdicts that hold
    # the installation finding back (pod-failed, compile-failed, untested,
    # unknown, or a Kubernetes run whose check pod never ran) leave installed
    # = false as an unfilled default, so the profiling row is then unverified
    # - mirroring the unverified skip on the companion installation row.
    "software.ncu.profilingEnabled": (
        _AMD_HARDWARE,
        GuardReason(
            lambda audit: (
                not _is_true(nested_get(audit, "software", "ncu", "installed"))
                and _ncu_install_verdict_available(audit)
            ),
            NOT_APPLICABLE_KIND,
            "Nsight Compute is not installed, so its profiling permissions do "
            "not apply; the separate installation check reports that gap.",
        ),
        GuardReason(
            lambda audit: not _is_true(
                nested_get(audit, "software", "ncu", "installed")
            ),
            UNVERIFIED_KIND,
            "The NCU check ended without an installation verdict, so whether "
            "profiling permissions apply is unverified rather than evidence "
            "of absence.",
        ),
    ),
    "software.nccl.installed": (_AMD_HARDWARE,),
    "gpus.gdrcopy.installed": (_AMD_HARDWARE,),
    "gpus.gpuDirectRdmaPath": (_AMD_HARDWARE,),
    "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy": (
        _AMD_HARDWARE,
        GuardReason(
            _modern_gpudirect_path_present,
            VERIFIED_KIND,
            "The audit found a modern GPUDirect path, so the loaded "
            "nvidia_peermem module does not indicate a legacy-only configuration.",
        ),
    ),
    "gpu_controls.vboost.allowed": (
        _AMD_HARDWARE,
        GuardReason(
            _vboost_check_unavailable,
            UNVERIFIED_KIND,
            "The vBoost check never executed nvidia-smi on any node, so this "
            "value is unverified rather than a provider denial.",
        ),
    ),
    "nccl_topo_file.status": (
        GuardReason(
            lambda audit: not _topo_container_check_did_not_run(audit),
            NOT_APPLICABLE_KIND,
            "This harness has no container launcher for the topology mount, "
            "so nothing is pending from the provider.",
        ),
    ),
    "healthChecks.monitoringStack.dcgmExporter": (_AMD_HARDWARE,),
    "healthChecks.dcgmInstalled": (_AMD_HARDWARE,),
    "healthChecks.dcgmSlurm": (_AMD_HARDWARE,),
}


def classify_suppression(key: str, audit: dict[str, Any]) -> tuple[str, str]:
    """Name why the guards kept a matched failing value out of the findings.

    Returns ``(kind, reason)`` where kind is one of NOT_APPLICABLE_KIND,
    VERIFIED_KIND, or UNVERIFIED_KIND. Reads only the audit blob and the rule
    key - never a report profile - so both audit commands classify a
    suppressed value identically.
    """
    for clause in GUARD_SUPPRESSIONS.get(key, ()):
        if clause.predicate(audit):
            return clause.kind, clause.reason
    return UNVERIFIED_KIND, ""




# Check-key -> dashboard criterion id (dashboard/src/data/audit-criteria.ts on
# master, vendored as criteria-checks.json next to this file). Several check
# keys can serve one criterion. None marks a CLI-only check with no criteria
# page row today: the DCGM / DCGM Exporter security floors, the Tier-0 HBM and
# kubelet CPU Manager platform checks, the worker-vantage meta check, and
# CUDA_VISIBLE_DEVICES (the criteria page lists cuda-visible-devices as a
# manual item). tests/audit/test_criteria_parity.py enforces that every rule
# key and security extension id appears here and that every mapped id exists
# in the vendored catalog.
CHECK_CRITERIA: dict[str, str | None] = {
    "securityVersions.nvidiaDriver.status": "security-nvidia-driver",
    "securityVersions.nvidiaContainerToolkit.status": "security-nvidia-container-toolkit",
    "securityVersions.cudaToolkit.status": "cuda-toolkit-security",
    "securityVersions.runc.status": "security-runc",
    "securityVersions.docker.status": "security-docker",
    "securityVersions.connectxFirmware.status": "security-connectx-firmware",
    "securityVersions.dcgm.status": None,
    "securityVersions.dcgmExporter.status": None,
    "securityVersions.virtioNetBluefield.status": "security-virtio-net-bluefield",
    "securityVersions.virtioNetBluefield.exposure": "security-virtio-net-bluefield",
    "securityVersions.dpuHostIsolation.status": "security-dpu-host-isolation",
    "security.januscape.status": "security-januscape",
    "security.guestKernel.newerInstalled": "guest-kernel-current",
    "security.fragnesia.status": "ubuntu-kernel-fragnesia-dirty-frag",
    "containers.nvidiaContainerToolkit": "container-toolkit",
    "containers.workerCheckOk": None,
    "containers.pyxisRuntimeWorks": "pyxis",
    "containers.enroot": "enroot",
    "containers.enrootImportWorks": "enroot",
    "containers.dockerOnWorkers": "docker-workers",
    "containers.singularity": "singularity",
    "software.nvhpc.status": "hpc-sdk",
    "software.ncu.installed": "ncu-profiling",
    "software.ncu.profilingEnabled": "ncu-profiling",
    "software.lmod.modulesStatus": "lmod",
    "software.cudaVisibleDevicesStatus": None,
    "software.nccl.installed": "nccl-installed",
    "software.perf.installed": "perf-access",
    "software.perf.perfEventParanoid": "perf-access",
    "software.perf.kptrRestrict": "perf-access",
    "gpus.gdrcopy.installed": "gdrcopy",
    "gpus.gpuDirectRdmaPath": "gpudirect-rdma",
    "gpus.gpuDirectRdmaPath.nvidiaPeermemLegacy": "gpudirect-rdma",
    "gpus.pcieAcs.enabled": "pcie-acs",
    "gpu_controls.vboost.allowed": "vboost-control",
    "hbm_memory_exposure.status": None,
    "kubelet_cpu_manager_policy.status": None,
    "vm_iommu.status": "vm-iommu-passthrough",
    "arm_smmu_virtualization.status": "arm-smmu-cmdqv",
    "nccl_topo_file.status": "nccl-topo-file-container",
    "nccl_ib_qps.status": "nccl-ib-qps-entropy",
    "networking.topologyConfigured": "topology-conf",
    "networking.hcaNamingValid": "hca-naming",
    "networking.ncclAutoConfig": "nccl-autoconfig",
    "storage.rwxStatus": "csi-rwx",
    "healthChecks.nhcInstalled": "healthcheck-program",
    "healthChecks.monitoringStack.dcgmExporter": "monitoring-stack",
    "healthChecks.dcgmInstalled": "dcgm-healthchecks",
    "healthChecks.dcgmSlurm": "dcgm-healthchecks",
    "access.sudoAvailable": "sudo-available",
    "access.userManagement": "user-management",
    "access.sshToComputeNodes": "ssh-between-nodes",
    "access.externalIdp.detected": "external-idp",
    "access.slurmCommandsOk": "slurm-commands",
    "slurm.accounting.sacctAvailable": "sacct-accounting",
    # Security extension checks merged by audit_report._security_extension_checks.
    "bmc-ipmi": "security-bmc-ipmi",
    "ufm-profile": "ufm-secured-bare-metal-cloud",
    "pcie-passthrough": "security-pcie-passthrough",
    "nvlink-boundary": "security-nvlink-boundary",
}


def nested_get(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Walk a dotted path into a nested dict. Mirrors merge_audit.nested_get."""
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _audit_data(values: dict[str, Any]) -> dict[str, Any]:
    """Return the nested audit blob the rules read.

    Accepts either a full audit.values.json (with the cluster/audit_data
    envelope) or a bare audit_data dict, so the detector works on new runs and
    on hand-built fixtures alike.
    """
    blob = values.get("audit_data")
    if isinstance(blob, dict):
        return blob
    return values


_COMPONENT_NAMES = {
    "connectxFirmware": "ConnectX firmware",
    "cudaToolkit": "CUDA Toolkit",
    "dcgm": "DCGM",
    "dcgmExporter": "DCGM Exporter",
    "docker": "Docker",
    "nvidiaContainerToolkit": "NVIDIA Container Toolkit",
    "nvidiaDriver": "NVIDIA driver",
    "runc": "runc",
    "virtioNetBluefield": "BlueField VIRTIO-Net controller",
}


def _minimum_versions() -> dict[str, Any]:
    """Minimum components read through the sanctioned minimum_versions module.

    AGENTS.md (Security minimum data) forbids a second reader of
    minimum-versions.json. minimum_versions.load() honors the
    CLUSTERMAX_MINIMUM_VERSIONS path override, validates schemaVersion, and
    caches the parse, so findings report the same table the audit graded with.
    """
    workload_dir = str(Path(__file__).resolve().parent)
    if workload_dir not in sys.path:
        sys.path.insert(0, workload_dir)
    try:
        import minimum_versions  # noqa: E402

        components = minimum_versions.load().get("components")
    except Exception:
        return {}
    return components if isinstance(components, dict) else {}


def _finding_component(key: str) -> str:
    parts = key.split(".")
    if len(parts) > 1 and parts[0] == "securityVersions":
        return parts[1]
    if len(parts) > 1 and parts[0] == "containers":
        return parts[1].removesuffix("VersionOk")
    return ""


def _version_context(
    audit: dict[str, Any], key: str
) -> tuple[str, Any, Any]:
    component = _finding_component(key)
    if key.startswith("securityVersions.") and component:
        block = nested_get(audit, "securityVersions", component, default={})
        if isinstance(block, dict):
            observed = block.get("version", block.get("gradedVersion"))
            if _missing_string(observed) and component == "connectxFirmware":
                devices = block.get("devices")
                if isinstance(devices, list):
                    failed_versions = sorted(
                        {
                            str(device.get("version")).strip()
                            for device in devices
                            if isinstance(device, dict)
                            and str(device.get("status")).strip().lower() == "fail"
                            and not _missing_string(device.get("version"))
                        }
                    )
                    if failed_versions:
                        observed = ", ".join(failed_versions)
            if _missing_string(observed):
                observed = "unknown"
            return component, observed, block.get("minimum")
    if key.startswith("containers.") and component:
        observed = nested_get(audit, "containers", f"{component}Version")
        minimum = nested_get(audit, "containers", f"{component}RecommendedMin")
        return component, observed, minimum
    return component, None, None


def _sentence(text: str) -> str:
    """Capitalize only the first character (e.g. "runc 1.2.5" -> "Runc 1.2.5")."""
    return text[:1].upper() + text[1:]


def _finding_guidance(
    audit: dict[str, Any], rule: Rule, value: Any
) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
    component, observed, minimum = _version_context(audit, rule.key)
    component_name = _COMPONENT_NAMES.get(component, component)
    if (
        rule.key == "security.januscape.status"
        and str(value).strip().lower() == "host-patch-required"
    ):
        detected = "Nested virtualization prerequisites are exposed"
        recommendation = (
            "Disable nested virtualization and remove guest access to /dev/kvm "
            "until the provider confirms the physical-host patch."
        )
    elif (
        rule.key == "securityVersions.docker.status"
        and str(value).strip().lower() == "unknown"
    ):
        client_version = nested_get(audit, "containers", "dockerVersion")
        detected = "The Docker Engine server version could not be read."
        if not _missing_string(client_version):
            detected += f" The installed Docker client is {client_version}."
        recommendation = (
            "If the worker uses Docker Engine, make its daemon version readable "
            "to the audit and confirm that the server meets the published "
            "minimum. If the worker uses containerd without Docker Engine, "
            "record Docker Engine as not applicable."
        )
    elif (
        rule.key == "securityVersions.dpuHostIsolation.status"
        and str(value).strip().lower() == "fail"
    ):
        isolation = nested_get(
            audit, "securityVersions", "dpuHostIsolation", default={}
        )
        detected = (
            str(isolation.get("detail") or "").strip()
            if isinstance(isolation, dict)
            else ""
        ) or "The host side can reach the BlueField DPU control plane."
        remediation = (
            str(isolation.get("remediation") or "").strip()
            if isinstance(isolation, dict)
            else ""
        ) or (
            "mlxprivhost -d <device> r --disable_rshim --disable_tracer "
            "--disable_counter_rd --disable_port_owner"
        )
        recommendation = (
            "Apply zero-trust mode on every affected BlueField with "
            f"`{remediation}`. Then verify that `INTERNAL_CPU_RSHIM=1`, "
            "`/dev/rshim0` is absent, and `tmfifo_net0` is absent."
        )
    elif (
        rule.key == "securityVersions.dpuHostIsolation.status"
        and str(value).strip().lower() == "unknown"
    ):
        isolation = nested_get(
            audit, "securityVersions", "dpuHostIsolation", default={}
        )
        if _bluefield_observed(audit):
            detected = (
                str(isolation.get("detail") or "").strip()
                if isinstance(isolation, dict)
                else ""
            ) or (
                "The audit found a BlueField device, but it could not verify "
                "DPU host isolation."
            )
            recommendation = (
                "Attest the isolation posture for every detected BlueField device. "
                "Verify that RShim is restricted and that /dev/rshim0 and "
                "tmfifo_net0 are not exposed to tenants."
            )
        else:
            detected = (
                "The collector could not complete the BlueField inventory, so it "
                "could not verify DPU host isolation."
            )
            recommendation = (
                "Complete the BlueField inventory on every GPU host. If a BlueField "
                "DPU is present, verify that RShim is restricted and that /dev/rshim0 "
                "and tmfifo_net0 are not exposed to tenants."
            )
    elif (
        rule.key.startswith("securityVersions.virtioNetBluefield.")
        and str(value).strip().lower() == "unknown"
    ):
        if _bluefield_observed(audit):
            mode = nested_get(
                audit, "securityVersions", "virtioNetBluefield", "platformMode"
            )
            mode_text = str(mode).strip().upper()
            mode_detail = f" in {mode_text} mode" if mode_text in {"NIC", "DPU"} else ""
            detected = (
                f"The audit found a BlueField device{mode_detail}, but it could "
                "not verify the controller version or exposure."
            )
            recommendation = (
                "Attest the controller version and exposure for every detected "
                "BlueField device. Record the running controller version with "
                "virtnet version and verify its tenant exposure."
            )
        else:
            detected = (
                "The collector could not complete the BlueField inventory, so it "
                "could not verify the controller version or exposure."
            )
            recommendation = (
                "Complete the BlueField inventory on every GPU host. For each "
                "BlueField device, record whether it uses NIC or DPU mode and record "
                "the controller firmware version."
            )
    elif rule.key == "kubelet_cpu_manager_policy.status":
        policy = nested_get(audit, "kubelet_cpu_manager_policy", default={})
        detected = (
            str(policy.get("message") or "").strip()
            if isinstance(policy, dict)
            else ""
        ) or str(value).capitalize()
        recommendation = (
            "Set the kubelet CPU Manager policy to static on GPU workers. Drain "
            "each worker before you restart its kubelet, then run the audit again."
        )
    elif rule.key == "networking.topologyConfigured":
        detected = "No topology-aware scheduling configuration was detected."
        recommendation = (
            "Add provider-defined block, rack, and host topology labels, then "
            "configure the workload scheduler to use them for distributed GPU jobs."
        )
    elif rule.key == "software.perf.perfEventParanoid":
        detected = f"kernel.perf_event_paranoid is {value}; the expected value is 1 or lower."
        recommendation = (
            "Set `kernel.perf_event_paranoid=1` or lower on every GPU worker, "
            "persist the setting in the worker sysctl configuration, and run "
            "the audit again."
        )
    elif rule.key == "software.perf.kptrRestrict":
        detected = f"kernel.kptr_restrict is {value}; the expected value is 0."
        recommendation = (
            "Set `kernel.kptr_restrict=0` on every GPU worker, persist the "
            "setting in the worker sysctl configuration, and run the audit again."
        )
    elif rule.severity == VERSION and observed not in (None, ""):
        detected = f"{component_name} {observed}" if component_name else str(observed)
        recommendation = (
            _sentence(f"{component_name} {minimum} or later.")
            if component_name and minimum not in (None, "")
            else "Install the applicable security update, and run the audit again."
        )
    elif isinstance(value, bool) and value is False:
        if rule.severity == MISSING or "not installed" in rule.title.lower():
            detected = "Not installed"
        elif any(word in rule.key.lower() for word in ("allowed", "configured")) or "enabled" in rule.title.lower():
            detected = "Disabled"
        else:
            detected = "Check failed"
        if rule.severity == MISSING or "not installed" in rule.title.lower():
            item = re.split(r"\s+not installed", rule.title, maxsplit=1, flags=re.I)[0]
            recommendation = f"Install {item}."
        elif "vboost" in rule.title.lower():
            recommendation = "Enable vBoost for tenant workloads."
        elif "topology.conf" in rule.title.lower():
            recommendation = "Configure topology.conf, and run the audit again."
        elif "pyxis" in rule.title.lower():
            recommendation = (
                "Install Pyxis with the NVIDIA instructions at "
                "https://github.com/NVIDIA/pyxis#installation, and run the audit again."
            )
        else:
            recommendation = "Enable the required configuration, and run the audit again."
    elif str(value).strip().lower() == "unknown":
        detected = (
            "The collector could not verify this check. Treat this value as "
            "unverified."
        )
        subject = component_name or rule.title.split(" requires", 1)[0]
        recommendation = (
            _sentence(f"{subject} {minimum} or later.")
            if minimum not in (None, "")
            else f"Ask the provider to attest the {subject} state."
        )
    else:
        detected = str(value).replace("_", " ").capitalize()
        if "reboot required" in rule.title.lower():
            recommendation = "Reboot the affected worker, and confirm that it runs the newer kernel."
        elif "attestation" in rule.title.lower() or "could not be verified" in rule.title.lower():
            recommendation = "Ask the provider to attest this state with host evidence."
        elif "nvidia_peermem" in rule.title.lower():
            recommendation = (
                "Enable the dma_buf GPUDirect path; once it is available, the "
                "driver and NCCL prefer dma_buf automatically, so nvidia_peermem "
                "may stay loaded for legacy consumers."
            )
        elif "hbm" in rule.title.lower():
            recommendation = "Disable operating-system HBM exposure, and run the audit again."
        else:
            recommendation = "Correct the reported configuration, and run the audit again."

    minimums = _minimum_versions()
    minimum = minimums.get(component) if component else None
    cves: list[str] = []
    advisories: list[str] = []
    known_below_minimum = (
        rule.severity == VERSION
        and str(observed).strip().lower() not in {"", "none", "unknown", "n/a"}
        and minimum not in (None, "")
    )
    if isinstance(minimum, dict) and known_below_minimum:
        cves.extend(str(item) for item in minimum.get("cves", []) if item)
        advisories.extend(str(item) for item in minimum.get("advisories", []) if item)
        # Most minimum components carry a singular `advisory` URL rather than the
        # plural `advisories` list; surface it too.
        single_advisory = minimum.get("advisory")
        if single_advisory:
            advisories.append(str(single_advisory))
    cves.extend(rule.cves)
    cves.extend(re.findall(r"CVE-\d{4}-\d+", rule.title))
    return (
        detected,
        recommendation,
        tuple(dict.fromkeys(cves)),
        tuple(dict.fromkeys(advisories)),
    )


def detect_findings(values: dict[str, Any], *, source: str = "") -> list[Finding]:
    """Pure detector: audit values in, list of findings out.

    `values` may be a full audit.values.json or a bare audit_data dict. `source`
    is stamped onto each finding as the evidence file path. The result is ordered
    by RULES so output is stable.
    """
    audit = _audit_data(values)
    cluster = values.get("cluster")
    harness = (
        str(cluster.get("orchestrator") or "").strip().lower()
        if isinstance(cluster, dict)
        else ""
    )
    findings: list[Finding] = []
    for rule in RULES:
        if harness and harness not in rule.harnesses:
            continue
        value = nested_get(audit, *rule.key.split("."))
        if value is None:
            if not rule.flag_when_missing:
                continue
            value = "not-present"
        if not rule.failing(value):
            continue
        if rule.guard is not None and not rule.guard(audit):
            continue
        finding_rule = rule
        component, observed, _minimum = _version_context(audit, rule.key)
        if (
            component == "connectxFirmware"
            and rule.severity == VERSION
            and _missing_string(observed)
        ):
            finding_rule = Rule(
                key=rule.key,
                title="ConnectX firmware security minimum could not be verified",
                severity=CONFIG,
                failing=rule.failing,
            )
        guidance_value = "unknown" if finding_rule is not rule else value
        detected, recommendation, cves, advisories = _finding_guidance(
            audit, finding_rule, guidance_value
        )
        findings.append(
            Finding(
                title=finding_rule.title,
                severity=finding_rule.severity,
                key=rule.key,
                value=value,
                source=source,
                detected=detected,
                recommendation=recommendation,
                cves=cves,
                advisories=advisories,
            )
        )
    return findings


_HEADER_WIDTH = 60

# NVD is the canonical public page for a CVE identifier.
_CVE_URL = "https://nvd.nist.gov/vuln/detail/{cve}"


def _osc8(text: str, url: str) -> str:
    """Render `text` as an OSC 8 terminal hyperlink to `url`.

    Terminals with hyperlink support show only `text` and make it clickable;
    the URL itself never appears in the output.
    """
    return (
        f"\x1b]8;;{url}\x1b\\"
        f"\x1b[4m{text}\x1b[24m"
        "\x1b]8;;\x1b\\"
    )


def _cve_label(cve: str, *, hyperlinks: bool) -> str:
    if not hyperlinks:
        return cve
    return _osc8(cve, _CVE_URL.format(cve=cve))


_GHSA_ID = re.compile(r"GHSA-[0-9a-z-]+", re.I)


def _advisory_link(advisory: str) -> tuple[str, str]:
    """Return a short visible label and its hidden HTTPS target."""
    value = str(advisory).strip()
    ghsa = _GHSA_ID.search(value)
    if ghsa:
        label = ghsa.group(0)
        target = value if value.startswith("https://") else f"https://github.com/advisories/{label}"
        return label, target

    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return value, ""
    path = parsed.path.rstrip("/")
    if parsed.netloc == "nvidia.custhelp.com":
        match = re.search(r"/a_id/(\d+)$", path)
        if match:
            return f"NVIDIA advisory {match.group(1)}", value
    if parsed.netloc == "docs.docker.com":
        match = re.search(r"/release-notes/([^/]+)$", path)
        if match:
            return f"Docker Engine {unquote(match.group(1))} release notes", value
    if parsed.netloc == "ubuntu.com" and path == "/security/notices":
        return "Ubuntu security notices", value
    leaf = unquote(path.rsplit("/", 1)[-1]) if path else "advisory"
    return f"{parsed.netloc} {leaf}", value


def _advisory_labels(advisories: tuple[str, ...], *, hyperlinks: bool) -> list[str]:
    targets: dict[str, str] = {}
    for advisory in advisories:
        label, target = _advisory_link(advisory)
        if label not in targets or str(advisory).startswith("https://"):
            targets[label] = target
    return [
        _osc8(label, target) if hyperlinks and target else label
        for label, target in targets.items()
    ]


def format_report(
    findings: list[Finding], *, source: str = "", hyperlinks: bool = False
) -> str:
    """Render actionable findings without exposing internal evidence paths."""
    bar = "=" * _HEADER_WIDTH
    lines: list[str] = [bar]
    if not findings:
        lines.append("AUDIT FINDINGS (0)")
        lines.append("No findings: no missing / not-OK components detected.")
        lines.append(bar)
        return "\n".join(lines)

    lines.append(f"AUDIT FINDINGS ({len(findings)})")
    lines.append("These items were detected as missing / not-OK. Verify them")
    lines.append("hands-on and report to the vendor with a screenshot while")
    lines.append("cluster access is available.")
    lines.append("")
    for finding in findings:
        lines.append(f"[{finding.severity:<7}] {finding.title}")
        lines.append(f"            Detected: {finding.detected}")
        lines.append(f"            Recommendation: {finding.recommendation}")
        if finding.cves:
            cves = ", ".join(_cve_label(cve, hyperlinks=hyperlinks) for cve in finding.cves)
            lines.append(f"            CVEs: {cves}")
        if finding.advisories:
            advisories = _advisory_labels(
                finding.advisories, hyperlinks=hyperlinks
            )
            lines.append(f"            Advisories: {', '.join(advisories)}")
    lines.append(bar)
    return "\n".join(lines)


def print_report(findings: list[Finding], *, source: str = "", stream=None) -> None:
    """Print the rendered report. Thin I/O wrapper over format_report.

    CVE identifiers become clickable terminal hyperlinks only on an
    interactive terminal; redirected or captured output stays plain text.
    """
    out = stream or sys.stdout
    hyperlinks = bool(getattr(out, "isatty", lambda: False)())
    print(format_report(findings, source=source, hyperlinks=hyperlinks), file=out)


def report_path(values_path: Path) -> list[Finding]:
    """Load an audit.values.json from disk and detect findings against it."""
    with values_path.open() as f:
        values = json.load(f)
    return detect_findings(values, source=str(values_path))


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if a != "--exit-code"]
    exit_code = "--exit-code" in argv[1:]
    if len(args) != 1:
        print(
            "usage: audit_findings.py [--exit-code] <audit.values.json>",
            file=sys.stderr,
        )
        return 2
    values_path = Path(args[0])
    if not values_path.exists():
        print(f"ERROR: no such file: {values_path}", file=sys.stderr)
        return 2
    findings = report_path(values_path)
    print_report(findings, source=str(values_path))
    # Report-only by default so the PR paste workflow (see AGENTS.md "Report
    # audit failures loudly") is never gated by findings. Pass --exit-code to
    # gate CI/scripts, mirroring `cmax audit security` which exits non-zero on
    # critical findings.
    if exit_code and findings:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
