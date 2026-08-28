#!/usr/bin/env python3
"""BlueField VIRTIO-Net controller check (NVIDIA bulletin a_id 5815).

CVE-2026-65094 (CVSS 9.0, AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H) lets a VM user
reach a Write-What-Where condition in Virtio-Net scope on a BlueField-3 DPU, so
it is a tenant-escape class defect. This check collects the evidence the
``virtioNetBluefield`` minimum version is graded against, and the DPU-boundary
posture that decides whether the bulletin applies at all.

Emits one check object to stdout::

    {"virtio_net_bluefield": {"hosts": {"worker-0": {...}}, "summary": {...}}}

Self-dispatches by harness (``CLUSTERMAX_AUDIT_HARNESS`` / ``CLUSTERMAX_HARNESS``)
the same way ``nic-topology-check.py`` does, because a DPU is per node and a
head-node-only answer is a false negative:

* ``slurm``  - srun one ``--collect-host`` worker per node.
* ``k8s``    - exec a POSIX-sh collector in each GPU node's driver pod (that
  image has no python3), then parse it here.
* otherwise  - run the worker on the local host (standalone).

Where the version actually lives
--------------------------------
The controller runs on the DPU ARM side as ``virtio-net-controller.service``
(``/usr/sbin/virtio_net_controller``). Its version comes from the ``virtnet``
CLI, which NVIDIA installs on the BlueField, not on the x86 host.

``virtnet version`` prints the running and staged controller versions::

    [{"Original Controller": "v24.10.17"}, {"Destination Controller": "v24.10.19"}]

``virtnet -v`` prints the CLI's own version, not the controller's ("Nvidia
virtio-net-controller command line interface v1.0.9"). It is recorded as
``cliVersion`` and is never used as the controller firmware version, because a
staged DOCA upgrade puts the CLI on the new release while the old controller is
still the one running. That is the same split ``virtnet version`` reports as
Original versus Destination Controller, and grading the CLI reading would pass
an unpatched running controller.

An administrator can also reach the DPU from the host over the RShim
point-to-point link (``/dev/rshim0``, ``tmfifo_net0``, host 192.168.100.1/30 and
DPU 192.168.100.2/30) and run ``virtnet`` there. That attempt is opportunistic,
non-interactive, and short: batch-mode SSH that cannot prompt, one try, then
fall through. Nothing is ever written to the RShim console.

Scope, settled from the host with no DPU credentials
----------------------------------------------------
``mlxconfig -d <device> q`` reports the mode controls:

* ``INTERNAL_CPU_MODEL``          0 separated host, 1 embedded (DPU) CPU
* ``INTERNAL_CPU_OFFLOAD_ENGINE`` 0 ENABLED = DPU mode, 1 DISABLED = NIC mode
* ``INTERNAL_CPU_RSHIM``          0 RShim enabled, 1 RShim restricted

In NIC mode the BlueField behaves as an ordinary adapter and no virtio-net
controller runs, so the bulletin does not apply. In DPU mode it does.

That read opens the device through /dev/mst or the raw PCI configuration space,
so an unprivileged caller gets ``-E- Failed to open the device`` while the answer
sits on the card. The unprivileged read runs first and the same read is then
retried under ``sudo -n``, exactly as ``checks/gpu/vboost.py`` escalates. Where
the operator account holds passwordless sudo, that turns two ``unknown`` grades
into real ones: the platform mode the controller criterion needs, and
``INTERNAL_CPU_RSHIM``, which is the only DPU host isolation evidence that does
not come from the filesystem. ``sudo -n`` never prompts, so a host
without passwordless sudo fails immediately and the state stays ``incomplete``.
``modeSource`` records which of the two reads answered, and ``modeEscalation``
records which privilege path the host was on.

When both queries fail the existing ``mst start`` fallback also carries the
prefix, because it loads the mst kernel modules and cannot work without the
rights the query needs. That module load is the one host-state change on this
path. Nothing is written to the device and nothing is written to the RShim
console.

The zero-trust observation
--------------------------
Zero-trust mode is the specialization of DPU mode that stops the host
administrator from reaching the BlueField, applied with ``mlxprivhost -d
<device> r --disable_rshim --disable_tracer --disable_counter_rd
--disable_port_owner``. A tenant-visible host that can reach the DPU over RShim
is therefore not in zero-trust mode, and the tenant side can reach the DPU
control plane. This check records that evidence (``rshimHostAccess``) and
deliberately does not grade it. Inventing a graded criterion inside a check
would put a security verdict somewhere no reviewer looks for one.

The verdict is computed from one host record, so which host the check hands
over is the whole verdict. ``_isolation_rung`` is that choice. It obeys the
same rule as the controller rollup, through the same shared helpers: a host
that reached the DPU control plane is a proven finding and outranks every
evidence gap, while a hardened host is outranked by any gap, because an
unassessed node must not be represented by a clean one.

Five reported states (``state`` per host, rolled up in ``summary``):

* ``version``        - a controller version was read.
* ``unknown``        - BlueField-3 present, DPU mode confirmed, no ``virtnet``.
  An informed unknown: the reason names the RShim posture and asks the provider
  to attest.
* ``not_running``    - BlueField-3 present in NIC mode. A latent exposure, never
  ``not_applicable``: the firmware stays installed and the mode is a setting.
* ``not_applicable`` - no BlueField-3 in a completed scan.
* ``incomplete``     - the scan itself could not run (no ``lspci``, an empty or
  failed listing, or the mode could not be read because ``mlxconfig`` is
  missing or not root), or the per-node fan-out did not reach every host.
  Never ``not_applicable``: absence of evidence is not evidence of absence.

The rollup ``state`` is a claim about the whole cluster, so an unresolved node
correctly blocks it. Beside it the summary carries ``observedControllers`` and
``worstObserved``, which are per-host facts and are never weakened by a
coverage gap: a host proven to run below-minimum firmware is a proven finding,
and an unreadable peer cannot soften it. Coverage gaps weaken a pass or a
not-applicable, never a fail.

Environment overrides:

* ``CLUSTERMAX_AUDIT_ROOT``          - filesystem root for the /dev and /sys
  reads (tests point this at a fixture tree).
* ``CLUSTERMAX_DPU_SSH_TARGET``      - RShim SSH target (default
  ``ubuntu@192.168.100.2``).
* ``CLUSTERMAX_DPU_SSH_DISABLE``     - set to skip the RShim SSH attempt.
* ``CLUSTERMAX_GPU_OPERATOR_NAMESPACE``, ``CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS``
  - as in nic-topology-check.py.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

Runner = Callable[..., subprocess.CompletedProcess]
Which = Callable[[str], str | None]

GPU_OPERATOR_NAMESPACES = (
    "gpu-operator",
    "gpu-operator-resources",
    "nvidia-gpu-operator",
    "nvidia",
    "gpu",
)
KUBECTL_TIMEOUT_S = 60
CHECK_CACHE_ENV = "CLUSTERMAX_VIRTIO_NET_CHECK_CACHE"
# Per-command timeout for every local tool. SLURM_TIMEOUT_S below is derived
# from it, so the two move together.
TOOL_TIMEOUT_S = 15
# ssh gets ConnectTimeout=SSH_TIMEOUT_S and a wall-clock budget of twice that,
# so a connection that opens and then stalls is still bounded.
SSH_TIMEOUT_S = 8

# srun budget for the whole per-node fan-out. `srun -N <nodes>
# --ntasks-per-node=1` runs the hosts in parallel, so this has to cover the
# worst-case SINGLE host, not the sum over hosts.
#
# Worst case for one host, every command hanging until its own timeout:
#
#   lspci                                        1 x 15 =  15 s
#   mlxconfig q, sudo -n mlxconfig q,
#     sudo -n mst start, sudo -n mlxconfig q      4 x 15 =  60 s
#   local `virtnet version` + `virtnet -v`        2 x 15 =  30 s
#   RShim SSH: version, -v, list, mlnx-release    4 x 16 =  64 s
#                                                         ------
#                                                          169 s
#
# The local-virtnet-succeeded path and the RShim SSH path are mutually
# exclusive (collect_version only reaches SSH when the local read produced no
# version), and the succeeded path is cheaper: 15 + 60 + 15 + 2 x 15 = 120 s.
# So 169 s is a true ceiling, not a sum of alternatives. Allow 60 s for srun
# dispatch and worker startup, giving 229 s against a 300 s budget, about 24%
# margin.
#
# Redo this arithmetic when changing TOOL_TIMEOUT_S or SSH_TIMEOUT_S, or when
# adding a command to gather(). An overrun is no longer a false clean, because
# apply_coverage_gap() catches it, but it costs the fleet answer and falls back
# to the local host. test_the_srun_budget_covers_the_worst_case_host pins it.
SLURM_TIMEOUT_S = 300

NVIDIA_PCI_VENDOR = "15b3"
# BlueField-3 integrated network controllers, from the repo's PCI registry
# (.claude/reference/network-hardware-identifiers.json). Lx is the same DPU
# generation and runs the same DOCA virtio-net stack, so both are in scope.
BLUEFIELD3_DEVICE_IDS = {
    "a2dc": "BlueField-3 integrated ConnectX-7",
    "a2d9": "BlueField-3 Lx integrated ConnectX-7",
}
# Standard virtio PCI vendor. A 1af4 device on its own proves nothing, because
# every QEMU guest has one; the BlueField-3 above is the discriminator. It is
# recorded only as supporting evidence that virtio-net devices are exposed here.
VIRTIO_PCI_VENDOR = "1af4"

STATE_VERSION = "version"
STATE_UNKNOWN = "unknown"
STATE_NOT_RUNNING = "not_running"
STATE_NOT_APPLICABLE = "not_applicable"
STATE_INCOMPLETE = "incomplete"
# ---------------------------------------------------------------------------
# Severity ladders: the one place the coverage rule is expressed
# ---------------------------------------------------------------------------
#
# THE RULE, stated once:
#
#     A coverage gap may weaken a clean answer. It may never erase a proven
#     failure. A criterion supplies only which rung a host sits on. It never
#     supplies the direction.
#
# This replaced four separate expressions of that rule: the controller state
# priority, the isolation rank function, and the two guards inside
# apply_coverage_gap. Two of the four had the direction backwards, and both
# turned a real finding into a reassuring answer. One patched host beside one
# unread NIC-mode host graded pass, so adding a healthy host turned the cluster
# green. A host proven to expose its DPU control plane, beside one host nobody
# could read, graded unknown. Both bugs happened for the same reason: the
# author re-derived the ordering instead of applying the shared one. This
# indirection exists so there is nothing left to re-derive. A new criterion
# writes a classifier and gets the direction for free.
#
# A ladder is an ordered tuple of rung names, MOST SEVERE FIRST. Each ladder
# names one gap rung: the rung a coverage gap clamps to. Rungs above it are
# findings that stand on their own evidence and are therefore unreachable by
# the clamp, structurally, rather than by a guard someone must remember to
# write. Rungs below it are answers an unexamined host could contradict.


def rung_position(rung: str | None, ladder: tuple[str, ...]) -> int:
    """Index of a rung on its ladder. An unrecognized rung ranks last."""
    return ladder.index(rung) if rung in ladder else len(ladder)


def most_severe(
    records: list[dict[str, Any]],
    *,
    ladder: tuple[str, ...],
    rung_of: Callable[[dict[str, Any]], str],
    tiebreak: Callable[[dict[str, Any]], str] | None = None,
) -> dict[str, Any]:
    """Select the record that decides a criterion.

    The lowest rung wins, so a proven finding outranks an evidence gap and an
    evidence gap outranks a clean host. This is the selection half of the rule.
    ``weaken_for_gap`` is the other half.
    """

    def key(record: dict[str, Any]) -> tuple[int, str]:
        return (
            rung_position(rung_of(record), ladder),
            tiebreak(record) if tiebreak else "",
        )

    return min(records, key=key)


def gap_can_weaken(rung: str | None, *, ladder: tuple[str, ...], gap_rung: str) -> bool:
    """Whether a coverage gap has anything to add to this rung.

    False for any rung at least as severe as the gap rung. That is what makes a
    proven finding unerasable: it sits above the gap rung, so the clamp cannot
    reach it.
    """
    return rung_position(rung, ladder) > rung_position(gap_rung, ladder)


def weaken_for_gap(rung: str | None, *, ladder: tuple[str, ...], gap_rung: str) -> str:
    """Clamp one rung down to the gap rung, leaving anything more severe alone."""
    if gap_can_weaken(rung, ladder=ladder, gap_rung=gap_rung):
        return gap_rung
    return str(rung)


# The controller criterion. STATE_PRIORITY is this ladder, derived rather than
# hand-ordered.
#
# STATE_NOT_RUNNING outranks STATE_VERSION deliberately. A NIC-mode host carries
# installed controller firmware that nobody read, so it is an unresolved host
# that happens to know why it is unresolved. Ranking it below STATE_VERSION let
# one host with a version speak for it: a fleet of {version, not_running} rolled
# up to `version`, the consumer read that as complete coverage, graded the one
# reading, and reported pass with exposure none.
#
# Ranking it here cannot weaken a proven fail. The rollup state feeds only the
# consumer's coverage-complete flag; the graded reading comes from
# `worstObserved` / `observedControllers`, which summarize() builds
# independently of the state, and the consumer's partial-coverage rule keeps a
# fail a fail and only weakens a pass.
CONTROLLER_LADDER = (
    STATE_UNKNOWN,
    STATE_INCOMPLETE,
    STATE_NOT_RUNNING,
    STATE_VERSION,
    STATE_NOT_APPLICABLE,
)
CONTROLLER_GAP_RUNG = STATE_INCOMPLETE
STATE_PRIORITY = CONTROLLER_LADDER


def _controller_rung(record: dict[str, Any]) -> str:
    """Which rung of the controller ladder one host sits on."""
    return str(record.get("state") or STATE_INCOMPLETE)


# The cluster-wide platform mode, most severe first. summarize() computes it as
# the worst mode across the hosts that ANSWERED, so every value here is a claim
# about every node.
#
# Only "dpu" survives a coverage gap. It is the exposed mode, so claiming it
# fleet-wide from partial data over-states and is safe. "nic" and "absent" are
# the permissive claims and both understate: "absent" says there is no DPU
# anywhere, and "nic" says the controller is installed but idle everywhere,
# which the consumer grades as a latent exposure rather than a live one. An
# unread host may be in DPU mode and actively exposed, so neither may be
# claimed for a fleet that was only partly read.
MODE_LADDER = ("dpu", "nic", "absent")
# The top of the ladder, so a gap weakens every rung strictly below it.
MODE_GAP_RUNG = MODE_LADDER[0]

_FANOUT = None


def load_fanout():
    global _FANOUT
    if _FANOUT is None:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        import _fanout  # type: ignore

        _FANOUT = _fanout
    return _FANOUT


def audit_root(env: dict[str, str] = os.environ) -> Path:
    return Path(env.get("CLUSTERMAX_AUDIT_ROOT") or "/")


def run_tool(
    command: list[str],
    *,
    runner: Runner = subprocess.run,
    timeout: int = TOOL_TIMEOUT_S,
) -> tuple[str, str | None]:
    """Return (stdout, error). error is None only on a clean exit."""
    try:
        proc = runner(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return "", f"{command[0]} is not installed"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", f"{command[0]} failed: {exc}"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = detail[0] if detail else f"exit {proc.returncode}"
        return proc.stdout or "", f"{command[0]} failed: {reason}"
    return proc.stdout or "", None


# ---------------------------------------------------------------------------
# PCI inventory
# ---------------------------------------------------------------------------

_LSPCI_ID_RE = re.compile(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{4})")


_LSPCI_SLOT_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]\s")


def parse_lspci(text: str) -> tuple[list[dict[str, str]], int, int]:
    """Return (BlueField-3 devices, count of virtio PCI devices, PCI lines seen).

    Accepts `lspci -Dnn` and `lspci -Dn` output. The vendor:device pair is
    matched anywhere on the line so both the bare `-n` form
    (``0000:03:00.0 0207: 15b3:a2dc``) and the bracketed `-nn` form parse.

    The third value is the number of lines that looked like a PCI device at all.
    It is what separates "this host has no BlueField" from "this listing is
    empty", and only the first of those is a finding about the hardware.
    """
    devices: list[dict[str, str]] = []
    virtio_count = 0
    total = 0
    for line in text.splitlines():
        slot = line.split(" ", 1)[0] if line else ""
        if _LSPCI_SLOT_RE.match(line):
            total += 1
        for vendor, device in _LSPCI_ID_RE.findall(line):
            vendor = vendor.lower()
            device = device.lower()
            if vendor == NVIDIA_PCI_VENDOR and device in BLUEFIELD3_DEVICE_IDS:
                devices.append(
                    {
                        "slot": slot,
                        "id": f"{vendor}:{device}",
                        "family": BLUEFIELD3_DEVICE_IDS[device],
                    }
                )
                break
            if vendor == VIRTIO_PCI_VENDOR:
                virtio_count += 1
                break
    return devices, virtio_count, total


def sysfs_pci_bus_empty(env: dict[str, str] = os.environ) -> bool:
    """True only when the kernel's own PCI tree is readable and holds nothing.

    An empty lspci listing on its own is indistinguishable from a broken read,
    but some virtual machines genuinely expose no PCI device at all, and on
    those hosts a readable, empty ``/sys/bus/pci/devices`` is the kernel
    stating the bus was enumerated and is empty. Anything unreadable answers
    False, so a permissions problem can never upgrade an unread bus into a
    claim of absence.
    """
    path = Path(env.get("CLUSTERMAX_AUDIT_ROOT", "") + "/sys/bus/pci/devices")
    try:
        return path.is_dir() and not any(path.iterdir())
    except OSError:
        return False


def pci_scan_result(
    text: str, error: str | None, *, empty_bus_confirmed: bool = False
) -> dict[str, Any]:
    """Grade one lspci reading into scan evidence.

    Positive and negative evidence are not symmetric here. A BlueField-3 that
    appears in the listing is present whatever else went wrong, so a partial
    listing that names one is still a complete answer to "is there a DPU".
    Nothing in the listing means nothing only when the listing itself is
    trustworthy: a non-zero exit, or a listing with no PCI device on it at all,
    is an unread bus, and calling that "no BlueField-3 is present" would turn a
    tool failure into a clean pass. The one exception is a clean lspci exit
    corroborated by sysfs (``empty_bus_confirmed``): two independent readers
    agreeing the bus holds zero devices is a read bus with no device on it,
    which is a real hardware fact and not a tool failure.
    """
    devices, virtio_count, total = parse_lspci(text)
    if devices:
        return {
            "scanComplete": True,
            "scanError": None,
            "devices": devices,
            "virtioPciDevices": virtio_count,
        }
    if error is not None:
        return {
            "scanComplete": False,
            "scanError": error,
            "devices": [],
            "virtioPciDevices": virtio_count,
        }
    if total == 0:
        if empty_bus_confirmed:
            return {
                "scanComplete": True,
                "scanError": None,
                "devices": [],
                "virtioPciDevices": 0,
            }
        return {
            "scanComplete": False,
            "scanError": "lspci listed no PCI device, so the bus was not read",
            "devices": [],
            "virtioPciDevices": 0,
        }
    return {
        "scanComplete": True,
        "scanError": None,
        "devices": [],
        "virtioPciDevices": virtio_count,
    }


def collect_pci(
    *, runner: Runner = subprocess.run, env: dict[str, str] = os.environ
) -> dict[str, Any]:
    text, error = run_tool(["lspci", "-Dnn"], runner=runner)
    return pci_scan_result(
        text, error, empty_bus_confirmed=sysfs_pci_bus_empty(env)
    )


# ---------------------------------------------------------------------------
# Mode and RShim posture (mlxconfig)
# ---------------------------------------------------------------------------

# Which privilege path the mode read took on this host. Recorded per host as
# `modeEscalation`, and read by decide() so a failed read says what was actually
# tried. An older collector reports no value at all, which decide() handles.
ESCALATION_ROOT = "root"
ESCALATION_SUDO = "sudo -n"
ESCALATION_UNAVAILABLE = "no-sudo"

_MLXCONFIG_KEYS = ("INTERNAL_CPU_MODEL", "INTERNAL_CPU_OFFLOAD_ENGINE", "INTERNAL_CPU_RSHIM")
_MLXCONFIG_LINE_RE = re.compile(
    r"^\s*(INTERNAL_CPU_MODEL|INTERNAL_CPU_OFFLOAD_ENGINE|INTERNAL_CPU_RSHIM)\s+(\S+)"
)


def parse_mlxconfig(text: str) -> dict[str, str]:
    """Pull the three mode controls out of `mlxconfig -d <dev> q` output.

    Values print as ``ENABLED(0)`` / ``EMBEDDED_CPU(1)`` / a bare number. The
    numeric in parentheses wins, because the symbolic names differ per firmware
    release while the numbers are the documented contract.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = _MLXCONFIG_LINE_RE.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        paren = re.search(r"\((\d+)\)", raw)
        values[key] = paren.group(1) if paren else raw.strip()
    return values


def privileged_prefix(
    *,
    which: Which = shutil.which,
    euid: Callable[[], int] = os.geteuid,
) -> tuple[list[str], str]:
    """Return (command prefix, which privilege path this host is on).

    The label is carried into the host record as ``modeEscalation``, because the
    three paths fail for different reasons and an operator reading a failed mode
    read has to know which one applied. A root caller already has the rights, a
    host with sudo gets one non-interactive attempt, and a host with no sudo has
    nothing left to try. Reporting "the sudo retry did not answer" on a host that
    never ran one is a false statement in an artifact that gets pasted into
    provider feedback.

    ``-n`` is what keeps the attempt non-interactive: sudo exits immediately
    instead of prompting, so a host without passwordless sudo costs one failed
    exec and nothing hangs.
    """
    if euid() == 0:
        return [], ESCALATION_ROOT
    sudo = which("sudo")
    if sudo:
        return [sudo, "-n"], ESCALATION_SUDO
    return [], ESCALATION_UNAVAILABLE


def collect_mode(
    devices: list[dict[str, str]],
    *,
    runner: Runner = subprocess.run,
    which: Which = shutil.which,
    euid: Callable[[], int] = os.geteuid,
) -> dict[str, Any]:
    """Query the first BlueField-3 device for its mode controls.

    The PCI slot is passed to mlxconfig directly, which avoids needing
    `mst start` first. `mst start` is attempted only as a fallback, and its
    failure is not fatal: `burnin-monitor.py` uses the same best-effort pattern.

    mlxconfig opens the device itself, so a tenant read fails with `-E- Failed to
    open the device` on a host that has the answer. The unprivileged read is
    tried first, so a host that needs no escalation is unaffected, then the same
    read runs under `sudo -n`. Without this the audit reported the platform mode
    and the RShim posture as unreadable on any cluster whose operator account
    holds passwordless sudo, and both criteria graded `unknown` while the
    evidence was one exec away.

    The unprivileged error is kept in preference to the sudo error, because
    `mlxconfig failed: -E- Failed to open the device` names the tool an operator
    has to run, and `sudo failed: a password is required` names the wrapper.
    """
    result: dict[str, Any] = {
        "mode": "unknown",
        "modeSource": None,
        "values": {},
        "error": None,
        "escalation": None,
    }
    if not devices:
        result["error"] = "no BlueField-3 device to query"
        return result

    slot = devices[0].get("slot") or ""
    query = ["mlxconfig", "-d", slot, "q"]
    prefix, escalation = privileged_prefix(which=which, euid=euid)
    result["escalation"] = escalation
    source = "mlxconfig"
    text, error = run_tool(query, runner=runner)
    values = parse_mlxconfig(text)
    if not values and prefix:
        text, sudo_error = run_tool([*prefix, *query], runner=runner)
        values = parse_mlxconfig(text)
        error = error or sudo_error
        if values:
            source = "sudo mlxconfig"
    if not values:
        # `mst start` loads the mst kernel modules and needs the same privilege
        # the query does, so it carries the same prefix.
        run_tool([*prefix, "mst", "start"], runner=runner)
        text, retry_error = run_tool([*prefix, *query], runner=runner)
        values = parse_mlxconfig(text)
        if not values:
            result["error"] = error or retry_error or "mlxconfig returned no mode parameters"
            return result
        source = "sudo mlxconfig" if prefix else "mlxconfig"

    result["values"] = values
    result["modeSource"] = source
    offload = values.get("INTERNAL_CPU_OFFLOAD_ENGINE")
    if offload == "0":
        result["mode"] = "dpu"
    elif offload == "1":
        result["mode"] = "nic"
    else:
        result["error"] = "INTERNAL_CPU_OFFLOAD_ENGINE was not reported"
    return result


def collect_rshim(
    mode_values: dict[str, str],
    *,
    env: dict[str, str] = os.environ,
) -> dict[str, Any]:
    """Host-side DPU-boundary evidence. Recorded, never graded here."""
    root = audit_root(env)
    device_node = (root / "dev" / "rshim0").exists()
    tmfifo = (root / "sys" / "class" / "net" / "tmfifo_net0").exists()
    restricted: bool | None = None
    if mode_values.get("INTERNAL_CPU_RSHIM") == "1":
        restricted = True
    elif mode_values.get("INTERNAL_CPU_RSHIM") == "0":
        restricted = False
    return {
        "rshimDeviceNode": device_node,
        "tmfifoNet0": tmfifo,
        "internalCpuRshim": mode_values.get("INTERNAL_CPU_RSHIM", "unknown"),
        "rshimRestricted": restricted,
        "dpuReachedFromHost": None,
    }


# ---------------------------------------------------------------------------
# Controller version
# ---------------------------------------------------------------------------


def strip_v(value: str) -> str:
    value = value.strip()
    return value[1:] if value[:1] in ("v", "V") else value


def parse_virtnet_version(text: str) -> str | None:
    """Read "Original Controller" out of `virtnet version` JSON output."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    entries = payload if isinstance(payload, list) else [payload]
    for entry in entries:
        if isinstance(entry, dict) and "Original Controller" in entry:
            value = strip_v(str(entry["Original Controller"]))
            return value or None
    return None


_CLI_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)*)\s*$")


def parse_virtnet_cli_version(text: str) -> str | None:
    for line in text.splitlines():
        match = _CLI_VERSION_RE.search(line.strip())
        if match:
            return match.group(1)
    return None


# Release-train labels the minimum table keys its lines by. Matched only when the
# evidence literally names one. The line is NOT inferred from the version
# number: GA and the newest LTS share a year.month prefix and are fixed at
# different patches, so a guess produces a confident wrong verdict in both
# directions, which is exactly what the evaluator refuses to do.
#
# LTS<yy> is distinctive enough to match case-insensitively. Bare "GA" is not:
# two letters that a case-insensitive match would find inside a build string, a
# device name, or a hostname fragment, and a wrong line grades the firmware
# against the wrong minimum with full confidence. NVIDIA writes it uppercase in
# the bundle identity, so only uppercase counts.
_LINE_TOKEN_RES = (
    re.compile(r"(?<![A-Za-z0-9])(LTS\d{2})(?![A-Za-z0-9])", re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9])(GA)(?![A-Za-z0-9])"),
)


def detect_line(texts: list[str]) -> str | None:
    """Return the one release-train label that appears verbatim in the evidence.

    Two different labels in the same evidence is ambiguity, not a majority vote,
    so nothing is returned and the evaluator grades against every line the
    version could belong to instead.

    Every pattern is read before deciding. Returning as soon as one pattern
    matched meant evidence naming both an LTS train and GA yielded the LTS
    label with full confidence, because the GA pattern was never consulted.
    Inside the interleaved 25.10 window the two lines are fixed at different
    patches, so that picks a minimum the firmware may not belong to and can grade
    a vulnerable controller as a pass.
    """
    found = {
        match.group(1).upper()
        for pattern in _LINE_TOKEN_RES
        for text in texts
        for match in pattern.finditer(text or "")
    }
    return found.pop() if len(found) == 1 else None


def read_virtnet(
    command_prefix: list[str], *, runner: Runner, timeout: int
) -> dict[str, Any] | None:
    """Read one virtnet command prefix. None when it produced nothing at all.

    Returns ``version`` (the RUNNING controller firmware, or None),
    ``source``, ``cliVersion``, and the raw ``evidence`` texts, which are kept
    so the release train can be read off any label they carry without a second
    round of calls.

    ``virtnet -v`` prints the version of the CLI itself, which is a different
    thing from the controller firmware. After a staged DOCA upgrade the CLI is
    already on the new release while the old controller is the one still
    running: that is the exact split ``virtnet version`` reports as Original
    versus Destination Controller, and it is why only "Original Controller" is
    read there. Putting the CLI version in ``version`` would let the evaluator
    grade the new CLI against the minimum and pass an unpatched running
    controller, so it is recorded as its own labelled field and never fills
    ``version``.
    """
    evidence: list[str] = []
    version: str | None = None
    source: str | None = None
    version_text, error = run_tool([*command_prefix, "version"], runner=runner, timeout=timeout)
    if error is None:
        evidence.append(version_text)
        version = parse_virtnet_version(version_text)
        if version:
            source = "virtnet-version"
    cli_version: str | None = None
    if version is None:
        cli_text, cli_error = run_tool([*command_prefix, "-v"], runner=runner, timeout=timeout)
        if cli_error is None:
            evidence.append(cli_text)
            cli_version = parse_virtnet_cli_version(cli_text)
    if version is None and cli_version is None:
        return None
    return {
        "version": version,
        "source": source,
        "cliVersion": cli_version,
        "evidence": evidence,
    }


def collect_line(
    command_prefix: list[str],
    evidence: list[str],
    *,
    runner: Runner,
    timeout: int,
) -> tuple[str | None, list[str]]:
    """Bounded search for the release train, then stop.

    Two extra reads at most, both on a DPU we have already reached: `virtnet
    list`, which may carry a channel label, and the BlueField bundle identity in
    /etc/mlnx-release, which names the BSP / DOCA release and normally
    distinguishes an LTS train from GA.

    Every step scans the ACCUMULATED evidence, never the newest text alone.
    Scoping a fallback to its own text discarded a contradiction the earlier
    evidence had already established: when `virtnet version` named both an LTS
    train and GA, `detect_line` correctly withdrew the line, and then a bare
    channel label from `virtnet list` claimed one with full confidence. That is
    the same false-pass mechanism `detect_line` guards against, reached one call
    up. A staged DOCA upgrade is exactly when one host carries both labels, and
    `read_virtnet` documents that shape.

    A later single-label source therefore cannot resolve an earlier
    contradiction, which is the point: it is one more opinion, not an
    adjudication.
    """
    line = detect_line(evidence)
    if line:
        return line, evidence
    listing, error = run_tool([*command_prefix, "list"], runner=runner, timeout=timeout)
    if error is None and listing.strip():
        evidence.append(listing)
        line = detect_line(evidence)
        if line:
            return line, evidence
    # Swap the trailing `virtnet` for the bundle read, so this runs wherever the
    # version came from: locally on the DPU, or over the same SSH prefix.
    release, error = run_tool(
        [*command_prefix[:-1], "cat", "/etc/mlnx-release"], runner=runner, timeout=timeout
    )
    if error is None and release.strip():
        evidence.append(release)
        line = detect_line(evidence)
    return line, evidence


def collect_version(
    rshim: dict[str, Any],
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    """Local virtnet first (we are on the DPU), then the RShim link."""

    def empty(cli: str | None) -> dict[str, Any]:
        return {
            "version": None,
            "versionSource": None,
            "line": None,
            "lineEvidence": [],
            "cliVersion": cli,
        }

    local = read_virtnet(["virtnet"], runner=runner, timeout=TOOL_TIMEOUT_S)
    local_cli = local["cliVersion"] if local else None
    if local and local["version"]:
        line, evidence = collect_line(
            ["virtnet"], local["evidence"], runner=runner, timeout=TOOL_TIMEOUT_S
        )
        return {
            "version": local["version"],
            "versionSource": local["source"],
            "line": line,
            "lineEvidence": evidence,
            "cliVersion": local_cli,
        }

    if env.get("CLUSTERMAX_DPU_SSH_DISABLE"):
        return empty(local_cli)
    if not (rshim.get("rshimDeviceNode") or rshim.get("tmfifoNet0")):
        return empty(local_cli)

    target = env.get("CLUSTERMAX_DPU_SSH_TARGET") or "ubuntu@192.168.100.2"
    # BatchMode=yes cannot prompt for a password or a passphrase, so this either
    # works with an already-trusted key or fails immediately. Nothing is ever
    # written to the RShim console and no interactive session is opened.
    # UserKnownHostsFile=/dev/null keeps the read-only audit from leaving a host
    # key behind in the operator's known_hosts, which StrictHostKeyChecking=no
    # would otherwise write on the first run.
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        f"ConnectTimeout={SSH_TIMEOUT_S}",
        target,
        "virtnet",
    ]
    remote = read_virtnet(ssh, runner=runner, timeout=SSH_TIMEOUT_S * 2)
    if remote is None:
        rshim["dpuReachedFromHost"] = False
        return empty(local_cli)
    # Anything at all came back over the link, so the host did reach the DPU.
    rshim["dpuReachedFromHost"] = True
    if not remote["version"]:
        return empty(remote["cliVersion"] or local_cli)
    line, evidence = collect_line(ssh, remote["evidence"], runner=runner, timeout=SSH_TIMEOUT_S * 2)
    return {
        "version": remote["version"],
        "versionSource": f"rshim-ssh/{remote['source']}",
        "line": line,
        "lineEvidence": evidence,
        "cliVersion": remote["cliVersion"] or local_cli,
    }


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


def decide(record: dict[str, Any]) -> tuple[str, str]:
    """Return (state, reason) from a fully collected host record."""
    if record.get("version"):
        return STATE_VERSION, f"controller version read via {record.get('versionSource')}"
    if not record.get("scanComplete"):
        return STATE_INCOMPLETE, str(record.get("scanError") or "PCI scan could not run")
    if not record.get("bluefield3Present"):
        return STATE_NOT_APPLICABLE, "no BlueField-3 device is present on this host"
    mode = record.get("mode")
    if mode == "nic":
        # Deliberately NOT not_applicable. The hardware is present and the
        # controller firmware stays installed on the card; only the running
        # state differs, and NIC versus DPU mode is an mlxconfig setting a
        # provider can flip. Reporting this as "not installed" would hide a
        # real, latent finding, which is the failure this state exists to stop.
        return (
            STATE_NOT_RUNNING,
            "BlueField-3 is in NIC mode (INTERNAL_CPU_OFFLOAD_ENGINE=1), so the "
            "virtio-net controller is not running and there is no exposure now. "
            "The firmware stays installed, so a change back to DPU mode would "
            "activate it unchanged.",
        )
    if mode != "dpu":
        # Name the privilege path that actually ran. Claiming a sudo retry on a
        # root caller, or on a container with no sudo, would put a false
        # statement in evidence an operator pastes into provider feedback.
        privilege = {
            ESCALATION_SUDO: (
                "mlxconfig needs root and the sudo -n retry did not answer either"
            ),
            ESCALATION_UNAVAILABLE: (
                "mlxconfig needs root and no sudo is installed to retry with"
            ),
            ESCALATION_ROOT: "mlxconfig ran with root rights and still reported no mode",
        }.get(str(record.get("modeEscalation")), "mlxconfig needs root")
        return (
            STATE_INCOMPLETE,
            "BlueField-3 is present but its mode could not be read "
            f"({record.get('modeError') or 'mlxconfig unavailable'}); "
            f"{privilege}, so this run cannot settle scope",
        )
    rshim = record.get("rshimHostAccess") or {}
    if rshim.get("rshimDeviceNode") or rshim.get("tmfifoNet0"):
        posture = "the RShim link is present but the DPU did not answer"
    else:
        posture = "no RShim device node or tmfifo_net0 interface is present on this host"
    cli = record.get("cliVersion")
    note = (
        f" The virtnet CLI reports its own version {cli}, which is a different "
        "thing from the controller firmware and is not graded as it."
        if cli
        else ""
    )
    return (
        STATE_UNKNOWN,
        "BlueField-3 is in DPU mode and the virtio-net controller version is "
        f"observable only on the DPU ARM side; {posture}. The provider must "
        f"attest the controller version.{note}",
    )


def gather(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    pci = collect_pci(runner=runner, env=env)
    devices = pci["devices"]
    mode = collect_mode(devices, runner=runner) if devices else {"mode": "unknown", "values": {}, "error": None}
    rshim = collect_rshim(mode.get("values") or {}, env=env)
    version = collect_version(rshim, env=env, runner=runner)

    record: dict[str, Any] = {
        "host": env.get("NODE_NAME") or socket.gethostname(),
        "scanComplete": pci["scanComplete"],
        "scanError": pci["scanError"],
        "bluefield3Present": bool(devices) if pci["scanComplete"] else None,
        "bluefieldDevices": devices,
        "virtioPciDevices": pci["virtioPciDevices"],
        "mode": mode.get("mode", "unknown"),
        "modeSource": mode.get("modeSource"),
        "modeEscalation": mode.get("escalation"),
        "modeParameters": mode.get("values") or {},
        "modeError": mode.get("error"),
        "rshimHostAccess": rshim,
        "version": version.get("version"),
        "versionSource": version.get("versionSource"),
        "cliVersion": version.get("cliVersion"),
        "line": version.get("line"),
        "lineEvidence": version.get("lineEvidence") or [],
    }
    record["state"], record["reason"] = decide(record)
    return record


def _version_key(value: str) -> tuple:
    return tuple(int(part) for part in re.findall(r"\d+", value)) or (0,)


def _version_scheme(value: str) -> str:
    """Which versioning scheme a controller version belongs to.

    The controller moved to a YY.MM.N calendar scheme. The bulletin still lists
    a retired 1.x scheme with its own affected range and no minimum of its own
    above that range. The two do not order against each other, so they are
    never compared.
    """
    return "calendar" if _version_key(value)[0] >= 20 else "legacy"


def observed_controllers(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every distinct controller version an individual host actually read.

    Deliberately independent of the rollup state. The rollup answers "can this
    cluster be cleared", and an unreadable node correctly blocks that. It must
    not also erase a version another node reported: a host proven to run
    below-minimum firmware is a proven finding, and incomplete coverage somewhere
    else cannot soften it. Coverage gaps weaken a pass or a not-applicable,
    never a fail. That is the exact inverse of apply_coverage_gap(), which is
    right for the opposite direction.

    Sorted lowest version first. Deduplicated on the three fields the evaluator
    grades, so an eight-node cluster on one bundle produces one entry.
    """
    seen: dict[tuple, dict[str, Any]] = {}
    for record in records:
        version = record.get("version")
        if not version:
            continue
        version = str(version)
        entry = {
            "version": version,
            "line": record.get("line") or None,
            "mode": str(record.get("mode") or "unknown"),
            "host": record.get("host"),
            "versionSource": record.get("versionSource"),
            "scheme": _version_scheme(version),
        }
        key = (entry["version"], entry["line"], entry["mode"])
        seen.setdefault(key, entry)
    return sorted(seen.values(), key=lambda entry: _version_key(entry["version"]))


def _known_line(line: Any) -> bool:
    """Whether a reading names a release line the evaluator can grade against.

    The collector reports the line only when the output names one, so absent,
    empty and the literal "unknown" all mean the same thing here.
    """
    return str(line or "").strip().lower() not in ("", "unknown", "none")


def worst_observed(observed: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The single worst reading, when every reading is comparable.

    Comparable means one versioning scheme and one release line. Across schemes
    or across lines a bare numeric minimum picks the WEAKER verdict, which
    would re-open the defect this field exists to close: 1.8.0 sits above the
    retired scheme's affected range and grades unknown, while 24.10.17 is below
    the LTS24 minimum and grades fail, so the lower number is the milder finding.
    When the readings are not comparable this is None and the caller must grade
    every entry in ``observedControllers`` and take the worst verdict.

    The mode has to match too, and for the same reason as the line. This field
    used to carry the worst mode across the readings rather than the mode of the
    host that reported the lowest version, on the argument that the combination
    can never under-report. Never under-reporting is only half the requirement:
    a verdict may assert only what the audit proved, in both directions. Pairing
    the lowest version with another host's mode invented a host that does not
    exist. A NIC-mode host below its minimum beside a patched DPU-mode host became
    (below-minimum, DPU mode) and graded a live critical failure, when the
    below-minimum firmware is idle and the running controller is patched.

    So when the modes differ this is None, exactly as for mixed schemes and
    mixed lines, and the caller grades every entry in ``observedControllers``
    and takes the worst verdict. That still reports the below-minimum host; it
    reports it as the latent exposure it is.

    An unknown line is not a shared line. Comparing the fields as sets read a
    fleet where every host reported ``line: None`` as one comparable release
    line, because ``{None}`` has one member, and that is the ordinary case: the
    line is usually not discoverable. The lines then interleave, so the bare
    numeric minimum picked the milder grade. A fleet of 23.10.30 (clears the
    LTS23 minimum) and 24.10.17 (below the LTS24 minimum) reported the lower NUMBER,
    23.10.30, and graded pass with exposure none while a below-minimum controller
    was running on the other host. Two readings with no line are comparable only
    by number, and by number the milder one can win, so they are not comparable.
    """
    if not observed:
        return None
    for field in ("scheme", "line", "mode"):
        if len({entry[field] for entry in observed}) > 1:
            return None
    if len(observed) > 1 and not _known_line(observed[0].get("line")):
        return None
    return dict(observed[0])


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll per-host records into the one answer the minimum version grades.

    Worst case wins. A cluster where one node reports a version and another
    cannot be cleared is not a cluster that passes, so the reported version is
    the oldest observed and any unresolved node keeps the state unresolved.
    """
    if not records:
        return {
            "state": STATE_INCOMPLETE,
            "version": None,
            "line": None,
            "versionSource": None,
            "mode": None,
            "bluefield3Present": None,
            "reason": "no host produced a virtio-net record",
            "hostsChecked": 0,
            "bluefield3Hosts": 0,
            "observedControllers": [],
            "worstObserved": None,
            "isolationEvidence": {
                "scanComplete": False,
                "scanError": "no host produced a virtio-net record",
                "bluefield3Present": None,
                "rshimHostAccess": {},
            },
        }

    observed = observed_controllers(records)
    states = {str(record.get("state") or STATE_INCOMPLETE) for record in records}
    modes = {str(record.get("mode") or "unknown") for record in records}
    versions = [str(record["version"]) for record in records if record.get("version")]
    bluefield_hosts = sum(1 for record in records if record.get("bluefield3Present"))
    state = _controller_rung(
        most_severe(records, ladder=CONTROLLER_LADDER, rung_of=_controller_rung)
    )
    if state not in CONTROLLER_LADDER:
        state = STATE_INCOMPLETE

    oldest = min(versions, key=_version_key) if versions else None
    oldest_record = next(
        (record for record in records if record.get("version") == oldest and oldest is not None),
        None,
    )
    source = str(oldest_record["versionSource"]) if oldest_record and oldest_record.get("versionSource") else None
    # Only the line that belongs to the version being reported. A line read off
    # a different node would grade this version against the wrong minimum.
    line = str(oldest_record["line"]) if oldest_record and oldest_record.get("line") else None
    reasons = sorted({str(record.get("reason") or "") for record in records if record.get("state") == state})

    # Cluster mode, worst case first: one node still in DPU mode keeps the
    # bulletin in scope for the cluster. "absent" is claimed only when every
    # host completed its scan and none carried a BlueField, because that is the
    # one mode the evaluator grades as not_applicable.
    if "dpu" in modes:
        cluster_mode = "dpu"
    elif "nic" in modes:
        cluster_mode = "nic"
    elif all(record.get("scanComplete") and not record.get("bluefield3Present") for record in records):
        cluster_mode = "absent"
    else:
        cluster_mode = None

    return {
        "state": state,
        "version": oldest,
        "line": line,
        "versionSource": source,
        "mode": cluster_mode,
        "bluefield3Present": bluefield_hosts > 0,
        "reason": "; ".join(reason for reason in reasons if reason),
        "hostsChecked": len(records),
        "bluefield3Hosts": bluefield_hosts,
        # Independent of `state` on purpose. `version` above is gated on the
        # rollup clearing, because it answers "what does this cluster run".
        # These two answer "what did we actually see on a host", which an
        # unresolved peer cannot take away.
        "observedControllers": observed,
        "worstObserved": worst_observed(observed),
        "isolationEvidence": isolation_evidence(records),
    }


def apply_coverage_gap(summary: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    """Withdraw every cluster-wide clean claim when the fan-out missed a host.

    ``not_applicable``, a permissive cluster mode (``absent`` or ``nic``), and a
    version the evaluator can pass are all claims about every node. The fan-out
    degrades to the local
    host when there is no allocation, when ``srun`` fails or times out, and per
    node when a driver pod cannot be reached, and a DPU is per node, so none of
    those readings speaks for the cluster. The evidence stays in the summary and
    in the per-host records; only the graded state drops to ``incomplete``, so
    the answer is "not assessed" rather than "clean". A host that was reached
    and is already ``unknown`` stays there, because that is the stronger finding.

    ``observedControllers`` and ``worstObserved`` are deliberately untouched.
    This function weakens a pass and a not-applicable. It must never weaken a
    fail: a host proven to run below-minimum firmware stays proven no matter how
    many other hosts went unread.
    """
    if not errors:
        return summary
    gap = "; ".join(error for error in errors if error)
    summary["state"] = weaken_for_gap(
        str(summary.get("state") or ""),
        ladder=CONTROLLER_LADDER,
        gap_rung=CONTROLLER_GAP_RUNG,
    )
    if gap_can_weaken(summary.get("mode"), ladder=MODE_LADDER, gap_rung=MODE_GAP_RUNG):
        # None, not an explicit "unknown" string: it is the value summarize()
        # already produces when no cluster-wide mode can be claimed, and it
        # round-trips through the collector as "unknown", which the consumer
        # normalizes away and then grades with the plain running verdict. That
        # is the more severe path, because it drops the NIC-mode softening that
        # would otherwise report a latent exposure the fleet was never read for.
        summary["mode"] = None
    prior = str(summary.get("reason") or "").strip().rstrip(";")
    note = (
        f"the per-node scan did not reach every host ({gap}), so no absence and no "
        "clean controller version can be claimed for the cluster"
    )
    summary["reason"] = f"{prior}; {note}" if prior else note

    # The isolation verdict grades not_applicable off scanComplete plus an
    # absent BlueField, so the same coverage gap has to reach it. A host that
    # already proves the DPU is reachable keeps its finding: that one is true
    # whatever the unvisited hosts look like.
    evidence = dict(summary.get("isolationEvidence") or {})
    if gap_can_weaken(
        _isolation_proof_rung(evidence),
        ladder=ISOLATION_LADDER,
        gap_rung=ISOLATION_GAP_RUNG,
    ):
        # scanComplete False IS this ladder's gap rung: it is what the consumer
        # reads to return unknown.
        evidence["scanComplete"] = False
        evidence["scanError"] = f"the per-node scan did not reach every host ({gap})"
        summary["isolationEvidence"] = evidence
    return summary


# The DPU host-isolation criterion, most severe first.
#
# ISO_SCAN_GAP and ISO_POSTURE_GAP both grade unknown, so their relative order
# does not move a verdict; the scan gap is first because it is the more
# fundamental one. ISO_POSTURE_GAP is separate from ISO_HARDENED so a host
# whose posture could not be read is not represented by a hardened peer, which
# is the same asymmetry as a gap against a clean host one rung up.
ISO_REACHABLE = "reachable"
ISO_SCAN_GAP = "scan-gap"
ISO_POSTURE_GAP = "posture-gap"
ISO_HARDENED = "hardened"
ISO_ABSENT = "absent"

ISOLATION_LADDER = (
    ISO_REACHABLE,
    ISO_SCAN_GAP,
    ISO_POSTURE_GAP,
    ISO_HARDENED,
    ISO_ABSENT,
)
ISOLATION_GAP_RUNG = ISO_SCAN_GAP


def _isolation_reachable(record: dict[str, Any]) -> bool:
    """Host-side evidence that the DPU control plane is reachable.

    Read from the host filesystem and from mlxconfig, so it does not depend on
    the PCI scan completing and nothing another host does can contradict it.
    """
    rshim = record.get("rshimHostAccess") or {}
    return bool(
        rshim.get("rshimDeviceNode")
        or rshim.get("tmfifoNet0")
        or rshim.get("rshimRestricted") is False
    )


def _isolation_path_reachable(record: dict[str, Any]) -> bool:
    """Reachability the PCI scan cannot affect: the two host filesystem paths.

    ``collect_rshim`` stats /dev/rshim0 and /sys/class/net/tmfifo_net0 and never
    runs lspci, so these two stay true on a host with no lspci. INTERNAL_CPU_RSHIM
    is deliberately excluded: it comes from mlxconfig reading the device the scan
    finds, so it cannot be trusted ahead of the scan. This is exactly the split
    ``dpu_host_isolation_verdict`` makes.
    """
    rshim = record.get("rshimHostAccess") or {}
    return bool(rshim.get("rshimDeviceNode") or rshim.get("tmfifoNet0"))


def _isolation_rung(record: dict[str, Any]) -> str:
    """Which rung of the isolation ladder one host sits on, for selection.

    Selection has to agree with the consumer about what produces a fail,
    otherwise this fan-out re-introduces one layer up the erasure the consumer
    just fixed. ``dpu_host_isolation_verdict`` grades a record `fail` on the two
    filesystem paths alone, before its scan gate, so such a record is
    ISO_REACHABLE here even with no completed scan. Filing it on ISO_SCAN_GAP
    put it on the same rung as a host that proved nothing, and another host
    could then be selected in its place.

    A reachability that rests on INTERNAL_CPU_RSHIM still needs the scan, for
    the same reason the consumer keeps it behind the gate.
    """
    assessed = bool(record.get("scanComplete")) and record.get("bluefield3Present") is not None
    if _isolation_path_reachable(record):
        return ISO_REACHABLE
    if assessed and record.get("bluefield3Present") and _isolation_reachable(record):
        return ISO_REACHABLE
    if not assessed:
        return ISO_SCAN_GAP
    if not record.get("bluefield3Present"):
        return ISO_ABSENT
    restricted = (record.get("rshimHostAccess") or {}).get("rshimRestricted")
    return ISO_HARDENED if restricted is True else ISO_POSTURE_GAP


def _isolation_proof_rung(record: dict[str, Any]) -> str:
    """Which rung a record's own RShim evidence establishes, ignoring the scan.

    The coverage clamp asks a narrower question than selection does. Selection
    asks which host produces the strongest verdict, which needs a completed
    scan. The clamp asks whether this record already carries proof that a gap
    elsewhere cannot add to, and reachability is exactly that proof: it does
    not stop being proof because a different part of the same scan failed. A
    record whose RShim evidence shows no reachability is, for this question, an
    unread posture.
    """
    return ISO_REACHABLE if _isolation_reachable(record) else ISO_POSTURE_GAP


def isolation_evidence(records: list[dict[str, Any]]) -> dict[str, Any]:
    """The one host record the DPU host-isolation verdict is graded from.

    A host that still carries the RShim path proves the cluster is not in
    zero-trust mode, and that proof is not weakened by a host nobody could
    read. See ``_isolation_severity`` for the ladder. ``unassessedHosts`` names
    the hosts that could not be assessed, so a fail selected here still records
    that the fleet was only partly covered.
    """
    chosen = most_severe(
        records,
        ladder=ISOLATION_LADDER,
        rung_of=_isolation_rung,
        tiebreak=lambda record: str(record.get("host") or ""),
    )
    return {
        "host": chosen.get("host"),
        "scanComplete": chosen.get("scanComplete"),
        "scanError": chosen.get("scanError"),
        "bluefield3Present": chosen.get("bluefield3Present"),
        "modeError": chosen.get("modeError"),
        "rshimHostAccess": chosen.get("rshimHostAccess") or {},
        "unassessedHosts": sorted(
            str(record.get("host") or "")
            for record in records
            if _isolation_rung(record) in (ISO_SCAN_GAP, ISO_POSTURE_GAP)
        ),
    }


# ---------------------------------------------------------------------------
# Fan-out orchestration
# ---------------------------------------------------------------------------


def slurm_records(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> tuple[list[dict[str, Any]], list[str]]:
    if not env.get("SLURM_JOB_ID"):
        return [gather(env=env, runner=runner)], [
            "SLURM_JOB_ID is not set; the virtio-net check only checked the local host"
        ]
    command = [
        "srun",
        "--overlap",
        "-N",
        env.get("SLURM_NNODES") or "1",
        "--ntasks-per-node=1",
        sys.executable,
        str(Path(__file__).resolve()),
        "--collect-host",
    ]
    try:
        proc = runner(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=SLURM_TIMEOUT_S)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [gather(env=env, runner=runner)], [f"srun virtio-net check failed; local host only: {exc}"]
    records = load_fanout().parse_json_lines(proc.stdout, require_host=True)
    if not records:
        return [gather(env=env, runner=runner)], [
            f"srun virtio-net check returned no host JSON (exit {proc.returncode}); local host only"
        ]
    # A partial fan-out is the dangerous middle case: srun returns the hosts
    # that answered and says nothing about the ones that did not, so the rollup
    # would read as a complete cluster answer built from a subset. Compare the
    # host records against the allocation to catch it.
    errors: list[str] = []
    hosts = {str(record.get("host") or "") for record in records}
    try:
        wanted = int(str(env.get("SLURM_NNODES") or len(hosts)))
    except (TypeError, ValueError):
        wanted = len(hosts)
    if len(hosts) < wanted:
        errors.append(
            f"srun virtio-net check returned {len(hosts)} of {wanted} host records"
        )
    if proc.returncode != 0:
        errors.append(
            f"srun virtio-net check exited {proc.returncode}: {proc.stderr.strip()}"
        )
    return records, errors


# The driver daemonset image has no python3, so the per-node worker is POSIX sh
# emitting tagged lines that this orchestrator parses. It reads only; it never
# runs mlxprivhost and never writes to the RShim console.
K8S_COLLECTOR_SH = r'''
if command -v lspci >/dev/null 2>&1; then
  echo @@LSPCI_BEGIN@@
  lspci -Dnn 2>/dev/null
  rc=$?
  echo @@LSPCI_END@@
  [ "$rc" -eq 0 ] || printf '@@SCAN_ERROR@@\t%s\n' "lspci failed: exit $rc"
else
  printf '@@SCAN_ERROR@@\t%s\n' "lspci is not installed"
fi
slot=$(lspci -Dn 2>/dev/null | grep -Eio '^[0-9a-f:.]+ [^ ]* 15b3:(a2dc|a2d9)' | head -1 | cut -d' ' -f1)
if [ -n "$slot" ] && command -v mlxconfig >/dev/null 2>&1; then
  echo @@MLXCONFIG_BEGIN@@
  mlxconfig -d "$slot" q 2>&1
  echo @@MLXCONFIG_END@@
elif [ -n "$slot" ]; then
  printf '@@MODE_ERROR@@\t%s\n' "mlxconfig is not installed"
fi
[ -e /dev/rshim0 ] && printf '@@RSHIM@@\t%s\n' "device"
[ -e /sys/class/net/tmfifo_net0 ] && printf '@@RSHIM@@\t%s\n' "tmfifo"
if command -v virtnet >/dev/null 2>&1; then
  echo @@VIRTNET_BEGIN@@
  virtnet version 2>/dev/null
  echo @@VIRTNET_END@@
fi
'''


def parse_k8s_collector(text: str) -> dict[str, Any]:
    sections: dict[str, list[str]] = {"lspci": [], "mlxconfig": [], "virtnet": []}
    current: str | None = None
    scan_error: str | None = None
    mode_error: str | None = None
    rshim_flags: set[str] = set()
    begins = {
        "@@LSPCI_BEGIN@@": "lspci",
        "@@MLXCONFIG_BEGIN@@": "mlxconfig",
        "@@VIRTNET_BEGIN@@": "virtnet",
    }
    ends = {"@@LSPCI_END@@", "@@MLXCONFIG_END@@", "@@VIRTNET_END@@"}
    for line in text.splitlines():
        if line in begins:
            current = begins[line]
            continue
        if line in ends:
            current = None
            continue
        if current:
            sections[current].append(line)
            continue
        if line.startswith("@@SCAN_ERROR@@\t"):
            scan_error = line.split("\t", 1)[1]
        elif line.startswith("@@MODE_ERROR@@\t"):
            mode_error = line.split("\t", 1)[1]
        elif line.startswith("@@RSHIM@@\t"):
            rshim_flags.add(line.split("\t", 1)[1])
    return {
        "lspci": "\n".join(sections["lspci"]),
        "mlxconfig": "\n".join(sections["mlxconfig"]),
        "virtnet": "\n".join(sections["virtnet"]),
        "scanError": scan_error,
        "modeError": mode_error,
        "rshim": rshim_flags,
    }


def record_from_k8s(node: str, parsed: dict[str, Any]) -> dict[str, Any]:
    # Same asymmetry as the local path: a BlueField named in a partial listing
    # is present, an empty or failed listing is an unread bus and never an
    # absent DPU.
    scan = pci_scan_result(parsed["lspci"], parsed["scanError"])
    scan_complete = scan["scanComplete"]
    devices = scan["devices"]
    virtio_count = scan["virtioPciDevices"]
    mode_values = parse_mlxconfig(parsed["mlxconfig"])
    offload = mode_values.get("INTERNAL_CPU_OFFLOAD_ENGINE")
    mode = {"0": "dpu", "1": "nic"}.get(offload or "", "unknown")
    mode_error = parsed["modeError"]
    if devices and mode == "unknown" and not mode_error:
        mode_error = "mlxconfig returned no mode parameters (it usually needs root)"
    rshim = {
        "rshimDeviceNode": "device" in parsed["rshim"],
        "tmfifoNet0": "tmfifo" in parsed["rshim"],
        "internalCpuRshim": mode_values.get("INTERNAL_CPU_RSHIM", "unknown"),
        "rshimRestricted": {"0": False, "1": True}.get(mode_values.get("INTERNAL_CPU_RSHIM", ""), None),
        "dpuReachedFromHost": None,
    }
    version = parse_virtnet_version(parsed["virtnet"])
    record: dict[str, Any] = {
        "host": node,
        "scanComplete": scan_complete,
        "scanError": scan["scanError"],
        "bluefield3Present": bool(devices) if scan_complete else None,
        "bluefieldDevices": devices,
        "virtioPciDevices": virtio_count,
        "mode": mode,
        "modeSource": "mlxconfig" if mode_values else None,
        # The driver daemonset pod runs privileged as root, so the k8s worker
        # already holds the rights the local arm has to escalate for.
        "modeEscalation": ESCALATION_ROOT,
        "modeParameters": mode_values,
        "modeError": mode_error,
        "rshimHostAccess": rshim,
        "version": version,
        "versionSource": "virtnet-version" if version else None,
        # The pod collector runs `virtnet version` only, never `virtnet -v`.
        "cliVersion": None,
        "line": detect_line([parsed["virtnet"]]) if version else None,
        "lineEvidence": [parsed["virtnet"]] if version else [],
    }
    record["state"], record["reason"] = decide(record)
    return record


def kubectl(args: list[str], *, runner: Runner, timeout: int = KUBECTL_TIMEOUT_S) -> subprocess.CompletedProcess:
    return runner(["kubectl", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)


def k8s_namespace(*, env: dict[str, str], runner: Runner) -> str | None:
    override = env.get("CLUSTERMAX_GPU_OPERATOR_NAMESPACE")
    if override:
        return override
    for namespace in GPU_OPERATOR_NAMESPACES:
        try:
            proc = kubectl(["get", "namespace", namespace], runner=runner, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return namespace
    try:
        proc = kubectl(["get", "namespaces", "-o", "json"], runner=runner, timeout=30)
        namespaces = json.loads(proc.stdout) if proc.returncode == 0 else {"items": []}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        namespaces = {"items": []}
    matches = sorted(
        item.get("metadata", {}).get("name", "")
        for item in namespaces.get("items", [])
        if re.search(r"gpu-operator|nvidia-gpu", item.get("metadata", {}).get("name", ""), re.I)
    )
    if matches:
        return matches[0]
    return None


def k8s_driver_pod(namespace: str, node: str, *, runner: Runner) -> dict[str, Any] | None:
    try:
        proc = kubectl(
            ["get", "pods", "-n", namespace, "--field-selector", f"spec.nodeName={node}", "-o", "json"],
            runner=runner,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        pods = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    candidates: list[tuple[int, str, str | None, bool]] = []
    for item in pods.get("items", []):
        name = item.get("metadata", {}).get("name", "")
        if item.get("status", {}).get("phase") != "Running":
            continue
        volumes = {
            volume.get("name")
            for volume in item.get("spec", {}).get("volumes", [])
            if volume.get("hostPath", {}).get("path") == "/"
        }
        if "nvidia-driver" in name:
            candidates.append((0, name, None, False))
        elif "nvidia-device-plugin" in name:
            for container in item.get("spec", {}).get("containers", []):
                host_root = any(
                    mount.get("name") in volumes and mount.get("mountPath") == "/host"
                    for mount in container.get("volumeMounts", [])
                )
                if host_root and container.get("securityContext", {}).get("privileged") is True:
                    candidates.append((1, name, container.get("name"), True))
    if not candidates:
        return None
    _, name, container, host_root = min(candidates)
    return {"name": name, "container": container, "hostRoot": host_root}


def run_k8s_node_check(namespace: str, node: str, *, runner: Runner) -> tuple[dict[str, Any] | None, str | None]:
    access = k8s_driver_pod(namespace, node, runner=runner)
    if not access:
        return None, f"{node}: no running nvidia-driver pod for the virtio-net check"
    exec_args = ["exec", "-i", "-n", namespace, access["name"]]
    if access["container"]:
        exec_args.extend(["-c", access["container"]])
    exec_args.extend(["--", "sh", "-c", K8S_COLLECTOR_SH])
    if access["hostRoot"]:
        exec_args[-4:] = ["--", "chroot", "/host", "sh", "-c", K8S_COLLECTOR_SH]
    try:
        proc = kubectl(
            exec_args,
            runner=runner,
            timeout=KUBECTL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{node}: virtio-net check exec failed: {exc}"
    if proc.returncode != 0:
        return None, f"{node}: virtio-net check exec failed: {proc.stderr.strip()}"
    return record_from_k8s(node, parse_k8s_collector(proc.stdout)), None


def k8s_records(
    *,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        nodes_proc = kubectl(["get", "nodes", "-o", "json"], runner=runner, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [f"kubectl get nodes failed: {exc}"]
    if nodes_proc.returncode != 0:
        return [], [f"kubectl get nodes failed: {nodes_proc.stderr.strip()}"]
    try:
        nodes_json = json.loads(nodes_proc.stdout)
    except json.JSONDecodeError as exc:
        return [], [f"kubectl get nodes returned invalid JSON: {exc}"]

    nodes = load_fanout().k8s_gpu_nodes(nodes_json)
    if not nodes:
        return [], ["no Kubernetes nodes advertise nvidia.com/gpu capacity"]
    namespace = k8s_namespace(env=env, runner=runner)
    if not namespace:
        return [], ["no NVIDIA GPU Operator namespace found; cannot reach a driver pod for the virtio-net check"]
    try:
        max_nodes = int(str(env.get("CLUSTERMAX_AUDIT_K8S_MAX_HOST_CHECKS")))
    except (TypeError, ValueError):
        max_nodes = len(nodes)
    per_node = lambda node: run_k8s_node_check(namespace, node["name"], runner=runner)  # noqa: E731
    return load_fanout().fan_out_k8s(per_node, nodes=nodes, max_nodes=max_nodes)


def build_check_payload(
    *,
    harness: str,
    env: dict[str, str] = os.environ,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    if harness == "slurm":
        records, errors = slurm_records(env=env, runner=runner)
    elif harness == "k8s":
        records, errors = k8s_records(env=env, runner=runner)
    else:
        records, errors = [gather(env=env, runner=runner)], []

    summary = apply_coverage_gap(summarize(records), errors)
    if summary["state"] in (STATE_UNKNOWN, STATE_INCOMPLETE):
        errors.append(f"virtio-net controller state is {summary['state']}: {summary['reason']}")
    for error in errors:
        print(f"  WARNING: virtio_net_bluefield: {error}", file=sys.stderr)
    return {
        "virtio_net_bluefield": {
            "hosts": {str(record.get("host") or f"host-{index}"): record for index, record in enumerate(records)},
            "summary": summary,
        }
    }


# ---------------------------------------------------------------------------
# Collector interface
# ---------------------------------------------------------------------------

# What the collectors pass to security_version_audit.py --virtio-net.
#
# "not-installed" belongs to exactly one state: a completed scan that found no
# BlueField at all, which the evaluator pairs with mode "absent" and grades
# not_applicable. NIC mode is NOT that state. The card and its firmware are
# present, so it reports "unknown" and lets mode "nic" carry the latent-exposure
# verdict. Everything unresolved also reports "unknown", so a check that could
# not run can never be graded as a pass or silently dismissed.
COLLECTOR_VALUES = {
    STATE_NOT_APPLICABLE: "not-installed",
    STATE_NOT_RUNNING: "unknown",
    STATE_UNKNOWN: "unknown",
    STATE_INCOMPLETE: "unknown",
}


def collector_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """Flatten the rollup into the arguments security_version_audit.py takes.

    Two independent readings come out of here and they answer different
    questions.

    ``virtioNet`` / ``virtioNetLine`` / ``virtioNetMode`` are the CLUSTER
    answer. A version fills ``virtioNet`` only when the rollup cleared, so one
    unresolved node correctly stops the cluster being graded as a pass.

    ``virtioNetWorstObserved*`` / ``virtioNetObservedJson`` are the HOST
    answer: what a machine was actually seen running, whatever happened
    elsewhere. They are populated whenever any host read a version, including
    when the rollup state is ``unknown`` or ``incomplete``.

    The consumer must treat the worst-observed reading as escalate-only. A
    below-minimum reading has to produce a fail even under partial coverage, with
    the coverage gap named in the detail. A reading that passes must never
    clear an ``unknown`` or ``incomplete`` rollup, because the hosts that did
    not answer are exactly the ones it says nothing about.

    ``virtioNetWorstObserved`` is empty when the observed readings are not
    mutually comparable (mixed release lines, or the retired 1.x scheme mixed
    with the calendar scheme). ``virtioNetObservedJson`` always carries every
    distinct reading, so the consumer grades each and takes the worst verdict
    rather than having an ordering invented for it here.
    """
    summary = (payload.get("virtio_net_bluefield") or {}).get("summary") or {}
    state = str(summary.get("state") or STATE_INCOMPLETE)
    version = summary.get("version") if state == STATE_VERSION else None
    worst = summary.get("worstObserved") or {}
    observed = summary.get("observedControllers") or []
    return {
        "virtioNet": version or COLLECTOR_VALUES.get(state, "unknown"),
        "virtioNetLine": summary.get("line"),
        "virtioNetMode": summary.get("mode") or "unknown",
        "virtioNetSource": summary.get("versionSource"),
        "virtioNetReason": summary.get("reason") or "",
        "virtioNetWorstObserved": worst.get("version") or "",
        "virtioNetWorstObservedLine": worst.get("line"),
        "virtioNetWorstObservedMode": worst.get("mode") or "unknown",
        "virtioNetWorstObservedHost": worst.get("host") or "",
        "virtioNetObservedJson": json.dumps(observed, sort_keys=True),
        "dpuIsolationJson": json.dumps(summary.get("isolationEvidence") or {}, sort_keys=True),
        "state": state,
        "reason": summary.get("reason") or "",
    }


def load_or_build_payload(
    *, harness: str, env: dict[str, str] = os.environ
) -> dict[str, Any]:
    """Reuse this run's full fleet result across collector and final checks."""
    cache_value = str(env.get(CHECK_CACHE_ENV) or "").strip()
    cache_path = Path(cache_value) if cache_value else None
    if cache_path is not None:
        try:
            cached = json.loads(cache_path.read_text())
            if isinstance(cached, dict) and isinstance(
                cached.get("virtio_net_bluefield"), dict
            ):
                return cached
        except (OSError, json.JSONDecodeError):
            pass

    payload = build_check_payload(harness=harness, env=env)
    if cache_path is not None:
        try:
            cache_path.write_text(json.dumps(payload, sort_keys=True))
        except OSError:
            # The cache is only a runtime optimization. Collection remains
            # authoritative when the temporary directory cannot be written.
            pass
    return payload


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="BlueField VIRTIO-Net controller check")
    parser.add_argument("--collect-host", action="store_true", help="emit one host record instead of the aggregate")
    parser.add_argument(
        "--summary",
        action="store_true",
        help="emit only the collector-facing rollup (virtioNet / virtioNetLine)",
    )
    parser.add_argument(
        "--harness",
        default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS") or os.environ.get("CLUSTERMAX_HARNESS") or "",
    )
    args = parser.parse_args(argv)

    if args.collect_host:
        print(json.dumps(gather(), sort_keys=True))
        return 0

    payload = load_or_build_payload(harness=args.harness)
    if args.summary:
        print(json.dumps(collector_summary(payload), sort_keys=True))
        return 0
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
