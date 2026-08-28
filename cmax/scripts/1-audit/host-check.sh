#!/bin/bash

scale_out_checks_enabled() {
    [[ "${CLUSTERMAX_AUDIT_HARNESS:-}" != "standalone" ]]
}

security_checks_only() {
    [[ "${CLUSTERMAX_AUDIT_SCOPE:-full}" == "security" ]]
}

echo "WORKER_HOSTNAME=$(hostname)"
echo "WORKER_ARCH=$(uname -m 2>/dev/null || echo unknown)"

# --- OS / Image identification ---
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "WORKER_OS_ID=${ID:-unknown}"
    echo "WORKER_OS_VERSION_ID=${VERSION_ID:-unknown}"
    echo "WORKER_OS_PRETTY_NAME=${PRETTY_NAME:-unknown}"
else
    echo "WORKER_OS_ID=unknown"
    echo "WORKER_OS_VERSION_ID=unknown"
    echo "WORKER_OS_PRETTY_NAME=unknown"
fi
echo "WORKER_KERNEL=$(uname -r 2>/dev/null || echo unknown)"

if ! security_checks_only; then
# --- CPU inventory (model, topology, clocks, power limit) ---
# OEMs and providers can set a CPU below its datasheet: a lowered RAPL package
# power limit (cTDP), a capped max frequency, or a powersave governor all
# change delivered CPU performance while the marketing SKU stays the same.
# Record what the node exposes instead of assuming datasheet values. Every
# read is best-effort: a missing file or tool reports "unknown" and never
# fails the check. CLUSTERMAX_AUDIT_ROOT re-roots the /proc and /sys reads
# for tests, the same override the virtualization block below takes. It is
# unset in every audit run.
collect_cpu_inventory() {
    local root="${CLUSTERMAX_AUDIT_ROOT:-}"
    local cpuinfo="${root}/proc/cpuinfo"
    local model=unknown sockets=unknown cores_per_socket=unknown
    local threads=unknown threads_per_core=unknown

    if [[ -r "$cpuinfo" ]]; then
        model=$(awk -F': ' '/^model name/ {print $2; exit}' "$cpuinfo" 2>/dev/null)
        local thread_count socket_count
        # grep -c prints the count even when it exits 1 on zero matches, so
        # "|| true" (not "|| echo 0") keeps the substitution single-line.
        thread_count=$(grep -c '^processor' "$cpuinfo" 2>/dev/null || true)
        [[ "$thread_count" =~ ^[0-9]+$ && "$thread_count" -gt 0 ]] && threads="$thread_count"
        socket_count=$(awk -F':' '/^physical id/ {value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value}' "$cpuinfo" 2>/dev/null \
            | sort -u | awk 'END {print NR}')
        [[ "$socket_count" -gt 0 ]] && sockets="$socket_count"
    fi
    # ARM /proc/cpuinfo (Grace, Neoverse) carries neither "model name" nor
    # "physical id"; lscpu resolves both there. lscpu reads the live /sys, so
    # it only fills fields the re-rootable reads above left unknown.
    if command -v lscpu >/dev/null 2>&1; then
        local lscpu_out
        lscpu_out=$(lscpu 2>/dev/null)
        if [[ -z "$model" || "$model" == unknown ]]; then
            model=$(printf '%s\n' "$lscpu_out" \
                | awk -F':[[:space:]]*' '/^Model name/ {print $2; exit}')
        fi
        if [[ "$sockets" == unknown ]]; then
            sockets=$(printf '%s\n' "$lscpu_out" \
                | awk -F':[[:space:]]*' '/^Socket\(s\)/ {print $2; exit}')
        fi
        cores_per_socket=$(printf '%s\n' "$lscpu_out" \
            | awk -F':[[:space:]]*' '/^Core\(s\) per socket/ {print $2; exit}')
        threads_per_core=$(printf '%s\n' "$lscpu_out" \
            | awk -F':[[:space:]]*' '/^Thread\(s\) per core/ {print $2; exit}')
    fi
    [[ -n "$model" ]] || model=unknown
    [[ -n "$sockets" ]] || sockets=unknown
    [[ -n "$cores_per_socket" ]] || cores_per_socket=unknown
    [[ -n "$threads" ]] || threads=unknown
    [[ -n "$threads_per_core" ]] || threads_per_core=unknown

    # cpufreq: kHz sysfs values reported in MHz. base_frequency exists only
    # under intel_pstate; it stays unknown elsewhere and that is a real read.
    local cpu0="${root}/sys/devices/system/cpu/cpu0/cpufreq"
    local base_mhz=unknown max_mhz=unknown cur_mhz=unknown
    local khz
    if khz=$(cat "${cpu0}/base_frequency" 2>/dev/null) && [[ "$khz" =~ ^[0-9]+$ ]]; then
        base_mhz=$((khz / 1000))
    fi
    if khz=$(cat "${cpu0}/cpuinfo_max_freq" 2>/dev/null) && [[ "$khz" =~ ^[0-9]+$ ]]; then
        max_mhz=$((khz / 1000))
    fi
    if khz=$(cat "${cpu0}/scaling_cur_freq" 2>/dev/null) && [[ "$khz" =~ ^[0-9]+$ ]]; then
        cur_mhz=$((khz / 1000))
    fi

    # Governor: the unique set across every online CPU, so one node stuck in
    # powersave among performance cores reads "performance,powersave" instead
    # of whichever CPU happened to be sampled.
    local governors=unknown gov_list
    gov_list=$(cat "${root}"/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor \
        2>/dev/null | sort -u | paste -sd, -)
    [[ -n "$gov_list" ]] && governors="$gov_list"

    # RAPL package power limit: the configured cTDP, which an OEM can set
    # below the datasheet TDP. Reads the long_term constraint of each
    # package domain (constraint_0 when no constraint is named long_term)
    # and reports the unique per-package limits in watts. Modern AMD EPYC
    # exposes the same intel-rapl interface.
    local rapl_packages=0 limits="" domain name idx limit_uw limit_w
    for domain in "${root}"/sys/class/powercap/intel-rapl:*; do
        [[ -d "$domain" ]] || continue
        [[ "$domain" == *:*:* ]] && continue  # skip sub-domains (dram, core)
        name=$(cat "${domain}/name" 2>/dev/null) || continue
        [[ "$name" == package* ]] || continue
        rapl_packages=$((rapl_packages + 1))
        limit_uw=""
        for idx in 0 1 2; do
            [[ -r "${domain}/constraint_${idx}_name" ]] || continue
            if [[ "$(cat "${domain}/constraint_${idx}_name" 2>/dev/null)" == long_term ]]; then
                limit_uw=$(cat "${domain}/constraint_${idx}_power_limit_uw" 2>/dev/null)
                break
            fi
        done
        [[ -z "$limit_uw" ]] \
            && limit_uw=$(cat "${domain}/constraint_0_power_limit_uw" 2>/dev/null)
        if [[ "$limit_uw" =~ ^[0-9]+$ ]]; then
            limit_w=$((limit_uw / 1000000))
            case ",${limits}," in
                *",${limit_w},"*) ;;
                *) limits="${limits:+${limits},}${limit_w}" ;;
            esac
        fi
    done
    [[ -n "$limits" ]] || limits=unknown

    echo "WORKER_CPU_MODEL=${model}"
    echo "WORKER_CPU_SOCKETS=${sockets}"
    echo "WORKER_CPU_CORES_PER_SOCKET=${cores_per_socket}"
    echo "WORKER_CPU_THREADS=${threads}"
    echo "WORKER_CPU_THREADS_PER_CORE=${threads_per_core}"
    echo "WORKER_CPU_BASE_MHZ=${base_mhz}"
    echo "WORKER_CPU_MAX_MHZ=${max_mhz}"
    echo "WORKER_CPU_CUR_MHZ=${cur_mhz}"
    echo "WORKER_CPU_GOVERNOR=${governors}"
    echo "WORKER_CPU_RAPL_PACKAGES=${rapl_packages}"
    echo "WORKER_CPU_PACKAGE_POWER_LIMIT_W=${limits}"
}
# Capture the CPU facts instead of streaming them: the memory inventory
# below needs the socket count to derive per-socket bandwidth, and the
# check protocol stays line-oriented either way.
CPU_INVENTORY_FACTS=$(collect_cpu_inventory)
printf '%s\n' "$CPU_INVENTORY_FACTS"

# Memory inventory: the populated DIMM count and the configured speed set
# the node's memory bandwidth ceiling (channels x MT/s x 8 bytes). A
# provider can populate fewer channels than the platform offers or run
# modules below their rated speed, and STREAM results cannot separate that
# from CPU limits without this evidence. Each read degrades to "unknown"
# and never fails the check.
collect_memory_inventory() {
    local sockets="${1:-}"
    local threads="${2:-}"
    local root="${CLUSTERMAX_AUDIT_ROOT:-}"
    local dimms=unknown sizes=unknown types=unknown
    local rated=unknown configured=unknown mem_source=unknown

    # dmidecode -t 17 reads the SMBIOS Memory Device records: one per DIMM
    # slot with size, type, locator, rated speed, and configured speed. It
    # needs root, and the slurm and standalone checks run as the operator
    # user, so mirror the WORKER_QEMU_MACHINE elevation: plain first (root
    # checks and privileged k8s pods), then passwordless sudo.
    local dmi=""
    if command -v dmidecode >/dev/null 2>&1; then
        dmi=$(dmidecode -t 17 2>/dev/null) || dmi=""
        if [[ -z "$dmi" ]] && sudo -n true 2>/dev/null; then
            dmi=$(sudo -n dmidecode -t 17 2>/dev/null) || dmi=""
        fi
    fi
    if [[ -n "$dmi" ]]; then
        # One record per device, flushed on the next record header. Only
        # populated RAM modules pass: empty slots say "No Module Installed",
        # and SMBIOS type 17 also lists firmware Flash/ROM chips, whose kB
        # sizes and non-RAM types must not count as DIMMs. dmidecode renamed
        # "Configured Clock Speed" to "Configured Memory Speed" in 3.1.
        local devices
        devices=$(printf '%s\n' "$dmi" | awk '
            function flush() {
                if (indev && gb != "" && \
                    type !~ /^(Flash|ROM|EEPROM|EPROM|FEPROM|NVRAM|CMOS)$/)
                    print gb "|" type "|" rated "|" conf
                indev = 0
            }
            /^Memory Device$/ {
                flush(); indev = 1; gb = ""; type = ""; rated = ""; conf = ""
                next
            }
            /^Handle / { flush(); next }
            indev && /^[ \t]+Size: [0-9]+ MB$/ { gb = $2 / 1024 }
            indev && /^[ \t]+Size: [0-9]+ GB$/ { gb = $2 }
            indev && /^[ \t]+Size: [0-9]+ TB$/ { gb = $2 * 1024 }
            indev && /^[ \t]+Type: / { type = $2 }
            indev && /^[ \t]+Speed: [0-9]/ { rated = $2 }
            indev && /^[ \t]+Configured (Memory|Clock) Speed: [0-9]/ {
                conf = $(NF - 1)
            }
            END { flush() }')
    fi
    if [[ -n "${devices:-}" ]]; then
        local dimm_count size_list type_list rated_list conf_list
        dimm_count=$(printf '%s\n' "$devices" | awk 'NF { n++ } END { print n + 0 }')
        size_list=$(printf '%s\n' "$devices" | cut -d'|' -f1 \
            | sort -un | paste -sd, -)
        type_list=$(printf '%s\n' "$devices" | cut -d'|' -f2 \
            | awk 'length && $0 != "Unknown" && $0 != "Other" && $0 != "None"' \
            | sort -u | paste -sd, -)
        rated_list=$(printf '%s\n' "$devices" | cut -d'|' -f3 \
            | awk '/^[0-9]+$/' | sort -un | paste -sd, -)
        conf_list=$(printf '%s\n' "$devices" | cut -d'|' -f4 \
            | awk '/^[0-9]+$/' | sort -un | paste -sd, -)
        if [[ "$dimm_count" =~ ^[0-9]+$ && "$dimm_count" -gt 0 ]]; then
            dimms="$dimm_count"
            mem_source=dmidecode
            [[ -n "$size_list" ]] && sizes="$size_list"
            [[ -n "$type_list" ]] && types="$type_list"
            [[ -n "$rated_list" ]] && rated="$rated_list"
            [[ -n "$conf_list" ]] && configured="$conf_list"
        fi
    fi

    # EDAC fallback: rootless and re-rootable, but it only exposes the
    # populated modules' count, size, and type - no speeds.
    if [[ "$dimms" == unknown ]]; then
        local edac_count=0 edac_sizes="" edac_types="" d size_mb gb mem_type
        for d in "${root}"/sys/devices/system/edac/mc/mc*/dimm*; do
            [[ -d "$d" ]] || continue
            size_mb=$(cat "${d}/size" 2>/dev/null)
            [[ "$size_mb" =~ ^[0-9]+$ && "$size_mb" -gt 0 ]] || continue
            edac_count=$((edac_count + 1))
            gb=$((size_mb / 1024))
            case ",${edac_sizes}," in
                *",${gb},"*) ;;
                *) edac_sizes="${edac_sizes:+${edac_sizes},}${gb}" ;;
            esac
            mem_type=$(cat "${d}/dimm_mem_type" 2>/dev/null)
            if [[ -n "$mem_type" && "$mem_type" != Unknown ]]; then
                case ",${edac_types}," in
                    *",${mem_type},"*) ;;
                    *) edac_types="${edac_types:+${edac_types},}${mem_type}" ;;
                esac
            fi
        done
        if [[ "$edac_count" -gt 0 ]]; then
            dimms="$edac_count"
            mem_source=edac
            [[ -n "$edac_sizes" ]] && sizes="$edac_sizes"
            [[ -n "$edac_types" ]] && types="$edac_types"
        fi
    fi

    # Effective bandwidth: node GB/s = DIMMs (channels at one DIMM per
    # channel) times the lowest configured MT/s (mixed-speed channels run
    # at the lowest common speed) times 8 bytes per transfer. Per socket
    # divides by the socket count; per core divides by the logical CPU
    # count, so SMT nodes charge each hardware thread its share. This is
    # the ceiling STREAM runs against; a 2DPC platform would halve the
    # channel term, which the populated-DIMM evidence makes reviewable.
    local bw=unknown bw_core=unknown
    local min_configured="${configured%%,*}"
    if [[ "$dimms" =~ ^[0-9]+$ && "$min_configured" =~ ^[0-9]+$ ]]; then
        if [[ "$sockets" =~ ^[0-9]+$ && "$sockets" -gt 0 ]]; then
            bw=$(awk -v d="$dimms" -v s="$sockets" -v m="$min_configured" \
                'BEGIN { printf "%.1f", d * m * 8 / 1000 / s }')
        fi
        if [[ "$threads" =~ ^[0-9]+$ && "$threads" -gt 0 ]]; then
            bw_core=$(awk -v d="$dimms" -v t="$threads" -v m="$min_configured" \
                'BEGIN { printf "%.2f", d * m * 8 / 1000 / t }')
        fi
    fi

    echo "WORKER_MEM_DIMMS=${dimms}"
    echo "WORKER_MEM_DIMM_SIZES_GB=${sizes}"
    echo "WORKER_MEM_TYPES=${types}"
    echo "WORKER_MEM_RATED_SPEED_MTS=${rated}"
    echo "WORKER_MEM_CONFIGURED_SPEED_MTS=${configured}"
    echo "WORKER_MEM_BW_PER_SOCKET_GBS=${bw}"
    echo "WORKER_MEM_BW_PER_CORE_GBS=${bw_core}"
    echo "WORKER_MEM_SOURCE=${mem_source}"
}
collect_memory_inventory \
    "$(printf '%s\n' "$CPU_INVENTORY_FACTS" | sed -n 's/^WORKER_CPU_SOCKETS=//p')" \
    "$(printf '%s\n' "$CPU_INVENTORY_FACTS" | sed -n 's/^WORKER_CPU_THREADS=//p')"
fi

# Detect the common state where patched kernel packages are installed but the
# host is still executing an older image. Package security tools inspect dpkg
# state and can otherwise report no pending update while the live kernel stays
# vulnerable until reboot.
WORKER_GUEST_KERNEL_RUNNING=$(uname -r 2>/dev/null || echo unknown)
WORKER_GUEST_KERNEL_NEWEST_INSTALLED=unknown
WORKER_GUEST_KERNEL_NEWER_INSTALLED=false
WORKER_GUEST_REBOOT_REQUIRED=false
WORKER_GUEST_KERNEL_FLAVOR=$(printf '%s\n' "$WORKER_GUEST_KERNEL_RUNNING" \
    | sed -E 's/^[0-9]+(\.[0-9]+)*-[0-9]+-//')
if [[ -e /var/run/reboot-required ]]; then
    WORKER_GUEST_REBOOT_REQUIRED=true
fi
if command -v dpkg-query >/dev/null 2>&1; then
    WORKER_GUEST_KERNEL_NEWEST_INSTALLED=$(
        dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 'linux-image-[0-9]*' 2>/dev/null \
            | awk -v suffix="-${WORKER_GUEST_KERNEL_FLAVOR}" \
                '$1 == "ii" && index($2, suffix) == length($2) - length(suffix) + 1 {
                    sub(/^linux-image-/, "", $2); print $2
                }' \
            | sort -V | tail -1
    )
    [[ -z "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED" ]] \
        && WORKER_GUEST_KERNEL_NEWEST_INSTALLED=unknown
elif command -v rpm >/dev/null 2>&1; then
    WORKER_GUEST_KERNEL_NEWEST_INSTALLED=$(
        rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' kernel-core kernel 2>/dev/null \
            | grep -v '^package ' | sort -V | tail -1
    )
    [[ -z "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED" ]] \
        && WORKER_GUEST_KERNEL_NEWEST_INSTALLED=unknown
fi
if [[ "$WORKER_GUEST_KERNEL_RUNNING" != unknown \
        && "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED" != unknown \
        && "$WORKER_GUEST_KERNEL_RUNNING" != "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED" ]]; then
    WORKER_GUEST_KERNEL_OLDEST=$(
        printf '%s\n%s\n' "$WORKER_GUEST_KERNEL_RUNNING" \
            "$WORKER_GUEST_KERNEL_NEWEST_INSTALLED" | sort -V | head -1
    )
    if [[ "$WORKER_GUEST_KERNEL_OLDEST" == "$WORKER_GUEST_KERNEL_RUNNING" ]]; then
        WORKER_GUEST_KERNEL_NEWER_INSTALLED=true
    fi
fi
echo "WORKER_GUEST_KERNEL_RUNNING=${WORKER_GUEST_KERNEL_RUNNING}"
echo "WORKER_GUEST_KERNEL_NEWEST_INSTALLED=${WORKER_GUEST_KERNEL_NEWEST_INSTALLED}"
echo "WORKER_GUEST_KERNEL_NEWER_INSTALLED=${WORKER_GUEST_KERNEL_NEWER_INSTALLED}"
echo "WORKER_GUEST_REBOOT_REQUIRED=${WORKER_GUEST_REBOOT_REQUIRED}"

# Ubuntu's CVE-2026-46300 (Fragnesia) Noble 6.8 fixed package carries a minimum
# kernel ABI, for example 6.8.0-124.124 whose running release is
# 6.8.0-124-generic. The minimum is published in the generated table
# minimum-versions.json and read through its sibling reader minimum_versions.py,
# so a refreshed table changes the grade without a code edit. Compare versions
# only; never execute the public local-privilege-escalation proof of concept.
#
# This check runs on the worker, where the reader is not always reachable: the
# slurm and k8s collectors deliver this script over stdin (`bash -s`, so
# BASH_SOURCE is empty) and the standalone collector copies it to /tmp. The
# minimum is resolved in this order:
#   1. CLUSTERMAX_FRAGNESIA_ABI_MINIMUM, a minimum the collector already resolved
#      and passed in. cluster-audit-k8s.sh uses this, because its check runs in
#      a container or a chroot that cannot see the checkout.
#   2. minimum_versions.py beside this script, when this script is on disk.
#   3. CLUSTERMAX_MINIMUM_VERSIONS_READER, exported by audit-common.sh, for the
#      collectors whose check runs on a filesystem that holds the checkout.
# An unresolved minimum reports "unknown" for both the minimum and the status. It
# never falls back to a literal: a stale or guessed minimum would report a
# vulnerable kernel as fixed, which is the one outcome this check must not
# produce.
WORKER_FRAGNESIA_ABI_FLOOR="${CLUSTERMAX_FRAGNESIA_ABI_MINIMUM:-}"
if [[ ! "$WORKER_FRAGNESIA_ABI_FLOOR" =~ ^[0-9]+$ ]]; then
    WORKER_FRAGNESIA_ABI_FLOOR=""
    fragnesia_check_dir=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        fragnesia_check_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) \
            || fragnesia_check_dir=""
    fi
    fragnesia_readers=()
    [[ -n "$fragnesia_check_dir" ]] \
        && fragnesia_readers+=("$fragnesia_check_dir/minimum_versions.py")
    [[ -n "${CLUSTERMAX_MINIMUM_VERSIONS_READER:-}" ]] \
        && fragnesia_readers+=("$CLUSTERMAX_MINIMUM_VERSIONS_READER")
    if command -v python3 >/dev/null 2>&1; then
        for fragnesia_reader in "${fragnesia_readers[@]}"; do
            [[ -f "$fragnesia_reader" ]] || continue
            WORKER_FRAGNESIA_ABI_FLOOR=$(python3 "$fragnesia_reader" \
                --get components.ubuntuNoble.packages.linuxFragnesia.abi 2>/dev/null) \
                || WORKER_FRAGNESIA_ABI_FLOOR=""
            [[ -n "$WORKER_FRAGNESIA_ABI_FLOOR" ]] && break
        done
    fi
fi
[[ "$WORKER_FRAGNESIA_ABI_FLOOR" =~ ^[0-9]+$ ]] || WORKER_FRAGNESIA_ABI_FLOOR=unknown

WORKER_FRAGNESIA_ABI=unknown
WORKER_FRAGNESIA_STATUS=not-applicable
if [[ "${ID:-unknown}" == ubuntu && "${VERSION_ID:-unknown}" == 24.04 \
        && "$WORKER_GUEST_KERNEL_RUNNING" == 6.8.* ]]; then
    WORKER_FRAGNESIA_ABI=$(printf '%s\n' "$WORKER_GUEST_KERNEL_RUNNING" \
        | sed -nE 's/^6\.8\.0-([0-9]+).*/\1/p')
    [[ -n "$WORKER_FRAGNESIA_ABI" ]] || WORKER_FRAGNESIA_ABI=unknown
    WORKER_FRAGNESIA_STATUS=unknown
    if [[ "$WORKER_FRAGNESIA_ABI" =~ ^[0-9]+$ \
            && "$WORKER_FRAGNESIA_ABI_FLOOR" =~ ^[0-9]+$ ]]; then
        if (( WORKER_FRAGNESIA_ABI >= WORKER_FRAGNESIA_ABI_FLOOR )); then
            WORKER_FRAGNESIA_STATUS=pass
        else
            WORKER_FRAGNESIA_STATUS=fail
        fi
    fi
fi
echo "WORKER_FRAGNESIA_ABI=${WORKER_FRAGNESIA_ABI}"
echo "WORKER_FRAGNESIA_ABI_FLOOR=${WORKER_FRAGNESIA_ABI_FLOOR}"
echo "WORKER_FRAGNESIA_STATUS=${WORKER_FRAGNESIA_STATUS}"

# --- Hypervisor security bulletins (read-only, never triggers a PoC) ---
# These checks identify guest-visible prerequisites and exact versions. Host
# patch state cannot be proven from a tenant VM, so unknown host facts remain
# explicit rather than being inferred from the QEMU machine compatibility name.
#
# Three facts, deliberately kept apart:
#
#   WORKER_VIRT_TYPE       the technology a reading named, "none" for a reading
#                          that proved bare metal, "unknown" when nothing read
#                          it.
#   WORKER_VIRT_GUEST      true / false / unknown: is this machine a guest.
#   WORKER_VIRT_DETECTION  which signal answered.
#
# systemd-detect-virt exits 0 and names the technology inside a guest, and
# exits 1 printing "none" on bare metal. Both of those are real reads. A
# missing binary, or a failure that is not that ordinary bare-metal exit, is
# not. The retired `systemd-detect-virt 2>/dev/null || echo none` collapsed the
# two into the bare-metal answer, so a VM with no systemd claimed bare metal
# and graded both hypervisor-boundary checks below as not-applicable, which the
# security report renders as a pass.
#
# The /proc/cpuinfo hypervisor flag is the fallback, and it concludes in one
# direction only. The flag present proves this machine is a guest. The flag
# absent proves nothing, because a hypervisor can hide it, so a negative
# fallback leaves the question unknown and never restores "none".
#
# CLUSTERMAX_AUDIT_ROOT re-roots the /proc, /dev, and /sys reads below for
# tests, the same override checks/fabric/virtio-net-check.py takes. It is unset
# in every audit run.
VIRT_AUDIT_ROOT="${CLUSTERMAX_AUDIT_ROOT:-}"
WORKER_VIRT_TYPE=unknown
WORKER_VIRT_GUEST=unknown
WORKER_VIRT_DETECTION=none
if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt_reading=$(systemd-detect-virt 2>/dev/null)
    virt_rc=$?
    virt_reading="${virt_reading//[[:space:]]/}"
    if [[ "$virt_rc" -eq 0 && -n "$virt_reading" && "$virt_reading" != none ]]; then
        WORKER_VIRT_TYPE="$virt_reading"
        WORKER_VIRT_GUEST=true
        WORKER_VIRT_DETECTION=systemd-detect-virt
    elif [[ "$virt_reading" == none && ( "$virt_rc" -eq 0 || "$virt_rc" -eq 1 ) ]]; then
        WORKER_VIRT_TYPE=none
        WORKER_VIRT_GUEST=false
        WORKER_VIRT_DETECTION=systemd-detect-virt
    fi
fi
if [[ "$WORKER_VIRT_GUEST" == unknown ]] && grep -qm1 -E \
        '(^|[[:space:]])hypervisor([[:space:]]|$)' \
        "${VIRT_AUDIT_ROOT}/proc/cpuinfo" 2>/dev/null; then
    # A guest for certain. Which hypervisor stays unknown, so the two
    # KVM/QEMU-specific bulletins below stay in scope rather than being graded
    # against a technology nothing named.
    WORKER_VIRT_GUEST=true
    WORKER_VIRT_DETECTION=cpuinfo-hypervisor
fi

# Scope for the two KVM/QEMU-specific bulletins. "unknown" covers both a
# machine nothing could classify and a confirmed guest whose technology is
# unknown. Neither may grade not-applicable, because that renders as a pass.
virt_kvm_scope=no
case "$WORKER_VIRT_TYPE" in
    kvm|qemu) virt_kvm_scope=yes ;;
    unknown)  virt_kvm_scope=unknown ;;
esac

WORKER_QEMU_MACHINE=unknown
if command -v dmidecode >/dev/null 2>&1; then
    if [[ "$(id -u)" -eq 0 ]]; then
        WORKER_QEMU_MACHINE=$(dmidecode -s system-version 2>/dev/null || echo unknown)
    elif sudo -n true 2>/dev/null; then
        WORKER_QEMU_MACHINE=$(sudo -n dmidecode -s system-version 2>/dev/null || echo unknown)
    fi
fi
[[ -z "$WORKER_QEMU_MACHINE" ]] && WORKER_QEMU_MACHINE=unknown

WORKER_NESTED_CPU_EXPOSED=false
grep -qm1 -E '(^|[[:space:]])(svm|vmx)([[:space:]]|$)' \
    "${VIRT_AUDIT_ROOT}/proc/cpuinfo" 2>/dev/null \
    && WORKER_NESTED_CPU_EXPOSED=true
WORKER_KVM_DEVICE=false
[[ -e "${VIRT_AUDIT_ROOT}/dev/kvm" ]] && WORKER_KVM_DEVICE=true
WORKER_NESTED_MODULE=none
WORKER_NESTED_ENABLED=unknown
for kvm_mod in kvm_amd kvm_intel; do
    nested_file="${VIRT_AUDIT_ROOT}/sys/module/${kvm_mod}/parameters/nested"
    if [[ -r "$nested_file" ]]; then
        WORKER_NESTED_MODULE="$kvm_mod"
        nested_value=$(cat "$nested_file" 2>/dev/null || echo unknown)
        case "$nested_value" in
            1|Y|y) WORKER_NESTED_ENABLED=true ;;
            0|N|n) WORKER_NESTED_ENABLED=false ;;
            *) WORKER_NESTED_ENABLED=unknown ;;
        esac
        break
    fi
done
WORKER_JANUSCAPE_EXPOSED=false
WORKER_JANUSCAPE_STATUS=not-exposed
if [[ "$virt_kvm_scope" == yes ]] \
        && [[ "$WORKER_NESTED_CPU_EXPOSED" == true ]] \
        && [[ "$WORKER_KVM_DEVICE" == true ]] \
        && [[ "$WORKER_NESTED_ENABLED" == true ]]; then
    WORKER_JANUSCAPE_EXPOSED=true
    WORKER_JANUSCAPE_STATUS=host-patch-required
elif [[ "$virt_kvm_scope" != no ]] \
        && [[ "$WORKER_NESTED_CPU_EXPOSED" == true ]] \
        && [[ "$WORKER_KVM_DEVICE" == true ]] \
        && [[ "$WORKER_NESTED_ENABLED" != false ]]; then
    # Every prerequisite this check can read is in place and exactly one fact
    # is missing: the nested-KVM parameter, or the platform classification. A
    # false here would be a confident claim resting on the fact nobody read.
    # The /dev/kvm and svm/vmx reads above stay hard prerequisites, because a
    # missing device node and a CPU with no virtualization flag are real reads
    # that rule the Januscape prerequisites out on their own.
    WORKER_JANUSCAPE_EXPOSED=unknown
    WORKER_JANUSCAPE_STATUS=unknown
fi

WORKER_VIRTIO_SERIAL=false
[[ -e "${VIRT_AUDIT_ROOT}/dev/virtio-ports/org.qemu.guest_agent.0" ]] \
    && WORKER_VIRTIO_SERIAL=true
WORKER_QEMU_CVE_2024_3446_STATUS=not-applicable
if [[ "$virt_kvm_scope" == yes && "$WORKER_VIRTIO_SERIAL" == true ]]; then
    WORKER_QEMU_CVE_2024_3446_STATUS=host-version-required
elif [[ "$virt_kvm_scope" == unknown ]]; then
    # Never not-applicable here: that renders as a pass, and nothing placed
    # this machine outside the bulletin's scope. "unknown" is already in the
    # warning set the security report grades this check with.
    WORKER_QEMU_CVE_2024_3446_STATUS=unknown
fi
WORKER_VMSCAPE_STATUS=not-applicable
if [[ "$virt_kvm_scope" == yes ]] && [[ "$(uname -m)" == x86_64 ]]; then
    WORKER_VMSCAPE_STATUS=host-mitigation-required
elif [[ "$virt_kvm_scope" == unknown ]] && [[ "$(uname -m)" == x86_64 ]]; then
    WORKER_VMSCAPE_STATUS=unknown
fi
WORKER_IOMMU_GROUPS=0
if [[ -d /sys/kernel/iommu_groups ]]; then
    WORKER_IOMMU_GROUPS=$(find -L /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d '[:space:]')
fi

echo "WORKER_VIRT_TYPE=${WORKER_VIRT_TYPE}"
echo "WORKER_VIRT_GUEST=${WORKER_VIRT_GUEST}"
echo "WORKER_VIRT_DETECTION=${WORKER_VIRT_DETECTION}"
echo "WORKER_QEMU_MACHINE=${WORKER_QEMU_MACHINE}"
echo "WORKER_NESTED_CPU_EXPOSED=${WORKER_NESTED_CPU_EXPOSED}"
echo "WORKER_KVM_DEVICE=${WORKER_KVM_DEVICE}"
echo "WORKER_NESTED_MODULE=${WORKER_NESTED_MODULE}"
echo "WORKER_NESTED_ENABLED=${WORKER_NESTED_ENABLED}"
echo "WORKER_JANUSCAPE_EXPOSED=${WORKER_JANUSCAPE_EXPOSED}"
echo "WORKER_JANUSCAPE_STATUS=${WORKER_JANUSCAPE_STATUS}"
echo "WORKER_VIRTIO_SERIAL=${WORKER_VIRTIO_SERIAL}"
echo "WORKER_QEMU_CVE_2024_3446_STATUS=${WORKER_QEMU_CVE_2024_3446_STATUS}"
echo "WORKER_VMSCAPE_STATUS=${WORKER_VMSCAPE_STATUS}"
echo "WORKER_IOMMU_GROUPS=${WORKER_IOMMU_GROUPS}"

# --- GPU ---
if command -v nvidia-smi &>/dev/null; then
    echo "WORKER_GPU_MODEL=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | tr ' ' '-' || echo unknown)"
    echo "WORKER_DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || echo unknown)"
    echo "WORKER_CUDA_VERSION=$(nvidia-smi 2>/dev/null | grep -oP 'CUDA Version: \K[0-9.]+' || echo unknown)"
    echo "WORKER_GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo 0)"
    echo "WORKER_GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l || echo 0)"
else
    echo "WORKER_GPU_MODEL=no-nvidia-smi"
    echo "WORKER_DRIVER_VERSION=unknown"
    echo "WORKER_CUDA_VERSION=unknown"
    echo "WORKER_GPU_MEMORY=0"
    echo "WORKER_GPU_COUNT=0"
fi

# NVIDIA May 2026 bulletin minimum fixed releases. This is a version check only;
# vGPU Manager patch state must be checked on the physical host.
WORKER_NVIDIA_MAY_2026_PATCHED=unknown
# This is tenant-visible topology evidence, not a claim about the hidden host
# fabric.  NVBleed demonstrated leakage over a physical NVLink joining GPUs in
# different VMs, so a guest with no visible NV# entry still needs provider-side
# domain ownership evidence.  Preserve unknown unless the command itself ran.
WORKER_NVLINK_EXPOSED=unknown
WORKER_NVLINK_TOPOLOGY_CHECKED=false
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia_driver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
    nvidia_min=""
    case "$nvidia_driver" in
        595.*) nvidia_min=595.71.05 ;;
        580.*) nvidia_min=580.159.03 ;;
        535.*) nvidia_min=535.309.01 ;;
    esac
    if [[ -n "$nvidia_min" ]]; then
        if [[ "$(printf '%s\n%s\n' "$nvidia_min" "$nvidia_driver" | sort -V | head -1)" == "$nvidia_min" ]]; then
            WORKER_NVIDIA_MAY_2026_PATCHED=true
        else
            WORKER_NVIDIA_MAY_2026_PATCHED=false
        fi
    else
        branch=${nvidia_driver%%.*}
        if [[ "$branch" =~ ^[0-9]+$ ]] && [ "$branch" -gt 595 ]; then
            WORKER_NVIDIA_MAY_2026_PATCHED=true   # branch newer than the newest in the May 2026 bulletin
        fi
    fi
    if nvlink_topology=$(nvidia-smi topo -m 2>/dev/null) \
            && [[ -n "$nvlink_topology" ]]; then
        WORKER_NVLINK_TOPOLOGY_CHECKED=true
        WORKER_NVLINK_EXPOSED=false
        if grep -qE '(^|[[:space:]])NV[0-9]+([[:space:]]|$)' <<< "$nvlink_topology"; then
            WORKER_NVLINK_EXPOSED=true
        fi
    fi
fi
echo "WORKER_NVIDIA_MAY_2026_PATCHED=${WORKER_NVIDIA_MAY_2026_PATCHED}"
echo "WORKER_NVLINK_EXPOSED=${WORKER_NVLINK_EXPOSED}"
echo "WORKER_NVLINK_TOPOLOGY_CHECKED=${WORKER_NVLINK_TOPOLOGY_CHECKED}"

if ! security_checks_only; then
# --- GPUDirect RDMA ---
if scale_out_checks_enabled; then
# nvidia_peermem is the legacy out-of-tree module path. NVIDIA has moved
# GPUDirect RDMA to the in-tree dma_buf interface (upstream Linux, blessed
# by Linus Torvalds and shipped by NVIDIA in the open kernel module). A
# modern cluster on the nvidia-open driver enables GPUDirect RDMA WITHOUT
# nvidia_peermem loaded - that is correct, not broken. The audit must
# accept either path.
WORKER_PEERMEM_LEGACY=false
WORKER_NVIDIA_OPEN=false
WORKER_NVIDIA_DMABUF=false

if lsmod 2>/dev/null | grep -q '^nvidia_peermem '; then
    WORKER_PEERMEM_LEGACY=true
fi
if [[ -r /proc/driver/nvidia/version ]] && \
        grep -qi "open kernel" /proc/driver/nvidia/version 2>/dev/null; then
    WORKER_NVIDIA_OPEN=true
fi
# Direct dma_buf-from-GPU export sysfs hooks. Present on nvidia-open and on
# closed-kernel >= 565 builds that ship the dma_buf path. This is the
# strongest positive signal for the new GPUDirect RDMA flow.
if [[ -d /sys/module/nvidia/drivers ]] && \
        find /sys/module/nvidia -maxdepth 4 -name 'dma_buf*' 2>/dev/null | grep -q .; then
    WORKER_NVIDIA_DMABUF=true
fi

echo "WORKER_PEERMEM_LEGACY=${WORKER_PEERMEM_LEGACY}"
echo "WORKER_NVIDIA_OPEN=${WORKER_NVIDIA_OPEN}"
echo "WORKER_NVIDIA_DMABUF=${WORKER_NVIDIA_DMABUF}"
# Roll-up: GPUDirect RDMA is enabled if EITHER path is in place. Kept
# under the historical WORKER_PEERMEM name so existing summary code and
# JSON consumers continue to work without a schema change.
if [[ "${WORKER_PEERMEM_LEGACY}" == "true" \
        || "${WORKER_NVIDIA_OPEN}" == "true" \
        || "${WORKER_NVIDIA_DMABUF}" == "true" ]]; then
    echo "WORKER_PEERMEM=true"
else
    echo "WORKER_PEERMEM=false"
fi

# --- PCIe ACS (Access Control Services), scoped to the GPU<->backend-NIC path ---
# ACS forces peer-to-peer PCIe transactions up through the CPU root complex.
# When ACS is ON on a switch/bridge that sits BETWEEN a GPU and its backend
# RDMA NIC, GPUDirect RDMA can no longer take the direct
# GPU<->PCIe-switch<->NIC route - traffic is rerouted through the root complex
# and NCCL/RCCL collectives get dramatically slower (or hang). This is the
# ClusterMAX footgun: "not disabling ACS, or not enabling GPUDirect RDMA".
#
# IMPORTANT (per review): we do NOT want ACS disabled on *every* PCIe switch -
# only on the switches attached to the backend NICs and GPUs (i.e. the ones on
# the GPU<->NIC data path). ACS on unrelated bridges (management NICs, boot
# storage, etc.) is fine and sometimes desirable for IOMMU isolation, so we
# must not flag those. We therefore:
#   1. find GPU PCI addresses (NVIDIA/AMD display/3D controllers), and
#   2. find backend RDMA NIC PCI addresses (from /sys/class/infiniband/*), then
#   3. walk each endpoint's sysfs parent chain up to the root port, and
#   4. treat as "on path" only the bridges that are an ancestor of BOTH a GPU
#      and a backend NIC (the shared PCIe switch and anything between them).
# We then read ACSCtl from `lspci -vvv` for ONLY those path bridges.
#
# Detection of the bit follows NVIDIA's NCCL troubleshooting guidance: an ACSCtl
# control bit shown with a trailing "+" (e.g. "SrcValid+") means that ACS
# enforcement bit is ENABLED. Any enforcement bit set on a path bridge blocks
# the direct P2P route, so we flag the path bridge as ACS-enabled.
#   docs: https://docs.nvidia.com/deeplearning/nccl/user-guide/docs/troubleshooting.html
#         https://docs.amd.com/r/en-US/ug1801-ai-nic-pollara-400-ops-guide
#         (AMD: "ACS must also be disabled on the PCIe switch" shared by GPU+NIC)
#
# Note on Grace Blackwell / DirectNIC (CX8): on those platforms NVIDIA wants
# *specific* ACS bits set (not a blanket disable). We only assert that a path
# bridge is not blocking P2P; we surface counts so the dashboard/operator can
# apply platform-specific nuance rather than blindly forcing all bits off.
#
# Emitted fields (semantics are now PATH-SCOPED):
#   WORKER_ACS_CHECK_OK       true if we could read lspci -vvv at all
#   WORKER_ACS_SUPPORTED      true if >=1 ACS-capable bridge is on the GPU<->NIC path
#   WORKER_ACS_BRIDGES        number of ACS-capable bridges ON the GPU<->NIC path
#   WORKER_ACS_ENABLED_COUNT  number of those path bridges with >=1 enforcement bit on
#   WORKER_ACS_ENABLED        true if any PATH bridge has ACS enabled (the footgun)
#   WORKER_ACS_TOTAL_BRIDGES  number of ACS-capable bridges on the whole host (context)
#   WORKER_ACS_SCOPED         true if we could resolve the GPU<->NIC topology;
#                             false means we fell back to host-wide (no topology)
WORKER_ACS_CHECK_OK=false
WORKER_ACS_SUPPORTED=false
WORKER_ACS_BRIDGES=0
WORKER_ACS_ENABLED_COUNT=0
WORKER_ACS_ENABLED=unknown
WORKER_ACS_TOTAL_BRIDGES=0
WORKER_ACS_SCOPED=false
WORKER_ACS_VIRTUALIZED=false

# Virtualization / passthrough detection for the ACS check. In a VM with SR-IOV
# or device passthrough, the guest sees each GPU and each NIC behind its own
# emulated bridge (QEMU/KVM root ports and switches); the real PCIe switches and
# their ACS state live on the hypervisor and are neither visible nor changeable
# from inside the guest. There, "could not resolve the GPU<->NIC switch" is
# expected and not actionable by the tenant, so the collector reports it as
# not-applicable instead of a warning and relies on the functional GPUDirect
# RDMA signal. systemd-detect-virt reports "docker" inside a pod even on a VM
# host, so also key on the emulated PCI host bridge / SR-IOV virtual functions
# that QEMU/KVM expose to the guest.
_acs_virt=$(systemd-detect-virt 2>/dev/null || echo none)
case "$_acs_virt" in
    qemu|kvm|vmware|microsoft|xen|amazon|oracle|bochs|parallels) WORKER_ACS_VIRTUALIZED=true ;;
esac
if [[ "$WORKER_ACS_VIRTUALIZED" != true ]] && command -v lspci >/dev/null 2>&1; then
    if lspci 2>/dev/null | grep -qiE 'QEMU PCIe|QEMU PCI|Virtual Function'; then
        WORKER_ACS_VIRTUALIZED=true
    fi
fi

# Helper: given a PCI endpoint sysfs dir, emit each upstream bridge BDF on its
# path to (but not including) the host bus, one per line. Walks the symlink
# parents under /sys/bus/pci/devices. A "bridge" here is any ancestor PCI dir.
acs_path_bridges() {
    # $1 = absolute /sys/bus/pci/devices/<BDF> path (may be a symlink)
    local dir cur parent bdf
    dir=$(readlink -f "$1" 2>/dev/null) || return 0
    cur="$dir"
    while true; do
        parent=$(dirname "$cur")
        # The PCI hierarchy lives under .../pciDDDD:BB/DDDD:BB:DD.F/...
        # A parent that is itself a PCI device dir has a name like DDDD:BB:DD.F.
        bdf=$(basename "$parent")
        if [[ "$bdf" =~ ^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$ ]]; then
            echo "$bdf"
            cur="$parent"
        else
            break
        fi
    done
}

if command -v lspci >/dev/null 2>&1; then
    # lspci -vvv needs root to read extended config space; without it the
    # ACSCtl line is simply absent and we report "unknown" rather than a
    # false "disabled". Try root, then sudo -n, then plain lspci.
    ACS_LSPCI=""
    if [[ "$(id -u)" -eq 0 ]]; then
        ACS_LSPCI=$(lspci -vvv 2>/dev/null)
    elif sudo -n true 2>/dev/null; then
        ACS_LSPCI=$(sudo -n lspci -vvv 2>/dev/null)
    else
        ACS_LSPCI=$(lspci -vvv 2>/dev/null)
    fi

    if [[ -n "$ACS_LSPCI" ]]; then
        ACS_CTL_ALL=$(printf '%s\n' "$ACS_LSPCI" | grep -E 'ACSCtl:' || true)
        if [[ -n "$ACS_CTL_ALL" ]]; then
            WORKER_ACS_CHECK_OK=true
            WORKER_ACS_TOTAL_BRIDGES=$(printf '%s\n' "$ACS_CTL_ALL" | grep -c 'ACSCtl:' | tr -d '[:space:]')

            # --- Resolve GPU and backend-NIC PCI endpoints from sysfs ---
            GPU_BDFS=""
            NIC_BDFS=""
            # GPUs: PCI class 0x0300 (VGA) or 0x0302 (3D controller) with an
            # NVIDIA (0x10de) or AMD (0x1002) vendor id.
            for d in /sys/bus/pci/devices/*; do
                [[ -e "$d/class" && -e "$d/vendor" ]] || continue
                cls=$(cat "$d/class" 2>/dev/null)
                ven=$(cat "$d/vendor" 2>/dev/null)
                case "$cls" in
                    0x0300*|0x0302*)
                        if [[ "$ven" == "0x10de" || "$ven" == "0x1002" ]]; then
                            GPU_BDFS+="$(basename "$d")"$'\n'
                        fi
                        ;;
                esac
            done
            # Backend RDMA NICs: every device under /sys/class/infiniband (IB or
            # RoCE mlx5, plus EFA which also registers an ibdev). This is exactly
            # the "backend NIC" set, and excludes plain management ethernet.
            for ibd in /sys/class/infiniband/*; do
                [[ -e "$ibd/device" ]] || continue
                nic=$(basename "$(readlink -f "$ibd/device" 2>/dev/null)")
                [[ -n "$nic" ]] && NIC_BDFS+="$nic"$'\n'
            done

            # Collect every backend NIC's ancestor bridges into one set.
            NIC_BRIDGES=""
            for n in $NIC_BDFS; do
                [[ -n "$n" ]] || continue
                NIC_BRIDGES+="$(acs_path_bridges "/sys/bus/pci/devices/$n")"$'\n'
            done
            NIC_BRIDGES_ALL=$(printf '%s\n' "$NIC_BRIDGES" | grep . | sort -u)

            # For each GPU, the "on path" switch is the NEAREST (deepest) bridge it
            # shares with ANY backend NIC - i.e. that GPU's GPU<->NIC switch. We do
            # NOT take the full ancestor intersection: shared root ports between
            # unrelated GPU/NIC pairs would be included, so ACS set on an upstream
            # root could fail the audit even when the PIX GPU<->NIC switches are fine.
            # acs_path_bridges emits ancestors deepest-first, so the first shared
            # bridge per GPU is its nearest shared switch.
            PATH_BRIDGES=""
            if [[ -n "$NIC_BRIDGES_ALL" ]]; then
                for g in $GPU_BDFS; do
                    [[ -n "$g" ]] || continue
                    while IFS= read -r gb; do
                        [[ -n "$gb" ]] || continue
                        if printf '%s\n' "$NIC_BRIDGES_ALL" | grep -qxF "$gb"; then
                            PATH_BRIDGES+="$gb"$'\n'
                            break
                        fi
                    done < <(acs_path_bridges "/sys/bus/pci/devices/$g")
                done
                PATH_BRIDGES=$(printf '%s\n' "$PATH_BRIDGES" | grep . | sort -u)
            fi

            if [[ -n "$PATH_BRIDGES" ]]; then
                # We have real topology: scope ACS to the shared path bridges.
                WORKER_ACS_SCOPED=true
                path_total=0
                path_enabled=0
                path_found=0
                while IFS= read -r b; do
                    [[ -n "$b" ]] || continue
                    # lspci uses the short BBB:DD.F form; strip the domain if 0000.
                    short="${b#0000:}"
                    stanza=$(printf '%s\n' "$ACS_LSPCI" \
                        | grep -A40 -iE "^${short} |^${b} " 2>/dev/null || true)
                    # Bridge BDF not located in the lspci output at all (format
                    # mismatch / unreadable): cannot judge it -> leave it out of
                    # path_found so the per-bridge read is treated as inconclusive.
                    [[ -z "$stanza" ]] && continue
                    path_found=$((path_found + 1))
                    line=$(printf '%s\n' "$stanza" | grep -m1 'ACSCtl:' || true)
                    # Bridge present but no ACSCtl line: it is genuinely not an
                    # ACS-capable bridge (nothing to disable there).
                    [[ -z "$line" ]] && continue
                    path_total=$((path_total + 1))
                    if printf '%s\n' "$line" | grep -qE 'ACSCtl:[^#]*[A-Za-z]+\+'; then
                        path_enabled=$((path_enabled + 1))
                    fi
                done <<< "$PATH_BRIDGES"

                WORKER_ACS_BRIDGES="$path_total"
                WORKER_ACS_ENABLED_COUNT="$path_enabled"
                if [[ "$path_total" -gt 0 ]]; then
                    WORKER_ACS_SUPPORTED=true
                    if [[ "$path_enabled" -gt 0 ]]; then
                        WORKER_ACS_ENABLED=true
                    else
                        WORKER_ACS_ENABLED=false
                    fi
                elif [[ "$path_found" -gt 0 ]]; then
                    # Shared bridges were located and read, but none are ACS-capable
                    # (e.g. GPU and NIC hang off root ports with no ACS). Nothing to
                    # disable -> genuinely good.
                    WORKER_ACS_SUPPORTED=false
                    WORKER_ACS_ENABLED=false
                else
                    # Shared path bridges exist but NONE could be located/read in the
                    # lspci output (format mismatch or unprivileged read). Do NOT
                    # claim "no ACS": report unknown so it is not a false pass. The
                    # functional fallback below can still produce a real verdict.
                    WORKER_ACS_SUPPORTED=false
                    WORKER_ACS_ENABLED=unknown
                fi
            else
                # No resolvable GPU<->NIC topology (no GPUs, no backend NICs, or
                # sysfs unreadable). Fall back to the host-wide signal but mark it
                # un-scoped so consumers can treat it cautiously rather than
                # failing a node for ACS on unrelated bridges.
                WORKER_ACS_SCOPED=false
                WORKER_ACS_BRIDGES="$WORKER_ACS_TOTAL_BRIDGES"
                if [[ "$WORKER_ACS_TOTAL_BRIDGES" -gt 0 ]]; then
                    WORKER_ACS_SUPPORTED=true
                fi
                hostwide_enabled=$(printf '%s\n' "$ACS_CTL_ALL" \
                    | grep -cE 'ACSCtl:[^#]*[A-Za-z]+\+' | tr -d '[:space:]')
                WORKER_ACS_ENABLED_COUNT="$hostwide_enabled"
                # Un-scoped: do NOT assert a hard true/false on the path, since we
                # cannot tell which bridges matter. Report unknown so the harness
                # warns instead of failing.
                WORKER_ACS_ENABLED=unknown
            fi
        else
            # lspci ran but exposed no ACSCtl lines: either no ACS-capable
            # bridges, or we lack the privilege to read extended config space.
            WORKER_ACS_CHECK_OK=true
        fi
    fi
fi
# --- Functional fallback (no root needed) -----------------------------------
# The static ACSCtl read above needs root to reach PCIe extended config space.
# Under an unprivileged tenant it yields WORKER_ACS_ENABLED=unknown - exactly
# where a provider footgun would otherwise hide. When ib_write_bw (a GDR-enabled
# perftest build) and a GPU are present we confirm the impact directly: ask a
# NIC to RDMA-write into the GPU that shares its PCIe switch (the PIX pair), then
# run the same transfer against host memory as a control. A GPU-memory fault
# (IBV_WC_LOC_PROT_ERR, vendor_err 0x51) while host memory succeeds is the
# signature of ACS P2P redirect breaking same-switch GPUDirect RDMA. This is the
# single implementation of the functional ACS detector (host-check.sh is piped
# to the node over stdin, so it cannot source a sibling); see tests/AUDIT-CRITERIA.md.
#   WORKER_ACS_METHOD               config | functional (how ENABLED was set)
#   WORKER_ACS_FUNCTIONAL_PAIR      gpu<idx>/<ibdev> tested, or none
#   WORKER_ACS_FUNCTIONAL_SYNDROME  vendor syndrome on GDR fault, e.g. 0x51
WORKER_ACS_METHOD=config
WORKER_ACS_FUNCTIONAL_PAIR=none
WORKER_ACS_FUNCTIONAL_SYNDROME=
ACS_IB_HELP="$(ib_write_bw --help 2>&1 || true)"
if [[ "${WORKER_ACS_ENABLED}" == "unknown" ]] \
        && command -v ib_write_bw >/dev/null 2>&1 \
        && command -v nvidia-smi >/dev/null 2>&1 \
        && printf '%s\n' "$ACS_IB_HELP" | grep -q -- '--use_cuda'; then
    acs_topo="$(nvidia-smi topo -m 2>/dev/null)"
    # NIC index -> ibdev from the "NIC Legend" (e.g. "NIC4: mlx5_4").
    declare -a acs_nicmap
    while IFS= read -r ln; do
        if [[ "$ln" =~ NIC([0-9]+):[[:space:]]*([A-Za-z0-9_]+) ]]; then
            acs_nicmap[${BASH_REMATCH[1]}]="${BASH_REMATCH[2]}"
        fi
    done <<< "$acs_topo"
    # Column-header line: leading whitespace, GPU0, and the NIC columns. Labels
    # may be "NIC<n>" (with a NIC Legend) or the bare "mlx5_<n>" device name -
    # accept either so layouts without a literal NIC0 token still select a pair.
    acs_gpu=""; acs_dev=""
    acs_cols="$(printf '%s\n' "$acs_topo" | grep -m1 -E '[[:space:]]GPU0[[:space:]].*(NIC[0-9]+|mlx5_)')"
    [[ -z "$acs_cols" ]] && acs_cols="$(printf '%s\n' "$acs_topo" | grep -m1 -E '^[[:space:]]+GPU0[[:space:]]')"
    if [[ -n "$acs_cols" ]]; then
        declare -a acs_labels; read -r -a acs_labels <<< "$acs_cols"
        while IFS= read -r ln; do
            # Some nvidia-smi versions indent the matrix rows; tolerate leading
            # whitespace. The header row also matches but carries no PIX cell.
            [[ "$ln" =~ ^[[:space:]]*GPU([0-9]+) ]] || continue
            acs_g="${BASH_REMATCH[1]}"; declare -a acs_cells; read -r -a acs_cells <<< "$ln"
            for ((acs_ci=1; acs_ci<${#acs_cells[@]}; acs_ci++)); do
                [[ "${acs_cells[$acs_ci]}" == "PIX" ]] || continue
                acs_lbl="${acs_labels[$((acs_ci-1))]}"; acs_d=""
                if [[ "$acs_lbl" =~ ^NIC([0-9]+)$ ]]; then
                    acs_d="${acs_nicmap[${BASH_REMATCH[1]}]:-}"
                elif [[ "$acs_lbl" =~ ^mlx5_[0-9]+$ ]]; then
                    acs_d="$acs_lbl"
                fi
                [[ -n "$acs_d" && -e "/sys/class/infiniband/$acs_d" ]] || continue
                acs_gpu="$acs_g"; acs_dev="$acs_d"; break
            done
            [[ -n "$acs_dev" ]] && break
        done < <(printf '%s\n' "$acs_topo" | grep -E '^[[:space:]]*GPU[0-9]+')
    fi
    if [[ -n "$acs_gpu" && -n "$acs_dev" ]]; then
        WORKER_ACS_FUNCTIONAL_PAIR="gpu${acs_gpu}/${acs_dev}"
        # The self-test RAN: attribute the outcome to the functional method even
        # when inconclusive, so the harness does not mistake it for the static path.
        WORKER_ACS_METHOD=functional
        acs_tmo=""; command -v timeout >/dev/null 2>&1 && acs_tmo="timeout 60"
        acs_loop() {  # $1 = extra ib_write_bw args (cuda flags or empty)
            local sl cl; sl="$(mktemp)"; cl="$(mktemp)"
            $acs_tmo ib_write_bw -d "$acs_dev" -p 18796 $1 -s 65536 -n 100 -F >"$sl" 2>&1 &
            local sp=$!; sleep 3
            $acs_tmo ib_write_bw -d "$acs_dev" -p 18796 $1 -s 65536 -n 100 -F 127.0.0.1 >"$cl" 2>&1
            wait "$sp" 2>/dev/null; cat "$sl" "$cl"; rm -f "$sl" "$cl"
        }
        acs_gdr="$(acs_loop "--use_cuda=${acs_gpu} --use_cuda_dmabuf")"
        if printf '%s\n' "$acs_gdr" | grep -qiE 'syndrom|completion with error|failed to (complete|exchange)'; then
            WORKER_ACS_FUNCTIONAL_SYNDROME="$(printf '%s\n' "$acs_gdr" | grep -oiE 'syndrom 0x[0-9a-f]+' | head -1 | grep -oiE '0x[0-9a-f]+')"
            acs_host="$(acs_loop "")"
            if printf '%s\n' "$acs_host" | grep -qE '^[[:space:]]*65536[[:space:]]'; then
                # GDR faults, host memory works -> ACS footgun, confirmed functionally.
                WORKER_ACS_ENABLED=true
                WORKER_ACS_SUPPORTED=true
            else
                # GDR faulted AND host-mem did not pass -> inconclusive (could be a
                # dead rail, not ACS). Keep unknown; method stays functional.
                WORKER_ACS_ENABLED=unknown
            fi
        elif printf '%s\n' "$acs_gdr" | grep -qE '^[[:space:]]*65536[[:space:]]'; then
            WORKER_ACS_ENABLED=false
        else
            # Self-test ran but produced neither a bandwidth row nor a fault.
            WORKER_ACS_ENABLED=unknown
        fi
    fi
fi

echo "WORKER_ACS_CHECK_OK=${WORKER_ACS_CHECK_OK}"
echo "WORKER_ACS_SUPPORTED=${WORKER_ACS_SUPPORTED}"
echo "WORKER_ACS_BRIDGES=${WORKER_ACS_BRIDGES}"
echo "WORKER_ACS_ENABLED_COUNT=${WORKER_ACS_ENABLED_COUNT}"
echo "WORKER_ACS_ENABLED=${WORKER_ACS_ENABLED}"
echo "WORKER_ACS_TOTAL_BRIDGES=${WORKER_ACS_TOTAL_BRIDGES}"
echo "WORKER_ACS_SCOPED=${WORKER_ACS_SCOPED}"
echo "WORKER_ACS_VIRTUALIZED=${WORKER_ACS_VIRTUALIZED}"
echo "WORKER_ACS_METHOD=${WORKER_ACS_METHOD}"
echo "WORKER_ACS_FUNCTIONAL_PAIR=${WORKER_ACS_FUNCTIONAL_PAIR}"
echo "WORKER_ACS_FUNCTIONAL_SYNDROME=${WORKER_ACS_FUNCTIONAL_SYNDROME}"

# AMD GPU peermem (only meaningful if AMD GPUs are present).
# amd_peermem is on the same deprecation track as nvidia_peermem; ROCm 6+
# routes GPUDirect RDMA through dma_buf via the in-tree amdgpu driver. So
# we accept "amdgpu loaded with dma_buf support" as a positive signal too.
if lsmod 2>/dev/null | grep -qE "amdgpu|amd_peermem|amdkfd"; then
    WORKER_AMD_PEERMEM_LEGACY=false
    WORKER_AMD_DMABUF=false
    if lsmod 2>/dev/null | grep -q '^amd_peermem '; then
        WORKER_AMD_PEERMEM_LEGACY=true
    fi
    if [[ -d /sys/module/amdgpu ]] && \
            find /sys/module/amdgpu -maxdepth 4 -name 'dma_buf*' 2>/dev/null | grep -q .; then
        WORKER_AMD_DMABUF=true
    fi
    echo "WORKER_AMD_PEERMEM_LEGACY=${WORKER_AMD_PEERMEM_LEGACY}"
    echo "WORKER_AMD_DMABUF=${WORKER_AMD_DMABUF}"
    if [[ "${WORKER_AMD_PEERMEM_LEGACY}" == "true" || "${WORKER_AMD_DMABUF}" == "true" ]]; then
        echo "WORKER_AMD_PEERMEM=true"
    else
        echo "WORKER_AMD_PEERMEM=false"
    fi
fi
else
    echo "WORKER_PEERMEM_LEGACY=false"
    echo "WORKER_NVIDIA_OPEN=false"
    echo "WORKER_NVIDIA_DMABUF=false"
    echo "WORKER_PEERMEM=false"
    echo "WORKER_ACS_CHECK_OK=false"
    echo "WORKER_ACS_SUPPORTED=false"
    echo "WORKER_ACS_BRIDGES=0"
    echo "WORKER_ACS_ENABLED_COUNT=0"
    echo "WORKER_ACS_ENABLED=unknown"
    echo "WORKER_ACS_TOTAL_BRIDGES=0"
    echo "WORKER_ACS_SCOPED=false"
    echo "WORKER_ACS_VIRTUALIZED=false"
    echo "WORKER_ACS_METHOD=skipped"
    echo "WORKER_ACS_FUNCTIONAL_PAIR=none"
    echo "WORKER_ACS_FUNCTIONAL_SYNDROME="
    echo "WORKER_AMD_PEERMEM_LEGACY=false"
    echo "WORKER_AMD_DMABUF=false"
    echo "WORKER_AMD_PEERMEM=false"
fi

# --- GDRCopy ---
# GDRCopy lets userspace map GPU memory for low-overhead CPU-driven copies.
# Library is shipped by the gdrcopy package; the gdrdrv kernel module enables it.
GDR_LIB=$(ldconfig -p 2>/dev/null | awk '/libgdrapi/{print $NF; exit}')
if [[ -z "$GDR_LIB" ]]; then
    GDR_LIB=$(find /usr/lib /usr/local/lib /opt -maxdepth 4 -name "libgdrapi.so*" 2>/dev/null | head -1)
fi
echo "WORKER_GDRCOPY_LIB=${GDR_LIB:-not-found}"
if lsmod 2>/dev/null | grep -q '^gdrdrv'; then
    echo "WORKER_GDRCOPY_GDRDRV=true"
else
    echo "WORKER_GDRCOPY_GDRDRV=false"
fi
[[ -c /dev/gdrdrv ]] && echo "WORKER_GDRCOPY_DEV=true" || echo "WORKER_GDRCOPY_DEV=false"
fi

# --- RDMA fabric devices (host-side, from /sys/class/infiniband) ---
# The k8s collector reports rdma/* SCHEDULABLE resources; this enumerates the
# actual RDMA NICs present on the host so a fabric that exists but is not exposed
# as a k8s resource (e.g. AMD Pensando `ionic` RoCE reachable only via
# hostNetwork) is not misreported as absent. Driver name (ionic / mlx5_core /
# bnxt_re / efa) identifies the NIC family; link_layer Ethernet => RoCE.
if scale_out_checks_enabled && [[ -d /sys/class/infiniband ]]; then
    _rdma_total=0; _rdma_active=0; _rdma_drivers=""; _rdma_layers=""; _rdma_rate_max=0
    for _ibd in /sys/class/infiniband/*; do
        [[ -e "$_ibd" ]] || continue
        _rdma_total=$((_rdma_total+1))
        _drv=$(basename "$(readlink -f "$_ibd/device/driver" 2>/dev/null)" 2>/dev/null)
        [[ -n "$_drv" && "$_drv" != "." ]] && _rdma_drivers="$_rdma_drivers $_drv"
        for _p in "$_ibd"/ports/*; do
            [[ -e "$_p" ]] || continue
            [[ "$(cat "$_p/state" 2>/dev/null)" == *ACTIVE* ]] && _rdma_active=$((_rdma_active+1))
            _ll=$(cat "$_p/link_layer" 2>/dev/null); [[ -n "$_ll" ]] && _rdma_layers="$_rdma_layers $_ll"
            _r=$(cat "$_p/rate" 2>/dev/null | grep -oE '^[0-9]+' | head -1)
            [[ -n "$_r" ]] && (( _r > _rdma_rate_max )) && _rdma_rate_max=$_r
        done
    done
    echo "WORKER_RDMA_DEVICES=${_rdma_total}"
    echo "WORKER_RDMA_ACTIVE_PORTS=${_rdma_active}"
    echo "WORKER_RDMA_DRIVERS=$(echo $_rdma_drivers | tr ' ' '\n' | grep . | sort -u | paste -sd, -)"
    echo "WORKER_RDMA_LINK_LAYERS=$(echo $_rdma_layers | tr ' ' '\n' | grep . | sort -u | paste -sd, -)"
    echo "WORKER_RDMA_MAX_RATE_GBPS=${_rdma_rate_max}"
elif ! scale_out_checks_enabled; then
    echo "WORKER_RDMA_DEVICES=0"
    echo "WORKER_RDMA_ACTIVE_PORTS=0"
    echo "WORKER_RDMA_DRIVERS="
    echo "WORKER_RDMA_LINK_LAYERS="
    echo "WORKER_RDMA_MAX_RATE_GBPS=0"
fi

# --- AMD GPU stack (rocm-smi, amd-smi, ROCm container toolkit) ---
# Model / driver / count: prefer rocm-smi when present, else fall back to
# amd-smi. MI350-series (CDNA4) on ROCm 7.x may ship ONLY amd-smi, so these
# facts must be derivable from either tool. amd-smi CSV column names vary across
# ROCm releases; if a field below reads "unknown" on a real node, confirm the
# `amd-smi static --asic --csv` / `amd-smi list --csv` output there.
# Driver version is collected into _amd_drv from whichever source is available
# and emitted exactly once below, so the sysfs fallback can fill it when no ROCm
# CLI is on the host (the downstream head -1 parser would otherwise keep an
# earlier "unknown" emitted from a branch).
detect_amd_gpu_model() {
    local model=""
    if command -v rocm-smi &>/dev/null; then
        model=$(rocm-smi --showproductname 2>/dev/null \
            | sed -nE 's/.*[Cc][Aa][Rr][Dd] [Ss][Ee][Rr][Ii][Ee][Ss]:[[:space:]]*//p' \
            | head -1)
    fi
    case "${model,,}" in
        ""|"n/a"|"unknown"|"not-found"|"none")
            model=""
            if command -v amd-smi &>/dev/null; then
                model=$(amd-smi static --asic --csv 2>/dev/null \
                    | awk -F, 'NR==1{for(i=1;i<=NF;i++) if(tolower($i) ~ /market[ _]?name/) c=i} NR==2 && c{print $c}' \
                    | tr -d '"')
                [[ -z "$model" ]] && model=$(amd-smi static --asic 2>/dev/null \
                    | sed -nE 's/.*[Mm][Aa][Rr][Kk][Ee][Tt][ _][Nn][Aa][Mm][Ee][[:space:]]*[:=]?[[:space:]]*//p' \
                    | head -1)
            fi
            ;;
    esac
    model=$(printf '%s\n' "$model" \
        | sed 's/[[:space:]]\+/ /g;s/^ //;s/ $//' \
        | tr ' ' '-')
    printf '%s\n' "${model:-unknown}"
}

_amd_drv=""
if command -v rocm-smi &>/dev/null; then
    echo "WORKER_ROCM_SMI_PATH=$(which rocm-smi)"
    # rocm-smi 7.x prints "Card Series:" (capitalized) with the value after a
    # second colon and tab padding, e.g. "GPU[0] : Card Series:   AMD Instinct
    # MI355X". Match case-insensitively and squeeze whitespace so the model
    # resolves (e.g. AMD-Instinct-MI355X) instead of "unknown".
    echo "WORKER_AMD_GPU_MODEL=$(detect_amd_gpu_model)"
    _amd_drv=$(rocm-smi --showdriverversion 2>/dev/null | grep -ioP 'Driver version:\s*\K.+' | head -1)
    # rocm-smi prints several lines per GPU (Device Name/ID/Rev/Subsystem/GUID),
    # so count UNIQUE GPU[n] indices, not matching lines (the latter over-counts
    # by ~5x, e.g. 40 for an 8-GPU node).
    echo "WORKER_AMD_GPU_COUNT=$(rocm-smi --showid 2>/dev/null | grep -oE '^GPU\[[0-9]+\]' | sort -u | wc -l | tr -d ' ' || echo 0)"
    # Per-GPU HBM (bytes -> MiB, matching the NVIDIA WORKER_GPU_MEMORY unit).
    _amd_vram_b=$(rocm-smi --showmeminfo vram 2>/dev/null | grep -m1 -oP 'VRAM Total Memory \(B\):\s*\K[0-9]+')
    [[ -n "$_amd_vram_b" ]] && echo "WORKER_AMD_GPU_MEMORY=$(( _amd_vram_b / 1048576 ))"
elif command -v amd-smi &>/dev/null; then
    echo "WORKER_ROCM_SMI_PATH="
    echo "WORKER_AMD_GPU_MODEL=$(detect_amd_gpu_model)"
    _amd_drv=$(amd-smi static --driver --csv 2>/dev/null | awk -F, 'NR==1{for(i=1;i<=NF;i++) if($i ~ /version/) c=i} NR==2 && c{print $c}' | tr -d '"')
    [[ -z "$_amd_drv" ]] && _amd_drv=$(amd-smi static --driver 2>/dev/null | grep -m1 -ioP 'version\s*[:=]?\s*\K.+')
    # Count: one data row per GPU from `amd-smi list`.
    _amd_count=$(amd-smi list --csv 2>/dev/null | awk 'NR>1 && NF' | wc -l | tr -d ' ')
    [[ -z "$_amd_count" || "$_amd_count" == "0" ]] && _amd_count=$(amd-smi list 2>/dev/null | grep -cE '^GPU[: ]' || echo 0)
    echo "WORKER_AMD_GPU_COUNT=${_amd_count:-0}"
else
    echo "WORKER_ROCM_SMI_PATH="
fi
# Tool-free fallback: the amdgpu KERNEL driver exposes its version in sysfs
# whenever the module is loaded - independent of the ROCm userspace CLI and of
# the AMD GPU Operator - and it is the same value rocm-smi --showdriverversion
# reports. Hosts that bake the driver into the node image but ship no ROCm CLI
# on the host (e.g. Oracle MI355X) reach this path. modinfo (reads the .ko) is a
# secondary source for in-tree builds where the sysfs version attribute is absent.
if [[ -z "$_amd_drv" ]]; then
    _amd_drv=$(cat /sys/module/amdgpu/version 2>/dev/null | head -1)
    [[ -z "$_amd_drv" ]] && _amd_drv=$(modinfo amdgpu 2>/dev/null | awk -F': +' '/^version:/{print $2; exit}')
fi
echo "WORKER_AMD_DRIVER_VERSION=${_amd_drv:-unknown}"
if ! security_checks_only; then
if command -v amd-smi &>/dev/null; then
    echo "WORKER_AMD_SMI_PATH=$(which amd-smi)"
    echo "WORKER_AMD_SMI_VERSION=$(amd-smi version 2>/dev/null | grep -oP 'AMDSMI[^ ]* \K[0-9.]+' | head -1 || echo unknown)"
else
    echo "WORKER_AMD_SMI_PATH="
fi
# ROCm version: prefer the authoritative version file (e.g. /opt/rocm/.info/version
# -> 7.2.1); fall back to the versioned install-dir name. The bare /opt/rocm
# symlink alone only yields "installed", so the .info file is consulted first.
_rocm_ver=$(cat /opt/rocm/.info/version /opt/rocm-*/.info/version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
if [[ -z "$_rocm_ver" ]]; then
    ROCM_DIR=$(ls -d /opt/rocm-* /opt/rocm 2>/dev/null | head -1)
    [[ -n "$ROCM_DIR" ]] && _rocm_ver=$(basename "$ROCM_DIR" | sed 's/^rocm-//;s/^rocm$/installed/')
fi
[[ -n "$_rocm_ver" ]] && echo "WORKER_ROCM_VERSION=${_rocm_ver}"
# rocm container toolkit (amd-container-toolkit binary on newer ROCm; legacy: rocm-docker)
if command -v amd-container-toolkit &>/dev/null; then
    echo "WORKER_ROCM_CT_PATH=$(which amd-container-toolkit)"
elif command -v rocm-container-toolkit &>/dev/null; then
    echo "WORKER_ROCM_CT_PATH=$(which rocm-container-toolkit)"
elif [[ -d /etc/amd-container-runtime ]] || dpkg -l 2>/dev/null | grep -q amd-container-toolkit; then
    echo "WORKER_ROCM_CT_PATH=installed"
fi

find_rocm_binary() {
    local rocm_bin_dir=${ROCM_BIN_DIR:-/opt/rocm/bin}
    local tool resolved
    for tool in "$@"; do
        resolved=$(command -v "$tool" 2>/dev/null || true)
        if [[ -n "$resolved" ]]; then
            echo "$resolved"
            return 0
        fi
        if [[ -x "$rocm_bin_dir/$tool" ]]; then
            echo "$rocm_bin_dir/$tool"
            return 0
        fi
    done
    return 1
}

# AMD RDC / ROCm bandwidth utilities. These are cheap presence/smoke checks
# that complement rocm-smi/amd-smi without running a performance benchmark.
RDC_P=$(find_rocm_binary rdci rdc || echo "")
if [[ -n "$RDC_P" ]]; then
    echo "WORKER_RDC_PATH=$RDC_P"
    RDC_VER=$("$RDC_P" --version 2>/dev/null | head -1 || echo unknown)
    echo "WORKER_RDC_VERSION=${RDC_VER:-unknown}"
    if [[ "$(basename "$RDC_P")" == "rdci" ]]; then
        if timeout 10 "$RDC_P" discovery -l >/dev/null 2>&1; then
            echo "WORKER_RDC_SMOKE=pass"
        else
            echo "WORKER_RDC_SMOKE=fail"
        fi
    else
        if timeout 10 "$RDC_P" --help >/dev/null 2>&1; then
            echo "WORKER_RDC_SMOKE=pass"
        else
            echo "WORKER_RDC_SMOKE=fail"
        fi
    fi
else
    echo "WORKER_RDC_PATH="
    echo "WORKER_RDC_VERSION=not-found"
    echo "WORKER_RDC_SMOKE=not-found"
fi

ROCM_BW_P=$(find_rocm_binary rocm-bandwidth-test rocm_bandwidth_test || echo "")
if [[ -n "$ROCM_BW_P" ]]; then
    echo "WORKER_ROCM_BANDWIDTH_TEST_PATH=$ROCM_BW_P"
else
    echo "WORKER_ROCM_BANDWIDTH_TEST_PATH="
fi

# AMD kernel profiler. rocprofv3 (and rocprof-compute) is the ROCm equivalent
# of ncu. ROCm has no NVreg_RestrictProfilingToAdminUsers flag: counter access
# is gated by /dev/kfd and /dev/dri render-node permissions plus render/video
# group membership, so the modcheck read used for NVIDIA has no analog here.
# Source: TensorWave AMD Command Reference, MI355X handover 2026-07-30.

find_transferbench_binary() {
    local rocm_bin_dir=${ROCM_BIN_DIR:-/opt/rocm/bin}
    local rocm_root=${ROCM_ROOT_DIR:-${rocm_bin_dir%/bin}}
    local tool candidate search_dir

    for tool in TransferBench transferbench; do
        candidate=$(command -v "$tool" 2>/dev/null || true)
        if [[ -n "$candidate" ]]; then
            echo "$candidate"
            return 0
        fi
    done
    for search_dir in "$rocm_bin_dir" "$rocm_root"/extras-*/bin; do
        for tool in TransferBench transferbench; do
            if [[ -x "$search_dir/$tool" ]]; then
                echo "$search_dir/$tool"
                return 0
            fi
        done
    done
    return 1
}

ROCPROF_P=$(find_rocm_binary rocprofv3 rocprof-compute rocprof || echo "")
if [[ -n "$ROCPROF_P" ]]; then
    echo "WORKER_ROCPROF_PATH=$ROCPROF_P"
    _rocprof_ver=$("$ROCPROF_P" --version 2>/dev/null | grep -m1 -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
    echo "WORKER_ROCPROF_VERSION=${_rocprof_ver:-unknown}"
else
    echo "WORKER_ROCPROF_PATH="
    echo "WORKER_ROCPROF_VERSION=not-found"
fi

# Counter-access proxy for rocprofv3: the calling user must open /dev/kfd and
# at least one /dev/dri/renderD* node. Report the device state and the relevant
# group membership so a denial can be traced to the group or to the node image.
if [[ -e /dev/kfd ]]; then
    if [[ -r /dev/kfd && -w /dev/kfd ]]; then
        echo "WORKER_ROCM_KFD_ACCESS=allowed"
    else
        echo "WORKER_ROCM_KFD_ACCESS=denied"
    fi
else
    echo "WORKER_ROCM_KFD_ACCESS=absent"
fi
_render_node=$(ls /dev/dri/renderD* 2>/dev/null | head -1)
if [[ -n "$_render_node" && -r "$_render_node" && -w "$_render_node" ]]; then
    echo "WORKER_ROCM_RENDER_ACCESS=allowed"
elif [[ -n "$_render_node" ]]; then
    echo "WORKER_ROCM_RENDER_ACCESS=denied"
else
    echo "WORKER_ROCM_RENDER_ACCESS=absent"
fi
_rocm_groups=$(id -nG 2>/dev/null | tr ' ' '\n' | grep -xE 'render|video' | paste -sd, -)
echo "WORKER_ROCM_PROFILING_GROUPS=${_rocm_groups:-none}"

# ROCm Validation Suite (rvs) is the active-diagnostic equivalent of
# `dcgmi diag -r 3`. AMD's Instinct Customer Acceptance Guide drives it through
# per-test configs (gst_single.conf, iet_single.conf, mem.conf, pebb_single.conf,
# peqt_single.conf, pbqt_single.conf), so record the config directory too.
RVS_P=$(find_rocm_binary rvs || echo "")
if [[ -n "$RVS_P" ]]; then
    echo "WORKER_RVS_PATH=$RVS_P"
    _rvs_ver=$("$RVS_P" --version 2>/dev/null | grep -m1 -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
    echo "WORKER_RVS_VERSION=${_rvs_ver:-unknown}"
    _rvs_conf=$(ls -d /opt/rocm*/share/rocm-validation-suite/conf 2>/dev/null | head -1)
    echo "WORKER_RVS_CONF_DIR=${_rvs_conf:-none}"
else
    echo "WORKER_RVS_PATH="
    echo "WORKER_RVS_VERSION=not-found"
    echo "WORKER_RVS_CONF_DIR=none"
fi

# AMD TransferBench measures GPU-to-GPU and host copy bandwidth. It complements
# rocm-bandwidth-test for XGMI (Infinity Fabric) pair bandwidth.
TRANSFERBENCH_P=$(find_transferbench_binary || echo "")
echo "WORKER_TRANSFERBENCH_PATH=${TRANSFERBENCH_P}"
fi

# BMC/IPMI should not be exposed to tenant users. We test access without
# prompting for a sudo password; allowed means the BMC is reachable from the
# tenant environment and should be reviewed.
IPMITOOL_P=$(command -v ipmitool 2>/dev/null || echo "")
echo "WORKER_IPMITOOL_PATH=$IPMITOOL_P"
if [[ -n "$IPMITOOL_P" ]]; then
    if timeout 5 "$IPMITOOL_P" mc info >/dev/null 2>&1; then
        echo "WORKER_IPMI_USER_ACCESS=allowed"
    else
        echo "WORKER_IPMI_USER_ACCESS=blocked"
    fi
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        if timeout 5 sudo -n "$IPMITOOL_P" chassis status >/dev/null 2>&1; then
            echo "WORKER_IPMI_SUDO_ACCESS=allowed"
        else
            echo "WORKER_IPMI_SUDO_ACCESS=blocked"
        fi
    else
        echo "WORKER_IPMI_SUDO_ACCESS=no-passwordless-sudo"
    fi
else
    echo "WORKER_IPMI_USER_ACCESS=not-installed"
    echo "WORKER_IPMI_SUDO_ACCESS=not-installed"
fi

if ! security_checks_only; then
# --- GPU idle thermal/power snapshot ---
# Single sample with no workload. High idle temp/power = wrong fan curve,
# stuck clocks, or background workload from another tenant. Computed across
# whichever GPU tool is present, then emitted once.
#   - NVIDIA: nvidia-smi
#   - AMD: rocm-smi (edge sensor) OR amd-smi. MI300/MI350 (CDNA3/4) commonly
#     ship amd-smi only and report EDGE as N/A, so use HOTSPOT (junction) +
#     SOCKET_POWER. amd-smi/rocm-smi often live under /opt/rocm/bin, which is
#     not always on the check PATH, so resolve there too.
IDLE_TEMP_MAX=""
IDLE_POWER_MAX=""
ROCM_SMI_BIN=$(command -v rocm-smi 2>/dev/null || { [[ -x /opt/rocm/bin/rocm-smi ]] && echo /opt/rocm/bin/rocm-smi; } || echo "")
AMD_SMI_BIN=$(command -v amd-smi 2>/dev/null || { [[ -x /opt/rocm/bin/amd-smi ]] && echo /opt/rocm/bin/amd-smi; } || echo "")
if command -v nvidia-smi &>/dev/null; then
    IDLE_TEMP_MAX=$(nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader,nounits 2>/dev/null | sort -n | tail -1)
    IDLE_POWER_MAX=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits 2>/dev/null | sort -n | tail -1)
elif [[ -n "$ROCM_SMI_BIN" ]]; then
    IDLE_TEMP_MAX=$("$ROCM_SMI_BIN" --showtemp 2>/dev/null | grep -oP 'Temperature \(Sensor edge\)[^:]*: \K[0-9.]+' | sort -n | tail -1)
    # MI300/MI350 (CDNA3/4) report the edge sensor as N/A; junction (hotspot) and
    # memory are the real sensors, so fall back to the hottest of those.
    [[ -z "$IDLE_TEMP_MAX" ]] && IDLE_TEMP_MAX=$("$ROCM_SMI_BIN" --showtemp 2>/dev/null | grep -oP 'Temperature \(Sensor (junction|memory)\)[^:]*: \K[0-9.]+' | sort -n | tail -1)
    # rocm-smi power label varies by release (Average Graphics Package / Current
    # Socket Graphics Package); match either, case-insensitively.
    IDLE_POWER_MAX=$("$ROCM_SMI_BIN" --showpower 2>/dev/null | grep -oiP '(Average Graphics Package Power|Current Socket Graphics Package Power|Socket Graphics Package Power) \(W\):\s*\K[0-9.]+' | sort -n | tail -1)
fi
# amd-smi fallback: fills temp/power when rocm-smi is absent or its edge sensor
# reads N/A (MI350-series). HOTSPOT is the junction temp; EDGE is a last resort.
if [[ -n "$AMD_SMI_BIN" && ( -z "$IDLE_TEMP_MAX" || -z "$IDLE_POWER_MAX" ) ]]; then
    _amd_metric=$("$AMD_SMI_BIN" metric 2>/dev/null)
    if [[ -z "$IDLE_TEMP_MAX" ]]; then
        IDLE_TEMP_MAX=$(printf '%s\n' "$_amd_metric" | grep -E 'HOTSPOT:|JUNCTION:' | grep -oE '[0-9]+(\.[0-9]+)?' | sort -n | tail -1)
        [[ -z "$IDLE_TEMP_MAX" ]] && IDLE_TEMP_MAX=$(printf '%s\n' "$_amd_metric" | grep -E '\bEDGE:' | grep -oE '[0-9]+(\.[0-9]+)?' | sort -n | tail -1)
    fi
    [[ -z "$IDLE_POWER_MAX" ]] && IDLE_POWER_MAX=$(printf '%s\n' "$_amd_metric" | grep -E 'SOCKET_POWER:' | grep -oE '[0-9]+(\.[0-9]+)?' | sort -n | tail -1)
fi
if command -v nvidia-smi &>/dev/null || [[ -n "$ROCM_SMI_BIN" || -n "$AMD_SMI_BIN" ]]; then
    echo "WORKER_GPU_IDLE_TEMP_MAX=${IDLE_TEMP_MAX:-unknown}"
    echo "WORKER_GPU_IDLE_POWER_MAX=${IDLE_POWER_MAX:-unknown}"
fi

# --- dmesg error scan (Xids for NVIDIA, amdgpu errors for AMD) ---
# Read-only ring buffer scan; non-root may need CAP_SYSLOG. Counts only.
if dmesg -T 2>/dev/null | head -1 | grep -q . ; then
    XID_LINES=$(dmesg -T 2>/dev/null | grep -iE "NVRM: Xid" || true)
    XID_COUNT=$(echo -n "$XID_LINES" | grep -c . || echo 0)
    LAST_XID=$(echo "$XID_LINES" | tail -1 | grep -oE 'Xid \(PCI:[^)]*\): [0-9]+' | grep -oE '[0-9]+$' || echo "")
    echo "WORKER_DMESG_XIDS_COUNT=${XID_COUNT}"
    echo "WORKER_DMESG_XID_LAST=${LAST_XID:-none}"
    AMDGPU_ERR_COUNT=$(dmesg -T 2>/dev/null | grep -cE "amdgpu:.*(error|fault|fail)" || echo 0)
    echo "WORKER_DMESG_AMDGPU_ERRORS_COUNT=${AMDGPU_ERR_COUNT}"
else
    echo "WORKER_DMESG_XIDS_COUNT=unavailable"
    echo "WORKER_DMESG_XID_LAST=unavailable"
    echo "WORKER_DMESG_AMDGPU_ERRORS_COUNT=unavailable"
fi

# --- NCU ---
NCU_P=$(which ncu 2>/dev/null || echo "")
if [[ -n "$NCU_P" ]]; then
    echo "WORKER_NCU_PATH=$NCU_P"
    echo "WORKER_NCU_VERSION=$(ncu --version 2>/dev/null | grep -oiP 'version\s+\K[0-9.]+' | head -1 || echo unknown)"

    # --- NCU Hardware Counter Access (live test) ---
    # Compile a trivial CUDA kernel and profile it with ncu to verify that
    # hardware performance counters are actually accessible at runtime.
    # Config checks (NVreg_RestrictProfilingToAdminUsers) can pass while
    # users still get ERR_NVGPUCTRPERM if the driver was not reloaded.
    NVCC_T=$(which nvcc 2>/dev/null || echo "")
    if [[ -n "$NVCC_T" ]]; then
        NCU_TEST_SRC=$(mktemp /tmp/ncu_counter_test_XXXX.cu)
        NCU_TEST_BIN="${NCU_TEST_SRC%.cu}"
        cat > "$NCU_TEST_SRC" <<'CUDA_EOF'
__global__ void ncu_counter_test_kernel() { }
int main() { ncu_counter_test_kernel<<<1,1>>>(); cudaDeviceSynchronize(); return 0; }
CUDA_EOF
        if nvcc -o "$NCU_TEST_BIN" "$NCU_TEST_SRC" 2>/dev/null; then
            NCU_COUNTER_TIMEOUT_S="${AUDIT_NCU_COUNTER_TIMEOUT_S:-60}"
            NCU_COUNTER_OUT=$(timeout -k 5 "$NCU_COUNTER_TIMEOUT_S" \
                "$NCU_P" --target-processes all --metrics sm__cycles_elapsed.avg \
                "$NCU_TEST_BIN" 2>&1)
            NCU_COUNTER_RC=$?
            if [[ "$NCU_COUNTER_RC" -eq 124 || "$NCU_COUNTER_RC" -eq 137 ]]; then
                echo "WORKER_NCU_COUNTER_ACCESS=timeout"
            elif echo "$NCU_COUNTER_OUT" | grep -q "ERR_NVGPUCTRPERM"; then
                echo "WORKER_NCU_COUNTER_ACCESS=denied"
            elif [[ "$NCU_COUNTER_RC" -ne 0 ]]; then
                echo "WORKER_NCU_COUNTER_ACCESS=error"
            else
                echo "WORKER_NCU_COUNTER_ACCESS=granted"
            fi
            rm -f "$NCU_TEST_BIN"
        else
            echo "WORKER_NCU_COUNTER_ACCESS=compile-failed"
        fi
        rm -f "$NCU_TEST_SRC"
    else
        echo "WORKER_NCU_COUNTER_ACCESS=no-nvcc"
    fi
else
    echo "WORKER_NCU_PATH="
    echo "WORKER_NCU_VERSION=not-found"
    echo "WORKER_NCU_COUNTER_ACCESS=no-ncu"
fi

# --- NCU profiling permission config (NVreg_RestrictProfilingToAdminUsers) ---
# Whether non-admin users can read GPU performance counters. This is a property
# of the driver as configured/loaded on THIS GPU node (modcheck.d + the live
# driver params), so it must be read here, not on the login node which usually
# has no NVIDIA driver loaded. The live counter test above is authoritative;
# this exposes the underlying config that explains a granted/denied result.
WORKER_NCU_PROFILING_ENABLED=unknown
WORKER_NCU_PROFILING_SOURCE=none
if [[ -r /proc/driver/nvidia/params ]]; then
    WORKER_NCU_PROFILING_SOURCE=/proc/driver/nvidia/params
    if grep -q "RmProfilingAdminOnly: 0" /proc/driver/nvidia/params 2>/dev/null; then
        WORKER_NCU_PROFILING_ENABLED=true
    else
        WORKER_NCU_PROFILING_ENABLED=false
    fi
else
    for conf_file in /etc/modcheck.d/*.conf /etc/modcheck.conf; do
        [[ -f "$conf_file" ]] || continue
        if grep -q "NVreg_RestrictProfilingToAdminUsers=" "$conf_file" 2>/dev/null; then
            WORKER_NCU_PROFILING_ENABLED=false
            WORKER_NCU_PROFILING_SOURCE="$conf_file"
            if grep -q "NVreg_RestrictProfilingToAdminUsers=0" "$conf_file" 2>/dev/null; then
                WORKER_NCU_PROFILING_ENABLED=true
            fi
            break
        fi
    done
fi
echo "WORKER_NCU_PROFILING_ENABLED=${WORKER_NCU_PROFILING_ENABLED}"
echo "WORKER_NCU_PROFILING_SOURCE=${WORKER_NCU_PROFILING_SOURCE}"

# --- perf (Linux performance counters) ---
# perf top/stat access issues typically come down to:
#
# 1. perf_event_paranoid (/proc/sys/kernel/perf_event_paranoid):
#    -1 = no restrictions (allow all)
#     0 = allow raw tracepoint access for non-root
#     1 = allow non-root per-process monitoring (default on many distros)
#     2 = allow non-root per-process monitoring only, no kernel profiling
#     3 = no perf event access for non-root at all (Ubuntu default since ~20.04)
#
# 2. kptr_restrict (/proc/sys/kernel/kptr_restrict):
#    0 = kernel symbol addresses visible to all
#    1 = hidden from non-root (perf top shows [unknown] for kernel functions)
#    2 = always hidden
#    Fix: need linux-tools-$(uname -r) package and possibly
#    linux-image-$(uname -r)-dbgsym for debug symbols
#
# 3. Container/VM issues: host kernel perf subsystem may not be accessible.
#    Need --privileged or CAP_SYS_ADMIN / CAP_PERFMON (Linux 5.8+).
#    With Pyxis/enroot: pass via --container-mounts or srun flags.
#
# 4. SELinux/AppArmor: can block perf access even if paranoid level is permissive.
#
# Quick fix (temporary):
#   sudo sysctl -w kernel.perf_event_paranoid=-1
#   sudo sysctl -w kernel.kptr_restrict=0
# Persistent: add to /etc/sysctl.conf or /etc/sysctl.d/99-perf.conf
PERF_P=$(which perf 2>/dev/null || echo "")
PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "unknown")
KPTR=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "unknown")
echo "WORKER_PERF_EVENT_PARANOID=$PARANOID"
echo "WORKER_KPTR_RESTRICT=$KPTR"
if [[ -n "$PERF_P" ]]; then
    echo "WORKER_PERF_PATH=$PERF_P"

    # Live test: perf stat on a trivial workload
    PERF_STAT_OUT=$(perf stat -e cycles,instructions -- sleep 0.1 2>&1 || true)
    if echo "$PERF_STAT_OUT" | grep -qE "cycles|instructions"; then
        if echo "$PERF_STAT_OUT" | grep -q "<not supported>\|<not counted>"; then
            echo "WORKER_PERF_STAT_ACCESS=partial"
        else
            echo "WORKER_PERF_STAT_ACCESS=granted"
        fi
    else
        echo "WORKER_PERF_STAT_ACCESS=denied"
    fi

    # Live test: perf top (non-interactive snapshot)
    PERF_TOP_OUT=$(timeout 5 perf top --no-tui --stdio -n 1 2>&1 || true)
    if echo "$PERF_TOP_OUT" | grep -qiE "permission denied|Access denied|perf_event_open|Operation not permitted"; then
        echo "WORKER_PERF_TOP_ACCESS=denied"
    elif echo "$PERF_TOP_OUT" | grep -qiE "Error|WARNING|paranoid"; then
        echo "WORKER_PERF_TOP_ACCESS=warning"
    elif [[ -n "$PERF_TOP_OUT" ]]; then
        echo "WORKER_PERF_TOP_ACCESS=granted"
    else
        echo "WORKER_PERF_TOP_ACCESS=denied"
    fi
else
    echo "WORKER_PERF_PATH="
    echo "WORKER_PERF_STAT_ACCESS=no-perf"
    echo "WORKER_PERF_TOP_ACCESS=no-perf"
fi
fi

# --- NVCC ---
NVCC_P=$(which nvcc 2>/dev/null || echo "")
if [[ -n "$NVCC_P" ]]; then
    echo "WORKER_NVCC_PATH=$NVCC_P"
    echo "WORKER_NVCC_VERSION=$($NVCC_P --version 2>/dev/null | grep -oP 'release \K[0-9.]+' || echo unknown)"
elif [[ -x /usr/local/cuda/bin/nvcc ]]; then
    # Keep PATH availability distinct from an installed toolkit version. The
    # security policy still needs the latter when an image omitted PATH setup.
    echo "WORKER_NVCC_PATH="
    echo "WORKER_NVCC_VERSION=$(/usr/local/cuda/bin/nvcc --version 2>/dev/null | grep -oP 'release \K[0-9.]+' || echo unknown)"
else
    echo "WORKER_NVCC_PATH="
    echo "WORKER_NVCC_VERSION=not-found"
fi

if ! security_checks_only; then
# --- MPI / HPC-X ---
echo "WORKER_CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-unset}"
echo "WORKER_NVIDIA_VISIBLE_DEVICES=${NVIDIA_VISIBLE_DEVICES:-unset}"

MPIRUN_P=""
if scale_out_checks_enabled; then
    MPIRUN_P=$(which mpirun 2>/dev/null || echo "")
fi
if [[ -n "$MPIRUN_P" ]]; then
    echo "WORKER_MPIRUN_PATH=$MPIRUN_P"
    MPI_VER=$(mpirun --version 2>/dev/null | head -1 || echo unknown)
    echo "WORKER_MPIRUN_VERSION=${MPI_VER}"
    if echo "$MPI_VER" | grep -qi "hpcx\|hpc-x"; then
        echo "WORKER_HPCX_DETECTED=true"
    elif ompi_info --version 2>/dev/null | grep -qi "hpcx\|hpc.x"; then
        echo "WORKER_HPCX_DETECTED=true"
    elif ompi_info 2>/dev/null | grep -qiE 'MCA (pml|spml): *ucx|MCA coll: *hcoll'; then
        # HPC-X ships its own Open MPI build that carries the UCX point-to-point
        # (pml/spml) and HCOLL collective (coll) MCA components. That build
        # reports a plain "Open MPI x.y" version string (no "hpcx" token) and is
        # often installed at a path like /usr/mpi/gcc/openmpi-* rather than under
        # /opt/hpcx, so the version greps above miss it. The UCX/HCOLL MCA
        # components are the reliable signal that this mpirun IS the HPC-X stack.
        echo "WORKER_HPCX_DETECTED=true"
    elif [[ "$(readlink -f "$MPIRUN_P" 2>/dev/null)" == *hpcx* ]]; then
        # mpirun resolves inside an HPC-X install tree.
        echo "WORKER_HPCX_DETECTED=true"
    else
        echo "WORKER_HPCX_DETECTED=false"
    fi
else
    echo "WORKER_MPIRUN_PATH="
    echo "WORKER_MPIRUN_VERSION=not-found"
    echo "WORKER_HPCX_DETECTED=false"
fi

# --- NCCL ---
# Prune Enroot/Pyxis data trees. Failed image imports can leave partial
# libnccl.so files there, and those files are not host-installed NCCL.
find_host_nccl_candidates() {
    find /usr /opt /lib /lib64 \
        \( -path '*/enroot-data' -o -path '*/enroot-data/*' \
           -o -path '*/enroot-cache' -o -path '*/enroot-cache/*' \) -prune \
        -o -name 'libnccl.so*' -print 2>/dev/null
}
NCCL_L=$(find_host_nccl_candidates | head -1 || echo "")
if [[ -n "$NCCL_L" ]]; then
    echo "WORKER_NCCL_LIB=$NCCL_L"
    NCCL_V=$(strings "$NCCL_L" 2>/dev/null | grep -oP 'NCCL version \K[0-9.]+' | head -1 || echo "")
    [[ -z "$NCCL_V" ]] && NCCL_V=$(strings "$NCCL_L" 2>/dev/null | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+$' | head -1 || echo installed)
    echo "WORKER_NCCL_VERSION=$NCCL_V"
else
    echo "WORKER_NCCL_LIB="
    echo "WORKER_NCCL_VERSION=not-found"
fi

# --- /etc/nccl.conf overrides ---
if scale_out_checks_enabled \
        && [[ -f /etc/nccl.conf ]] \
        && grep -qE "NCCL_MIN_NCHANNELS|NCCL_PROTO|NCCL_ALGO" /etc/nccl.conf 2>/dev/null; then
    echo "WORKER_NCCL_CONF_OVERRIDES=true"
else
    echo "WORKER_NCCL_CONF_OVERRIDES=false"
fi

# Capture NCCL_IB_GID_INDEX value separately (RoCEv2 needs =3).
NCCL_GID_VAL=""
if scale_out_checks_enabled && [[ -f /etc/nccl.conf ]]; then
    NCCL_GID_VAL=$(grep -oP '^\s*NCCL_IB_GID_INDEX\s*=\s*\K\d+' /etc/nccl.conf 2>/dev/null | head -1)
fi
echo "WORKER_NCCL_GID_INDEX=${NCCL_GID_VAL:-unset}"

# --- MOFED (Mellanox OFED) version ---
# The fabric stack lives on the compute node; the login node frequently has only
# a management NIC and no MOFED at all, so this is read here, not on the head.
#
# Detection order:
#   1. Classic MLNX_OFED: ofed_info / /etc/mlnx-release.
#   2. DOCA-OFED (the current Mellanox stack) ships no ofed_info and no
#      /etc/mlnx-release. Detect it from the MLNX-built rdma-core package (its
#      version carries an "mlnx" tag, e.g. 2507mlnx58-1.2507097) and the mlx5
#      kernel driver version in sysfs, so a DOCA-OFED node is reported as present
#      instead of "not detected".
# The sysfs driver-version path and the DOCA install dir are overridable so the
# detection can be exercised in a test with fixture paths (production uses the
# real defaults).
_mofed_mlx5_path="${CLUSTERMAX_MLX5_VERSION_PATH:-/sys/module/mlx5_core/version}"
_mofed_opt_dir="${CLUSTERMAX_OPT_MELLANOX_DIR:-/opt/mellanox}"
WORKER_MOFED_VERSION=none
WORKER_MOFED_FLAVOR=none
WORKER_MLX5_DRIVER_VERSION=unknown
if ! scale_out_checks_enabled; then
    :
elif command -v ofed_info &>/dev/null; then
    WORKER_MLX5_DRIVER_VERSION=$(cat "$_mofed_mlx5_path" 2>/dev/null || echo unknown)
    WORKER_MOFED_VERSION=$(ofed_info -s 2>/dev/null | grep -oP 'MLNX_OFED_LINUX-\K[0-9.-]+' || echo "unknown")
    WORKER_MOFED_FLAVOR=mlnx-ofed
elif [[ -f /etc/mlnx-release ]]; then
    WORKER_MLX5_DRIVER_VERSION=$(cat "$_mofed_mlx5_path" 2>/dev/null || echo unknown)
    WORKER_MOFED_VERSION=$(head -1 /etc/mlnx-release 2>/dev/null || echo "unknown")
    WORKER_MOFED_FLAVOR=mlnx-ofed
else
    WORKER_MLX5_DRIVER_VERSION=$(cat "$_mofed_mlx5_path" 2>/dev/null || echo unknown)
    _rc_ver=""
    if command -v dpkg-query &>/dev/null; then
        _rc_ver=$(dpkg-query -W -f='${Version}' rdma-core 2>/dev/null || echo "")
    elif command -v rpm &>/dev/null; then
        _rc_ver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' rdma-core 2>/dev/null | grep -vi 'not installed' || echo "")
    fi
    if [[ "$_rc_ver" == *mlnx* ]]; then
        WORKER_MOFED_VERSION="DOCA-OFED rdma-core ${_rc_ver}"
        WORKER_MOFED_FLAVOR=doca-ofed
    elif [[ -d "$_mofed_opt_dir" && "$WORKER_MLX5_DRIVER_VERSION" != unknown ]]; then
        WORKER_MOFED_VERSION="DOCA-OFED mlx5_core ${WORKER_MLX5_DRIVER_VERSION}"
        WORKER_MOFED_FLAVOR=doca-ofed
    fi
fi
echo "WORKER_MOFED_VERSION=${WORKER_MOFED_VERSION}"
echo "WORKER_MOFED_FLAVOR=${WORKER_MOFED_FLAVOR}"
echo "WORKER_MLX5_DRIVER_VERSION=${WORKER_MLX5_DRIVER_VERSION}"

# --- NVIDIA HPC SDK ---
# /opt is typically node-local, so the head node's /opt does not reflect the
# compute image. Read the newest installed release on the worker and verify the
# SDK payload instead of treating an empty hpc_sdk directory as an install.
WORKER_NVHPC_INSTALLED=false
WORKER_NVHPC_PATH=
WORKER_NVHPC_VERSION=unknown
WORKER_NVHPC_NVC_VERSION=not-found
WORKER_NVHPC_NVCXX_VERSION=not-found
WORKER_NVHPC_NVFORTRAN_VERSION=not-found
WORKER_NVHPC_COMPILERS_OK=false
WORKER_NVHPC_COMPONENTS_OK=false
WORKER_NVHPC_COMPONENTS_MISSING=not-checked
NVHPC_CONFIGURED_ROOT="${CLUSTERMAX_NVHPC_ROOT:-/opt/nvidia/hpc_sdk}"
if [[ -d "$NVHPC_CONFIGURED_ROOT" ]]; then
    WORKER_NVHPC_PATH="$NVHPC_CONFIGURED_ROOT"
else
    NVHPC_ALT=
    if [[ -z "${CLUSTERMAX_NVHPC_ROOT:-}" ]]; then
        NVHPC_ALT=$(find /opt -maxdepth 4 -type d -name "hpc_sdk" 2>/dev/null | head -1)
    fi
    if [[ -n "$NVHPC_ALT" ]]; then
        WORKER_NVHPC_PATH="$NVHPC_ALT"
    fi
fi
if [[ -n "$WORKER_NVHPC_PATH" ]]; then
    WORKER_NVHPC_RELEASE_ROOT=$(find "$WORKER_NVHPC_PATH" -mindepth 2 -maxdepth 2 \
        -type d 2>/dev/null \
        | awk -F/ '$NF ~ /^[0-9]+\.[0-9]+$/ {print}' | sort -V | tail -1)
    if [[ -n "$WORKER_NVHPC_RELEASE_ROOT" ]]; then
        WORKER_NVHPC_INSTALLED=true
        WORKER_NVHPC_VERSION="${WORKER_NVHPC_RELEASE_ROOT##*/}"
        NVHPC_COMPILER_BIN="$WORKER_NVHPC_RELEASE_ROOT/compilers/bin"
        nvhpc_tool_version() {
            local tool="$1"
            [[ -x "$tool" ]] || { printf '%s\n' not-found; return; }
            "$tool" --version 2>/dev/null \
                | grep -oE '[0-9]{2}\.[0-9]{1,2}' | head -1 \
                || printf '%s\n' unknown
        }
        WORKER_NVHPC_NVC_VERSION=$(nvhpc_tool_version "$NVHPC_COMPILER_BIN/nvc")
        WORKER_NVHPC_NVCXX_VERSION=$(nvhpc_tool_version "$NVHPC_COMPILER_BIN/nvc++")
        WORKER_NVHPC_NVFORTRAN_VERSION=$(nvhpc_tool_version "$NVHPC_COMPILER_BIN/nvfortran")
        if [[ "$WORKER_NVHPC_NVC_VERSION" == "$WORKER_NVHPC_VERSION" \
                && "$WORKER_NVHPC_NVCXX_VERSION" == "$WORKER_NVHPC_VERSION" \
                && "$WORKER_NVHPC_NVFORTRAN_VERSION" == "$WORKER_NVHPC_VERSION" ]]; then
            WORKER_NVHPC_COMPILERS_OK=true
        fi

        NVHPC_MISSING=()
        nvhpc_require_file() {
            local label="$1" pattern="$2"
            find "$WORKER_NVHPC_RELEASE_ROOT" \( -type f -o -type l \) \
                -name "$pattern" -print -quit \
                2>/dev/null | grep -q . || NVHPC_MISSING+=("$label")
        }
        nvhpc_require_dir() {
            local label="$1" pattern="$2"
            find "$WORKER_NVHPC_RELEASE_ROOT" -type d -name "$pattern" -print -quit \
                2>/dev/null | grep -q . || NVHPC_MISSING+=("$label")
        }
        nvhpc_require_file nccl 'libnccl.so*'
        nvhpc_require_dir hpcx 'hpcx*'
        nvhpc_require_file nvshmem 'libnvshmem*.so*'
        nvhpc_require_file cublas 'libcublas.so*'
        nvhpc_require_file cufft 'libcufft.so*'
        nvhpc_require_file curand 'libcurand.so*'
        nvhpc_require_file cusolver 'libcusolver.so*'
        nvhpc_require_file cusparse 'libcusparse.so*'
        nvhpc_require_file cutensor 'libcutensor.so*'
        nvhpc_require_file ncu ncu
        nvhpc_require_file nsys nsys
        nvhpc_require_file cuda-gdb cuda-gdb
        nvhpc_require_dir thrust thrust
        nvhpc_require_dir cub cub
        nvhpc_require_file openblas 'libopenblas.so*'
        nvhpc_require_file scalapack 'libscalapack.so*'
        if [[ "$(uname -m 2>/dev/null)" == aarch64 ]]; then
            nvhpc_require_file nvpl 'libnvpl*.so*'
        fi
        if [[ ${#NVHPC_MISSING[@]} -eq 0 ]]; then
            WORKER_NVHPC_COMPONENTS_OK=true
            WORKER_NVHPC_COMPONENTS_MISSING=none
        else
            WORKER_NVHPC_COMPONENTS_MISSING=$(IFS=,; printf '%s' "${NVHPC_MISSING[*]}")
        fi
    fi
fi
echo "WORKER_NVHPC_INSTALLED=${WORKER_NVHPC_INSTALLED}"
echo "WORKER_NVHPC_PATH=${WORKER_NVHPC_PATH}"
echo "WORKER_NVHPC_VERSION=${WORKER_NVHPC_VERSION}"
echo "WORKER_NVHPC_NVC_VERSION=${WORKER_NVHPC_NVC_VERSION}"
echo "WORKER_NVHPC_NVCXX_VERSION=${WORKER_NVHPC_NVCXX_VERSION}"
echo "WORKER_NVHPC_NVFORTRAN_VERSION=${WORKER_NVHPC_NVFORTRAN_VERSION}"
echo "WORKER_NVHPC_COMPILERS_OK=${WORKER_NVHPC_COMPILERS_OK}"
echo "WORKER_NVHPC_COMPONENTS_OK=${WORKER_NVHPC_COMPONENTS_OK}"
echo "WORKER_NVHPC_COMPONENTS_MISSING=${WORKER_NVHPC_COMPONENTS_MISSING}"

# --- HPC-X install tree under /opt (the in-PATH signal is WORKER_HPCX_DETECTED
# above; this is the on-disk tree, also node-local so it must come from here) ---
WORKER_HPCX_OPT_PATH=""
if scale_out_checks_enabled; then
    WORKER_HPCX_OPT_PATH=$(find /opt -maxdepth 3 -type d -name "hpcx*" 2>/dev/null | head -1)
fi
echo "WORKER_HPCX_OPT_PATH=${WORKER_HPCX_OPT_PATH}"

# --- SHARP (in-network reductions) ---
# sharp_hello, the SHARP tree, and AM-key config are compute/fabric node
# properties; check them on the worker rather than the login node.
WORKER_SHARP_HELLO_PATH=""
WORKER_SHARP_ENV=false
if scale_out_checks_enabled; then
    WORKER_SHARP_HELLO_PATH=$(command -v sharp_hello 2>/dev/null || find /opt /usr -name "sharp_hello" 2>/dev/null | head -1 || echo "")
    [[ -n "${SHARP_HOME:-}" || -n "${HPCX_SHARP_DIR:-}" ]] && WORKER_SHARP_ENV=true
fi
echo "WORKER_SHARP_HELLO_PATH=${WORKER_SHARP_HELLO_PATH}"
echo "WORKER_SHARP_ENV=${WORKER_SHARP_ENV}"
WORKER_SHARP_AM_KEY_CONFIGURED=false
WORKER_SHARP_CONF=
if scale_out_checks_enabled; then
    for SHARP_CONF in /etc/sharp/sharp_am_auth.conf /opt/mellanox/sharp/share/sharp/conf/sharp_am.cfg; do
        if [[ -f "$SHARP_CONF" ]]; then
            WORKER_SHARP_CONF="$SHARP_CONF"
            AM_KEY=$(grep -iE "am_key|amkey|key" "$SHARP_CONF" 2>/dev/null | grep -v "^#" | head -1 || echo "")
            [[ -n "$AM_KEY" ]] && WORKER_SHARP_AM_KEY_CONFIGURED=true
            break
        fi
    done
fi
echo "WORKER_SHARP_AM_KEY_CONFIGURED=${WORKER_SHARP_AM_KEY_CONFIGURED}"
echo "WORKER_SHARP_CONF=${WORKER_SHARP_CONF}"
fi

if ! security_checks_only; then
# --- DCGM ---
WORKER_HEALTH_PROGRAM_DCGM=false
WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE=none
if command -v scontrol &>/dev/null; then
    WORKER_HEALTH_PROGRAM=$(scontrol show config 2>/dev/null \
        | awk '$1 == "HealthCheckProgram" {print $3; exit}')
    if [[ -r "$WORKER_HEALTH_PROGRAM" ]]; then
        if grep -qiE 'dcgm|dcgmi|nv-hostengine' "$WORKER_HEALTH_PROGRAM" 2>/dev/null; then
            WORKER_HEALTH_PROGRAM_DCGM=true
            WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE="$WORKER_HEALTH_PROGRAM"
        else
            WORKER_HEALTH_DIR=$(dirname "$WORKER_HEALTH_PROGRAM")
            for WORKER_HEALTH_PLUGIN_DIR in \
                    "$WORKER_HEALTH_DIR/checks.d" \
                    "$WORKER_HEALTH_DIR/checks.d.custom"; do
                [[ -d "$WORKER_HEALTH_PLUGIN_DIR" ]] || continue
                while IFS= read -r WORKER_HEALTH_PLUGIN; do
                    if grep -qiE 'dcgm|dcgmi|nv-hostengine' "$WORKER_HEALTH_PLUGIN" 2>/dev/null; then
                        WORKER_HEALTH_PROGRAM_DCGM=true
                        WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE="$WORKER_HEALTH_PLUGIN"
                        break 2
                    fi
                done < <(find -L "$WORKER_HEALTH_PLUGIN_DIR" -maxdepth 1 \
                    -type f -perm -u+x 2>/dev/null | sort)
            done
        fi
    fi
fi
echo "WORKER_HEALTH_PROGRAM_DCGM=${WORKER_HEALTH_PROGRAM_DCGM}"
echo "WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE=${WORKER_HEALTH_PROGRAM_DCGM_EVIDENCE}"

# --- NHC (Node Health Check) ---
# NHC runs on compute nodes via the slurm.conf HealthCheckProgram; login and
# head nodes commonly do not carry the binary at all, so worker detection is
# the authoritative signal (GMI GB300 was reported as a false negative from a
# head-node-only check).
WORKER_NHC_INSTALLED=false
WORKER_NHC_PATH=none
if command -v nhc &>/dev/null; then
    WORKER_NHC_INSTALLED=true
    WORKER_NHC_PATH=$(command -v nhc)
elif [[ -x /usr/sbin/nhc || -x /usr/local/sbin/nhc ]]; then
    WORKER_NHC_INSTALLED=true
    WORKER_NHC_PATH=$(ls /usr/sbin/nhc /usr/local/sbin/nhc 2>/dev/null | head -1)
fi
WORKER_NHC_CONF_CHECKS=0
if [[ -f /etc/nhc/nhc.conf ]]; then
    WORKER_NHC_CONF_CHECKS=$(grep -cv -E '^\s*(#|$)' /etc/nhc/nhc.conf 2>/dev/null || echo 0)
fi
echo "WORKER_NHC_INSTALLED=${WORKER_NHC_INSTALLED}"
echo "WORKER_NHC_PATH=${WORKER_NHC_PATH}"
echo "WORKER_NHC_CONF_CHECKS=${WORKER_NHC_CONF_CHECKS}"
fi

if ! security_checks_only && (systemctl is-active dcgm &>/dev/null || pgrep nv-hostengine &>/dev/null); then
    echo "WORKER_DCGM_ACTIVE=true"
else
    echo "WORKER_DCGM_ACTIVE=false"
fi
if command -v dcgmi &>/dev/null; then
    echo "WORKER_DCGM_VERSION=$(dcgmi --version 2>/dev/null | grep -m1 -v '^[[:space:]]*$' || echo unknown)"
    if ! security_checks_only; then
    if dcgmi health -g 0 -s a &>/dev/null 2>&1; then
        echo "WORKER_DCGM_HEALTH_OK=true"
    else
        echo "WORKER_DCGM_HEALTH_OK=false"
    fi
    timeout 60 dcgmi diag -r 1 >/dev/null 2>&1
    DCGM_DIAG_R1_RC=$?
    if [[ $DCGM_DIAG_R1_RC -eq 0 ]]; then
        echo "WORKER_DCGM_DIAG_R1=pass"
    elif [[ $DCGM_DIAG_R1_RC -eq 124 ]]; then
        echo "WORKER_DCGM_DIAG_R1=timeout"
    else
        echo "WORKER_DCGM_DIAG_R1=fail"
    fi

    if [[ "${AUDIT_DCGM_DIAG_R2:-false}" == "true" || "${AUDIT_DCGM_DIAG_R2:-0}" == "1" ]]; then
        timeout 120 dcgmi diag -r 2 >/dev/null 2>&1
        DCGM_DIAG_R2_RC=$?
        if [[ $DCGM_DIAG_R2_RC -eq 0 ]]; then
            echo "WORKER_DCGM_DIAG_R2=pass"
        elif [[ $DCGM_DIAG_R2_RC -eq 124 ]]; then
            echo "WORKER_DCGM_DIAG_R2=timeout"
        else
            echo "WORKER_DCGM_DIAG_R2=fail"
        fi
    else
        echo "WORKER_DCGM_DIAG_R2=skipped"
    fi
    else
        echo "WORKER_DCGM_HEALTH_OK=skipped"
        echo "WORKER_DCGM_DIAG_R1=skipped"
        echo "WORKER_DCGM_DIAG_R2=skipped"
    fi
else
    echo "WORKER_DCGM_VERSION=not-found"
    echo "WORKER_DCGM_HEALTH_OK=false"
    echo "WORKER_DCGM_DIAG_R1=no-dcgmi"
    echo "WORKER_DCGM_DIAG_R2=no-dcgmi"
fi

# Local PCI security inventory is independent of the scale-out fabric. The
# standalone audit needs these facts so a host without an NVIDIA GPU can grade
# the NVIDIA driver requirement as not applicable.
#
# An lspci that exits cleanly with an empty listing needs a second, independent
# reader before it can count as a read bus. Some virtual machines expose no PCI
# device, so a readable and empty /sys/bus/pci/devices directory confirms that
# the kernel enumerated an empty bus. An empty listing without that confirmation
# stays an unread bus because it can also indicate a broken lspci command.
SECURITY_PCI_SYSFS="${CLUSTERMAX_AUDIT_ROOT:-}/sys/bus/pci/devices"
security_pci_bus_confirmed_empty() {
    # The exit status of ls matters because an unreadable directory also
    # produces a blank capture. Confirmation needs a successful empty read.
    local listing
    [[ -d "$SECURITY_PCI_SYSFS" ]] || return 1
    listing=$(ls -A "$SECURITY_PCI_SYSFS" 2>/dev/null) || return 1
    [[ -z "$listing" ]]
}

# NVIDIA GPU presence supports the security version audit. The NVIDIA driver
# minimum applies only to a host that has an NVIDIA GPU. Only a read PCI bus can
# claim absence. A missing or failed lspci command keeps the result unknown.
# Any 10de vendor entry counts as present because an audio function or NVSwitch
# must also prevent an incorrect absence claim.
WORKER_SECURITY_GPU_INVENTORY_COMPLETE=false
WORKER_SECURITY_NVIDIA_GPU_PRESENT=unknown
if command -v lspci >/dev/null 2>&1; then
    if SECURITY_GPU_PCI_LISTING=$(lspci -n 2>/dev/null); then
        if [[ -n "$SECURITY_GPU_PCI_LISTING" ]]; then
            WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true
            if grep -qiE '(^| )10de:' <<< "$SECURITY_GPU_PCI_LISTING"; then
                WORKER_SECURITY_NVIDIA_GPU_PRESENT=true
            else
                WORKER_SECURITY_NVIDIA_GPU_PRESENT=false
            fi
        elif security_pci_bus_confirmed_empty; then
            WORKER_SECURITY_GPU_INVENTORY_COMPLETE=true
            WORKER_SECURITY_NVIDIA_GPU_PRESENT=false
        fi
    fi
fi
echo "WORKER_SECURITY_GPU_INVENTORY_COMPLETE=${WORKER_SECURITY_GPU_INVENTORY_COMPLETE}"
echo "WORKER_SECURITY_NVIDIA_GPU_PRESENT=${WORKER_SECURITY_NVIDIA_GPU_PRESENT}"

# --- InfiniBand devices ---
if scale_out_checks_enabled; then
IB_DEVS=$(ls /sys/class/infiniband/ 2>/dev/null | grep -v bond | tr '\n' ',' | sed 's/,$//')
echo "WORKER_IB_DEVICES=$IB_DEVS"

for dev in $(ls /sys/class/infiniband/ 2>/dev/null | grep -v bond); do
    rate=$(cat /sys/class/infiniband/${dev}/ports/1/rate 2>/dev/null || echo unknown)
    state=$(cat /sys/class/infiniband/${dev}/ports/1/state 2>/dev/null | grep -oP '\d+: \K\w+' || echo unknown)
    link_layer=$(cat /sys/class/infiniband/${dev}/ports/1/link_layer 2>/dev/null || echo unknown)
    pci_vendor=$(cat /sys/class/infiniband/${dev}/device/vendor 2>/dev/null || echo unknown)
    pci_device=$(cat /sys/class/infiniband/${dev}/device/device 2>/dev/null || echo unknown)
    hca_type=$(cat /sys/class/infiniband/${dev}/hca_type 2>/dev/null || echo unknown)
    fw_ver=$(cat /sys/class/infiniband/${dev}/fw_ver 2>/dev/null || echo unknown)
    echo "WORKER_IB_RATE_${dev}=${rate}"
    echo "WORKER_IB_STATE_${dev}=${state}"
    echo "WORKER_IB_LINK_LAYER_${dev}=${link_layer}"
    echo "WORKER_IB_PCI_VENDOR_${dev}=${pci_vendor}"
    echo "WORKER_IB_PCI_DEVICE_${dev}=${pci_device}"
    echo "WORKER_IB_HCA_TYPE_${dev}=${hca_type}"
    echo "WORKER_IB_FW_VER_${dev}=${fw_ver}"

    # PKeys. Some clusters expose many inactive PKey slots, and a few sysfs
    # reads can block long enough to make the audit check look hung. Sample the
    # first slots on active ports only; tenant/default PKeys normally appear
    # there, and this keeps the check bounded.
    pkeys=""
    if [[ "$state" == "ACTIVE" ]]; then
        pkey_seen=0
        for pf in /sys/class/infiniband/${dev}/ports/1/pkeys/*; do
            pkey_seen=$((pkey_seen + 1))
            [[ "$pkey_seen" -gt 16 ]] && break
            idx="${pf##*/}"
            [[ "$idx" =~ ^[0-9]+$ && "$idx" -gt 15 ]] && continue
            v=$(timeout 1s cat "$pf" 2>/dev/null | tr -d '[:space:]' || true)
            [[ "$v" != "0x0000" && -n "$v" ]] && pkeys="${pkeys}${v},"
        done
    fi
    pkeys="${pkeys%,}"
    echo "WORKER_PKEYS_${dev}=${pkeys}"

    # RoCE
    if grep -rl "RoCE v2\|roce_v2\|RoCEv2" /sys/class/infiniband/${dev}/ports/1/gid_attrs/types/ 2>/dev/null | grep -q .; then
        echo "WORKER_ROCE_${dev}=true"
    else
        echo "WORKER_ROCE_${dev}=false"
    fi
done

# Security inventory includes logical/bonded devices that are deliberately
# excluded from the benchmark rail list above. A management or BlueField bond
# can still carry firmware covered by NVIDIA's ConnectX/BlueField bulletin.
#
# The completeness flag is the whole contract with the evaluator: a complete
# inventory that names no NVIDIA device grades not_applicable, which the report
# renders as a pass. So it is claimed only when a device was actually read.
#
# Enumerating at least one device in the RDMA sysfs tree is that read. Nothing
# else in this tree is: the directory is created by ib_core, which loads with
# the rdma-core stack even when no HCA driver is bound, so a present but empty
# tree is the same picture as an unloaded or blacklisted mlx5_ib, which
# Ethernet-only deployments configure on purpose. A missing tree says even
# less. In both of those cases the ConnectX and the firmware the bulletin
# covers sit on the PCI bus unread, so both fall through to the same proof of
# absence: a PCI listing that was read and names no NVIDIA (15b3) device.
# Anything else leaves the inventory incomplete, and the evaluator reports
# unknown and asks for the firmware instead of clearing a host nobody
# inspected.
#
# CLUSTERMAX_AUDIT_ROOT re-roots the sysfs read for tests, the same override
# checks/fabric/virtio-net-check.py takes. It is unset in every audit run.
SECURITY_NIC_SYSFS="${CLUSTERMAX_AUDIT_ROOT:-}/sys/class/infiniband"
WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false
SECURITY_NIC_DEVICES_SEEN=false
if [[ -d "$SECURITY_NIC_SYSFS" ]]; then
    for ib_path in "$SECURITY_NIC_SYSFS"/*; do
        [[ -e "$ib_path" ]] || continue
        SECURITY_NIC_DEVICES_SEEN=true
        dev=$(basename "$ib_path")
        pci_vendor=$(cat "$ib_path/device/vendor" 2>/dev/null || echo unknown)
        fw_ver=$(cat "$ib_path/fw_ver" 2>/dev/null || echo unknown)
        echo "WORKER_SECURITY_NIC_PCI_VENDOR_${dev}=${pci_vendor}"
        echo "WORKER_SECURITY_NIC_FW_VER_${dev}=${fw_ver}"
    done
fi
if [[ "$SECURITY_NIC_DEVICES_SEEN" == true ]]; then
    WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true
elif command -v lspci >/dev/null 2>&1; then
    if SECURITY_NIC_PCI_LISTING=$(lspci -n 2>/dev/null); then
        if [[ -n "$SECURITY_NIC_PCI_LISTING" ]] \
            && ! grep -qiE '(^| )15b3:' <<< "$SECURITY_NIC_PCI_LISTING"; then
            WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true
        elif [[ -z "$SECURITY_NIC_PCI_LISTING" ]] \
            && security_pci_bus_confirmed_empty; then
            WORKER_SECURITY_NIC_INVENTORY_COMPLETE=true
        fi
    fi
fi
echo "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=${WORKER_SECURITY_NIC_INVENTORY_COMPLETE}"

if ! security_checks_only; then
# AWS EFA detection. EFA exposes /dev/infiniband/uverbs_ via the efa kernel
# module but the device is an Amazon NIC (PCI vendor 0x1d0f), not a Mellanox
# HCA. Surface separately so audit can flag the EFA fabric class.
EFA_DEVS=""
if [[ -d /sys/class/infiniband ]]; then
    for d in /sys/class/infiniband/*; do
        [[ -d "$d" ]] || continue
        v=$(cat "$d/device/vendor" 2>/dev/null || echo "")
        if [[ "$v" == "0x1d0f" ]]; then
            EFA_DEVS="${EFA_DEVS}$(basename "$d"),"
        fi
    done
fi
EFA_DEVS="${EFA_DEVS%,}"
echo "WORKER_EFA_DEVICES=${EFA_DEVS}"
# Fallback: AWS EFA install marker (some AMIs expose efa-info)
if [[ -x /opt/amazon/efa/bin/fi_info ]] || command -v fi_info &>/dev/null; then
    echo "WORKER_EFA_LIBFABRIC=true"
else
    echo "WORKER_EFA_LIBFABRIC=false"
fi

# Explicit RDMA/HCA utility checks named in the audit checklist. The sysfs
# checks above are the source of truth; these confirm operators have the normal
# diagnostics installed and usable on compute nodes.
check_netutil() {
    key="$1"
    binary="$2"
    shift 2
    path=$(command -v "$binary" 2>/dev/null || echo "")
    echo "WORKER_NETUTIL_${key}_PATH=$path"
    if [[ -z "$path" ]]; then
        echo "WORKER_NETUTIL_${key}_STATUS=not-found"
        return
    fi
    timeout 10 "$binary" "$@" >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "WORKER_NETUTIL_${key}_STATUS=pass"
    elif [[ $rc -eq 124 ]]; then
        echo "WORKER_NETUTIL_${key}_STATUS=timeout"
    else
        echo "WORKER_NETUTIL_${key}_STATUS=fail"
    fi
}

check_netutil IBDEV2NETDEV ibdev2netdev -v
check_netutil IBV_DEVICES ibv_devices
check_netutil RDMA_LINK_SHOW rdma link show
check_netutil RDMA_DEV_SHOW rdma dev show
check_netutil IBSTAT ibstat
check_netutil IBSTATUS ibstatus
check_netutil LSPCI lspci -D

# --- ibhosts for tenant isolation ---
if command -v ibhosts &>/dev/null; then
    CNT=$(ibhosts 2>/dev/null | wc -l | tr -d '[:space:]' || echo 0)
    SAMPLE=$(ibhosts 2>/dev/null | head -5 | tr '\n' '|' | sed "s/'//g")
    echo "WORKER_IBHOSTS_COUNT=$CNT"
    echo "WORKER_IBHOSTS_SAMPLE=$SAMPLE"
fi
fi
else
    echo "WORKER_IB_DEVICES="
    echo "WORKER_SECURITY_NIC_INVENTORY_COMPLETE=false"
    echo "WORKER_EFA_DEVICES="
    echo "WORKER_EFA_LIBFABRIC=false"
    echo "WORKER_IBHOSTS_COUNT=0"
    echo "WORKER_IBHOSTS_SAMPLE="
fi

if ! security_checks_only; then
# --- Storage / Drive Config ---
# Boot device
W_BOOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || df / 2>/dev/null | tail -1 | awk '{print $1}')
W_BOOT_FSTYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || df -T / 2>/dev/null | tail -1 | awk '{print $2}')
W_BOOT_SIZE=$(df -h / 2>/dev/null | tail -1 | awk '{print $2}')
echo "WORKER_BOOT_DEVICE=${W_BOOT_DEV:-unknown}"
echo "WORKER_BOOT_FSTYPE=${W_BOOT_FSTYPE:-unknown}"
echo "WORKER_BOOT_SIZE=${W_BOOT_SIZE:-unknown}"

# Block devices (pipe-delimited for safe parsing)
# Format per line: WORKER_BLKDEV_<name>=<type>|<sizeBytes>|<mountpoint>|<fstype>|<transport>
if command -v lsblk &>/dev/null; then
    lsblk -d -b -o NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,TRAN -P -n 2>/dev/null | while IFS= read -r line; do
        eval "$line" 2>/dev/null || continue
        echo "WORKER_BLKDEV_${NAME}=${TYPE}|${SIZE}|${MOUNTPOINT}|${FSTYPE}|${TRAN}"
    done
fi

# NVMe summary
if command -v lsblk &>/dev/null; then
    W_NVME_DEVS=$(lsblk -d -o NAME -n 2>/dev/null | grep '^nvme' | tr '\n' ',' | sed 's/,$//')
    W_NVME_COUNT=$(lsblk -d -o NAME -n 2>/dev/null | grep -c '^nvme' || echo 0)
    W_NVME_TOTAL=$(lsblk -d -b -o NAME,SIZE -n 2>/dev/null | awk '$1~/^nvme/{s+=$2}END{printf "%.0f\n",s/1073741824}')
else
    W_NVME_DEVS=""
    W_NVME_COUNT=0
    W_NVME_TOTAL=0
fi
echo "WORKER_NVME_DEVICES=${W_NVME_DEVS}"
echo "WORKER_NVME_COUNT=${W_NVME_COUNT}"
echo "WORKER_NVME_TOTAL_GB=${W_NVME_TOTAL}"

# Shared mounts (pipe-delimited)
if command -v findmnt &>/dev/null; then
    findmnt -t nfs,nfs4,lustre,gpfs,ceph,glusterfs,fuse.weka,fuse.lustre,fuse.ceph,fuse.beegfs,beegfs,wekafs,panfs \
        -n -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | while read -r target source fstype opts; do
        [[ -z "$target" ]] && continue
        SAFE_TARGET=$(echo "$target" | sed 's#^/##; s#[^A-Za-z0-9_]#_#g; s#/#_#g')
        echo "WORKER_SHAREDMNT_${SAFE_TARGET}=${target}|${source}|${fstype}|${opts}"
    done
fi

# df for well-known shared paths
for mnt in /home /scratch /data /shared /work /projects /lustre /gpfs /weka /beegfs; do
    if [[ -d "$mnt" ]] && mountpoint -q "$mnt" 2>/dev/null; then
        W_FS=$(df -T "$mnt" 2>/dev/null | tail -1 | awk '{print $2}')
        W_SIZE=$(df -h "$mnt" 2>/dev/null | tail -1 | awk '{print $2}')
        W_USED=$(df -h "$mnt" 2>/dev/null | tail -1 | awk '{print $3}')
        W_AVAIL=$(df -h "$mnt" 2>/dev/null | tail -1 | awk '{print $4}')
        SAFE_MNT=$(echo "$mnt" | sed 's#^/##; s#[^A-Za-z0-9_]#_#g; s#/#_#g')
        echo "WORKER_MNTDF_${SAFE_MNT}=${W_FS}|${W_SIZE}|${W_USED}|${W_AVAIL}"
    fi
done
fi
