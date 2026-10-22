#!/bin/bash
# Passive PwnEscape (CVE-2026-99999) facts for one host.
#
# `cmax audit security` runs this script on every worker and control-plane
# host that it can reach, because a sandbox escape on any one host defeats the
# tenant boundary. The full host-check.sh collects the same facts on the
# sampled GPU worker. The callers deliver this script over stdin
# (`bash -s`), so it must not source a sibling file.
#
# Nothing here opens a device, sends traffic, or changes a setting.
# CLUSTERMAX_AUDIT_ROOT re-roots the /proc, /dev, and /sys reads for tests.

echo "WORKER_HOSTNAME=$(hostname 2>/dev/null || echo unknown)"
echo "WORKER_GUEST_KERNEL_RUNNING=$(uname -r 2>/dev/null || echo unknown)"

# Keep this classification identical to the one in host-check.sh. A missing
# systemd-detect-virt is not a bare-metal reading, and the cpuinfo hypervisor
# flag can prove only that this host is a guest.
detect_pwnescape_virtualization() {
    local root="${CLUSTERMAX_AUDIT_ROOT:-}"
    local virt_type=unknown virt_guest=unknown reading rc
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        reading=$(systemd-detect-virt --vm 2>/dev/null)
        rc=$?
        reading="${reading//[[:space:]]/}"
        if [[ "$rc" -eq 0 && -n "$reading" && "$reading" != none ]]; then
            virt_type="$reading"
            virt_guest=true
        elif [[ "$reading" == none && ( "$rc" -eq 0 || "$rc" -eq 1 ) ]]; then
            virt_type=none
            virt_guest=false
        fi
    fi
    if [[ "$virt_guest" == unknown ]] && grep -qm1 -E \
            '(^|[[:space:]])hypervisor([[:space:]]|$)' \
            "${root}/proc/cpuinfo" 2>/dev/null; then
        virt_guest=true
    fi
    printf 'WORKER_VIRT_TYPE=%s\n' "$virt_type"
    printf 'WORKER_VIRT_GUEST=%s\n' "$virt_guest"
}
detect_pwnescape_virtualization

# Keep this function identical to collect_pwnescape_facts in host-check.sh.
# tests/audit/test_pwnescape.py compares the two definitions.
collect_pwnescape_facts() {
    local root="${CLUSTERMAX_AUDIT_ROOT:-}"
    local livepatch=unknown tun=unknown virtio=unknown userns=unknown
    local entry enabled
    if [[ -d "${root}/sys/kernel/livepatch" && -r "${root}/sys/kernel/livepatch" \
          && -x "${root}/sys/kernel/livepatch" ]]; then
        livepatch=none
        for entry in "${root}"/sys/kernel/livepatch/*; do
            [[ -e "$entry" ]] || continue
            enabled=$(cat "$entry/enabled" 2>/dev/null) || enabled=unknown
            if [[ "$enabled" != 0 ]]; then
                livepatch=active-or-unreadable
            fi
        done
    elif [[ -d "${root}/sys/kernel" && -r "${root}/sys/kernel" \
            && -x "${root}/sys/kernel" && ! -e "${root}/sys/kernel/livepatch" \
            && ! -L "${root}/sys/kernel/livepatch" ]]; then
        livepatch=not-supported
    fi
    if [[ -d "${root}/dev/net" && -r "${root}/dev/net" && -x "${root}/dev/net" ]]; then
        tun=false
        [[ -c "${root}/dev/net/tun" ]] && tun=true
    fi
    if [[ -r "${root}/sys/class/net" && -x "${root}/sys/class/net" ]]; then
        virtio=false
        for entry in "${root}"/sys/class/net/*/device/driver; do
            [[ -L "$entry" ]] || continue
            [[ "$(readlink "$entry" 2>/dev/null)" == */virtio_net ]] && virtio=true
        done
    fi
    userns=$(cat "${root}/proc/sys/user/max_user_namespaces" 2>/dev/null) || userns=unknown
    [[ "$userns" =~ ^[0-9]+$ ]] || userns=unknown
    printf 'WORKER_PWNESCAPE_LIVEPATCH=%s\n' "$livepatch"
    printf 'WORKER_PWNESCAPE_TUN_PRESENT=%s\n' "$tun"
    printf 'WORKER_PWNESCAPE_VIRTIO_NET=%s\n' "$virtio"
    printf 'WORKER_PWNESCAPE_USERNS_MAX=%s\n' "$userns"
}
collect_pwnescape_facts
