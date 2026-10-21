#!/usr/bin/env python3
"""Check THP policy and static HugeTLB capacity without changing the host.

The explicit --try-allocate option tests an additional 1 GiB of the default
HugeTLB page size on one idle host. It requires root and restores the pool.
Workers run from standard input, so controller-only imports must stay lazy.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import signal
import socket
import sys
from pathlib import Path

GIB = 1024 ** 3
THP = "sys/kernel/mm/transparent_hugepage"
HUGETLB = "sys/kernel/mm/hugepages"
NR = "proc/sys/vm/nr_hugepages"


def read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return ""


def number(path: Path) -> int | None:
    text = read(path)
    return int(text) if text.isdigit() else None


def meminfo(root: Path) -> dict[str, int]:
    return {
        key: int(value)
        for key, value in re.findall(
            r"^(\w+):\s+(\d+)(?:\s+kB)?\s*$", read(root / "proc/meminfo"), re.M
        )
    }


def active_mode(text: str) -> str:
    modes = re.findall(r"\[(always|madvise|never|inherit)\]", text)
    return modes[0] if len(modes) == 1 else "unknown"


def thp_report(root: Path) -> dict:
    base = root / THP
    if not base.exists():
        base = root / "sys/kernel/mm/redhat_transparent_hugepage"
    raw = read(base / "enabled")
    top = active_mode(raw)
    sizes = {}
    for path in sorted(base.glob("hugepages-*kB/enabled")):
        mode = active_mode(read(path))
        sizes[path.parent.name] = {
            "configured": mode, "effective": top if mode == "inherit" else mode
        }
    effective = [entry["effective"] for entry in sizes.values()] or [top]
    # The check rewards an effective madvise policy.
    status = "pass" if effective and all(mode == "madvise" for mode in effective) else "neutral"
    if "unknown" in effective or top == "unknown":
        status = "unknown"
    return {
        "status": status, "top_level": top, "raw": raw, "sizes": sizes,
        "message": f"THP top-level policy is {top}; effective modes are {', '.join(sorted(set(effective)))}",
    }


def static_report(root: Path) -> dict:
    info = meminfo(root)
    pools = []
    for path in sorted((root / HUGETLB).glob("hugepages-*kB")):
        match = re.fullmatch(r"hugepages-(\d+)kB", path.name)
        if not match:
            continue
        pools.append({
            "page_size_bytes": int(match[1]) * 1024,
            "total_pages": number(path / "nr_hugepages"),
            "free_pages": number(path / "free_hugepages"),
            "reserved_pages": number(path / "resv_hugepages"),
            "surplus_pages": number(path / "surplus_hugepages"),
        })
    complete = bool(pools) and all(
        p["total_pages"] is not None and p["surplus_pages"] is not None
        and p["free_pages"] is not None
        and 0 <= p["surplus_pages"] <= p["total_pages"]
        and p["free_pages"] <= p["total_pages"] for p in pools
    )
    for pool in pools:
        total_pages, surplus = pool["total_pages"], pool["surplus_pages"]
        pool["persistent_pages"] = (
            total_pages - surplus
            if total_pages is not None and surplus is not None and total_pages >= surplus
            else None
        )
    persistent = sum(p["persistent_pages"] * p["page_size_bytes"] for p in pools) if complete else None
    free = sum(p["free_pages"] * p["page_size_bytes"] for p in pools) if complete else None
    # Hugetlb includes all sizes and surplus pages. HugePages_* cover one size.
    total = info.get("Hugetlb")
    total = total * 1024 if total is not None else None
    size = info.get("Hugepagesize")
    default = {
        "page_size_bytes": size * 1024 if size is not None else None,
        **{key: info.get(key) for key in (
            "HugePages_Total", "HugePages_Free", "HugePages_Rsvd", "HugePages_Surp"
        )},
        "nr_hugepages": number(root / NR),
    }
    if total is None and complete:
        total = sum(p["total_pages"] * p["page_size_bytes"] for p in pools)
    amount = f"{total / 1e9:.6f} GB ({total / GIB:.6f} GiB)" if total is not None else "unknown"
    return {
        "status": "neutral" if total is not None else "unknown",
        "message": f"HugeTLB pool capacity is {amount}; capacity does not affect the score",
        "total_bytes": total, "total_gb": total / 1e9 if total is not None else None,
        "total_gib": total / GIB if total is not None else None,
        "persistent_bytes": persistent, "free_bytes": free,
        "all_sizes_complete": complete, "default": default, "pools": pools,
    }


def allocation_trial(root: Path, *, enabled: bool = False) -> dict:
    result = {"status": "skipped", "requested_bytes": GIB,
              "message": "The allocation test requires --try-allocate on an idle host."}
    if not enabled:
        return result
    if root != Path("/") or os.geteuid() != 0:
        result["message"] = "The allocation test requires root and the real host root."
        return result
    # An exclusive host is an operator prerequisite. This lock excludes only
    # other ClusterMAX trials, not applications or external pool managers.
    try:
        fd = os.open("/run/clustermax-hugepages.lock",
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return _allocation_trial(root)
    except OSError as exc:
        result["message"] = f"The allocation lock is unavailable: {exc}"
        return result


def _allocation_trial(root: Path) -> dict:
    before = meminfo(root)
    original = number(root / NR)
    size = before.get("Hugepagesize", 0) * 1024
    result = {"status": "skipped", "requested_bytes": GIB, "before": before,
              "original_pages": original, "restored": None}
    required = ("HugePages_Total", "HugePages_Free", "HugePages_Rsvd", "HugePages_Surp")
    if original is None or size <= 0 or size > GIB or GIB % size:
        result["message"] = "The default huge-page size cannot represent exactly 1 GiB."
        return result
    if any(key not in before for key in required):
        result["message"] = "The HugeTLB pool counters are incomplete."
        return result
    if (before["HugePages_Total"] != before["HugePages_Free"]
            or before["HugePages_Rsvd"] or before["HugePages_Surp"]
            or before["HugePages_Total"] != original):
        result["message"] = "The default pool is busy, reserved, surplus, or changing."
        return result
    if before.get("MemAvailable", 0) * 1024 < 2 * GIB:
        result["message"] = "The host has less than 2 GiB of available memory."
        return result
    pages = GIB // size
    target = original + pages
    result.update(additional_pages=pages, target_pages=target, page_size_bytes=size)
    previous_handlers = {}

    def interrupted(signum, _frame):
        raise InterruptedError(f"The allocation test received signal {signum}.")

    try:
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            previous_handlers[sig] = signal.signal(sig, interrupted)
        # The proc write has the same count semantics as sysctl -w.
        (root / NR).write_text(f"{target}\n")
        after = meminfo(root)
        observed = number(root / NR)
        result.update(after=after, observed_pages=observed)
        growth = (after.get("HugePages_Total", 0) - before["HugePages_Total"]) * size
        result["allocated_bytes"] = max(0, growth)
        result["status"] = "pass" if observed == target and growth == GIB else "incomplete"
        result["message"] = "The kernel grew the pool by 1 GiB." if result["status"] == "pass" else "The kernel did not supply the full 1 GiB."
    except (OSError, KeyboardInterrupt) as exc:
        result.update(status="error", message=str(exc))
    finally:
        # Ignore termination during cleanup so a second signal does not
        # interrupt restoration. SIGKILL and host loss remain unrecoverable.
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            current = number(root / NR)
            current_info = meminfo(root)
            if (current is None or not original <= current <= target
                    or current_info.get("HugePages_Total") != current_info.get("HugePages_Free")
                    or current_info.get("HugePages_Rsvd") != 0
                    or current_info.get("HugePages_Surp") != 0):
                raise OSError("The pool changed concurrently; automatic shrink is unsafe")
            (root / NR).write_text(f"{original}\n")
            final = meminfo(root)
            result["final"] = final
            result["restored"] = number(root / NR) == original and all(
                final.get(key) == before[key] for key in required
            )
            if not result["restored"]:
                result.update(status="error", message="Pool restoration is incomplete; an operator must inspect the host.")
        except OSError as exc:
            result.update(status="error", restored=False,
                          message=f"Pool restoration failed: {exc}; restore vm.nr_hugepages={original}.")
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
    return result


def collect_host(root: Path, *, try_allocate: bool = False) -> dict:
    return {
        # A Kubernetes check pod has its own UTS namespace, so the host-root
        # procfs reports the pod name. The pod spec passes the node name.
        "host": os.environ.get("NODE_NAME") or read(root / "proc/sys/kernel/hostname") or socket.gethostname(),
        "thp_madvise": thp_report(root),
        "static_hugepages": static_report(root),
        "hugepage_allocation": allocation_trial(root, enabled=try_allocate),
    }


def aggregate(reports: list[dict], errors: list[str]) -> dict:
    result = {}
    for key in ("thp_madvise", "static_hugepages", "hugepage_allocation"):
        hosts = {r["host"]: r[key] for r in reports if "host" in r and key in r}
        statuses = [r["status"] for r in hosts.values()]
        if not hosts or "unknown" in statuses:
            status = "unknown"
        elif key == "thp_madvise":
            status = "pass" if all(s == "pass" for s in statuses) else "neutral"
        elif key == "static_hugepages":
            status = "neutral"
        else:
            status = statuses[0] if len(set(statuses)) == 1 else "incomplete"
        complete = not errors and len(hosts) == len(reports)
        if not complete and hosts and status in {"pass", "neutral"}:
            status = "warning"
        messages = [f"{host}: {r['message']}" for host, r in hosts.items()]
        result[key] = {"status": status, "hosts": hosts, "errors": errors, "coverageComplete": complete,
                       "message": "; ".join(messages + errors) or "No worker reported."}
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-host", action="store_true")
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--harness", default=os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone"))
    parser.add_argument("--try-allocate", action="store_true",
                        help="temporarily grow the default pool by 1 GiB on this idle host")
    args = parser.parse_args(argv)
    if args.try_allocate and (not args.collect_host or args.root != Path("/")):
        parser.error("--try-allocate requires --collect-host and --root /")
    if args.collect_host:
        report = collect_host(args.root, try_allocate=args.try_allocate)
        print(json.dumps(report, sort_keys=True))
        return 1 if args.try_allocate and report["hugepage_allocation"]["status"] != "pass" else 0
    errors = []
    if args.harness in {"slurm", "k8s"}:
        import hbm_memory_exposure as transport
        source = Path(__file__).read_text()
        if args.harness == "slurm":
            reports, errors = transport.run_slurm_check(args.harness, worker_source=source)
            expected = int(os.environ.get("SLURM_NNODES") or "1")
            if len({r.get("host") for r in reports}) != expected:
                errors.append(f"Expected {expected} workers; received {len(reports)} reports.")
        else:
            reports, errors = transport.run_k8s_check(worker_source=source)
        errors = [e.replace("HBM", "huge-page") for e in errors]
    else:
        reports = [collect_host(args.root)]
    print(json.dumps(aggregate(reports, errors), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
