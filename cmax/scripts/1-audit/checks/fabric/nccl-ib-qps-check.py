#!/usr/bin/env python3
"""Check NCCL InfiniBand queue pairs for a multi-tier Clos fabric."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from platform_config import run_named_check


if __name__ == "__main__":
    harness = os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "slurm")
    print(json.dumps(run_named_check("nccl_ib_qps", harness), sort_keys=True))
