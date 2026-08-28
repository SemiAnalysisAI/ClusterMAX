#!/usr/bin/env python3
"""Check SMMU command queue virtualization on Arm virtual machines."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from platform_config import run_named_check


if __name__ == "__main__":
    harness = os.environ.get("CLUSTERMAX_AUDIT_HARNESS", "standalone")
    print(
        json.dumps(
            run_named_check("arm_smmu_virtualization", harness),
            sort_keys=True,
        )
    )
