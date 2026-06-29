from __future__ import annotations

from pathlib import Path

from app.rules.base import BaseDetector, RulesConfig
from app.rules.idle_lb import IdleLoadBalancerDetector
from app.rules.idle_vm import IdleVMDetector
from app.rules.old_snapshot import OldSnapshotDetector
from app.rules.unattached_disk import UnattachedDiskDetector
from app.rules.unused_ip import UnusedIPDetector
from app.rules.unused_nat import UnusedNATGatewayDetector


def all_detectors(config: RulesConfig | None = None) -> list[BaseDetector]:
    """Return one instance of every registered detector, sharing the same config."""
    cfg = config or RulesConfig()
    return [
        UnattachedDiskDetector(cfg),
        IdleVMDetector(cfg),
        UnusedIPDetector(cfg),
        OldSnapshotDetector(cfg),
        IdleLoadBalancerDetector(cfg),
        UnusedNATGatewayDetector(cfg),
    ]


def all_detectors_from_yaml(path: Path | str) -> list[BaseDetector]:
    cfg = RulesConfig.from_yaml(path)
    return all_detectors(cfg)
