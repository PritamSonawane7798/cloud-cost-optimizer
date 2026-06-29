from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel

from app.models.schema import Resource, ResourceType


class WasteCategory(str, Enum):
    UNATTACHED_DISK  = "unattached_disk"
    IDLE_VM          = "idle_vm"
    UNUSED_IP        = "unused_ip"
    OLD_SNAPSHOT     = "old_snapshot"
    IDLE_LOAD_BALANCER = "idle_load_balancer"
    UNUSED_NAT_GATEWAY = "unused_nat_gateway"


class Confidence(str, Enum):
    HIGH   = "high"
    MEDIUM = "medium"
    LOW    = "low"


class Finding(BaseModel):
    resource_id:               str
    resource_name:             str | None = None
    provider:                  str
    region:                    str | None = None
    resource_type:             ResourceType
    service:                   str | None = None
    waste_category:            WasteCategory
    reason:                    str
    estimated_monthly_savings: float
    confidence:                Confidence
    remediation_hint:          str
    tags:                      dict[str, str] = {}


@dataclass
class RulesConfig:
    """Runtime-configurable thresholds and skip rules.

    Load from rules.yaml via :meth:`from_yaml`, or use the defaults directly.
    """
    skip_tags: dict[str, list[str]] = field(
        default_factory=lambda: {
            "env":           ["prod"],
            "do-not-delete": ["*"],
        }
    )
    snapshot_age_threshold_days: int   = 90
    vm_cpu_threshold_pct:        float = 5.0
    flag_stopped_vms:            bool  = True
    lb_request_count_threshold:  int   = 0
    nat_bytes_threshold:         int   = 0

    @classmethod
    def from_yaml(cls, path: Path | str) -> "RulesConfig":
        import yaml  # optional; only needed when loading from file
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        skip_raw: dict = data.get("skip_tags", {})
        skip_tags: dict[str, list[str]] = {}
        for k, v in skip_raw.items():
            skip_tags[str(k)] = [str(x) for x in v] if isinstance(v, list) else [str(v)]

        dets = data.get("detectors", {})
        snap = dets.get("snapshot", {})
        vm   = dets.get("vm", {})
        lb   = dets.get("load_balancer", {})
        nat  = dets.get("nat_gateway", {})

        return cls(
            skip_tags=skip_tags or {"env": ["prod"], "do-not-delete": ["*"]},
            snapshot_age_threshold_days=int(snap.get("age_threshold_days", 90)),
            vm_cpu_threshold_pct=float(vm.get("cpu_threshold_pct", 5.0)),
            flag_stopped_vms=bool(vm.get("flag_stopped", True)),
            lb_request_count_threshold=int(lb.get("request_count_threshold", 0)),
            nat_bytes_threshold=int(nat.get("bytes_threshold", 0)),
        )


class BaseDetector(ABC):
    """Contract every detector must satisfy."""

    name:             ClassVar[str]
    required_signals: ClassVar[list[str]]

    def __init__(self, config: RulesConfig | None = None) -> None:
        self.config = config or RulesConfig()

    # ── public API ────────────────────────────────────────────────────────────

    @abstractmethod
    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        """Return a Finding for each wasteful resource, or [] if clean."""

    # ── helpers for sub-classes ───────────────────────────────────────────────

    def _should_skip(self, resource: Resource) -> bool:
        """Return True if any skip-tag rule matches this resource."""
        for tag_key, skip_values in self.config.skip_tags.items():
            tag_val = resource.tags.get(tag_key)
            if tag_val is None:
                continue
            lower_val = tag_val.lower()
            if "*" in skip_values or lower_val in [v.lower() for v in skip_values]:
                return True
        return False

    def _get_signals(
        self,
        resource: Resource,
        signals: dict[str, dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Look up signals by resource_id first, then resource_name fallback.

        The fallback supports Azure resources where the resource_id is a long
        ARM path but the signals dict is keyed by the short resource_name.
        """
        if not signals:
            return {}
        result = signals.get(resource.resource_id)
        if result is None and resource.resource_name:
            result = signals.get(resource.resource_name)
        return result or {}

    def _has_required_signals(self, sigs: dict[str, Any]) -> bool:
        return all(s in sigs for s in self.required_signals)
