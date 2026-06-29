"""Mock enrichment provider.

Returns deterministic signals for resources in FORCED_SIGNALS (the planted
waste cases from WASTE_MANIFEST.md), and healthy statistical defaults for
everything else — keyed by resource_id hash for reproducibility.
"""
from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType

# Exact signals for every planted waste case.  Keys match either resource_id
# (AWS short IDs) or resource_name (Azure short names — the fallback in
# BaseDetector._get_signals handles the ARM-path → name lookup).
FORCED_SIGNALS: dict[str, dict[str, Any]] = {
    # ── Unattached EBS volumes ───────────────────────────────────────────────
    "vol-0orph0001dead0001": {"disk.is_attached": False},
    "vol-0orph0002dead0002": {"disk.is_attached": False},
    "vol-0orph0003dead0003": {"disk.is_attached": False},
    "vol-0orph0004dead0004": {"disk.is_attached": False},
    # ── Idle EC2 instances ───────────────────────────────────────────────────
    "i-0idle00001dead0001": {"vm.avg_cpu_7d": 1.2, "vm.state": "running"},
    "i-0idle00002dead0002": {"vm.avg_cpu_7d": 0.8, "vm.state": "running"},
    "i-0idle00003dead0003": {"vm.avg_cpu_7d": 1.5, "vm.state": "running"},
    "i-0idle00004dead0004": {"vm.avg_cpu_7d": 0.5, "vm.state": "running"},
    # ── Unassociated Elastic IPs ─────────────────────────────────────────────
    "eipalloc-0dead0001aaaa0001": {"ip.is_associated": False},
    "eipalloc-0dead0002bbbb0002": {"ip.is_associated": False},
    "eipalloc-0dead0003cccc0003": {"ip.is_associated": False},
    "eipalloc-0dead0004dddd0004": {"ip.is_associated": False},
    # ── Old EBS snapshots ────────────────────────────────────────────────────
    "snap-0old00001dead001": {"snapshot.age_days": 150},
    "snap-0old00002dead002": {"snapshot.age_days": 200},
    "snap-0old00003dead003": {"snapshot.age_days": 130},
    "snap-0old00004dead004": {"snapshot.age_days": 150},
    "snap-0old00005dead005": {"snapshot.age_days": 95},
    # ── Idle ALBs ────────────────────────────────────────────────────────────
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef": {
        "lb.request_count_7d": 0,
        "lb.active_connection_count": 0,
    },
    "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/idle-alb-02/1234567890abcdef": {
        "lb.request_count_7d": 0,
        "lb.active_connection_count": 0,
    },
    # ── Idle RDS instances ───────────────────────────────────────────────────
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-001": {"vm.avg_cpu_7d": 0.3},
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-002": {"vm.avg_cpu_7d": 0.1},
    # ── Azure unattached managed disks ───────────────────────────────────────
    "disk-orphan-01": {"disk.is_attached": False},
    "disk-orphan-02": {"disk.is_attached": False},
    "disk-orphan-03": {"disk.is_attached": False},
    "vm-deallocated-01-osdisk": {"disk.is_attached": False},
    # ── Azure unused public IPs ──────────────────────────────────────────────
    "pip-unused-01": {"ip.is_associated": False},
    "pip-unused-02": {"ip.is_associated": False},
    "pip-unused-03": {"ip.is_associated": False},
    # ── Azure old snapshots ──────────────────────────────────────────────────
    "snap-old-disk-01": {"snapshot.age_days": 180},
    "snap-old-disk-02": {"snapshot.age_days": 120},
    # ── Azure idle load balancers ────────────────────────────────────────────
    "lb-dev-idle-01":     {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    "lb-staging-idle-01": {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
}


def _default_signals(resource: Resource) -> dict[str, Any]:
    """Return healthy (non-waste) signals seeded by resource_id hash."""
    seed = abs(hash(resource.resource_id)) % 100
    rt = resource.resource_type
    if rt == ResourceType.DISK:
        return {"disk.is_attached": True}
    if rt in (ResourceType.VM, ResourceType.DATABASE):
        return {"vm.avg_cpu_7d": 20.0 + seed % 60, "vm.state": "running"}
    if rt == ResourceType.IP:
        return {"ip.is_associated": True}
    if rt == ResourceType.SNAPSHOT:
        return {"snapshot.age_days": 14 + seed % 60}  # 14–73 days, below 90 threshold
    if rt == ResourceType.LOAD_BALANCER:
        return {
            "lb.request_count_7d": 1000 + seed * 100,
            "lb.active_connection_count": 10 + seed,
        }
    if rt == ResourceType.NAT_GATEWAY:
        return {"nat.bytes_processed_7d": 1_000_000_000 + seed * 1_000_000}
    return {}


def get_signals(resources: list[Resource]) -> dict[str, dict[str, Any]]:
    """Return a signals dict keyed by resource_id for all given resources.

    Forced signals (from FORCED_SIGNALS) take priority; everything else gets
    healthy statistical defaults so non-waste resources are not flagged.
    """
    result: dict[str, dict[str, Any]] = {}
    for resource in resources:
        sig = FORCED_SIGNALS.get(resource.resource_id)
        if sig is None and resource.resource_name:
            sig = FORCED_SIGNALS.get(resource.resource_name)

        if sig is not None:
            result[resource.resource_id] = dict(sig)
        else:
            default = _default_signals(resource)
            if default:
                result[resource.resource_id] = default
    return result
