from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory

_IDLE_TYPES = {ResourceType.VM, ResourceType.DATABASE}
_STOPPED_STATES = {"stopped", "deallocated", "terminated"}


class IdleVMDetector(BaseDetector):
    """Flags VMs and DB instances that are either low-CPU or stopped-but-billing.

    Requires at least one of: vm.avg_cpu_7d (for idle-while-running) or
    vm.state (for stopped-but-still-costing).  Both together give HIGH confidence.
    """
    name             = "idle-vm"
    required_signals = ["vm.avg_cpu_7d"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        threshold = self.config.vm_cpu_threshold_pct

        for resource in resources:
            if resource.resource_type not in _IDLE_TYPES:
                continue
            if resource.monthly_cost == 0:
                continue  # nothing to save — billing already $0
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue

            cpu = float(sigs["vm.avg_cpu_7d"])
            state = str(sigs.get("vm.state", "")).lower()

            if cpu >= threshold and state not in _STOPPED_STATES:
                continue  # healthy

            if state in _STOPPED_STATES:
                reason = (
                    f"Instance is {state} but still incurring "
                    f"${resource.monthly_cost:.2f}/mo"
                )
                confidence = Confidence.HIGH if cpu < threshold else Confidence.MEDIUM
            else:
                reason = (
                    f"Average CPU over 7 days is {cpu:.1f}% "
                    f"(threshold {threshold:.0f}%) — instance appears idle"
                )
                confidence = Confidence.HIGH

            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.IDLE_VM,
                reason=reason,
                estimated_monthly_savings=resource.monthly_cost,
                confidence=confidence,
                remediation_hint=_remedy(resource),
                tags=resource.tags,
            ))
        return findings


def _remedy(r: Resource) -> str:
    region = r.region or "us-east-1"
    if r.provider == "aws":
        if r.resource_type == ResourceType.DATABASE:
            db_id = r.resource_id.split(":db:")[-1] if ":db:" in r.resource_id else r.resource_id
            return f"aws rds stop-db-instance --db-instance-identifier {db_id} --region {region}"
        return f"aws ec2 stop-instances --instance-ids {r.resource_id} --region {region}"
    return f'az vm deallocate --ids "{r.resource_id}"'
