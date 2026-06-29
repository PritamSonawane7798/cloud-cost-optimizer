from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory


class UnattachedDiskDetector(BaseDetector):
    name             = "unattached-disk"
    required_signals = ["disk.is_attached"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for resource in resources:
            if resource.resource_type != ResourceType.DISK:
                continue
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue
            if sigs["disk.is_attached"]:
                continue
            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.UNATTACHED_DISK,
                reason=(
                    f"Disk is unattached and incurring "
                    f"${resource.monthly_cost:.2f}/mo in storage costs"
                ),
                estimated_monthly_savings=resource.monthly_cost,
                confidence=Confidence.HIGH,
                remediation_hint=_remedy(resource),
                tags=resource.tags,
            ))
        return findings


def _remedy(r: Resource) -> str:
    region = r.region or "us-east-1"
    if r.provider == "aws":
        return f"aws ec2 delete-volume --volume-id {r.resource_id} --region {region}"
    return f'az disk delete --ids "{r.resource_id}" --yes'
