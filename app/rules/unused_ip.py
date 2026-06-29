from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory


class UnusedIPDetector(BaseDetector):
    name             = "unused-ip"
    required_signals = ["ip.is_associated"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for resource in resources:
            if resource.resource_type != ResourceType.IP:
                continue
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue
            if sigs["ip.is_associated"]:
                continue
            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.UNUSED_IP,
                reason=(
                    f"Public IP is unassociated and incurring "
                    f"${resource.monthly_cost:.2f}/mo"
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
        return f"aws ec2 release-address --allocation-id {r.resource_id} --region {region}"
    return f'az network public-ip delete --ids "{r.resource_id}"'
