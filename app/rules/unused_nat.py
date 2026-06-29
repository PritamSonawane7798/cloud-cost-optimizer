from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory


class UnusedNATGatewayDetector(BaseDetector):
    name             = "unused-nat-gateway"
    required_signals = ["nat.bytes_processed_7d"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        threshold = self.config.nat_bytes_threshold

        for resource in resources:
            if resource.resource_type != ResourceType.NAT_GATEWAY:
                continue
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue

            bytes_processed = int(sigs["nat.bytes_processed_7d"])
            if bytes_processed > threshold:
                continue

            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.UNUSED_NAT_GATEWAY,
                reason=(
                    f"NAT Gateway processed {bytes_processed} bytes "
                    f"over 7 days — appears unused"
                ),
                estimated_monthly_savings=resource.monthly_cost,
                confidence=Confidence.HIGH,
                remediation_hint=_remedy(resource),
                tags=resource.tags,
            ))
        return findings


def _remedy(r: Resource) -> str:
    region = r.region or "us-east-1"
    nat_id = r.resource_id.split("natgateway/")[-1] if "natgateway/" in r.resource_id else r.resource_id
    if r.provider == "aws":
        return f"aws ec2 delete-nat-gateway --nat-gateway-id {nat_id} --region {region}"
    return f'az network nat gateway delete --ids "{r.resource_id}"'
