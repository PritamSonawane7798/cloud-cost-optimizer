from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory


class IdleLoadBalancerDetector(BaseDetector):
    name             = "idle-load-balancer"
    required_signals = ["lb.request_count_7d"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        threshold = self.config.lb_request_count_threshold

        for resource in resources:
            if resource.resource_type != ResourceType.LOAD_BALANCER:
                continue
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue

            request_count = int(sigs["lb.request_count_7d"])
            if request_count > threshold:
                continue

            active_conns = int(sigs.get("lb.active_connection_count", 0))
            confidence = Confidence.HIGH if active_conns == 0 else Confidence.MEDIUM

            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.IDLE_LOAD_BALANCER,
                reason=(
                    f"Load balancer received {request_count} requests "
                    f"over 7 days — appears idle"
                ),
                estimated_monthly_savings=resource.monthly_cost,
                confidence=confidence,
                remediation_hint=_remedy(resource),
                tags=resource.tags,
            ))
        return findings


def _remedy(r: Resource) -> str:
    region = r.region or "us-east-1"
    if r.provider == "aws":
        return (
            f"aws elbv2 delete-load-balancer "
            f"--load-balancer-arn {r.resource_id} --region {region}"
        )
    return f'az network lb delete --ids "{r.resource_id}"'
