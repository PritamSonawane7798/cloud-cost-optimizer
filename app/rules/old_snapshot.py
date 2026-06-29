from __future__ import annotations

from typing import Any

from app.models.schema import Resource, ResourceType
from app.rules.base import BaseDetector, Confidence, Finding, RulesConfig, WasteCategory


class OldSnapshotDetector(BaseDetector):
    name             = "old-snapshot"
    required_signals = ["snapshot.age_days"]

    def detect(
        self,
        resources: list[Resource],
        signals: dict[str, dict[str, Any]] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        threshold = self.config.snapshot_age_threshold_days

        for resource in resources:
            if resource.resource_type != ResourceType.SNAPSHOT:
                continue
            if self._should_skip(resource):
                continue
            sigs = self._get_signals(resource, signals)
            if not self._has_required_signals(sigs):
                continue

            age = int(sigs["snapshot.age_days"])
            if age <= threshold:
                continue

            findings.append(Finding(
                resource_id=resource.resource_id,
                resource_name=resource.resource_name,
                provider=resource.provider,
                region=resource.region,
                resource_type=resource.resource_type,
                service=resource.service,
                waste_category=WasteCategory.OLD_SNAPSHOT,
                reason=(
                    f"Snapshot is {age} days old "
                    f"(threshold {threshold} days) — likely stale"
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
        return f"aws ec2 delete-snapshot --snapshot-id {r.resource_id} --region {region}"
    return f'az snapshot delete --ids "{r.resource_id}"'
