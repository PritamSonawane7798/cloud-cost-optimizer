"""
Detector framework tests.

MOCK_SIGNALS deliberately includes waste signals on prod-tagged resources
so that _should_skip() is the only guard preventing those findings.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from app.ingestion.base import ingest
from app.models.schema import Resource, ResourceType
from app.rules.base import Confidence, Finding, RulesConfig, WasteCategory
from app.rules.idle_lb import IdleLoadBalancerDetector
from app.rules.idle_vm import IdleVMDetector
from app.rules.old_snapshot import OldSnapshotDetector
from app.rules.registry import all_detectors, all_detectors_from_yaml
from app.rules.unattached_disk import UnattachedDiskDetector
from app.rules.unused_ip import UnusedIPDetector
from app.rules.unused_nat import UnusedNATGatewayDetector

SAMPLES = Path(__file__).parent.parent / "data" / "samples"
RULES_YAML = Path(__file__).parent.parent / "rules.yaml"

# ---------------------------------------------------------------------------
# MOCK_SIGNALS
#
# Waste cases from WASTE_MANIFEST.md get explicit waste signals.
# Prod-tagged resources also get waste signals so _should_skip() is the
# genuine gate (not missing signals).
# Healthy resources get signals that confirm they are NOT waste.
# ---------------------------------------------------------------------------
MOCK_SIGNALS: dict[str, dict[str, Any]] = {
    # ── AWS: Unattached EBS (W-AWS-01..04) ─────────────────────────────────
    "vol-0orph0001dead0001": {"disk.is_attached": False},
    "vol-0orph0002dead0002": {"disk.is_attached": False},
    "vol-0orph0003dead0003": {"disk.is_attached": False},
    "vol-0orph0004dead0004": {"disk.is_attached": False},
    # AWS: Healthy attached disks
    "vol-0prod0001a1b2c3d4": {"disk.is_attached": True},
    "vol-0prod0002b2c3d4e5": {"disk.is_attached": True},
    # Prod-tagged with waste signal — must be SKIPPED by skip-tag logic
    "vol-0prod0003c3d4e5f6": {"disk.is_attached": False},

    # ── AWS: Idle EC2 (W-AWS-05..08) ───────────────────────────────────────
    "i-0idle00001dead0001": {"vm.avg_cpu_7d": 1.2, "vm.state": "running"},
    "i-0idle00002dead0002": {"vm.avg_cpu_7d": 0.8, "vm.state": "running"},
    "i-0idle00003dead0003": {"vm.avg_cpu_7d": 1.5, "vm.state": "running"},
    "i-0idle00004dead0004": {"vm.avg_cpu_7d": 0.5, "vm.state": "running"},
    # Healthy VMs
    "i-0web00001a1b2c3d4e": {"vm.avg_cpu_7d": 42.0, "vm.state": "running"},
    "i-0api00001a1b2c3d4f": {"vm.avg_cpu_7d": 35.0, "vm.state": "running"},
    # Prod-tagged with waste signal — must be SKIPPED
    "i-0batch0001aa2bb3cc": {"vm.avg_cpu_7d": 1.0, "vm.state": "running"},

    # ── AWS: Unassociated EIPs (W-AWS-09..12) ──────────────────────────────
    "eipalloc-0dead0001aaaa0001": {"ip.is_associated": False},
    "eipalloc-0dead0002bbbb0002": {"ip.is_associated": False},
    "eipalloc-0dead0003cccc0003": {"ip.is_associated": False},
    "eipalloc-0dead0004dddd0004": {"ip.is_associated": False},
    # Healthy associated EIPs
    "eipalloc-0live0001aaaa0001": {"ip.is_associated": True},
    "eipalloc-0live0002bbbb0002": {"ip.is_associated": True},

    # ── AWS: Old snapshots (W-AWS-13..17) ──────────────────────────────────
    "snap-0old00001dead001": {"snapshot.age_days": 150},
    "snap-0old00002dead002": {"snapshot.age_days": 200},
    "snap-0old00003dead003": {"snapshot.age_days": 130},
    "snap-0old00004dead004": {"snapshot.age_days": 150},
    "snap-0old00005dead005": {"snapshot.age_days": 95},
    # Healthy recent snapshots
    "snap-0rec000025b3c4d5": {"snapshot.age_days": 7},
    "snap-0rec000035c4d5e6": {"snapshot.age_days": 14},
    # Prod-tagged with waste signal — must be SKIPPED
    "snap-0prod00001aa2bb3": {"snapshot.age_days": 200},

    # ── AWS: Idle ALBs (W-AWS-18..19) ──────────────────────────────────────
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef":
        {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/idle-alb-02/1234567890abcdef":
        {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    # Healthy ALB
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb-01/abcdef1234567890":
        {"lb.request_count_7d": 50000, "lb.active_connection_count": 120},

    # ── AWS: Idle RDS (W-AWS-20..21) ───────────────────────────────────────
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-001": {"vm.avg_cpu_7d": 0.3},
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-002": {"vm.avg_cpu_7d": 0.1},
    # Healthy RDS
    "arn:aws:rds:us-east-1:123456789012:db:db-read-001": {"vm.avg_cpu_7d": 28.0},

    # ── Azure: Unattached disks (W-AZ-01..03 + W-AZ-04b) ──────────────────
    # Azure signal lookups use resource_name as fallback
    "disk-orphan-01":          {"disk.is_attached": False},
    "disk-orphan-02":          {"disk.is_attached": False},
    "disk-orphan-03":          {"disk.is_attached": False},
    "vm-deallocated-01-osdisk": {"disk.is_attached": False},
    # Healthy Azure disk
    "vm-prod-linux-01-osdisk": {"disk.is_attached": True},

    # ── Azure: Unused Public IPs (W-AZ-05..07) ─────────────────────────────
    "pip-unused-01": {"ip.is_associated": False},
    "pip-unused-02": {"ip.is_associated": False},
    "pip-unused-03": {"ip.is_associated": False},
    # Healthy PIP
    "pip-prod-linux-01": {"ip.is_associated": True},

    # ── Azure: Old snapshots (W-AZ-08..09) ─────────────────────────────────
    "snap-old-disk-01": {"snapshot.age_days": 180},
    "snap-old-disk-02": {"snapshot.age_days": 120},
    # Healthy snapshot
    "snap-recent-disk-01": {"snapshot.age_days": 30},

    # ── Azure: Idle LBs (W-AZ-10..11) ──────────────────────────────────────
    "lb-dev-idle-01":     {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    "lb-staging-idle-01": {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    # Healthy LB
    "lb-prod-web-01": {"lb.request_count_7d": 10000, "lb.active_connection_count": 50},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def aws_resources() -> list[Resource]:
    return ingest(SAMPLES / "aws_cur_sample.csv")


@pytest.fixture(scope="module")
def azure_resources() -> list[Resource]:
    return ingest(SAMPLES / "azure_cost_sample.csv")


@pytest.fixture(scope="module")
def all_resources(aws_resources, azure_resources) -> list[Resource]:
    return aws_resources + azure_resources


def _found_by(findings: list[Finding], rid: str) -> Finding | None:
    """Return finding whose resource_id OR resource_name matches rid."""
    for f in findings:
        if f.resource_id == rid or f.resource_name == rid:
            return f
    return None


def _assert_found(findings: list[Finding], rid: str) -> Finding:
    f = _found_by(findings, rid)
    assert f is not None, f"{rid!r} was NOT flagged but should be"
    return f


def _assert_not_found(findings: list[Finding], rid: str) -> None:
    f = _found_by(findings, rid)
    assert f is None, f"{rid!r} was flagged but should NOT be"


# ---------------------------------------------------------------------------
# UnattachedDiskDetector
# ---------------------------------------------------------------------------

class TestUnattachedDiskDetector:
    detector = UnattachedDiskDetector()

    @pytest.mark.parametrize("rid", [
        "vol-0orph0001dead0001",
        "vol-0orph0002dead0002",
        "vol-0orph0003dead0003",
        "vol-0orph0004dead0004",
    ])
    def test_catches_aws_orphan_disks(self, aws_resources, rid):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    @pytest.mark.parametrize("rid", [
        "disk-orphan-01",
        "disk-orphan-02",
        "disk-orphan-03",
        "vm-deallocated-01-osdisk",
    ])
    def test_catches_azure_orphan_disks(self, azure_resources, rid):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    def test_skips_prod_tagged_disk_with_waste_signal(self, aws_resources):
        # vol-0prod0003c3d4e5f6 has disk.is_attached=False in MOCK_SIGNALS
        # but tagged env=prod — skip-tag logic must be the guard
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "vol-0prod0003c3d4e5f6")

    def test_skips_do_not_delete_tagged(self):
        resource = Resource(
            resource_id="vol-0donotdelete",
            resource_name="do-not-delete-disk",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.DISK,
            monthly_cost=10.0,
            usage_amount=310.0,
            tags={"do-not-delete": "true", "env": "dev"},
            raw={},
        )
        sigs = {"vol-0donotdelete": {"disk.is_attached": False}}
        findings = self.detector.detect([resource], sigs)
        assert findings == [], "do-not-delete tagged resource must not be flagged"

    def test_does_not_flag_attached_disks(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "vol-0prod0001a1b2c3d4")
        _assert_not_found(findings, "vol-0prod0002b2c3d4e5")

    def test_finding_fields(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "vol-0orph0001dead0001")
        assert f.waste_category == WasteCategory.UNATTACHED_DISK
        assert f.confidence == Confidence.HIGH
        assert f.estimated_monthly_savings > 0
        assert "delete-volume" in f.remediation_hint
        assert "vol-0orph0001dead0001" in f.remediation_hint

    def test_skips_resources_without_signal(self, aws_resources):
        findings = self.detector.detect(aws_resources, signals=None)
        assert findings == []

    def test_azure_remedy_uses_az_cli(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "disk-orphan-01")
        assert f.remediation_hint.startswith("az disk delete")


# ---------------------------------------------------------------------------
# IdleVMDetector
# ---------------------------------------------------------------------------

class TestIdleVMDetector:
    detector = IdleVMDetector()

    @pytest.mark.parametrize("rid", [
        "i-0idle00001dead0001",
        "i-0idle00002dead0002",
        "i-0idle00003dead0003",
        "i-0idle00004dead0004",
    ])
    def test_catches_idle_ec2(self, aws_resources, rid):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    @pytest.mark.parametrize("rid", [
        "arn:aws:rds:us-east-1:123456789012:db:db-idle-001",
        "arn:aws:rds:us-east-1:123456789012:db:db-idle-002",
    ])
    def test_catches_idle_rds(self, aws_resources, rid):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    def test_skips_prod_tagged_vm_with_waste_signal(self, aws_resources):
        # i-0batch0001aa2bb3cc has vm.avg_cpu_7d=1.0 in MOCK_SIGNALS but env=prod
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "i-0batch0001aa2bb3cc")

    def test_does_not_flag_healthy_vms(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "i-0web00001a1b2c3d4e")
        _assert_not_found(findings, "i-0api00001a1b2c3d4f")

    def test_does_not_flag_healthy_rds(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "arn:aws:rds:us-east-1:123456789012:db:db-read-001")

    def test_skips_zero_cost_resources(self):
        resource = Resource(
            resource_id="vm-deallocated-01",
            resource_name="vm-deallocated-01",
            provider="azure",
            service="Compute",
            region="eastus",
            resource_type=ResourceType.VM,
            monthly_cost=0.0,
            usage_amount=0.0,
            tags={"env": "dev"},
            raw={},
        )
        sigs = {"vm-deallocated-01": {"vm.avg_cpu_7d": 0.0, "vm.state": "deallocated"}}
        findings = self.detector.detect([resource], sigs)
        assert findings == [], "zero-cost VM must not emit a $0 finding"

    def test_rds_remedy_uses_stop_db_instance(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "arn:aws:rds:us-east-1:123456789012:db:db-idle-001")
        assert "stop-db-instance" in f.remediation_hint
        assert "db-idle-001" in f.remediation_hint

    def test_finding_fields(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "i-0idle00001dead0001")
        assert f.waste_category == WasteCategory.IDLE_VM
        assert f.confidence == Confidence.HIGH
        assert f.estimated_monthly_savings > 0
        assert "stop-instances" in f.remediation_hint

    def test_skips_resources_without_signal(self, aws_resources):
        findings = self.detector.detect(aws_resources, signals=None)
        assert findings == []


# ---------------------------------------------------------------------------
# UnusedIPDetector
# ---------------------------------------------------------------------------

class TestUnusedIPDetector:
    detector = UnusedIPDetector()

    @pytest.mark.parametrize("rid", [
        "eipalloc-0dead0001aaaa0001",
        "eipalloc-0dead0002bbbb0002",
        "eipalloc-0dead0003cccc0003",
        "eipalloc-0dead0004dddd0004",
    ])
    def test_catches_aws_eips(self, aws_resources, rid):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    @pytest.mark.parametrize("rid", [
        "pip-unused-01",
        "pip-unused-02",
        "pip-unused-03",
    ])
    def test_catches_azure_pips(self, azure_resources, rid):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    def test_does_not_flag_associated_ips(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "eipalloc-0live0001aaaa0001")
        _assert_not_found(findings, "eipalloc-0live0002bbbb0002")

    def test_does_not_flag_associated_azure_pip(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "pip-prod-linux-01")

    def test_finding_fields(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "eipalloc-0dead0001aaaa0001")
        assert f.waste_category == WasteCategory.UNUSED_IP
        assert f.confidence == Confidence.HIGH
        assert f.estimated_monthly_savings > 0
        assert "release-address" in f.remediation_hint

    def test_skips_do_not_delete_tagged(self):
        resource = Resource(
            resource_id="eipalloc-0dnf",
            resource_name="eip-do-not-delete",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.IP,
            monthly_cost=3.72,
            usage_amount=744.0,
            tags={"do-not-delete": "yes"},
            raw={},
        )
        sigs = {"eipalloc-0dnf": {"ip.is_associated": False}}
        findings = self.detector.detect([resource], sigs)
        assert findings == []

    def test_azure_remedy_uses_az_cli(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "pip-unused-01")
        assert "az network public-ip delete" in f.remediation_hint


# ---------------------------------------------------------------------------
# OldSnapshotDetector
# ---------------------------------------------------------------------------

class TestOldSnapshotDetector:
    detector = OldSnapshotDetector()

    @pytest.mark.parametrize("rid", [
        "snap-0old00001dead001",
        "snap-0old00002dead002",
        "snap-0old00003dead003",
        "snap-0old00004dead004",
        "snap-0old00005dead005",
    ])
    def test_catches_old_aws_snapshots(self, aws_resources, rid):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    @pytest.mark.parametrize("rid", [
        "snap-old-disk-01",
        "snap-old-disk-02",
    ])
    def test_catches_old_azure_snapshots(self, azure_resources, rid):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    def test_skips_prod_tagged_snapshot_with_waste_signal(self, aws_resources):
        # snap-0prod00001aa2bb3 has snapshot.age_days=200 in MOCK_SIGNALS but env=prod
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "snap-0prod00001aa2bb3")

    def test_does_not_flag_recent_aws_snapshots(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "snap-0rec000025b3c4d5")
        _assert_not_found(findings, "snap-0rec000035c4d5e6")

    def test_does_not_flag_recent_azure_snapshot(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "snap-recent-disk-01")

    def test_threshold_respected(self):
        resource = Resource(
            resource_id="snap-exactly-90",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.SNAPSHOT,
            monthly_cost=2.0,
            usage_amount=40.0,
            tags={},
            raw={},
        )
        sigs_at_threshold = {"snap-exactly-90": {"snapshot.age_days": 90}}
        sigs_over_threshold = {"snap-exactly-90": {"snapshot.age_days": 91}}
        assert self.detector.detect([resource], sigs_at_threshold) == []
        assert len(self.detector.detect([resource], sigs_over_threshold)) == 1

    def test_finding_fields(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "snap-0old00001dead001")
        assert f.waste_category == WasteCategory.OLD_SNAPSHOT
        assert f.confidence == Confidence.HIGH
        assert f.estimated_monthly_savings > 0
        assert "delete-snapshot" in f.remediation_hint


# ---------------------------------------------------------------------------
# IdleLoadBalancerDetector
# ---------------------------------------------------------------------------

class TestIdleLoadBalancerDetector:
    detector = IdleLoadBalancerDetector()

    @pytest.mark.parametrize("arn", [
        "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef",
        "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/idle-alb-02/1234567890abcdef",
    ])
    def test_catches_idle_aws_albs(self, aws_resources, arn):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_found(findings, arn)

    @pytest.mark.parametrize("rid", [
        "lb-dev-idle-01",
        "lb-staging-idle-01",
    ])
    def test_catches_idle_azure_lbs(self, azure_resources, rid):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_found(findings, rid)

    def test_does_not_flag_active_aws_lb(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        _assert_not_found(
            findings,
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb-01/abcdef1234567890",
        )

    def test_does_not_flag_active_azure_lb(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        _assert_not_found(findings, "lb-prod-web-01")

    def test_high_confidence_when_no_active_connections(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(
            findings,
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef",
        )
        assert f.confidence == Confidence.HIGH

    def test_finding_fields(self, aws_resources):
        findings = self.detector.detect(aws_resources, MOCK_SIGNALS)
        f = _assert_found(
            findings,
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef",
        )
        assert f.waste_category == WasteCategory.IDLE_LOAD_BALANCER
        assert f.estimated_monthly_savings > 0
        assert "delete-load-balancer" in f.remediation_hint

    def test_azure_remedy_uses_az_cli(self, azure_resources):
        findings = self.detector.detect(azure_resources, MOCK_SIGNALS)
        f = _assert_found(findings, "lb-dev-idle-01")
        assert "az network lb delete" in f.remediation_hint


# ---------------------------------------------------------------------------
# UnusedNATGatewayDetector
# ---------------------------------------------------------------------------

class TestUnusedNATGatewayDetector:
    detector = UnusedNATGatewayDetector()

    def test_catches_idle_nat_inline(self):
        """Positive catch via inline fixture — prod-tagged NAT in sample must be skipped."""
        resource = Resource(
            resource_id="nat-0unused001dead0001",
            resource_name="nat-dev-unused-01",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.NAT_GATEWAY,
            monthly_cost=32.40,
            usage_amount=720.0,
            tags={"env": "dev"},
            raw={},
        )
        sigs = {"nat-0unused001dead0001": {"nat.bytes_processed_7d": 0}}
        findings = self.detector.detect([resource], sigs)
        assert len(findings) == 1
        f = findings[0]
        assert f.waste_category == WasteCategory.UNUSED_NAT_GATEWAY
        assert f.confidence == Confidence.HIGH
        assert f.estimated_monthly_savings == pytest.approx(32.40)
        assert "delete-nat-gateway" in f.remediation_hint
        assert "nat-0unused001dead0001" in f.remediation_hint

    def test_skips_prod_nat_from_sample(self, aws_resources):
        """The NAT in the sample is prod-tagged — must never be flagged."""
        sigs_with_nat_waste: dict[str, dict] = dict(MOCK_SIGNALS)
        # Even if someone seeds a waste signal for the prod NAT, skip must hold
        for r in aws_resources:
            if r.resource_type == ResourceType.NAT_GATEWAY:
                sigs_with_nat_waste[r.resource_id] = {"nat.bytes_processed_7d": 0}
        findings = self.detector.detect(aws_resources, sigs_with_nat_waste)
        assert findings == [], "prod-tagged NAT must not be flagged"

    def test_does_not_flag_active_nat(self):
        resource = Resource(
            resource_id="nat-0active001",
            resource_name="nat-prod-main",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.NAT_GATEWAY,
            monthly_cost=32.40,
            usage_amount=720.0,
            tags={"env": "dev"},
            raw={},
        )
        sigs = {"nat-0active001": {"nat.bytes_processed_7d": 5_000_000_000}}
        findings = self.detector.detect([resource], sigs)
        assert findings == []

    def test_skips_resources_without_signal(self):
        resource = Resource(
            resource_id="nat-0nosignal",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.NAT_GATEWAY,
            monthly_cost=32.40,
            usage_amount=720.0,
            tags={},
            raw={},
        )
        findings = self.detector.detect([resource], signals=None)
        assert findings == []

    def test_nat_id_extracted_in_remedy(self):
        resource = Resource(
            resource_id="arn:aws:ec2:us-east-1:123456789012:natgateway/nat-0abc1234def56gh78",
            resource_name="nat-dev-arn",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.NAT_GATEWAY,
            monthly_cost=32.40,
            usage_amount=720.0,
            tags={"env": "dev"},
            raw={},
        )
        sigs = {
            "arn:aws:ec2:us-east-1:123456789012:natgateway/nat-0abc1234def56gh78":
                {"nat.bytes_processed_7d": 0}
        }
        findings = self.detector.detect([resource], sigs)
        assert len(findings) == 1
        assert "nat-0abc1234def56gh78" in findings[0].remediation_hint


# ---------------------------------------------------------------------------
# RulesConfig
# ---------------------------------------------------------------------------

class TestRulesConfig:
    def test_from_yaml_loads_correctly(self):
        cfg = RulesConfig.from_yaml(RULES_YAML)
        assert cfg.snapshot_age_threshold_days == 90
        assert cfg.vm_cpu_threshold_pct == pytest.approx(5.0)
        assert cfg.flag_stopped_vms is True
        assert cfg.lb_request_count_threshold == 0
        assert cfg.nat_bytes_threshold == 0
        assert "env" in cfg.skip_tags
        assert "prod" in cfg.skip_tags["env"]
        assert "do-not-delete" in cfg.skip_tags

    def test_default_config_skips_prod(self):
        resource = Resource(
            resource_id="vol-testprod",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.DISK,
            monthly_cost=10.0,
            usage_amount=310.0,
            tags={"env": "prod"},
            raw={},
        )
        detector = UnattachedDiskDetector()
        sigs = {"vol-testprod": {"disk.is_attached": False}}
        findings = detector.detect([resource], sigs)
        assert findings == []

    def test_custom_snapshot_threshold(self):
        resource = Resource(
            resource_id="snap-custom-threshold",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.SNAPSHOT,
            monthly_cost=2.0,
            usage_amount=40.0,
            tags={},
            raw={},
        )
        # Default threshold is 90 — 60 day old snap should NOT be flagged
        default_sigs = {"snap-custom-threshold": {"snapshot.age_days": 60}}
        assert OldSnapshotDetector().detect([resource], default_sigs) == []

        # Custom threshold 30 — 60 day old snap SHOULD be flagged
        cfg = RulesConfig(snapshot_age_threshold_days=30)
        assert len(OldSnapshotDetector(cfg).detect([resource], default_sigs)) == 1

    def test_custom_skip_tag_prevents_flagging(self):
        resource = Resource(
            resource_id="vol-managed",
            provider="aws",
            service="AmazonEC2",
            region="us-east-1",
            resource_type=ResourceType.DISK,
            monthly_cost=10.0,
            usage_amount=310.0,
            tags={"managed-by": "terraform"},
            raw={},
        )
        cfg = RulesConfig(skip_tags={"managed-by": ["terraform"]})
        sigs = {"vol-managed": {"disk.is_attached": False}}
        findings = UnattachedDiskDetector(cfg).detect([resource], sigs)
        assert findings == []


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_all_detectors_returns_six(self):
        detectors = all_detectors()
        assert len(detectors) == 6

    def test_all_detectors_names_unique(self):
        names = [d.name for d in all_detectors()]
        assert len(names) == len(set(names))

    def test_all_detectors_from_yaml(self):
        detectors = all_detectors_from_yaml(RULES_YAML)
        assert len(detectors) == 6
        cfg = detectors[0].config
        assert cfg.snapshot_age_threshold_days == 90

    def test_all_detectors_have_required_signals(self):
        for d in all_detectors():
            assert isinstance(d.required_signals, list)
            assert len(d.required_signals) >= 1, f"{d.name} must declare at least one required signal"


# ---------------------------------------------------------------------------
# End-to-end: all detectors on full sample set
# ---------------------------------------------------------------------------

class TestEndToEnd:
    """Run every detector on both sample files together."""

    def test_total_findings_count(self, all_resources):
        findings: list[Finding] = []
        for det in all_detectors():
            findings.extend(det.detect(all_resources, MOCK_SIGNALS))

        # We planted 32 waste cases in WASTE_MANIFEST.md
        # (4 AWS disk + 4 EC2 + 4 EIP + 5 snap + 2 ALB + 2 RDS  = 21 AWS
        #  + 4 Az disk + 3 Az PIP + 2 Az snap + 2 Az LB = 11 Azure)
        assert len(findings) == 32, (
            f"Expected 32 total findings across all detectors, got {len(findings)}: "
            + ", ".join(f.resource_id for f in findings)
        )

    def test_no_prod_resources_flagged(self, all_resources):
        prod_ids = {
            "vol-0prod0003c3d4e5f6",
            "snap-0prod00001aa2bb3",
            "i-0batch0001aa2bb3cc",
        }
        findings: list[Finding] = []
        for det in all_detectors():
            findings.extend(det.detect(all_resources, MOCK_SIGNALS))
        flagged_ids = {f.resource_id for f in findings} | {f.resource_name for f in findings}
        overlap = prod_ids & flagged_ids
        assert overlap == set(), f"Prod-tagged resources were flagged: {overlap}"

    def test_no_zero_savings_findings(self, all_resources):
        findings: list[Finding] = []
        for det in all_detectors():
            findings.extend(det.detect(all_resources, MOCK_SIGNALS))
        zero_savings = [f for f in findings if f.estimated_monthly_savings == 0]
        assert zero_savings == [], (
            "Findings with $0 estimated savings: "
            + str([(f.resource_id, f.waste_category) for f in zero_savings])
        )

    def test_all_findings_have_remediation_hint(self, all_resources):
        for det in all_detectors():
            for f in det.detect(all_resources, MOCK_SIGNALS):
                assert f.remediation_hint.strip(), (
                    f"Empty remediation_hint for {f.resource_id}"
                )
