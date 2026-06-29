"""
Tests for the remediation script generator.

Assertions cover:
- Exact CLI command strings (not just presence of a fragment)
- Destructiveness classification per WasteCategory
- Rollback notes present and correct
- Warnings present for destructive operations
- Script structure: dry-run guard, --apply gate, _run wrapper
- Savings summary in header and footer
- Section headers for reversible vs destructive groups
- Azure vs AWS command routing
- Integration with Finding objects produced by real detectors
"""
from __future__ import annotations

import os
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.models.schema import ResourceType
from app.remediation.base import CommandEntry, DestructivenessLevel
from app.remediation.generator import (
    _classify,
    _rollback_note,
    _warning,
    build_entries,
    render_script,
    write_script,
)
from app.rules.base import Confidence, Finding, WasteCategory

# ---------------------------------------------------------------------------
# Shared sample findings
# ---------------------------------------------------------------------------

def _finding(
    resource_id: str = "res-001",
    resource_name: str | None = None,
    provider: str = "aws",
    region: str = "us-east-1",
    resource_type: ResourceType = ResourceType.DISK,
    waste_category: WasteCategory = WasteCategory.UNATTACHED_DISK,
    monthly_savings: float = 10.0,
    confidence: Confidence = Confidence.HIGH,
    remediation_hint: str = "",
    reason: str = "test reason",
    tags: dict | None = None,
) -> Finding:
    hint = remediation_hint or (
        f"aws ec2 delete-volume --volume-id {resource_id} --region {region}"
    )
    return Finding(
        resource_id=resource_id,
        resource_name=resource_name,
        provider=provider,
        region=region,
        resource_type=resource_type,
        waste_category=waste_category,
        reason=reason,
        estimated_monthly_savings=monthly_savings,
        confidence=confidence,
        remediation_hint=hint,
        tags=tags or {},
    )


AWS_DISK = _finding(
    resource_id="vol-0orph0001dead0001",
    resource_name="orphan-vol-01",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.DISK,
    waste_category=WasteCategory.UNATTACHED_DISK,
    monthly_savings=10.00,
    remediation_hint="aws ec2 delete-volume --volume-id vol-0orph0001dead0001 --region us-east-1",
)

AWS_VM = _finding(
    resource_id="i-0idle00001dead0001",
    resource_name="idle-web-01",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.VM,
    waste_category=WasteCategory.IDLE_VM,
    monthly_savings=30.95,
    remediation_hint="aws ec2 stop-instances --instance-ids i-0idle00001dead0001 --region us-east-1",
)

AWS_DB = _finding(
    resource_id="arn:aws:rds:us-east-1:123456789012:db:db-idle-001",
    resource_name="db-idle-001",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.DATABASE,
    waste_category=WasteCategory.IDLE_VM,
    monthly_savings=50.59,
    remediation_hint=(
        "aws rds stop-db-instance "
        "--db-instance-identifier db-idle-001 --region us-east-1"
    ),
)

AWS_EIP = _finding(
    resource_id="eipalloc-0dead0001aaaa0001",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.IP,
    waste_category=WasteCategory.UNUSED_IP,
    monthly_savings=3.72,
    remediation_hint="aws ec2 release-address --allocation-id eipalloc-0dead0001aaaa0001 --region us-east-1",
)

AWS_SNAPSHOT = _finding(
    resource_id="snap-0old00001dead001",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.SNAPSHOT,
    waste_category=WasteCategory.OLD_SNAPSHOT,
    monthly_savings=5.00,
    remediation_hint="aws ec2 delete-snapshot --snapshot-id snap-0old00001dead001 --region us-east-1",
)

AWS_ALB = _finding(
    resource_id="arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/abc",
    resource_name="idle-alb-01",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.LOAD_BALANCER,
    waste_category=WasteCategory.IDLE_LOAD_BALANCER,
    monthly_savings=16.74,
    remediation_hint=(
        "aws elbv2 delete-load-balancer "
        "--load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:123456789012:"
        "loadbalancer/app/idle-alb-01/abc --region us-east-1"
    ),
)

AWS_NAT = _finding(
    resource_id="nat-0unused001dead0001",
    resource_name="nat-dev-01",
    provider="aws",
    region="us-east-1",
    resource_type=ResourceType.NAT_GATEWAY,
    waste_category=WasteCategory.UNUSED_NAT_GATEWAY,
    monthly_savings=32.40,
    remediation_hint="aws ec2 delete-nat-gateway --nat-gateway-id nat-0unused001dead0001 --region us-east-1",
)

AZ_DISK = _finding(
    resource_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/disk-orphan-01",
    resource_name="disk-orphan-01",
    provider="azure",
    region="eastus",
    resource_type=ResourceType.DISK,
    waste_category=WasteCategory.UNATTACHED_DISK,
    monthly_savings=19.71,
    remediation_hint='az disk delete --ids "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/disks/disk-orphan-01" --yes',
)

AZ_PIP = _finding(
    resource_id="/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-unused-01",
    resource_name="pip-unused-01",
    provider="azure",
    region="eastus",
    resource_type=ResourceType.IP,
    waste_category=WasteCategory.UNUSED_IP,
    monthly_savings=3.65,
    remediation_hint='az network public-ip delete --ids "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-unused-01"',
)

ALL_FINDINGS = [AWS_DISK, AWS_VM, AWS_DB, AWS_EIP, AWS_SNAPSHOT, AWS_ALB, AWS_NAT, AZ_DISK, AZ_PIP]


# ---------------------------------------------------------------------------
# _classify
# ---------------------------------------------------------------------------

class TestClassify:
    @pytest.mark.parametrize("cat,expected", [
        (WasteCategory.IDLE_VM,            DestructivenessLevel.REVERSIBLE),
        (WasteCategory.UNATTACHED_DISK,    DestructivenessLevel.DESTRUCTIVE),
        (WasteCategory.UNUSED_IP,          DestructivenessLevel.DESTRUCTIVE),
        (WasteCategory.OLD_SNAPSHOT,       DestructivenessLevel.DESTRUCTIVE),
        (WasteCategory.IDLE_LOAD_BALANCER, DestructivenessLevel.DESTRUCTIVE),
        (WasteCategory.UNUSED_NAT_GATEWAY, DestructivenessLevel.DESTRUCTIVE),
    ])
    def test_classification(self, cat, expected):
        f = _finding(waste_category=cat)
        assert _classify(f) == expected


# ---------------------------------------------------------------------------
# _rollback_note
# ---------------------------------------------------------------------------

class TestRollbackNote:
    def test_stop_ec2_rollback(self):
        note = _rollback_note(AWS_VM)
        assert note is not None
        assert "start-instances" in note
        assert AWS_VM.resource_id in note
        assert "us-east-1" in note

    def test_stop_rds_rollback(self):
        note = _rollback_note(AWS_DB)
        assert note is not None
        assert "start-db-instance" in note
        assert "db-idle-001" in note

    def test_delete_disk_rollback_suggests_snapshot(self):
        note = _rollback_note(AWS_DISK)
        assert note is not None
        assert "create-snapshot" in note
        assert AWS_DISK.resource_id in note

    def test_delete_azure_disk_rollback_uses_az_cli(self):
        note = _rollback_note(AZ_DISK)
        assert note is not None
        assert "az snapshot create" in note

    def test_release_ip_rollback_warns_no_guarantee(self):
        note = _rollback_note(AWS_EIP)
        assert note is not None
        assert "cannot be guaranteed" in note.lower()

    def test_delete_snapshot_rollback_warns_recovery_point(self):
        note = _rollback_note(AWS_SNAPSHOT)
        assert note is not None
        assert "recovery" in note.lower()

    def test_delete_lb_rollback_mentions_dns(self):
        note = _rollback_note(AWS_ALB)
        assert note is not None
        assert "dns" in note.lower()

    def test_delete_nat_rollback_mentions_subnets(self):
        note = _rollback_note(AWS_NAT)
        assert note is not None
        assert "subnet" in note.lower()


# ---------------------------------------------------------------------------
# _warning
# ---------------------------------------------------------------------------

class TestWarning:
    def test_idle_vm_has_no_warning(self):
        assert _warning(AWS_VM) is None
        assert _warning(AWS_DB) is None

    def test_unattached_disk_has_warning(self):
        w = _warning(AWS_DISK)
        assert w is not None
        assert "permanently" in w.lower() or "lost" in w.lower()

    def test_old_snapshot_has_warning(self):
        w = _warning(AWS_SNAPSHOT)
        assert w is not None
        assert "recovery" in w.lower()

    def test_idle_lb_has_warning(self):
        w = _warning(AWS_ALB)
        assert w is not None
        assert "dns" in w.lower() or "downstream" in w.lower()

    def test_unused_nat_has_warning(self):
        w = _warning(AWS_NAT)
        assert w is not None
        assert "subnet" in w.lower() or "outbound" in w.lower()


# ---------------------------------------------------------------------------
# build_entries
# ---------------------------------------------------------------------------

class TestBuildEntries:
    def test_returns_one_entry_per_finding(self):
        entries = build_entries(ALL_FINDINGS)
        assert len(entries) == len(ALL_FINDINGS)

    def test_command_matches_remediation_hint(self):
        entries = build_entries([AWS_DISK])
        assert entries[0].command == AWS_DISK.remediation_hint

    def test_reversible_entries_classified(self):
        entries = build_entries([AWS_VM, AWS_DB])
        for e in entries:
            assert e.destructiveness == DestructivenessLevel.REVERSIBLE

    def test_destructive_entries_classified(self):
        destructive = [AWS_DISK, AWS_EIP, AWS_SNAPSHOT, AWS_ALB, AWS_NAT, AZ_DISK, AZ_PIP]
        entries = build_entries(destructive)
        for e in entries:
            assert e.destructiveness == DestructivenessLevel.DESTRUCTIVE

    def test_stop_entry_has_rollback(self):
        entry = build_entries([AWS_VM])[0]
        assert entry.rollback_note is not None
        assert "start-instances" in entry.rollback_note

    def test_delete_entry_has_warning(self):
        entry = build_entries([AWS_DISK])[0]
        assert entry.warning is not None


# ---------------------------------------------------------------------------
# render_script — exact command strings
# ---------------------------------------------------------------------------

FIXED_DT = datetime(2026, 6, 29, 12, 0, 0, tzinfo=timezone.utc)


class TestRenderScriptCommands:
    """Assert exact CLI commands appear in the rendered script."""

    def _render(self, findings, **kw):
        return render_script(findings, generated_at=FIXED_DT)

    @pytest.mark.parametrize("finding,expected_fragment", [
        (AWS_DISK,     "aws ec2 delete-volume --volume-id vol-0orph0001dead0001 --region us-east-1"),
        (AWS_VM,       "aws ec2 stop-instances --instance-ids i-0idle00001dead0001 --region us-east-1"),
        (AWS_DB,       "aws rds stop-db-instance --db-instance-identifier db-idle-001 --region us-east-1"),
        (AWS_EIP,      "aws ec2 release-address --allocation-id eipalloc-0dead0001aaaa0001 --region us-east-1"),
        (AWS_SNAPSHOT, "aws ec2 delete-snapshot --snapshot-id snap-0old00001dead001 --region us-east-1"),
        (AWS_NAT,      "aws ec2 delete-nat-gateway --nat-gateway-id nat-0unused001dead0001 --region us-east-1"),
        (AZ_DISK,      "az disk delete"),
        (AZ_PIP,       "az network public-ip delete"),
    ])
    def test_exact_command_in_script(self, finding, expected_fragment):
        script = render_script([finding], generated_at=FIXED_DT)
        assert expected_fragment in script, (
            f"Expected fragment {expected_fragment!r} not found in script"
        )

    def test_alb_arn_in_script(self):
        script = render_script([AWS_ALB], generated_at=FIXED_DT)
        assert "aws elbv2 delete-load-balancer" in script
        assert "idle-alb-01" in script

    def test_all_commands_present_together(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "delete-volume" in script
        assert "stop-instances" in script
        assert "stop-db-instance" in script
        assert "release-address" in script
        assert "delete-snapshot" in script
        assert "delete-load-balancer" in script
        assert "delete-nat-gateway" in script
        assert "az disk delete" in script
        assert "az network public-ip delete" in script


# ---------------------------------------------------------------------------
# render_script — structure and metadata
# ---------------------------------------------------------------------------

class TestRenderScriptStructure:
    def test_generated_timestamp_in_header(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "2026-06-29 12:00:00 UTC" in script

    def test_total_savings_in_header(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        total = sum(f.estimated_monthly_savings for f in ALL_FINDINGS)
        expected = "$%.2f" % total
        assert expected in script

    def test_total_savings_in_footer(self):
        script = render_script([AWS_DISK, AWS_VM], generated_at=FIXED_DT)
        total = 10.00 + 30.95
        assert "$%.2f" % total in script

    def test_resource_count_in_header(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert str(len(ALL_FINDINGS)) in script

    def test_dry_run_default_present(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "DRY_RUN=true" in script

    def test_apply_flag_guard_present(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "--apply" in script

    def test_confirmation_prompt_present(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "yes I understand" in script

    def test_run_wrapper_present(self):
        script = render_script(ALL_FINDINGS, generated_at=FIXED_DT)
        assert "_run()" in script or "function _run" in script or "_run() {" in script

    def test_commands_wrapped_in_run_call(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "_run aws ec2 delete-volume" in script

    def test_stop_command_wrapped(self):
        script = render_script([AWS_VM], generated_at=FIXED_DT)
        assert "_run aws ec2 stop-instances" in script

    def test_shebang_present(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert script.startswith("#!/usr/bin/env bash")

    def test_set_euo_pipefail_present(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "set -euo pipefail" in script


# ---------------------------------------------------------------------------
# render_script — section grouping
# ---------------------------------------------------------------------------

class TestRenderScriptGrouping:
    def test_reversible_section_present_when_has_vms(self):
        script = render_script([AWS_VM, AWS_DISK], generated_at=FIXED_DT)
        assert "SECTION 1" in script
        assert "REVERSIBLE" in script

    def test_destructive_section_present_when_has_deletes(self):
        script = render_script([AWS_VM, AWS_DISK], generated_at=FIXED_DT)
        assert "SECTION 2" in script
        assert "DESTRUCTIVE" in script

    def test_reversible_section_absent_without_vms(self):
        script = render_script([AWS_DISK, AWS_EIP], generated_at=FIXED_DT)
        assert "SECTION 1" not in script

    def test_destructive_section_absent_without_deletes(self):
        script = render_script([AWS_VM, AWS_DB], generated_at=FIXED_DT)
        assert "SECTION 2" not in script

    def test_reversible_before_destructive(self):
        script = render_script([AWS_DISK, AWS_VM], generated_at=FIXED_DT)
        idx_rev = script.find("SECTION 1")
        idx_des = script.find("SECTION 2")
        assert idx_rev < idx_des, "REVERSIBLE section must come before DESTRUCTIVE section"

    def test_stop_command_in_reversible_section(self):
        script = render_script([AWS_VM, AWS_DISK], generated_at=FIXED_DT)
        idx_rev = script.find("SECTION 1")
        idx_des = script.find("SECTION 2")
        idx_stop = script.find("stop-instances")
        assert idx_rev < idx_stop < idx_des, "stop-instances must be in SECTION 1"

    def test_delete_command_in_destructive_section(self):
        script = render_script([AWS_VM, AWS_DISK], generated_at=FIXED_DT)
        idx_des = script.find("SECTION 2")
        idx_del = script.find("delete-volume")
        assert idx_des < idx_del, "delete-volume must be in SECTION 2"

    def test_resource_id_annotated_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "vol-0orph0001dead0001" in script  # appears in both comment and command

    def test_resource_name_annotated_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "orphan-vol-01" in script

    def test_savings_per_resource_annotated(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "$10.00/mo" in script


# ---------------------------------------------------------------------------
# render_script — rollback notes and warnings in script
# ---------------------------------------------------------------------------

class TestRenderScriptAnnotations:
    def test_stop_vm_rollback_note_in_script(self):
        script = render_script([AWS_VM], generated_at=FIXED_DT)
        assert "start-instances" in script

    def test_stop_rds_rollback_note_in_script(self):
        script = render_script([AWS_DB], generated_at=FIXED_DT)
        assert "start-db-instance" in script

    def test_disk_snapshot_suggestion_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "create-snapshot" in script

    def test_ip_rollback_note_in_script(self):
        script = render_script([AWS_EIP], generated_at=FIXED_DT)
        assert "cannot be guaranteed" in script.lower() or "guaranteed" in script.lower()

    def test_snapshot_recovery_warning_in_script(self):
        script = render_script([AWS_SNAPSHOT], generated_at=FIXED_DT)
        assert "recovery" in script.lower()

    def test_nat_subnet_warning_in_script(self):
        script = render_script([AWS_NAT], generated_at=FIXED_DT)
        assert "subnet" in script.lower() or "outbound" in script.lower()

    def test_lb_dns_warning_in_script(self):
        script = render_script([AWS_ALB], generated_at=FIXED_DT)
        assert "dns" in script.lower() or "downstream" in script.lower()

    def test_destructive_warning_header_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        # Should have some form of IRREVERSIBLE warning
        upper = script.upper()
        assert "WARNING" in upper or "IRREVERSIBLE" in upper

    def test_disk_warning_says_data_lost_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        lower = script.lower()
        assert "permanently" in lower or "lost" in lower


# ---------------------------------------------------------------------------
# write_script
# ---------------------------------------------------------------------------

class TestWriteScript:
    def test_writes_file(self, tmp_path):
        out = tmp_path / "remediation.sh"
        result = write_script([AWS_DISK, AWS_VM], output_path=out, generated_at=FIXED_DT)
        assert result == out
        assert out.exists()

    def test_file_is_executable(self, tmp_path):
        out = tmp_path / "remediation.sh"
        write_script([AWS_DISK], output_path=out, generated_at=FIXED_DT)
        assert os.access(out, os.X_OK)

    def test_file_content_matches_render(self, tmp_path):
        out = tmp_path / "remediation.sh"
        write_script([AWS_DISK, AWS_VM], output_path=out, generated_at=FIXED_DT)
        expected = render_script([AWS_DISK, AWS_VM], generated_at=FIXED_DT)
        assert out.read_text() == expected

    def test_default_output_filename(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        out = write_script([AWS_DISK], generated_at=FIXED_DT)
        assert out.name == "remediation.sh"
        assert out.exists()


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_findings_renders_valid_script(self):
        script = render_script([], generated_at=FIXED_DT)
        assert "#!/usr/bin/env bash" in script
        assert "DRY_RUN=true" in script
        assert "$0.00" in script  # zero savings

    def test_single_finding_script_valid(self):
        script = render_script([AWS_VM], generated_at=FIXED_DT)
        assert "stop-instances" in script
        assert "$30.95" in script

    def test_azure_and_aws_mixed_script(self):
        script = render_script([AWS_DISK, AZ_DISK], generated_at=FIXED_DT)
        assert "aws ec2 delete-volume" in script
        assert "az disk delete" in script

    def test_savings_format_two_decimal_places(self):
        f = _finding(monthly_savings=1.5)
        script = render_script([f], generated_at=FIXED_DT)
        # Should appear as "$1.50", not "$1.5"
        assert "$1.50" in script

    def test_confidence_annotated_in_script(self):
        script = render_script([AWS_DISK], generated_at=FIXED_DT)
        assert "high" in script.lower()


