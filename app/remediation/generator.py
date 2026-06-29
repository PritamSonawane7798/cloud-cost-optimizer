"""Remediation script generator.

Takes a list of :class:`Finding` objects produced by the rule engine and
renders an executable bash script (``remediation.sh``) that:

- Dry-runs by default (echoes commands, executes nothing).
- Groups commands by destructiveness (reversible first, destructive second).
- Annotates each command with a rollback note and/or warning where relevant.
- Prints a savings summary at the top and bottom.
- Requires ``--apply`` + interactive confirmation to actually execute.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from app.remediation.base import CommandEntry, DestructivenessLevel
from app.rules.base import Finding, WasteCategory
from app.models.schema import ResourceType

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# WasteCategories whose primary action is reversible (stop / deallocate)
_REVERSIBLE_CATEGORIES = {WasteCategory.IDLE_VM}


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def _classify(finding: Finding) -> DestructivenessLevel:
    if finding.waste_category in _REVERSIBLE_CATEGORIES:
        return DestructivenessLevel.REVERSIBLE
    return DestructivenessLevel.DESTRUCTIVE


def _rollback_note(finding: Finding) -> str | None:
    """Return a human-readable rollback / undo hint, or None if N/A."""
    cat    = finding.waste_category
    rid    = finding.resource_id
    region = finding.region or "us-east-1"
    prov   = finding.provider

    if cat == WasteCategory.IDLE_VM:
        if prov == "aws":
            if finding.resource_type == ResourceType.DATABASE:
                db_id = rid.split(":db:")[-1] if ":db:" in rid else rid
                return (
                    f"aws rds start-db-instance "
                    f"--db-instance-identifier {db_id} --region {region}"
                )
            return f"aws ec2 start-instances --instance-ids {rid} --region {region}"
        return f'az vm start --ids "{rid}"'

    if cat == WasteCategory.UNATTACHED_DISK:
        if prov == "aws":
            return (
                f"Snapshot first (optional safety net): "
                f"aws ec2 create-snapshot --volume-id {rid} "
                f"--description pre-delete-backup --region {region}"
            )
        return (
            f"Snapshot first (optional): az snapshot create "
            f'--name pre-delete-backup --source "{rid}" --resource-group <rg>'
        )

    if cat == WasteCategory.UNUSED_IP:
        return (
            "A new public IP will be assigned on next allocation; "
            "the original address cannot be guaranteed to return."
        )

    if cat == WasteCategory.OLD_SNAPSHOT:
        return (
            "Verify this is NOT the only recovery point for the source "
            "volume before deleting."
        )

    if cat == WasteCategory.IDLE_LOAD_BALANCER:
        return (
            "Update DNS / service discovery entries before recreating "
            "if service needs to be restored."
        )

    if cat == WasteCategory.UNUSED_NAT_GATEWAY:
        return (
            "Deleting removes outbound internet for private subnets. "
            "Provision a replacement NAT before deleting if traffic is expected."
        )

    return None


def _warning(finding: Finding) -> str | None:
    """Return a ⚠ warning string for destructive operations, or None."""
    cat = finding.waste_category

    if cat == WasteCategory.UNATTACHED_DISK:
        return (
            "All data on this disk will be permanently lost. "
            "Confirm the disk is truly unused before proceeding."
        )
    if cat == WasteCategory.OLD_SNAPSHOT:
        return (
            "This may be the only point-in-time recovery for the source volume. "
            "Check for dependent AMIs / images before deleting."
        )
    if cat == WasteCategory.UNUSED_NAT_GATEWAY:
        return (
            "Outbound internet will be disrupted for ALL private-subnet "
            "resources until a replacement NAT is provisioned."
        )
    if cat == WasteCategory.IDLE_LOAD_BALANCER:
        return (
            "DNS entries pointing at this load balancer will break. "
            "Verify downstream dependencies before deleting."
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_entries(findings: list[Finding]) -> list[CommandEntry]:
    """Convert a list of findings into annotated command entries."""
    return [
        CommandEntry(
            finding=f,
            command=f.remediation_hint,
            destructiveness=_classify(f),
            rollback_note=_rollback_note(f),
            warning=_warning(f),
        )
        for f in findings
    ]


def render_script(
    findings: list[Finding],
    generated_at: datetime | None = None,
) -> str:
    """Render the remediation bash script as a string (no side effects)."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc)

    entries      = build_entries(findings)
    reversible   = [e for e in entries if e.destructiveness == DestructivenessLevel.REVERSIBLE]
    destructive  = [e for e in entries if e.destructiveness == DestructivenessLevel.DESTRUCTIVE]
    total_savings = sum(f.estimated_monthly_savings for f in findings)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )
    tmpl = env.get_template("remediation.sh.j2")
    return tmpl.render(
        generated_at=generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        total_commands=len(entries),
        total_savings=total_savings,
        total_savings_fmt="$%.2f" % total_savings,
        reversible_entries=reversible,
        destructive_entries=destructive,
    )


def write_script(
    findings: list[Finding],
    output_path: Path | str = Path("remediation.sh"),
    generated_at: datetime | None = None,
) -> Path:
    """Write the rendered script to *output_path* and make it executable."""
    path    = Path(output_path)
    content = render_script(findings, generated_at=generated_at)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path
