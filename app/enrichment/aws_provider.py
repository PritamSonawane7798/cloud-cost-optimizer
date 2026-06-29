"""Real AWS enrichment provider using boto3.

Used when --enrich is passed to the CLI and AWS credentials are present.

Safety invariant (CLAUDE.md §9.1): on *any* API error or missing datapoint,
the signal key is **omitted** from the result dict — never defaulted to a value
that implies waste (e.g. cpu=0.0 would trigger "idle" and emit a stop command
against a possibly-running instance).  Absent signal → detector's
_has_required_signals() returns False → detector skips → no false finding.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.schema import Resource, ResourceType

log = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    _BOTO3_OK = True
except ImportError:  # pragma: no cover
    _BOTO3_OK = False
    # Sentinel classes so except-clauses below don't NameError at definition time.
    ClientError = Exception       # type: ignore[assignment,misc]
    NoCredentialsError = Exception  # type: ignore[assignment,misc]


# ── credential check ──────────────────────────────────────────────────────────


def check_credentials() -> tuple[bool, str]:
    """Return (True, identity_arn) or (False, human-readable reason)."""
    if not _BOTO3_OK:
        return False, "boto3 is not installed — run: pip install boto3"
    try:
        sts = boto3.client("sts")
        ident = sts.get_caller_identity()
        return True, f"Authenticated as {ident['Arn']}"
    except NoCredentialsError:
        return False, (
            "No AWS credentials found. "
            "Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, "
            "run 'aws configure', or use AWS SSO."
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        return False, (
            f"AWS credential check failed ({code}): "
            f"{exc.response['Error']['Message']}"
        )


# ── public entry point ────────────────────────────────────────────────────────


def get_signals(
    resources: list[Resource],
    session: Any | None = None,
) -> dict[str, dict[str, Any]]:
    """Fetch real-time signals for AWS resources via EC2 / CloudWatch APIs.

    Only AWS resources are processed; Azure resources are silently skipped so
    the caller can merge this result with mock signals for Azure (no Azure SDK).

    Pass a custom *session* (e.g. a MagicMock) to override the default
    boto3.Session(); this is the seam used by unit tests.

    Returns a dict keyed by resource_id.  Keys are absent when we could not
    fetch a signal — callers must not interpret absence as "everything is fine."
    """
    if not _BOTO3_OK:
        raise RuntimeError("boto3 is not installed — run: pip install boto3")

    sess: Any = session if session is not None else boto3.Session()
    result: dict[str, dict[str, Any]] = {}

    by_region: dict[str, list[Resource]] = defaultdict(list)
    for r in resources:
        if r.provider == "aws" and r.region:
            by_region[r.region].append(r)

    for region, rlist in by_region.items():
        _enrich_region(sess, region, rlist, result)

    return result


# ── region-level dispatcher ───────────────────────────────────────────────────


def _enrich_region(
    sess: Any,
    region: str,
    resources: list[Resource],
    out: dict[str, dict[str, Any]],
) -> None:
    ec2 = sess.client("ec2", region_name=region)
    cw  = sess.client("cloudwatch", region_name=region)

    disks = [r for r in resources if r.resource_type == ResourceType.DISK]
    vms   = [r for r in resources if r.resource_type == ResourceType.VM]
    dbs   = [r for r in resources if r.resource_type == ResourceType.DATABASE]
    ips   = [r for r in resources if r.resource_type == ResourceType.IP]
    snaps = [r for r in resources if r.resource_type == ResourceType.SNAPSHOT]
    lbs   = [r for r in resources if r.resource_type == ResourceType.LOAD_BALANCER]

    if disks: _fetch_disk_signals(ec2, disks, out)
    if vms:   _fetch_vm_signals(ec2, cw, vms, out)
    if dbs:   _fetch_rds_signals(cw, dbs, out)
    if ips:   _fetch_ip_signals(ec2, ips, out)
    if snaps: _fetch_snapshot_signals(ec2, snaps, out)
    if lbs:   _fetch_lb_signals(cw, lbs, out)


# ── per-type fetchers ─────────────────────────────────────────────────────────


def _fetch_disk_signals(
    ec2: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    ids = [r.resource_id for r in resources if r.resource_id]
    if not ids:
        return
    try:
        resp = ec2.describe_volumes(VolumeIds=ids)
    except ClientError as exc:
        log.warning("describe_volumes failed: %s", exc)
        return  # omit all signals → detectors skip
    for vol in resp.get("Volumes", []):
        attachments = vol.get("Attachments", [])
        is_attached = bool(attachments) and attachments[0].get("State") == "attached"
        out[vol["VolumeId"]] = {"disk.is_attached": is_attached}


def _fetch_vm_signals(
    ec2: Any, cw: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    ids = [r.resource_id for r in resources if r.resource_id]
    if not ids:
        return
    try:
        resp = ec2.describe_instances(InstanceIds=ids)
    except ClientError as exc:
        log.warning("describe_instances failed: %s", exc)
        return  # omit → detectors skip
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            iid = inst["InstanceId"]
            state = inst.get("State", {}).get("Name", "unknown")
            out.setdefault(iid, {})["vm.state"] = state

    # CloudWatch CPU — 14-day average via daily datapoints (Period=86400).
    # Empty Datapoints means the metric was never published (e.g. stopped
    # instance with no monitoring), NOT that CPU is 0 — so we omit the key.
    # The signal name stays "vm.avg_cpu_7d" to match the detector's required_signals.
    end   = datetime.now(tz=timezone.utc)
    start = end - timedelta(days=14)
    for r in resources:
        iid = r.resource_id
        try:
            cw_resp = cw.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": iid}],
                StartTime=start,
                EndTime=end,
                Period=86400,       # daily granularity; average computed below
                Statistics=["Average"],
            )
        except ClientError as exc:
            log.warning("CloudWatch CPUUtilization for %s failed: %s", iid, exc)
            continue  # omit → detector skips

        dps = cw_resp.get("Datapoints", [])
        if not dps:
            continue  # no metric published — omit rather than fabricate "idle"
        avg_cpu = sum(dp["Average"] for dp in dps) / len(dps)
        out.setdefault(iid, {})["vm.avg_cpu_7d"] = avg_cpu


def _fetch_rds_signals(
    cw: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    """14-day average CPU for RDS instances (uses vm.avg_cpu_7d signal name)."""
    end   = datetime.now(tz=timezone.utc)
    start = end - timedelta(days=14)
    for r in resources:
        # ARN format: arn:aws:rds:<region>:<account>:db:<identifier>
        db_id = r.resource_id.split(":")[-1]
        try:
            resp = cw.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "DBInstanceIdentifier", "Value": db_id}],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=["Average"],
            )
        except ClientError as exc:
            log.warning("CloudWatch RDS CPU for %s failed: %s", r.resource_id, exc)
            continue  # omit → detector skips
        dps = resp.get("Datapoints", [])
        if not dps:
            continue
        avg_cpu = sum(dp["Average"] for dp in dps) / len(dps)
        out[r.resource_id] = {"vm.avg_cpu_7d": avg_cpu}


def _fetch_ip_signals(
    ec2: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    ids = [r.resource_id for r in resources if r.resource_id]
    if not ids:
        return
    try:
        resp = ec2.describe_addresses(AllocationIds=ids)
    except ClientError as exc:
        log.warning("describe_addresses failed: %s", exc)
        return
    for addr in resp.get("Addresses", []):
        alloc_id = addr.get("AllocationId")
        if alloc_id:
            out[alloc_id] = {"ip.is_associated": bool(addr.get("AssociationId"))}


def _fetch_snapshot_signals(
    ec2: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    ids = [r.resource_id for r in resources if r.resource_id]
    if not ids:
        return
    try:
        resp = ec2.describe_snapshots(SnapshotIds=ids)
    except ClientError as exc:
        log.warning("describe_snapshots failed: %s", exc)
        return
    now = datetime.now(tz=timezone.utc)
    for snap in resp.get("Snapshots", []):
        snap_id = snap["SnapshotId"]
        start_time = snap.get("StartTime")
        if start_time is None:
            continue  # can't compute age — omit rather than guess
        out[snap_id] = {"snapshot.age_days": (now - start_time).days}


def _fetch_lb_signals(
    cw: Any, resources: list[Resource], out: dict[str, dict[str, Any]]
) -> None:
    """7-day request count + 1-hour active connections from CloudWatch for ALBs."""
    end    = datetime.now(tz=timezone.utc)
    req_start  = end - timedelta(days=7)
    conn_start = end - timedelta(hours=1)

    for r in resources:
        # CloudWatch ALB dimension is the suffix after 'loadbalancer/'
        arn = r.resource_id
        lb_dim = arn.split("loadbalancer/")[-1] if "loadbalancer/" in arn else arn

        signals: dict[str, Any] = {}

        try:
            req_resp = cw.get_metric_statistics(
                Namespace="AWS/ApplicationELB",
                MetricName="RequestCount",
                Dimensions=[{"Name": "LoadBalancer", "Value": lb_dim}],
                StartTime=req_start,
                EndTime=end,
                Period=86400,       # daily; sum across days below
                Statistics=["Sum"],
            )
            req_dps = req_resp.get("Datapoints", [])
            if req_dps:
                signals["lb.request_count_7d"] = int(sum(dp["Sum"] for dp in req_dps))
        except ClientError as exc:
            log.warning("CloudWatch RequestCount for %s failed: %s", arn, exc)

        try:
            conn_resp = cw.get_metric_statistics(
                Namespace="AWS/ApplicationELB",
                MetricName="ActiveConnectionCount",
                Dimensions=[{"Name": "LoadBalancer", "Value": lb_dim}],
                StartTime=conn_start,
                EndTime=end,
                Period=3600,
                Statistics=["Average"],
            )
            conn_dps = conn_resp.get("Datapoints", [])
            if conn_dps:
                signals["lb.active_connection_count"] = int(
                    conn_dps[0].get("Average", 0)
                )
        except ClientError as exc:
            log.warning("CloudWatch ActiveConnectionCount for %s failed: %s", arn, exc)

        if signals:  # only write entry if we got at least one metric
            out[arn] = signals
