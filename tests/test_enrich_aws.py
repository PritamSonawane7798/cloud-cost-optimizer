"""Unit tests for the real AWS enrichment provider (aws_provider.py).

All boto3 interactions are mocked via a MagicMock session so no real AWS
credentials are required.  The safety invariant under test: when an API call
fails or returns no datapoints, the signal key must be *absent* from the
result — never defaulted to a value that could trigger a "waste" finding.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import app.enrichment.aws_provider as aws_provider
from app.enrichment.aws_provider import (
    _fetch_disk_signals,
    _fetch_ip_signals,
    _fetch_lb_signals,
    _fetch_rds_signals,
    _fetch_snapshot_signals,
    _fetch_vm_signals,
    check_credentials,
    get_signals,
)
from app.models.schema import Resource, ResourceType


# ── helpers ────────────────────────────────────────────────────────────────────


def _resource(
    rid: str,
    rtype: ResourceType,
    *,
    provider: str = "aws",
    region: str = "us-east-1",
    name: str | None = None,
) -> Resource:
    return Resource(
        resource_id=rid,
        provider=provider,
        account_id="123456789012",
        region=region,
        resource_type=rtype,
        service="EC2",
        resource_name=name or rid,
        monthly_cost=10.0,
        usage_amount=720.0,
        tags={},
        raw={},
    )


def _mock_session(ec2_mock: MagicMock, cw_mock: MagicMock) -> MagicMock:
    """Return a MagicMock session whose .client() dispatches to the right mock."""
    sess = MagicMock()
    sess.client.side_effect = lambda svc, **kw: {"ec2": ec2_mock, "cloudwatch": cw_mock}[svc]
    return sess


# ── check_credentials ─────────────────────────────────────────────────────────


class TestCheckCredentials:
    def test_returns_false_when_boto3_not_installed(self):
        with patch.object(aws_provider, "_BOTO3_OK", False):
            ok, msg = check_credentials()
        assert ok is False
        assert "boto3" in msg.lower()

    def test_returns_false_on_no_credentials_error(self):
        from botocore.exceptions import NoCredentialsError

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        with patch("app.enrichment.aws_provider.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_sts
            ok, msg = check_credentials()
        assert ok is False
        assert "credentials" in msg.lower()

    def test_returns_false_on_client_error(self):
        from botocore.exceptions import ClientError

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "bad token"}},
            "GetCallerIdentity",
        )
        with patch("app.enrichment.aws_provider.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_sts
            ok, msg = check_credentials()
        assert ok is False
        assert "InvalidClientTokenId" in msg

    def test_returns_true_and_arn_on_success(self):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Arn": "arn:aws:iam::123456789012:user/test-user"
        }
        with patch("app.enrichment.aws_provider.boto3") as mock_boto3:
            mock_boto3.client.return_value = mock_sts
            ok, msg = check_credentials()
        assert ok is True
        assert "arn:aws:iam" in msg


# ── get_signals top-level ─────────────────────────────────────────────────────


class TestGetSignalsTopLevel:
    def test_raises_without_boto3(self):
        with patch.object(aws_provider, "_BOTO3_OK", False):
            with pytest.raises(RuntimeError, match="boto3"):
                get_signals([])

    def test_skips_azure_resources(self):
        r = _resource("disk-orphan-01", ResourceType.DISK, provider="azure", region="eastus")
        # No real AWS calls should be made; session returns empty
        ec2 = MagicMock()
        cw  = MagicMock()
        sess = _mock_session(ec2, cw)
        result = get_signals([r], session=sess)
        assert result == {}  # Azure resource silently skipped
        ec2.describe_volumes.assert_not_called()

    def test_returns_empty_for_empty_input(self):
        ec2 = MagicMock()
        cw  = MagicMock()
        result = get_signals([], session=_mock_session(ec2, cw))
        assert result == {}


# ── disk signals ──────────────────────────────────────────────────────────────


class TestFetchDiskSignals:
    def test_unattached_volume(self):
        ec2 = MagicMock()
        ec2.describe_volumes.return_value = {
            "Volumes": [{"VolumeId": "vol-001", "Attachments": []}]
        }
        out: dict = {}
        _fetch_disk_signals(ec2, [_resource("vol-001", ResourceType.DISK)], out)
        assert out["vol-001"]["disk.is_attached"] is False

    def test_attached_volume(self):
        ec2 = MagicMock()
        ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-002",
                    "Attachments": [{"State": "attached", "InstanceId": "i-abc"}],
                }
            ]
        }
        out: dict = {}
        _fetch_disk_signals(ec2, [_resource("vol-002", ResourceType.DISK)], out)
        assert out["vol-002"]["disk.is_attached"] is True

    def test_api_error_omits_signal(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()
        ec2.describe_volumes.side_effect = ClientError(
            {"Error": {"Code": "InvalidVolume.NotFound", "Message": "not found"}},
            "DescribeVolumes",
        )
        out: dict = {}
        _fetch_disk_signals(ec2, [_resource("vol-bad", ResourceType.DISK)], out)
        # Safety: signal must be absent, not defaulted
        assert "vol-bad" not in out

    def test_attaching_state_counts_as_unattached(self):
        ec2 = MagicMock()
        ec2.describe_volumes.return_value = {
            "Volumes": [
                {
                    "VolumeId": "vol-003",
                    "Attachments": [{"State": "attaching", "InstanceId": "i-xyz"}],
                }
            ]
        }
        out: dict = {}
        _fetch_disk_signals(ec2, [_resource("vol-003", ResourceType.DISK)], out)
        # "attaching" != "attached" → not considered fully attached
        assert out["vol-003"]["disk.is_attached"] is False


# ── VM signals ────────────────────────────────────────────────────────────────


class TestFetchVMSignals:
    def _cw_response(self, averages: list[float]) -> dict:
        return {
            "Datapoints": [
                {"Average": v, "Timestamp": datetime.now(tz=timezone.utc)}
                for v in averages
            ]
        }

    def test_running_instance_state(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-001", "State": {"Name": "running"}}]}
            ]
        }
        cw = MagicMock()
        cw.get_metric_statistics.return_value = self._cw_response([2.0, 3.0])
        out: dict = {}
        _fetch_vm_signals(ec2, cw, [_resource("i-001", ResourceType.VM)], out)
        assert out["i-001"]["vm.state"] == "running"
        assert abs(out["i-001"]["vm.avg_cpu_7d"] - 2.5) < 0.01

    def test_empty_cloudwatch_datapoints_omits_cpu_signal(self):
        """No CW data → omit vm.avg_cpu_7d rather than fabricate 0.0 (idle risk)."""
        ec2 = MagicMock()
        ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-002", "State": {"Name": "stopped"}}]}
            ]
        }
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        out: dict = {}
        _fetch_vm_signals(ec2, cw, [_resource("i-002", ResourceType.VM)], out)
        assert out["i-002"]["vm.state"] == "stopped"
        assert "vm.avg_cpu_7d" not in out["i-002"]  # omitted, not 0.0

    def test_cloudwatch_error_omits_cpu_signal(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()
        ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-003", "State": {"Name": "running"}}]}
            ]
        }
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetMetricStatistics",
        )
        out: dict = {}
        _fetch_vm_signals(ec2, cw, [_resource("i-003", ResourceType.VM)], out)
        assert out["i-003"]["vm.state"] == "running"
        assert "vm.avg_cpu_7d" not in out["i-003"]

    def test_describe_instances_error_omits_all_vm_signals(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()
        ec2.describe_instances.side_effect = ClientError(
            {"Error": {"Code": "InvalidInstanceID.NotFound", "Message": "not found"}},
            "DescribeInstances",
        )
        cw = MagicMock()
        out: dict = {}
        _fetch_vm_signals(ec2, cw, [_resource("i-bad", ResourceType.VM)], out)
        assert "i-bad" not in out

    def test_cpu_average_over_multiple_datapoints(self):
        ec2 = MagicMock()
        ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-004", "State": {"Name": "running"}}]}
            ]
        }
        cw = MagicMock()
        cw.get_metric_statistics.return_value = self._cw_response([10.0, 20.0, 30.0])
        out: dict = {}
        _fetch_vm_signals(ec2, cw, [_resource("i-004", ResourceType.VM)], out)
        # 14-day average: (10+20+30)/3 = 20.0
        assert abs(out["i-004"]["vm.avg_cpu_7d"] - 20.0) < 0.01


# ── RDS signals ───────────────────────────────────────────────────────────────


class TestFetchRDSSignals:
    def test_rds_cpu_extracted(self):
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {
            "Datapoints": [{"Average": 0.5, "Timestamp": datetime.now(tz=timezone.utc)}]
        }
        out: dict = {}
        arn = "arn:aws:rds:us-east-1:123456789012:db:my-db"
        _fetch_rds_signals(cw, [_resource(arn, ResourceType.DATABASE)], out)
        assert abs(out[arn]["vm.avg_cpu_7d"] - 0.5) < 0.01

    def test_empty_datapoints_omits_signal(self):
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        out: dict = {}
        arn = "arn:aws:rds:us-east-1:123:db:idle-db"
        _fetch_rds_signals(cw, [_resource(arn, ResourceType.DATABASE)], out)
        assert arn not in out  # safety: omit, don't fabricate


# ── IP signals ────────────────────────────────────────────────────────────────


class TestFetchIPSignals:
    def test_unassociated_ip(self):
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = {
            "Addresses": [{"AllocationId": "eipalloc-001"}]
        }
        out: dict = {}
        _fetch_ip_signals(ec2, [_resource("eipalloc-001", ResourceType.IP)], out)
        assert out["eipalloc-001"]["ip.is_associated"] is False

    def test_associated_ip(self):
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = {
            "Addresses": [
                {"AllocationId": "eipalloc-002", "AssociationId": "eipassoc-abc"}
            ]
        }
        out: dict = {}
        _fetch_ip_signals(ec2, [_resource("eipalloc-002", ResourceType.IP)], out)
        assert out["eipalloc-002"]["ip.is_associated"] is True

    def test_api_error_omits_signal(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()
        ec2.describe_addresses.side_effect = ClientError(
            {"Error": {"Code": "InvalidAllocationID.NotFound", "Message": "not found"}},
            "DescribeAddresses",
        )
        out: dict = {}
        _fetch_ip_signals(ec2, [_resource("eipalloc-bad", ResourceType.IP)], out)
        assert "eipalloc-bad" not in out


# ── snapshot signals ──────────────────────────────────────────────────────────


class TestFetchSnapshotSignals:
    def test_age_computed_from_start_time(self):
        ec2 = MagicMock()
        start = datetime.now(tz=timezone.utc) - timedelta(days=120)
        ec2.describe_snapshots.return_value = {
            "Snapshots": [{"SnapshotId": "snap-001", "StartTime": start}]
        }
        out: dict = {}
        _fetch_snapshot_signals(ec2, [_resource("snap-001", ResourceType.SNAPSHOT)], out)
        assert out["snap-001"]["snapshot.age_days"] >= 119  # allow 1-day clock skew

    def test_missing_start_time_omits_signal(self):
        ec2 = MagicMock()
        ec2.describe_snapshots.return_value = {
            "Snapshots": [{"SnapshotId": "snap-002"}]  # no StartTime key
        }
        out: dict = {}
        _fetch_snapshot_signals(ec2, [_resource("snap-002", ResourceType.SNAPSHOT)], out)
        assert "snap-002" not in out

    def test_api_error_omits_signal(self):
        from botocore.exceptions import ClientError

        ec2 = MagicMock()
        ec2.describe_snapshots.side_effect = ClientError(
            {"Error": {"Code": "InvalidSnapshot.NotFound", "Message": "nf"}},
            "DescribeSnapshots",
        )
        out: dict = {}
        _fetch_snapshot_signals(ec2, [_resource("snap-bad", ResourceType.SNAPSHOT)], out)
        assert "snap-bad" not in out


# ── LB signals ────────────────────────────────────────────────────────────────


class TestFetchLBSignals:
    _ARN = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/idle/abc123"

    def test_lb_signals_written_when_fetched(self):
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = [
            {"Datapoints": [{"Sum": 0.0, "Timestamp": datetime.now(tz=timezone.utc)}]},
            {"Datapoints": [{"Average": 0.0, "Timestamp": datetime.now(tz=timezone.utc)}]},
        ]
        out: dict = {}
        _fetch_lb_signals(cw, [_resource(self._ARN, ResourceType.LOAD_BALANCER)], out)
        assert out[self._ARN]["lb.request_count_7d"] == 0
        assert out[self._ARN]["lb.active_connection_count"] == 0

    def test_no_datapoints_means_no_signals(self):
        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": []}
        out: dict = {}
        _fetch_lb_signals(cw, [_resource(self._ARN, ResourceType.LOAD_BALANCER)], out)
        # No datapoints → omit rather than write zeros that look like "idle"
        assert self._ARN not in out

    def test_request_count_api_error_omits_entry(self):
        from botocore.exceptions import ClientError

        cw = MagicMock()
        cw.get_metric_statistics.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}},
            "GetMetricStatistics",
        )
        out: dict = {}
        _fetch_lb_signals(cw, [_resource(self._ARN, ResourceType.LOAD_BALANCER)], out)
        assert self._ARN not in out

    def test_request_count_summed_across_days(self):
        cw = MagicMock()
        cw.get_metric_statistics.side_effect = [
            {
                "Datapoints": [
                    {"Sum": 100.0, "Timestamp": datetime.now(tz=timezone.utc)},
                    {"Sum": 200.0, "Timestamp": datetime.now(tz=timezone.utc)},
                ]
            },
            {"Datapoints": []},  # conn count — no data, omit that key
        ]
        out: dict = {}
        _fetch_lb_signals(cw, [_resource(self._ARN, ResourceType.LOAD_BALANCER)], out)
        assert out[self._ARN]["lb.request_count_7d"] == 300
        assert "lb.active_connection_count" not in out[self._ARN]
