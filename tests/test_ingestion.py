"""
Ingestion-layer tests.

Covers:
  - Row counts for all three sample files
  - Field mapping correctness for AWS CUR and Azure CSV/JSON
  - ResourceType derivation for every type produced in the samples
  - Presence of all waste-case IDs documented in WASTE_MANIFEST.md
  - state == None for every parsed Resource (enrichment responsibility)
  - Tag extraction and normalisation
  - Auto-detection via ingest()
  - Malformed-cost rows are skipped; valid rows are kept (both providers)
"""

from __future__ import annotations

import pytest
from io import StringIO
from pathlib import Path

from app.ingestion.base import ingest
from app.ingestion.aws_cur import AWSCURParser
from app.ingestion.azure_cost import AzureCostParser
from app.models.schema import Resource, ResourceType

SAMPLES = Path(__file__).parent.parent / "data" / "samples"


# ── helpers ────────────────────────────────────────────────────────────────────

def by_id(resources: list[Resource]) -> dict[str, Resource]:
    return {r.resource_id: r for r in resources}


def by_name(resources: list[Resource]) -> dict[str, Resource]:
    return {r.resource_name: r for r in resources if r.resource_name}


# ══════════════════════════════════════════════════════════════════════════════
# Row-count assertions
# ══════════════════════════════════════════════════════════════════════════════

class TestRowCounts:
    def test_aws_cur_row_count(self, aws_csv):
        resources = ingest(aws_csv)
        assert len(resources) == 56, (
            f"Expected 56 AWS rows (all rows kept including empty-id ones), got {len(resources)}"
        )

    def test_azure_csv_row_count(self, azure_csv):
        resources = ingest(azure_csv)
        assert len(resources) == 32

    def test_azure_json_row_count(self, azure_json):
        resources = ingest(azure_json)
        assert len(resources) == 32


# ══════════════════════════════════════════════════════════════════════════════
# Field mapping — AWS CUR
# ══════════════════════════════════════════════════════════════════════════════

class TestAWSFieldMapping:
    @pytest.fixture(scope="class")
    def aws(self, aws_csv):
        return ingest(aws_csv)

    def test_provider_is_aws(self, aws):
        assert all(r.provider == "aws" for r in aws)

    def test_ec2_instance_fields(self, aws):
        r = by_id(aws)["i-0prod0001a1b2c3d4"]
        assert r.resource_type == ResourceType.VM
        assert r.region == "us-east-1"
        assert r.monthly_cost == pytest.approx(71.42)
        assert r.usage_amount == pytest.approx(744.0)
        assert r.service == "AmazonEC2"
        assert r.tags.get("env") == "prod"
        assert r.tags.get("team") == "platform"
        assert r.resource_name == "prod-app-01"
        assert r.account_id == "123456789012"

    def test_ebs_volume_fields(self, aws):
        r = by_id(aws)["vol-0prod0001a1b2c3d4"]
        assert r.resource_type == ResourceType.DISK
        assert r.region == "us-east-1"
        assert r.monthly_cost == pytest.approx(8.0)

    def test_snapshot_fields(self, aws):
        r = by_id(aws)["snap-0rec000015a2b3c4"]
        assert r.resource_type == ResourceType.SNAPSHOT
        assert r.monthly_cost == pytest.approx(5.0)

    def test_eip_fields(self, aws):
        r = by_id(aws)["eipalloc-0a1b2c3d4e5f6789"]
        assert r.resource_type == ResourceType.IP

    def test_alb_fields(self, aws):
        alb_key = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/prod-alb-01/1234567890abcdef"
        r = by_id(aws)[alb_key]
        assert r.resource_type == ResourceType.LOAD_BALANCER

    def test_rds_fields(self, aws):
        rds_key = "arn:aws:rds:us-east-1:123456789012:db:db-prod-001"
        r = by_id(aws)[rds_key]
        assert r.resource_type == ResourceType.DATABASE
        assert r.monthly_cost > 100

    def test_s3_fields(self, aws):
        r = by_id(aws)["arn:aws:s3:::prod-data-archive-112233"]
        assert r.resource_type == ResourceType.STORAGE

    def test_raw_present(self, aws):
        r = by_id(aws)["i-0prod0001a1b2c3d4"]
        assert "lineItem/ResourceId" in r.raw
        assert r.raw["lineItem/ResourceId"] == "i-0prod0001a1b2c3d4"


# ══════════════════════════════════════════════════════════════════════════════
# Waste-case presence — AWS
# ══════════════════════════════════════════════════════════════════════════════

class TestAWSWasteCases:
    WASTE_IDS = [
        # Unattached EBS
        "vol-0orph0001dead0001",
        "vol-0orph0002dead0002",
        "vol-0orph0003dead0003",
        "vol-0orph0004dead0004",
        # Idle EC2
        "i-0idle00001dead0001",
        "i-0idle00002dead0002",
        "i-0idle00003dead0003",
        "i-0idle00004dead0004",
        # Unassociated EIPs
        "eipalloc-0dead0001aaaa0001",
        "eipalloc-0dead0002bbbb0002",
        "eipalloc-0dead0003cccc0003",
        "eipalloc-0dead0004dddd0004",
        # Old snapshots
        "snap-0old00001dead001",
        "snap-0old00002dead002",
        "snap-0old00003dead003",
        "snap-0old00004dead004",
        "snap-0old00005dead005",
        # Idle RDS
        "arn:aws:rds:us-east-1:123456789012:db:db-idle-001",
        "arn:aws:rds:us-east-1:123456789012:db:db-idle-002",
    ]

    @pytest.fixture(scope="class")
    def ids(self, aws_csv):
        return {r.resource_id for r in ingest(aws_csv)}

    @pytest.mark.parametrize("waste_id", WASTE_IDS)
    def test_waste_id_present(self, ids, waste_id):
        assert waste_id in ids, f"Waste resource not found in parsed output: {waste_id}"

    def test_idle_alb_present(self, aws_csv):
        resources = ingest(aws_csv)
        alb_ids = {r.resource_id for r in resources
                   if r.resource_type == ResourceType.LOAD_BALANCER}
        idle_albs = [i for i in alb_ids if "idle-alb" in i]
        assert len(idle_albs) == 2

    def test_prod_protected_resources_present(self, aws_csv):
        """Prod-tagged resources are ingested (detection filter is detector's job)."""
        ids = {r.resource_id for r in ingest(aws_csv)}
        assert "vol-0prod0003c3d4e5f6" in ids
        assert "i-0batch0001aa2bb3cc" in ids


# ══════════════════════════════════════════════════════════════════════════════
# Field mapping — Azure CSV
# ══════════════════════════════════════════════════════════════════════════════

class TestAzureFieldMapping:
    @pytest.fixture(scope="class")
    def azure(self, azure_csv):
        return ingest(azure_csv)

    def test_provider_is_azure(self, azure):
        assert all(r.provider == "azure" for r in azure)

    def test_vm_fields(self, azure):
        r = by_name(azure)["vm-prod-web-01"]
        assert r.resource_type == ResourceType.VM
        assert r.region == "eastus"
        assert r.monthly_cost == pytest.approx(105.12)
        assert r.tags.get("env") == "prod"
        assert r.tags.get("team") == "frontend"
        assert r.account_id is not None

    def test_dev_vm_region(self, azure):
        r = by_name(azure)["vm-dev-build-01"]
        assert r.region == "westus2"

    def test_disk_type(self, azure):
        r = by_name(azure)["disk-orphan-01"]
        assert r.resource_type == ResourceType.DISK

    def test_snapshot_type(self, azure):
        r = by_name(azure)["snap-old-disk-01"]
        assert r.resource_type == ResourceType.SNAPSHOT

    def test_public_ip_type(self, azure):
        r = by_name(azure)["pip-unused-01"]
        assert r.resource_type == ResourceType.IP

    def test_lb_type(self, azure):
        r = by_name(azure)["lb-dev-idle-01"]
        assert r.resource_type == ResourceType.LOAD_BALANCER

    def test_storage_type(self, azure):
        r = by_name(azure)["stproddata01"]
        assert r.resource_type == ResourceType.STORAGE

    def test_database_type(self, azure):
        r = by_name(azure)["db-prod-postgres-01"]
        assert r.resource_type == ResourceType.DATABASE

    def test_resource_id_is_arm_path(self, azure):
        r = by_name(azure)["vm-prod-web-01"]
        assert r.resource_id.startswith("/subscriptions/")
        assert "Microsoft.Compute/virtualMachines" in r.resource_id

    def test_tags_json_parsed(self, azure):
        r = by_name(azure)["vm-prod-web-01"]
        assert isinstance(r.tags, dict)
        assert r.tags.get("managed-by") == "terraform"


# ══════════════════════════════════════════════════════════════════════════════
# Azure JSON == Azure CSV (same resource IDs)
# ══════════════════════════════════════════════════════════════════════════════

class TestAzureJsonMatchesCsv:
    def test_resource_ids_match(self, azure_csv, azure_json):
        csv_ids  = {r.resource_id for r in ingest(azure_csv)}
        json_ids = {r.resource_id for r in ingest(azure_json)}
        assert csv_ids == json_ids

    def test_costs_match(self, azure_csv, azure_json):
        csv_costs  = sorted(r.monthly_cost for r in ingest(azure_csv))
        json_costs = sorted(r.monthly_cost for r in ingest(azure_json))
        assert csv_costs == pytest.approx(json_costs, rel=1e-6)


# ══════════════════════════════════════════════════════════════════════════════
# Invariants across both providers
# ══════════════════════════════════════════════════════════════════════════════

class TestCrossProviderInvariants:
    @pytest.mark.parametrize("path_fixture", ["aws_csv", "azure_csv"])
    def test_state_always_none(self, request, path_fixture):
        path = request.getfixturevalue(path_fixture)
        resources = ingest(path)
        assert all(r.state is None for r in resources), (
            "state must be None after ingestion — enrichment fills it later"
        )

    @pytest.mark.parametrize("path_fixture", ["aws_csv", "azure_csv"])
    def test_tags_is_dict(self, request, path_fixture):
        path = request.getfixturevalue(path_fixture)
        for r in ingest(path):
            assert isinstance(r.tags, dict), f"tags must be dict for {r.resource_id}"

    @pytest.mark.parametrize("path_fixture", ["aws_csv", "azure_csv"])
    def test_monthly_cost_is_float(self, request, path_fixture):
        path = request.getfixturevalue(path_fixture)
        for r in ingest(path):
            assert isinstance(r.monthly_cost, float)

    @pytest.mark.parametrize("path_fixture", ["aws_csv", "azure_csv"])
    def test_resource_type_enum(self, request, path_fixture):
        path = request.getfixturevalue(path_fixture)
        valid = set(ResourceType)
        for r in ingest(path):
            assert r.resource_type in valid


# ══════════════════════════════════════════════════════════════════════════════
# Auto-detection via ingest()
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoDetect:
    def test_detects_aws_csv(self, aws_csv):
        resources = ingest(aws_csv)
        assert all(r.provider == "aws" for r in resources)

    def test_detects_azure_csv(self, azure_csv):
        resources = ingest(azure_csv)
        assert all(r.provider == "azure" for r in resources)

    def test_detects_azure_json(self, azure_json):
        resources = ingest(azure_json)
        assert all(r.provider == "azure" for r in resources)

    def test_unknown_extension_raises(self, tmp_path):
        bad_file = tmp_path / "export.xlsx"
        bad_file.write_text("not a real file")
        with pytest.raises(ValueError, match="Unsupported file extension"):
            ingest(bad_file)

    def test_unknown_csv_headers_raises(self, tmp_path):
        bad_csv = tmp_path / "export.csv"
        bad_csv.write_text("ColA,ColB\nval1,val2\n")
        with pytest.raises(ValueError, match="Cannot detect provider"):
            ingest(bad_csv)


# ══════════════════════════════════════════════════════════════════════════════
# Malformed-row robustness
# ══════════════════════════════════════════════════════════════════════════════

# Minimal valid header row for an inline AWS CUR CSV
_AWS_HDR = (
    "identity/LineItemId,bill/BillingEntity,bill/BillType,bill/PayerAccountId,"
    "bill/BillingPeriodStartDate,bill/BillingPeriodEndDate,"
    "lineItem/UsageAccountId,lineItem/LineItemType,lineItem/UsageStartDate,"
    "lineItem/UsageEndDate,lineItem/ProductCode,lineItem/UsageType,"
    "lineItem/Operation,lineItem/AvailabilityZone,lineItem/ResourceId,"
    "lineItem/UsageAmount,lineItem/UnblendedRate,lineItem/UnblendedCost,"
    "lineItem/BlendedRate,lineItem/BlendedCost,lineItem/LineItemDescription,"
    "lineItem/CurrencyCode,product/ProductName,product/instanceType,"
    "product/region,product/servicecode,resourceTags/user:Name,"
    "resourceTags/user:env,resourceTags/user:team,resourceTags/user:created-by"
)

def _aws_data_row(lid, rid, cost):
    return (
        f"{lid},AWS,Anniversary,111111111111,"
        "2026-05-01T00:00:00Z,2026-06-01T00:00:00Z,"
        "111111111111,Usage,2026-05-01T00:00:00Z,2026-06-01T00:00:00Z,"
        f"AmazonEC2,USE1-BoxUsage:t3.medium,RunInstances,us-east-1a,{rid},"
        f"744,0.0416,{cost},0.0416,{cost},instance,USD,"
        "Amazon Elastic Compute Cloud,t3.medium,us-east-1,AmazonEC2,"
        "my-instance,dev,backend,terraform"
    )


class TestMalformedRows:
    def test_aws_bad_cost_skipped_good_kept(self):
        csv_content = "\n".join([
            _AWS_HDR,
            _aws_data_row("li-1", "i-0good001", "30.95"),   # valid
            _aws_data_row("li-2", "i-0bad0001", "NOT_A_NUMBER"),  # invalid cost
        ])
        parser = AWSCURParser()
        resources = parser.parse(StringIO(csv_content))
        assert len(resources) == 1
        assert resources[0].resource_id == "i-0good001"

    def test_aws_multiple_valid_after_bad(self):
        csv_content = "\n".join([
            _AWS_HDR,
            _aws_data_row("li-1", "i-0aaa0001", "10.00"),
            _aws_data_row("li-2", "i-0bbb0001", "OOPS"),
            _aws_data_row("li-3", "i-0ccc0001", "20.00"),
        ])
        resources = AWSCURParser().parse(StringIO(csv_content))
        assert len(resources) == 2
        ids = {r.resource_id for r in resources}
        assert ids == {"i-0aaa0001", "i-0ccc0001"}

    def test_azure_bad_cost_skipped(self):
        header = (
            "Date,SubscriptionId,ResourceGroupName,ResourceId,ResourceType,"
            "ResourceName,ServiceFamily,MeterCategory,MeterSubCategory,MeterName,"
            "Quantity,UnitOfMeasure,CostInBillingCurrency,BillingCurrencyCode,Tags,ResourceLocation"
        )
        good = (
            "2026-05-01,sub-123,rg-demo,"
            "/subscriptions/sub-123/resourceGroups/rg-demo/providers/"
            "Microsoft.Compute/disks/disk-ok,"
            "Microsoft.Compute/disks,disk-ok,Storage,Storage,,P10,"
            '31,1/Month,19.71,USD,"{}",eastus'
        )
        bad = (
            "2026-05-01,sub-123,rg-demo,"
            "/subscriptions/sub-123/resourceGroups/rg-demo/providers/"
            "Microsoft.Compute/disks/disk-bad,"
            "Microsoft.Compute/disks,disk-bad,Storage,Storage,,P10,"
            '31,1/Month,NOT_MONEY,USD,"{}",eastus'
        )
        csv_content = "\n".join([header, good, bad])
        resources = AzureCostParser().parse(StringIO(csv_content))
        assert len(resources) == 1
        assert "disk-ok" in resources[0].resource_id

    def test_aws_missing_required_column_raises(self):
        bad_header = "ColA,ColB\n"
        with pytest.raises(ValueError, match="missing required columns"):
            AWSCURParser().parse(StringIO(bad_header))

    def test_azure_missing_required_column_raises(self):
        bad_header = "Date,ResourceType\n"
        with pytest.raises(ValueError, match="missing required columns"):
            AzureCostParser().parse(StringIO(bad_header))
