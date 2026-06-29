from __future__ import annotations

import csv
import logging
from io import StringIO
from pathlib import Path
from typing import IO, Any

from app.ingestion.base import Parser
from app.models.schema import Resource, ResourceType

logger = logging.getLogger(__name__)

# Prefix stripped from tag column names
_TAG_PREFIX = "resourceTags/user:"


def _derive_resource_type(product_code: str, usage_type: str) -> ResourceType:
    ut = usage_type.lower()

    if product_code == "AmazonEC2":
        if "boxusage" in ut:
            return ResourceType.VM
        if "ebs:volumeusage" in ut:
            return ResourceType.DISK
        if "snapshotusage" in ut or "ebs:snapshot" in ut:
            return ResourceType.SNAPSHOT
        if "elasticip" in ut:
            return ResourceType.IP
        if "natgateway" in ut:
            return ResourceType.NAT_GATEWAY
        # data-transfer, etc. fall through to UNKNOWN

    if product_code in ("AWSApplicationLoadBalancer", "ElasticLoadBalancing",
                        "AWSElasticLoadBalancing"):
        return ResourceType.LOAD_BALANCER

    if product_code == "AmazonRDS":
        return ResourceType.DATABASE

    if product_code == "AmazonS3":
        return ResourceType.STORAGE

    return ResourceType.UNKNOWN


def _extract_tags(row: dict[str, str]) -> dict[str, str]:
    tags: dict[str, str] = {}
    for col, val in row.items():
        if col.startswith(_TAG_PREFIX) and val:
            key = col[len(_TAG_PREFIX):]
            tags[key] = val
    return tags


def _map_row(row: dict[str, str]) -> Resource:
    cost_raw = row.get("lineItem/UnblendedCost", "") or "0"
    try:
        monthly_cost = float(cost_raw)
    except ValueError:
        raise ValueError(f"Non-numeric cost: {cost_raw!r}")

    usage_raw = row.get("lineItem/UsageAmount", "") or "0"
    try:
        usage_amount = float(usage_raw)
    except ValueError:
        usage_amount = 0.0

    product_code = row.get("lineItem/ProductCode", "")
    usage_type   = row.get("lineItem/UsageType",   "")
    tags         = _extract_tags(row)

    return Resource(
        resource_id   = row.get("lineItem/ResourceId", ""),
        resource_name = tags.get("Name") or None,
        provider      = "aws",
        account_id    = row.get("bill/PayerAccountId") or None,
        service       = product_code,
        region        = row.get("product/region") or None,
        resource_type = _derive_resource_type(product_code, usage_type),
        monthly_cost  = monthly_cost,
        usage_amount  = usage_amount,
        state         = None,
        tags          = tags,
        raw           = dict(row),
    )


class AWSCURParser(Parser):
    """Parse AWS Cost and Usage Report CSV files into Resource objects.

    Accepts a file path, path string, or any readable text stream (StringIO
    works — handy for tests).  Rows that fail to parse are skipped with a
    WARNING log; all parseable rows are returned.
    """

    def parse(self, source: Path | str | IO) -> list[Resource]:
        if hasattr(source, "read"):
            return self._parse_stream(source)
        path = Path(source)
        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            return self._parse_stream(fh)

    def _parse_stream(self, stream: IO) -> list[Resource]:
        resources: list[Resource] = []
        reader = csv.DictReader(stream)

        if reader.fieldnames is None:
            logger.warning("AWSCURParser: empty or header-less stream")
            return resources

        missing = {"lineItem/ResourceId", "lineItem/UnblendedCost"} - set(
            reader.fieldnames
        )
        if missing:
            raise ValueError(
                f"AWS CUR CSV is missing required columns: {missing}"
            )

        for i, row in enumerate(reader):
            try:
                resources.append(_map_row(row))
            except Exception as exc:
                rid = row.get("lineItem/ResourceId", "?")
                logger.warning("Skipping AWS CUR row %d (id=%r): %s", i, rid, exc)

        return resources
