from __future__ import annotations

import csv
import json
import logging
from io import StringIO
from pathlib import Path
from typing import IO, Any

from app.ingestion.base import Parser
from app.models.schema import Resource, ResourceType

logger = logging.getLogger(__name__)


def _derive_resource_type(arm_type: str) -> ResourceType:
    rt = arm_type.lower()

    if rt == "microsoft.compute/virtualmachines":
        return ResourceType.VM
    if rt == "microsoft.compute/disks":
        return ResourceType.DISK
    if rt == "microsoft.compute/snapshots":
        return ResourceType.SNAPSHOT
    if rt == "microsoft.network/publicipaddresses":
        return ResourceType.IP
    if rt == "microsoft.network/loadbalancers":
        return ResourceType.LOAD_BALANCER
    if rt.startswith("microsoft.storage/"):
        return ResourceType.STORAGE
    if any(x in rt for x in ("dbfor", "sql", "postgresql", "mysql",
                              "cosmos", "mariadb", "cache/redis")):
        return ResourceType.DATABASE

    return ResourceType.UNKNOWN


def _parse_tags(raw: Any) -> dict[str, str]:
    """Handle Tags as JSON string, plain dict, or 'key:value;...' string."""
    if isinstance(raw, dict):
        return {str(k).lower(): str(v) for k, v in raw.items() if v is not None}

    if not isinstance(raw, str) or not raw.strip():
        return {}

    # Try JSON first (Azure CSV format encloses in double-quotes)
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return {str(k).lower(): str(v) for k, v in parsed.items()
                    if v is not None}
    except json.JSONDecodeError:
        pass

    # Fallback: "key:value;key2:value2" format
    tags: dict[str, str] = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if ":" in pair:
            k, _, v = pair.partition(":")
            tags[k.strip().lower()] = v.strip()
    return tags


def _map_row(row: dict[str, Any]) -> Resource:
    cost_raw = row.get("CostInBillingCurrency", "") or "0"
    try:
        monthly_cost = float(cost_raw)
    except (ValueError, TypeError):
        raise ValueError(f"Non-numeric cost: {cost_raw!r}")

    qty_raw = row.get("Quantity", "") or "0"
    try:
        usage_amount = float(qty_raw)
    except (ValueError, TypeError):
        usage_amount = 0.0

    arm_type = row.get("ResourceType", "")
    region   = (
        row.get("ResourceLocation")
        or row.get("Location")
        or None
    )
    if region:
        region = region.strip() or None

    tags = _parse_tags(row.get("Tags", ""))

    return Resource(
        resource_id   = row.get("ResourceId", ""),
        resource_name = row.get("ResourceName") or None,
        provider      = "azure",
        account_id    = row.get("SubscriptionId") or None,
        service       = row.get("MeterCategory", ""),
        region        = region,
        resource_type = _derive_resource_type(arm_type),
        monthly_cost  = monthly_cost,
        usage_amount  = usage_amount,
        state         = None,
        tags          = tags,
        raw           = dict(row),
    )


class AzureCostParser(Parser):
    """Parse Azure Cost Management CSV or JSON exports into Resource objects.

    Auto-detects JSON vs CSV when given a file path; also accepts a text
    stream (the caller is responsible for format detection in that case —
    pass the string content via StringIO and the parser tries JSON first,
    then falls back to CSV).
    """

    def parse(self, source: Path | str | IO) -> list[Resource]:
        if hasattr(source, "read"):
            return self._parse_stream_auto(source)

        path = Path(source)
        if path.suffix.lower() == ".json":
            with open(path, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            return self._parse_json_data(data)

        with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
            return self._parse_csv_stream(fh)

    # ── internal helpers ───────────────────────────────────────────────────────

    def _parse_stream_auto(self, stream: IO) -> list[Resource]:
        content = stream.read()
        try:
            data = json.loads(content)
            return self._parse_json_data(data)
        except (json.JSONDecodeError, ValueError):
            return self._parse_csv_stream(StringIO(content))

    def _parse_json_data(self, data: Any) -> list[Resource]:
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            # Our format: {billingPeriod, currency, rows:[...]}
            # Microsoft actual format: {value:[...]}
            rows = data.get("rows") or data.get("value") or []
        else:
            raise ValueError(f"Unexpected JSON root type: {type(data).__name__}")

        resources: list[Resource] = []
        for i, row in enumerate(rows):
            try:
                resources.append(_map_row(row))
            except Exception as exc:
                rid = row.get("ResourceId") or row.get("ResourceName") or "?"
                logger.warning(
                    "Skipping Azure JSON row %d (id=%r): %s", i, rid, exc
                )
        return resources

    def _parse_csv_stream(self, stream: IO) -> list[Resource]:
        reader = csv.DictReader(stream)

        if reader.fieldnames is None:
            logger.warning("AzureCostParser: empty or header-less CSV stream")
            return []

        missing = {"ResourceId", "CostInBillingCurrency"} - set(reader.fieldnames)
        if missing:
            raise ValueError(
                f"Azure Cost CSV is missing required columns: {missing}"
            )

        resources: list[Resource] = []
        for i, row in enumerate(reader):
            try:
                resources.append(_map_row(row))
            except Exception as exc:
                rid = row.get("ResourceId") or row.get("ResourceName") or "?"
                logger.warning(
                    "Skipping Azure CSV row %d (id=%r): %s", i, rid, exc
                )
        return resources
