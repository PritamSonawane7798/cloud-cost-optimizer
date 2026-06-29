from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator


class ResourceType(str, Enum):
    VM            = "vm"
    DISK          = "disk"
    SNAPSHOT      = "snapshot"
    IP            = "ip"
    LOAD_BALANCER = "load_balancer"
    NAT_GATEWAY   = "nat_gateway"
    STORAGE       = "storage"
    DATABASE      = "database"
    UNKNOWN       = "unknown"


class Resource(BaseModel):
    """Provider-agnostic representation of one billable cloud resource."""

    resource_id:   str
    resource_name: str | None = None
    provider:      str                    # "aws" | "azure"
    account_id:    str | None = None      # AWS account ID / Azure subscription ID
    service:       str                    # e.g. "AmazonEC2", "Compute"
    region:        str | None = None
    resource_type: ResourceType
    monthly_cost:  float
    usage_amount:  float
    state:         str | None = None      # always None from ingestion; enrichment fills later
    tags:          dict[str, str] = {}
    raw:           dict[str, Any] = {}

    @field_validator("monthly_cost", "usage_amount", mode="before")
    @classmethod
    def _coerce_float(cls, v: Any) -> float:
        if isinstance(v, (int, float)):
            return float(v)
        try:
            return float(str(v).strip() or "0")
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Cannot coerce {v!r} to float") from exc

    @field_validator("tags", mode="before")
    @classmethod
    def _ensure_str_values(cls, v: Any) -> dict[str, str]:
        if not isinstance(v, dict):
            return {}
        return {str(k): str(val) for k, val in v.items() if val is not None}
