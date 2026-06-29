from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import IO

from app.models.schema import Resource

logger = logging.getLogger(__name__)

_AWS_SENTINEL  = "lineItem/ResourceId"
_AZURE_SENTINEL = "SubscriptionId"


class Parser(ABC):
    @abstractmethod
    def parse(self, source: Path | str | IO) -> list[Resource]:
        """Parse billing data from a file path or file-like object."""


def ingest(path: Path | str) -> list[Resource]:
    """Auto-detect provider + format from *path* and return parsed Resources.

    Detection order:
      1. .json extension → Azure JSON
      2. .csv extension → sniff first line for AWS CUR vs Azure CSV headers
      3. Anything else → ValueError
    """
    from app.ingestion.aws_cur import AWSCURParser
    from app.ingestion.azure_cost import AzureCostParser

    path = Path(path)
    suffix = path.suffix.lower()

    if suffix == ".json":
        logger.debug("Auto-detected: Azure JSON (%s)", path.name)
        return AzureCostParser().parse(path)

    if suffix == ".csv":
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            first_line = fh.readline()

        if _AWS_SENTINEL in first_line:
            logger.debug("Auto-detected: AWS CUR CSV (%s)", path.name)
            return AWSCURParser().parse(path)

        if _AZURE_SENTINEL in first_line:
            logger.debug("Auto-detected: Azure Cost CSV (%s)", path.name)
            return AzureCostParser().parse(path)

        raise ValueError(
            f"Cannot detect provider from CSV headers in {path.name}. "
            f"Expected '{_AWS_SENTINEL}' (AWS) or '{_AZURE_SENTINEL}' (Azure)."
        )

    raise ValueError(
        f"Unsupported file extension '{suffix}' for {path.name}. "
        "Supported: .csv, .json"
    )
