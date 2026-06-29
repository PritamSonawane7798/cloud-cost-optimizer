# Cloud Cost Optimizer & Remediation Engine — Architecture Reference

This file is the canonical architecture guide. All implementation decisions must
align with what is documented here. Update this file when a design decision
changes, not after.

---

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI / API Clients                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │ FastAPI (app/api/)
┌───────────────────────────────▼─────────────────────────────────┐
│                         Service Layer                           │
│  IngestService │ EnrichService │ AnalyzeService │ RemediateService│
└───┬───────────────────┬──────────────┬──────────────┬───────────┘
    │                   │              │              │
┌───▼───┐  ┌───────────▼──┐  ┌───────▼──────┐  ┌───▼────────────┐
│Parsers│  │ Enrichment   │  │  Rule Engine │  │ Remediation    │
│AWS CUR│  │ Providers    │  │  (Detectors) │  │ Builders       │
│Azure  │  │ (Mock/Real)  │  │  (pluggable) │  │ (aws/az CLI)   │
└───┬───┘  └───────────┬──┘  └───────┬──────┘  └───┬────────────┘
    │                  │             │              │
┌───▼──────────────────▼─────────────▼──────────────▼────────────┐
│                      SQLite (SQLAlchemy)                        │
│  normalized_records │ enrichment_signals │ recommendations      │
│  audit_log                                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Project Structure

```
assignment2/
├── app/
│   ├── __init__.py
│   ├── cli.py                   # Typer CLI entry point
│   ├── database.py              # SQLAlchemy engine + session factory
│   ├── config.py                # Settings (pydantic-settings, .env)
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   ├── schema.py            # Pydantic models (NormalizedRecord, etc.)
│   │   └── db.py                # SQLAlchemy ORM models
│   │
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── base.py              # Parser ABC
│   │   ├── aws_cur.py           # AWS CUR CSV → NormalizedRecord
│   │   └── azure_cost.py        # Azure CSV/JSON → NormalizedRecord
│   │
│   ├── enrichment/
│   │   ├── __init__.py
│   │   ├── base.py              # EnrichmentProvider ABC + signal registry
│   │   └── mock_provider.py     # MockEnrichmentProvider
│   │
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── base.py              # Detector ABC + Recommendation model
│   │   ├── unattached_disk.py
│   │   ├── idle_vm.py
│   │   ├── unused_ip.py
│   │   ├── old_snapshot.py
│   │   └── idle_lb.py
│   │
│   ├── remediation/
│   │   ├── __init__.py
│   │   ├── base.py              # RemediationBuilder ABC + DryRunResult
│   │   ├── aws_commands.py
│   │   └── azure_commands.py
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── ingest.py
│   │   ├── enrich.py
│   │   ├── analyze.py
│   │   └── remediate.py
│   │
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app + mounts static
│   │   ├── deps.py              # get_db dependency
│   │   └── routes/
│   │       ├── resources.py
│   │       ├── recommendations.py
│   │       └── audit.py
│   │
│   └── static/
│       └── index.html           # Single-page dashboard (vanilla JS)
│
├── tests/
│   ├── conftest.py
│   ├── test_ingestion.py
│   ├── test_detectors.py
│   └── test_api.py
│
├── data/
│   └── samples/
│       ├── aws_cur_sample.csv
│       └── azure_cost_sample.csv
│
├── PLAN.md
├── CLAUDE.md                    # ← this file
├── prompts.md                   # Audit log of every user prompt
├── requirements.txt
├── .env.example
└── Makefile
```

---

## 3. Normalized Schema

### 3.1 The Core Insight

AWS CUR and Azure Cost Management exports describe **billing line items**, not
resource state. A single EBS volume appears once per day in the CUR. The parser
must **aggregate** per-resource and **cannot infer** whether the resource is
currently attached, running, or idle.

**Rule:** Detectors that need state MUST declare `required_signals`. If those
signals are absent, the detector must either skip or degrade to a `low`-
confidence cost-only heuristic. Never guess state from billing data.

### 3.2 NormalizedRecord (Pydantic — used in transit)

```python
class NormalizedRecord(BaseModel):
    # Identity
    resource_id: str              # provider-native ID (e.g. "vol-0abc123")
    provider: Literal["aws", "azure"]
    account_id: str               # AWS account or Azure subscription ID
    region: str                   # normalized to e.g. "us-east-1", "eastus"

    # Classification
    resource_type: ResourceType   # see §3.4
    service: str                  # e.g. "EC2", "Microsoft.Compute/disks"

    # Billing window
    usage_start: date
    usage_end: date
    usage_amount: float
    usage_unit: str               # "Hrs", "GB-Mo", etc.

    # Cost
    cost_usd: float               # always USD; parser converts if needed
    currency_original: str        # original currency from export

    # Context
    resource_name: str | None     # human name from tags or resource metadata
    tags: dict[str, str]          # normalized lowercase keys
    raw: dict[str, Any]           # original row as-parsed (for debugging)
```

### 3.3 DB Models (SQLAlchemy)

**`normalized_records`**
```
id (PK)         INTEGER
resource_id     TEXT NOT NULL
provider        TEXT NOT NULL   -- "aws" | "azure"
account_id      TEXT
region          TEXT
resource_type   TEXT            -- see §3.4
service         TEXT
usage_start     DATE
usage_end       DATE
usage_amount    REAL
usage_unit      TEXT
cost_usd        REAL
currency_original TEXT
resource_name   TEXT
tags            JSON
raw             JSON
ingested_at     DATETIME DEFAULT now
```
Unique index on `(resource_id, usage_start, usage_end, provider)` to prevent
double-ingest.

**`enrichment_signals`**
```
id (PK)         INTEGER
resource_id     TEXT NOT NULL
signal_name     TEXT NOT NULL   -- e.g. "disk.is_attached"
signal_value    JSON            -- any JSON-serializable value
provider        TEXT
enriched_at     DATETIME DEFAULT now
```
Unique index on `(resource_id, signal_name)`. Upsert on conflict.

**`recommendations`**
```
id (PK)         INTEGER
resource_id     TEXT NOT NULL
detector_id     TEXT NOT NULL   -- slug, e.g. "unattached-disk"
provider        TEXT
region          TEXT
resource_type   TEXT
monthly_cost_usd  REAL
estimated_savings_usd REAL
confidence      TEXT            -- "high" | "medium" | "low"
status          TEXT DEFAULT "open"  -- "open" | "dismissed" | "remediated"
remediation_command TEXT        -- exact CLI string
dry_run_output  JSON
created_at      DATETIME DEFAULT now
updated_at      DATETIME
```

**`audit_log`**
```
id (PK)         INTEGER
recommendation_id INTEGER FK
action          TEXT            -- "dry_run" | "execute" | "dismiss"
triggered_by    TEXT            -- "api" | "cli"
command         TEXT
result          JSON
created_at      DATETIME DEFAULT now
```

### 3.4 ResourceType Enum

```python
class ResourceType(str, Enum):
    VM          = "vm"            # EC2 instance / Azure VM
    DISK        = "disk"          # EBS volume / Azure Managed Disk
    SNAPSHOT    = "snapshot"      # EBS snapshot / Azure snapshot
    IP          = "ip"            # Elastic IP / Azure Public IP
    LOAD_BALANCER = "load_balancer"  # ELB/ALB/NLB / Azure LB
    STORAGE     = "storage"       # S3 / Azure Blob (for future)
    UNKNOWN     = "unknown"
```

---

## 4. Provider Field Mappings

### 4.1 AWS CUR → NormalizedRecord

| NormalizedRecord field | CUR column(s) |
|---|---|
| `resource_id` | `lineItem/ResourceId` |
| `account_id` | `bill/PayerAccountId` |
| `region` | `product/region` |
| `service` | `lineItem/ProductCode` |
| `resource_type` | derived from `lineItem/ProductCode` + `lineItem/UsageType` |
| `usage_start` | `lineItem/UsageStartDate` |
| `usage_end` | `lineItem/UsageEndDate` |
| `usage_amount` | `lineItem/UsageAmount` |
| `usage_unit` | `pricing/unit` |
| `cost_usd` | `lineItem/BlendedCost` |
| `currency_original` | `lineItem/CurrencyCode` (always USD in CUR) |
| `resource_name` | `resourceTags/user:Name` |
| `tags` | all `resourceTags/user:*` columns |

**ResourceType derivation for AWS:**
- `ProductCode == "AmazonEC2"` + `UsageType` contains `BoxUsage` → `VM`
- `ProductCode == "AmazonEC2"` + `UsageType` contains `EBS:VolumeUsage` → `DISK`
- `ProductCode == "AmazonEC2"` + `UsageType` contains `EBS:Snapshot` → `SNAPSHOT`
- `ProductCode == "AmazonEC2"` + `UsageType` contains `ElasticIP` → `IP`
- `ProductCode` in `{"ElasticLoadBalancing", "AWSApplicationLoadBalancer"}` → `LOAD_BALANCER`

### 4.2 Azure Cost Management → NormalizedRecord

| NormalizedRecord field | Azure column(s) |
|---|---|
| `resource_id` | `ResourceId` |
| `account_id` | `SubscriptionId` |
| `region` | `ResourceLocation` |
| `service` | `MeterCategory` |
| `resource_type` | derived from `ResourceType` (ARM type string) |
| `usage_start` | `Date` |
| `usage_end` | `Date` (same; daily granularity) |
| `usage_amount` | `Quantity` |
| `usage_unit` | `UnitOfMeasure` |
| `cost_usd` | `CostInBillingCurrency` × exchange_rate (if not USD) |
| `currency_original` | `BillingCurrencyCode` |
| `resource_name` | parsed from `ResourceId` last segment |
| `tags` | `Tags` column (parsed as JSON or `key:value` pairs) |

**ResourceType derivation for Azure:**
- ARM type `Microsoft.Compute/virtualMachines` → `VM`
- ARM type `Microsoft.Compute/disks` → `DISK`
- ARM type `Microsoft.Compute/snapshots` → `SNAPSHOT`
- ARM type `Microsoft.Network/publicIPAddresses` → `IP`
- ARM type `Microsoft.Network/loadBalancers` → `LOAD_BALANCER`

---

## 5. Enrichment Signal Catalog

Signals are the bridge between billing data (cost only) and resource state.
They are stored in `enrichment_signals` and queried by detectors at analysis
time.

| Signal name | Type | Description | Used by |
|---|---|---|---|
| `disk.is_attached` | bool | Disk is attached to a running VM | UnattachedDiskDetector |
| `vm.avg_cpu_7d` | float | Average CPU % over last 7 days | IdleVMDetector |
| `vm.state` | str | "running" / "stopped" / "deallocated" | IdleVMDetector |
| `ip.is_associated` | bool | IP is associated with a resource | UnusedIPDetector |
| `snapshot.age_days` | int | Days since snapshot was created | OldSnapshotDetector |
| `lb.request_count_7d` | int | Total requests in last 7 days | IdleLoadBalancerDetector |
| `lb.active_connection_count` | int | Current active connections | IdleLoadBalancerDetector |

**Mock values** (used when `--provider mock` is passed to `enrich`):
- `disk.is_attached`: 70% True, 30% False (seeded by resource_id hash for reproducibility)
- `vm.avg_cpu_7d`: uniform 1–5% for "idle" resources (lowest cost quartile)
- `ip.is_associated`: 75% True, 25% False
- `snapshot.age_days`: uniform 90–400
- `lb.request_count_7d`: 80% > 1000; 20% = 0

---

## 6. Detector Contract

Every detector MUST implement:

```python
class Detector(ABC):
    id: ClassVar[str]                        # kebab-case slug
    display_name: ClassVar[str]
    required_signals: ClassVar[list[str]]    # detector SKIPS if any missing
    optional_signals: ClassVar[list[str]]    # used if present
    providers: ClassVar[list[str]]           # ["aws"], ["azure"], or ["aws","azure"]

    def can_run(self, available_signals: set[str]) -> bool:
        return all(s in available_signals for s in self.required_signals)

    @abstractmethod
    def detect(
        self,
        resource: NormalizedRecord,
        signals: dict[str, Any],
    ) -> Recommendation | None: ...
```

**Confidence levels:**
- `high`: all required AND optional signals present; threshold clearly exceeded
- `medium`: required signals present; optional signals absent OR threshold borderline
- `low`: required signals absent; detector fell back to cost-only heuristic

---

## 7. Remediation Contract

```python
@dataclass
class DryRunResult:
    command: str
    resource_id: str
    provider: str
    action: str           # "delete" | "stop" | "release" | "deallocate"
    estimated_savings_usd: float
    warning: str | None   # e.g. "snapshot is only recovery point"
    dry_run: bool = True

class RemediationBuilder(ABC):
    provider: ClassVar[str]
    resource_types: ClassVar[list[ResourceType]]

    @abstractmethod
    def build_command(self, rec: RecommendationRecord) -> str: ...

    @abstractmethod
    def dry_run(self, rec: RecommendationRecord) -> DryRunResult: ...
```

**Invariant:** `dry_run` NEVER calls subprocess. It returns the exact command
string plus metadata. Real execution (if ever implemented) is gated behind
`--execute` flag and an interactive confirmation prompt.

---

## 8. API Response Envelope

All API responses use:
```json
{
  "data": <payload>,
  "meta": { "page": 1, "page_size": 50, "total": 120 },
  "errors": []
}
```
Errors return HTTP 4xx/5xx with `data: null` and `errors` populated.

---

## 9. Key Constraints & Non-Negotiables

1. **Billing data ≠ resource state.** Never infer `disk.is_attached` from cost
   alone. Always use enrichment signals; declare them in `required_signals`.

2. **Dry-run by default.** The `POST /recommendations/{id}/remediate` endpoint
   defaults to `dry_run=true`. Execute mode must be explicitly requested.

3. **No real subprocess in MVP.** Remediation builders return strings; they do
   not `subprocess.run(...)` anything.

4. **Reproducible mock data.** Mock enrichment values are seeded from
   `resource_id` so the same resource always gets the same mock signals across
   runs.

5. **Idempotent ingest.** Re-ingesting the same file must not create duplicate
   records (unique constraint + upsert).

6. **No auth in MVP.** Add an API-key middleware only when explicitly requested.

7. **SQLite only in MVP.** No Postgres, no Redis, no external services required
   to run the project.

---

## 10. Dependencies

```
# requirements.txt (actual — updated through Turn 7)
fastapi==0.111.0
uvicorn[standard]==0.29.0
sqlalchemy==2.0.30
pydantic>=2.7
pydantic-settings==2.2.1
typer==0.12.3
click==8.1.8        # pinned; click 8.2+ breaks typer 0.12.3 make_metavar()
httpx==0.27.0
pytest==8.2.0
pytest-asyncio==0.23.6
python-dotenv==1.0.1
pyyaml>=6.0
jinja2>=3.1
rich>=13.0
boto3>=1.34         # optional: real AWS enrichment via --enrich CLI flag
```

**boto3** is now included as an optional dependency (Turn 7). It is used
exclusively by `app/enrichment/aws_provider.py` and only invoked when the user
passes `--enrich` to the CLI.  The tool runs fully without AWS credentials when
`--enrich` is omitted — the mock provider handles all signal generation.

No Azure SDK in MVP. Azure resources use mock signals when `--enrich` is active.

---

## 11. Environment Variables (.env.example)

```
DATABASE_URL=sqlite:///./cloud_cost_optimizer.db
LOG_LEVEL=INFO
# Future real-enrichment (not used in MVP)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AZURE_SUBSCRIPTION_ID=
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=
```
