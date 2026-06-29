# Cloud Cost Optimizer & Remediation Engine — Build Plan

## Project Summary
A Python API-first tool that ingests AWS CUR (CSV) and Azure Cost Management
exports (CSV/JSON), normalizes them into a provider-agnostic schema, runs a
pluggable rule engine to flag wasteful resources, and produces exact `aws`/`az`
CLI commands for remediation — dry-run by default.

---

## Phase 0 — Skeleton & Tooling (≈30 min)
**Goal:** Runnable repo, nothing broken.

- [ ] Initialize project structure (see CLAUDE.md §Structure)
- [ ] `requirements.txt` pinned
- [ ] `pyproject.toml` / `setup.cfg` for editable install
- [ ] SQLite DB init via SQLAlchemy (alembic migration for schema evolution)
- [ ] `.env.example` for future AWS/Azure creds
- [ ] `Makefile` targets: `install`, `ingest`, `analyze`, `serve`, `test`
- [ ] Sample data files: `data/samples/aws_cur_sample.csv`, `data/samples/azure_cost_sample.csv`

**Exit criteria:** `make install && python -m app.cli --help` runs without error.

---

## Phase 1 — Ingestion & Normalization (≈1 h)
**Goal:** Both provider exports parsed, validated, stored in common schema.

### 1a — Normalized Schema (Pydantic + SQLAlchemy)
Define `NormalizedRecord` and `ResourceEntry` (see CLAUDE.md §Schema).

### 1b — AWS CUR Parser
- Input: Cost and Usage Report CSV (may be gzipped)
- Key columns: `lineItem/ResourceId`, `lineItem/ProductCode`, `lineItem/UsageType`,
  `lineItem/BlendedCost`, `lineItem/UsageStartDate`, `lineItem/UsageEndDate`,
  `lineItem/UsageAmount`, `product/region`, `bill/PayerAccountId`, resource tags
- Map to `NormalizedRecord`

### 1c — Azure Cost Management Parser
- Input: CSV (`Date,SubscriptionId,ResourceId,ResourceType,ResourceGroupName,
  MeterCategory,MeterSubCategory,Quantity,UnitPrice,Cost,Currency,Tags`)
  or JSON (same fields, array-wrapped)
- Map to `NormalizedRecord`

### 1d — Ingest CLI command
```
python -m app.cli ingest --provider aws --file data/samples/aws_cur_sample.csv
python -m app.cli ingest --provider azure --file data/samples/azure_cost_sample.csv
```

**Exit criteria:** Both sample files parse cleanly; rows appear in SQLite `normalized_records` table.

---

## Phase 2 — Enrichment Layer (≈45 min)
**Goal:** Detectors can declare required signals; enrichment is optional but pluggable.

**Core insight:** Billing data records *cost* but not *state* (e.g., is a disk
attached? what is VM CPU utilization?). Detectors must declare which signals
they need. If a signal is absent, the detector either skips or degrades
gracefully to a cost-only heuristic.

### 2a — `EnrichmentSignal` registry
- Each signal has a `name`, `description`, `provider` scope, and `type`
  (`boolean`, `float`, `datetime`, `string`).
- Signals are stored in `enrichment_signals` table keyed by `(resource_id, signal_name)`.

### 2b — `EnrichmentProvider` ABC
```python
class EnrichmentProvider(ABC):
    @abstractmethod
    def signals_provided(self) -> list[str]: ...
    @abstractmethod
    def enrich(self, resource_ids: list[str]) -> dict[str, dict[str, Any]]: ...
```

### 2c — `MockEnrichmentProvider`
Returns synthetic signals so the full pipeline runs without cloud creds:
- `disk.is_attached` → False for ~30% of disks
- `vm.avg_cpu_7d` → random 1–15% for "idle" VMs
- `ip.is_associated` → False for ~25% of IPs
- `snapshot.age_days` → 90–400 days
- `lb.request_count_7d` → 0 for ~20% of LBs

### 2d — Enrich CLI command
```
python -m app.cli enrich --provider mock
```

**Exit criteria:** `enrichment_signals` table populated; detectors can query signals by resource_id.

---

## Phase 3 — Rule Engine (≈1.5 h)
**Goal:** Pluggable detectors produce `Recommendation` records.

### 3a — `Detector` ABC
```python
class Detector(ABC):
    id: str                          # slug, e.g. "unattached-disk"
    display_name: str
    required_signals: list[str]      # detector skips if ANY missing
    optional_signals: list[str]      # used if present, improves confidence
    providers: list[str]             # ["aws", "azure", "both"]

    @abstractmethod
    def detect(self, resource: NormalizedRecord,
               signals: dict[str, Any]) -> Recommendation | None: ...
```

### 3b — Built-in detectors (one per file under `app/rules/`)

| Detector | Required signal | Heuristic fallback |
|---|---|---|
| `UnattachedDiskDetector` | `disk.is_attached` | cost > $X/mo with no sibling compute |
| `IdleVMDetector` | `vm.avg_cpu_7d` | none — skip without signal |
| `UnusedIPDetector` | `ip.is_associated` | none — skip without signal |
| `OldSnapshotDetector` | `snapshot.age_days` | creation date from billing start |
| `IdleLoadBalancerDetector` | `lb.request_count_7d` | none — skip without signal |

### 3c — `RecommendationRecord`
Stored in `recommendations` table:
- `resource_id`, `detector_id`, `provider`, `region`
- `monthly_cost_usd` (from billing)
- `estimated_savings_usd`
- `confidence` (`high`/`medium`/`low` based on signal availability)
- `status` (`open`/`dismissed`/`remediated`)
- `remediation_command` (pre-rendered CLI string)
- `dry_run_output` (populated after dry-run)
- `created_at`

### 3d — Analyze CLI command
```
python -m app.cli analyze
```

**Exit criteria:** `recommendations` table populated with real $ savings figures and CLI commands.

---

## Phase 4 — Remediation Command Generation (≈45 min)
**Goal:** Each recommendation carries an exact, copy-pasteable CLI command; engine can dry-run it.

### 4a — `RemediationBuilder` ABC
```python
class RemediationBuilder(ABC):
    @abstractmethod
    def build_command(self, rec: RecommendationRecord) -> str: ...
    @abstractmethod
    def dry_run(self, rec: RecommendationRecord) -> DryRunResult: ...
```

### 4b — AWS command builders
- Unattached EBS: `aws ec2 delete-volume --volume-id {id} --region {region}`
- Idle EC2: `aws ec2 stop-instances --instance-ids {id} --region {region}`
- Unused EIP: `aws ec2 release-address --allocation-id {id} --region {region}`
- Old snapshot: `aws ec2 delete-snapshot --snapshot-id {id} --region {region}`
- Idle ELB: `aws elb delete-load-balancer --load-balancer-name {name} --region {region}`

### 4c — Azure command builders
- Unattached disk: `az disk delete --ids {id} --yes`
- Idle VM: `az vm deallocate --ids {id}`
- Unused IP: `az network public-ip delete --ids {id}`
- Old snapshot: `az snapshot delete --ids {id}`
- Idle LB: `az network lb delete --ids {id}`

### 4d — Dry-run execution
The `dry_run` method simulates the command (no subprocess call) and returns:
```json
{ "command": "...", "would_delete": true, "resource_id": "...", "estimated_savings_usd": 42.0 }
```

### 4e — Remediate CLI command
```
python -m app.cli remediate --recommendation-id {id} --dry-run   # default
python -m app.cli remediate --recommendation-id {id} --execute   # real; prompts confirm
```

**Exit criteria:** Every recommendation has a non-empty `remediation_command`; dry-run returns structured JSON.

---

## Phase 5 — FastAPI (≈1 h)
**Goal:** All data surfaces via REST; API is the source of truth for the dashboard.

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/resources` | List normalized records (filter: provider, region, type) |
| `GET` | `/api/v1/resources/{id}` | Single resource + its signals |
| `GET` | `/api/v1/recommendations` | List recs (filter: status, detector, provider) |
| `GET` | `/api/v1/recommendations/summary` | Totals: count, total savings, by detector |
| `POST` | `/api/v1/recommendations/{id}/remediate` | Dry-run (default) or execute |
| `POST` | `/api/v1/recommendations/{id}/dismiss` | Mark dismissed |
| `GET` | `/api/v1/audit` | Audit log of all remediation actions |
| `GET` | `/health` | Liveness check |

### Notes
- No auth in MVP (add API-key header in Phase 6+ if needed)
- All responses are JSON with a consistent envelope: `{data, meta, errors}`
- Pagination via `?page=&page_size=`

**Exit criteria:** `uvicorn app.api.main:app --reload` starts; all endpoints return valid JSON.

---

## Phase 6 — Dashboard (≈45 min)
**Goal:** Single HTML page reads the API and renders savings summary + recommendations table.

- Static `app/static/index.html` served by FastAPI at `/`
- Plain JS (no build step, no npm)
- Sections:
  1. **Summary bar:** Total monthly waste (USD), # open recommendations, by provider
  2. **Recommendations table:** resource_id, type, region, detector, est. savings, confidence, action buttons (Dry-Run / Dismiss)
  3. **Dry-Run modal:** shows the CLI command and JSON output
  4. **Audit log panel:** last 20 actions

**Exit criteria:** Dashboard loads in browser; clicking "Dry-Run" shows the CLI command.

---

## Phase 7 — Tests & Sample Data (≈30 min)
**Goal:** Confidence the core pipeline is correct; no flaky tests.

- `tests/test_ingestion.py` — parse both sample CSVs, assert field counts and normalization
- `tests/test_detectors.py` — unit-test each detector with known signal values
- `tests/test_api.py` — `httpx` integration test hitting live FastAPI (with test DB)
- `data/samples/aws_cur_sample.csv` — 50 rows, mix of EC2/EBS/EIP/snapshot/ELB
- `data/samples/azure_cost_sample.csv` — 50 rows, same resource types

---

## Milestone Summary

| Phase | Deliverable | Est. Time |
|---|---|---|
| 0 | Skeleton, tooling, sample data | 30 min |
| 1 | Ingestion + normalization | 1 h |
| 2 | Enrichment layer + mock provider | 45 min |
| 3 | Rule engine + 5 detectors | 1.5 h |
| 4 | Remediation command generation | 45 min |
| 5 | FastAPI | 1 h |
| 6 | Dashboard | 45 min |
| 7 | Tests + sample data | 30 min |
| **Total** | | **~6.25 h** |

---

## Deferred (post-MVP)
- Real AWS/Azure enrichment via boto3 / azure-sdk
- Background scheduler (APScheduler) for periodic re-analysis
- Auth (API key or OAuth)
- Multi-account / multi-subscription support
- Alerting (email/Slack on new high-confidence recommendations)
- Alembic migrations (use `create_all` for MVP)
