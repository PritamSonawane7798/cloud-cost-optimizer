---
marp: true
theme: gaia
class: invert
paginate: true
style: |
  :root {
    --color-background: #0f172a;
    --color-foreground: #e2e8f0;
  }
  section {
    background: #0f172a;
    color: #e2e8f0;
    font-family: "Inter", "Segoe UI", sans-serif;
  }
  h1 { color: #38bdf8; }
  h2 { color: #7dd3fc; }
  h3 { color: #a5f3fc; }
  strong { color: #38bdf8; }
  em { color: #94a3b8; font-style: normal; }
  a { color: #38bdf8; }
  code {
    background: #1e293b;
    color: #a5f3fc;
    border-radius: 4px;
    padding: 0.1em 0.35em;
    font-size: 0.9em;
  }
  pre {
    background: #1e293b !important;
    border-left: 4px solid #38bdf8;
    border-radius: 6px;
    font-size: 0.72em;
    line-height: 1.5;
  }
  pre code {
    background: transparent;
    padding: 0;
    color: #e2e8f0;
  }
  table {
    font-size: 0.82em;
    border-collapse: collapse;
    width: 100%;
  }
  th { background: #1e293b; color: #38bdf8; padding: 0.4em 0.8em; }
  td { padding: 0.35em 0.8em; border-bottom: 1px solid #334155; }
  ul li { margin: 0.3em 0; }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2.5rem;
    align-items: start;
  }
  .tag {
    display: inline-block;
    background: #1e3a5f;
    color: #38bdf8;
    border: 1px solid #38bdf8;
    border-radius: 4px;
    padding: 0.05em 0.4em;
    font-size: 0.78em;
    margin: 0.1em;
  }
  section.title-slide h1 { font-size: 2.4em; margin-bottom: 0.15em; }
  section.title-slide p  { color: #94a3b8; }
  section.lead { text-align: center; }
---

<!-- _class: title-slide -->

# Cloud Cost Optimizer
## & Remediation Engine

Detect orphaned cloud resources. Generate safe remediation scripts. Ship nothing without review.

<br>

**Pritam Sonawane** · *Cloud FinOps Tool · Python / CLI*

---

## The Problem: Cloud Waste is Silent

<div class="columns">
<div>

Organizations waste **30–35%** of cloud spend on resources that are running but doing nothing.

<br>

**Common culprits:**
- Unattached disks still charging for storage
- Idle VMs with < 5% CPU — billing hourly
- Elastic IPs without an association — $0.005/hr/IP
- Load balancers with zero requests in 7 days
- Stale snapshots accumulating since last quarter

</div>
<div>

```
AWS monthly bill
─────────────────────────────
EC2 instances      $1,420.00
EBS volumes          $320.00   ← 30% unattached?
RDS databases        $890.00
Load balancers       $180.00
Elastic IPs           $22.00
─────────────────────────────
Total              $2,832.00
                      ↑
           How much is waste?
```

</div>
</div>

---

## The Core Design Challenge

**Billing exports show COST — not STATE**

<br>

```
AWS Cost & Usage Report (one line per resource per day)

lineItem/ResourceId    lineItem/BlendedCost    lineItem/UsageType
─────────────────────────────────────────────────────────────────
vol-0abc123dead001          $0.40            EBS:VolumeUsage
vol-0abc123dead002          $0.80            EBS:VolumeUsage
```

<br>

> ❓ Is `vol-0abc123dead001` attached to an instance — or floating, billing for nothing?

> **The CUR cannot tell you.** You need a second data source: live resource inventory and utilization signals.

---

## Solution: Enrich Billing Data with Live State

```
Billing Export                   Live State (boto3 / mock)
──────────────────               ───────────────────────────────────
vol-0abc123dead001 $0.40  ──┐   disk.is_attached  = False   ← EBS API
vol-0abc123dead002 $0.80  ──┤   vm.avg_cpu_7d     = 1.2%    ← CloudWatch
i-0ec2idle001      $30.95 ──┤   ip.is_associated  = False   ← EC2 API
eipalloc-dead001   $3.72  ──┘   snapshot.age_days = 127     ← Snapshots API
                                                   │
                                     Rule Engine (6 Detectors)
                                     required_signals = ["disk.is_attached"]
                                     → SKIP if signal missing (never guess)
                                     → FLAG if signal confirms waste
                                                   │
                                     Finding: delete vol-0abc123dead001
                                              saves $0.40/day = $12/mo
```

**Key invariant:** a missing signal means *skip*, never *default to waste*.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    CLI  (Typer + Rich)                           │
│          scan │ report (json/csv/summary) │ remediate            │
└──────────────────────────┬───────────────────────────────────────┘
                           │
            ┌──────────────▼────────────────┐
            │       Ingestion Layer          │
            │  aws_cur.py  azure_cost.py     │
            │  auto-detect by CSV header     │
            │  → list[Resource] (Pydantic)   │
            └──────────────┬────────────────┘
                           │
            ┌──────────────▼────────────────┐
            │      Enrichment Layer          │
            │  MockProvider  (deterministic) │
            │  AWSProvider   (--enrich flag) │
            │  → dict[resource_id → signals] │
            └──────────────┬────────────────┘
                           │
            ┌──────────────▼────────────────┐
            │       Rule Engine              │
            │  6 pluggable Detectors         │
            │  each declares required_signals│
            │  → list[Finding]               │
            └──────────────┬────────────────┘
                           │
            ┌──────────────▼────────────────┐
            │    Remediation Generator       │
            │  Jinja2 template → bash        │
            │  DRY_RUN=true by default       │
            └───────────────────────────────┘
```

---

## Ingestion & Normalization

Two very different billing formats → **one schema**

<div class="columns">
<div>

**AWS CUR** (CSV, 30+ columns)
```python
# Field mapping
resource_id  ← lineItem/ResourceId
account_id   ← bill/PayerAccountId
region       ← product/region
service      ← lineItem/ProductCode
cost_usd     ← lineItem/BlendedCost
tags         ← resourceTags/user:*
```

</div>
<div>

**Azure Cost Mgmt** (CSV + JSON)
```python
# Field mapping
resource_id  ← ResourceId (ARM path)
account_id   ← SubscriptionId
region       ← ResourceLocation
service      ← MeterCategory
cost_usd     ← CostInBillingCurrency
tags         ← Tags (JSON string)
```

</div>
</div>

**Unified `Resource` model (Pydantic v2):**
```python
class Resource(BaseModel):
    resource_id: str;  provider: str;  service: str
    resource_type: ResourceType  # vm / disk / snapshot / ip / load_balancer / nat_gateway
    monthly_cost: float;  region: str | None;  tags: dict[str, str]
```

Format is **auto-detected** from CSV header — no `--provider` flag needed.

---

## Detection Engine

**Pluggable `BaseDetector` contract**

```python
class BaseDetector(ABC):
    name:             ClassVar[str]       # "unattached-disk"
    required_signals: ClassVar[list[str]] # ["disk.is_attached"]

    @abstractmethod
    def detect(self, resources, signals) -> list[Finding]: ...
```

<br>

**6 Detectors shipped:**

| Detector | Required Signal | Action |
|---|---|---|
| `unattached-disk` | `disk.is_attached` | `aws ec2 delete-volume` |
| `idle-vm` | `vm.avg_cpu_7d` | `aws ec2 stop-instances` |
| `unused-ip` | `ip.is_associated` | `aws ec2 release-address` |
| `old-snapshot` | `snapshot.age_days` | `aws ec2 delete-snapshot` |
| `idle-load-balancer` | `lb.request_count_7d` | `aws elbv2 delete-load-balancer` |
| `unused-nat-gateway` | `nat.bytes_processed_7d` | `aws ec2 delete-nat-gateway` |

*Resources tagged `env: prod` or `do-not-delete: *` are **always skipped**.*

---

## Remediation & Safety

**Three layers of protection before anything runs:**

```bash
# Step 1 — generate the script (no network calls, no state changes)
python -m app.cli remediate billing.csv --output remediation.sh

# Step 2 — read and review the script (it's plain bash, audit it)
cat remediation.sh

# Step 3 — dry-run (default) — prints every command, executes NOTHING
bash remediation.sh
# [DRY-RUN] aws ec2 stop-instances --instance-ids i-0idle00001dead0001 --region us-east-1
# [DRY-RUN] aws ec2 delete-volume --volume-id vol-0orph0001dead0001 --region us-east-1

# Step 4 — execute (requires typed confirmation)
bash remediation.sh --apply
# Type 'yes I understand' to proceed: _
```

**Script structure:**
- Section 1: **Reversible** operations (stop / deallocate) — safe to undo
- Section 2: **Destructive** operations (delete) — with rollback notes & warnings
- `_run()` wrapper: either echoes or executes, never silently swallows

---

## Demo — Real Scan on Sample Data

```
$ python -m app.cli scan data/samples/aws_cur_sample.csv
```

```
                          Cloud Cost Findings
 #   Provider  Resource         Type      Category         Savings/mo
 1   AWS       old-etl-…        disk      unattached_disk     $10.00
 2   AWS       stale-ml-…       disk      unattached_disk     $16.00
 3   AWS       old-etl-01       vm        idle_vm             $30.95
 4   AWS       stale-batch-01   vm        idle_vm             $61.90
 5   AWS       old-analytics-…  database  idle_vm             $50.59
 6   AWS       prod-snap-01     snapshot  old_snapshot         $8.00
 7   AWS       orphan-elb-…     lb        idle_load_balancer  $18.00
    ...21 total findings...
╭──────────────────── Savings Summary ────────────────────╮
│ Monthly savings : $331.53  │  Annual estimate : $3,978  │
│ By Category:  idle_vm $215 · unattached_disk $39 · ...  │
╰─────────────────────────────────────────────────────────╯
```

```
$ python -m app.cli scan data/samples/azure_cost_sample.csv
# 11 findings  ·  $142.86/mo  ·  $1,714/yr
```

**Combined: 32 findings across two providers — $474.39/mo — $5,692/yr identified**

---

## Tech Stack

<div class="columns">
<div>

**Core**
- Python 3.13 · Pydantic v2
- Typer (CLI) · Rich (tables/panels)
- Jinja2 (bash script templating)
- PyYAML (rules config)

**Testing**
- pytest · Typer `CliRunner`
- `unittest.mock` (patch / MagicMock)
- **274 tests · 100% passing**

</div>
<div>

**Optional enrichment**
- boto3 ≥ 1.34 (`--enrich` flag)
- EC2 `describe-volumes` / `describe-instances`
- CloudWatch `GetMetricStatistics`
- Graceful fallback to mock on credential failure

**Planned (not yet built)**
- FastAPI REST API
- SQLAlchemy + SQLite persistence
- Single-page dashboard

</div>
</div>

---

## Challenges & What I Learned

**1. Billing ≠ State — and that distinction runs deep**
Billing line items are facts about *past usage*. Live state is a separate API call.
Conflating the two produces false positives at scale. The enrichment signal layer keeps them cleanly separated.

**2. Safety-first enrichment**
On any API error or empty CloudWatch datapoints, the signal is *omitted* — never defaulted to a waste-implying value (e.g. `cpu = 0.0` would stop a possibly-healthy instance).
*"Omit on error"* is a design invariant tested explicitly.

**3. Testable CLI output**
Rich wraps text and truncates columns — raw string matching fails.
Solution: assert on 7-character prefixes (`"unattac"`) and test number substrings, not full formatted strings.

**4. Dependency pinning matters**
`click 8.2+` broke Typer 0.12.3's `TyperArgument.make_metavar()`. Pin `click==8.1.8`.

---

## Future Work

**Near-term (next sprints)**

- **REST API** — FastAPI endpoints: `GET /resources`, `POST /recommendations/{id}/remediate`
- **Persistence** — SQLAlchemy + SQLite: store ingested records, findings, audit log
- **Dashboard** — single-page vanilla-JS UI reading the API

**Medium-term**

- **Real Azure enrichment** — `az vm list`, `az disk list` via Azure SDK
- **Scheduling** — cron-triggered scans with change-detection and email/Slack alerts
- **Cost forecasting** — trend line per resource: flag resources growing toward a threshold
- **More providers** — GCP billing export support

**Longer-term**

- GitHub Actions integration — scan on PR and comment cost delta
- Anomaly detection on billing time-series (spike detection, sudden new resource types)

---

<!-- _class: lead -->

## Thank You

<br>

**Cloud Cost Optimizer & Remediation Engine**

*Detect waste · Generate safe remediation · Never delete without review*

<br>

| Resource | Location |
|---|---|
| Source code | `assignment2/` |
| Architecture guide | `CLAUDE.md` |
| Full documentation | `README.md` |
| Run tests | `pytest tests/ -q` |
| Quick scan | `python -m app.cli scan data/samples/aws_cur_sample.csv` |

<br>

**Pritam Sonawane** · pritam8956sonawane@gmail.com
