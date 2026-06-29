# Cloud Cost Optimizer & Remediation Engine

A Python CLI that ingests AWS Cost and Usage Reports (CUR) and Azure Cost Management exports, detects orphaned or idle cloud resources, and generates exact `aws`/`az` CLI remediation commands — **dry-run by default, never executes anything without explicit opt-in**.

---

## The Billing-vs-State Problem

AWS CUR and Azure Cost Management exports are **billing line items**, not resource state snapshots. A detached EBS volume appears once per day in the CUR with its storage cost — but the export contains no "is this attached?" column. Naively flagging every disk as wasteful would generate false positives on healthy, attached volumes.

**How this tool solves it — the enrichment signal layer:**

```
Billing export  →  Ingestion  →  NormalizedRecord (cost data only)
                                        │
                              Enrichment Provider
                           (mock or real boto3 calls)
                                        │
                              EnrichmentSignals
                           disk.is_attached = False   ← real state
                           vm.avg_cpu_7d    = 1.2%    ← CloudWatch
                                        │
                              Rule Engine (Detectors)
                           required_signals = ["disk.is_attached"]
                           → skip if signal missing
                           → flag only if signal confirms waste
```

Each detector declares `required_signals`. If a signal is absent (e.g. no CloudWatch data published yet), the detector **skips** that resource rather than guessing. This prevents false positives on resources where state cannot be determined.

---

## How It Works

```
┌──────────────────────────────────────────────────────────┐
│                       CLI (Typer)                        │
│          scan  │  report  │  remediate                   │
└──────────────────────────┬───────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │    Ingestion Layer      │
              │  AWS CUR CSV parser     │
              │  Azure CSV/JSON parser  │
              │  auto-detect by header  │
              └────────────┬────────────┘
                           │  list[Resource]
              ┌────────────▼────────────┐
              │   Enrichment Layer      │
              │  MockProvider (default) │
              │  AWSProvider (--enrich) │
              └────────────┬────────────┘
                           │  dict[resource_id → signals]
              ┌────────────▼────────────┐
              │     Rule Engine         │
              │  UnattachedDiskDetector │
              │  IdleVMDetector         │
              │  UnusedIPDetector       │
              │  OldSnapshotDetector    │
              │  IdleLoadBalancerDetector│
              │  UnusedNATGatewayDetector│
              └────────────┬────────────┘
                           │  list[Finding]
              ┌────────────▼────────────┐
              │  Remediation Generator  │
              │  Jinja2 → bash script   │
              │  DRY_RUN=true by default│
              └─────────────────────────┘
```

**Data never flows the wrong direction:** cost-only billing data is enriched with live state signals before detection runs. Detectors never infer state from cost.

---

## Installation

**Prerequisites:** Python 3.10+ (tested on 3.13.1)

```bash
git clone <repo>
cd assignment2
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Optional — for real AWS enrichment via `--enrich`:
```bash
pip install boto3
# Set AWS credentials (env vars or ~/.aws/credentials)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

Copy and edit the environment file:
```bash
cp .env.example .env
```

---

## Quick Start

**Scan billing data and view findings table + savings summary:**
```bash
python -m app.cli scan data/samples/aws_cur_sample.csv
```

**Export findings as JSON:**
```bash
python -m app.cli report data/samples/aws_cur_sample.csv --format json --output findings.json
```

**Export a three-axis Markdown summary report:**
```bash
python -m app.cli report data/samples/aws_cur_sample.csv --format summary --output summary.md
```

**Generate a dry-run remediation script:**
```bash
python -m app.cli remediate data/samples/aws_cur_sample.csv --output remediation.sh
```

**Use real AWS resource state (requires credentials):**
```bash
python -m app.cli scan data/samples/aws_cur_sample.csv --enrich
```

**Use a custom rules config:**
```bash
python -m app.cli scan data/samples/aws_cur_sample.csv --rules rules.yaml
```

---

## Sample Output

### `scan` — findings table and savings summary

```
                          Cloud Cost Findings
 #   Provider  Resource      Type      Category    Savings/mo  Conf
 1   AWS       old-etl-…     disk      unattac…     $10.00     high
 2   AWS       stale-ml-…    disk      unattac…     $16.00     high
 3   AWS       qa-runner-…   disk      unattac…      $5.00     high
 4   AWS       temp-anal-…   disk      unattac…      $8.00     high
 5   AWS       old-etl-…     vm        idle_vm      $30.95     high
 6   AWS       stale-bat-…   vm        idle_vm      $61.90     high
 ...

╭──────────────────── Savings Summary ────────────────────╮
│ Total findings  : 21                                    │
│ Monthly savings : $331.53                               │
│ Annual estimate : $3978.36                              │
│                                                         │
│ By Provider                                             │
│   AWS     $  331.53/mo  (21)                            │
│                                                         │
│ By Category                                             │
│   idle_vm                $  215.17/mo  ( 6)             │
│   unattached_disk        $   39.00/mo  ( 4)             │
│   idle_load_balancer     $   33.48/mo  ( 2)             │
│   old_snapshot           $   29.00/mo  ( 5)             │
│   unused_ip              $   14.88/mo  ( 4)             │
╰─────────────────────────────────────────────────────────╯
```

### `report --format summary` — Markdown breakdown

```markdown
# Cloud Cost Optimizer — Summary Report

Generated: 2026-06-29T06:06:26Z

## Overview

| Metric | Value |
|--------|-------|
| Total findings | 21 |
| Monthly savings | $331.53 |
| Annual estimate | $3978.36 |

## By Provider

| Provider | Findings | Monthly Savings | Annual Estimate |
|----------|----------|-----------------|-----------------|
| AWS | 21 | $331.53 | $3978.36 |

## By Service

| Service | Provider | Findings | Monthly Savings |
|---------|----------|----------|-----------------|
| AmazonEC2 | AWS | 17 | $222.16 |
| AmazonRDS | AWS | 2 | $75.89 |
| AWSApplicationLoadBalancer | AWS | 2 | $33.48 |

## By Waste Category

| Category | Findings | Monthly Savings | Annual Estimate |
|----------|----------|-----------------|-----------------|
| idle_vm | 6 | $215.17 | $2582.04 |
| unattached_disk | 4 | $39.00 | $468.00 |
| idle_load_balancer | 2 | $33.48 | $401.76 |
| old_snapshot | 5 | $29.00 | $348.00 |
| unused_ip | 4 | $14.88 | $178.56 |
```

### `remediate` — dry-run bash script (excerpt)

```bash
#!/usr/bin/env bash
# Cloud Cost Optimizer — Remediation Script
# Generated    : 2026-06-29 UTC
# Resources    : 21 finding(s)
# Est. savings : $331.53/mo
#
# Dry-run (default — prints commands, executes nothing):
#   bash remediation.sh
#
# Execute (irreversible for delete operations):
#   bash remediation.sh --apply

set -euo pipefail
DRY_RUN=true

if [[ "${1:-}" == "--apply" ]]; then
  read -rp "Type 'yes I understand' to proceed: " _confirm
  [[ "$_confirm" == "yes I understand" ]] || { echo "Aborted."; exit 1; }
  DRY_RUN=false
fi

# ── SECTION 1: Reversible (stop / deallocate) ─────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY RUN] aws ec2 stop-instances --instance-ids i-0idle0001 --region us-east-1"
else
  aws ec2 stop-instances --instance-ids i-0idle0001 --region us-east-1
fi

# ── SECTION 2: Destructive (delete) ──────────────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
  echo "[DRY RUN] aws ec2 delete-volume --volume-id vol-0orph0001dead0001 --region us-east-1"
else
  aws ec2 delete-volume --volume-id vol-0orph0001dead0001 --region us-east-1
fi
```

---

## Command Reference

### `scan`
Ingest billing data, run all detectors, print findings table and savings panel.

```
python -m app.cli scan <path> [--rules RULES_YAML] [--enrich]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--rules` | `rules.yaml` (if present) | Custom thresholds and skip-tag rules |
| `--enrich` | off | Fetch real AWS resource state via boto3 |

### `report`
Write findings to disk.

```
python -m app.cli report <path> --format (json|csv|summary) [--output FILE] [--rules RULES_YAML] [--enrich]
```

| Format | Output | Description |
|--------|--------|-------------|
| `json` | `findings.json` | List of Finding objects |
| `csv` | `findings.csv` | Tabular, one row per finding |
| `summary` | `findings.md` | Markdown tables: by provider, service, category |

### `remediate`
Generate a bash remediation script.

```
python -m app.cli remediate <path> [--output FILE] [--apply] [--rules RULES_YAML] [--enrich]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output` | `remediation.sh` | Script output path |
| `--apply` | off | Execute the script after generating it (requires interactive confirmation) |

---

## Detector Reference

| Detector | Waste Category | Required Signal | What It Flags | Remediation |
|----------|---------------|-----------------|---------------|-------------|
| `unattached-disk` | `unattached_disk` | `disk.is_attached` | EBS volumes / Azure Managed Disks not attached to any instance | `aws ec2 delete-volume` / `az disk delete` |
| `idle-vm` | `idle_vm` | `vm.avg_cpu_7d` | VMs and RDS instances with avg CPU < 5% over 7 days, or stopped-but-billing | `aws ec2 stop-instances` / `az vm deallocate` |
| `unused-ip` | `unused_ip` | `ip.is_associated` | Elastic IPs / Azure Public IPs not associated with any resource | `aws ec2 release-address` / `az network public-ip delete` |
| `old-snapshot` | `old_snapshot` | `snapshot.age_days` | Snapshots older than 90 days (configurable) | `aws ec2 delete-snapshot` / `az snapshot delete` |
| `idle-load-balancer` | `idle_load_balancer` | `lb.request_count_7d` | Load balancers with zero requests in 7 days | `aws elbv2 delete-load-balancer` / `az network lb delete` |
| `unused-nat-gateway` | `unused_nat_gateway` | `nat.bytes_processed_7d` | NAT Gateways with zero bytes processed in 7 days | `aws ec2 delete-nat-gateway` / `az network nat gateway delete` |

Thresholds are configurable via `rules.yaml`:

```yaml
detectors:
  vm:
    cpu_threshold_pct: 5.0    # flag VMs below this CPU %
    flag_stopped: true         # also flag stopped-but-billing VMs
  snapshot:
    age_threshold_days: 90
  load_balancer:
    request_count_threshold: 0
  nat_gateway:
    bytes_threshold: 0
skip_tags:
  env: [prod]                  # never touch production resources
  do-not-delete: ["*"]         # honour explicit opt-out tag
```

---

## Enrichment Signals

Detectors require named signals that bridge billing data to live resource state:

| Signal | Type | Source | Used by |
|--------|------|--------|---------|
| `disk.is_attached` | bool | `ec2:describe-volumes` | `unattached-disk` |
| `vm.avg_cpu_7d` | float | CloudWatch `CPUUtilization` | `idle-vm` |
| `vm.state` | str | `ec2:describe-instances` | `idle-vm` |
| `ip.is_associated` | bool | `ec2:describe-addresses` | `unused-ip` |
| `snapshot.age_days` | int | `ec2:describe-snapshots` | `old-snapshot` |
| `lb.request_count_7d` | int | CloudWatch `RequestCount` | `idle-load-balancer` |
| `lb.active_connection_count` | int | CloudWatch `ActiveConnectionCount` | `idle-load-balancer` |
| `nat.bytes_processed_7d` | int | CloudWatch `BytesOutToSource` | `unused-nat-gateway` |

**Without `--enrich`** (the default): signals are provided by `MockEnrichmentProvider`, which seeds deterministic values from `hash(resource_id)`. Planted waste cases in the sample data always produce waste-indicating signals; other resources get healthy defaults. Results are fully reproducible.

**With `--enrich`**: `AWSEnrichmentProvider` calls the real AWS APIs (boto3). If credentials are absent or an API call fails, the tool prints a warning and falls back to mock signals. Azure resources always use mock signals (no Azure SDK in this release).

**Safety invariant for real enrichment:** on any API error or empty CloudWatch datapoints, the signal key is **omitted** — never defaulted to a waste-implying value. A missing `vm.avg_cpu_7d` causes the `idle-vm` detector to skip that resource entirely, rather than fabricating a "0% CPU" finding against a possibly-running instance.

---

## Safety: Dry-Run First

**The tool never executes cloud API calls.** Remediation builders construct the exact CLI command string and return it — they do not call `subprocess.run(...)`.

The generated bash script enforces a two-stage model:

1. **Default (dry-run):** prints each command prefixed with `[DRY RUN]`. Nothing is deleted, stopped, or released.
2. **Execute mode:** pass `--apply` to the CLI. The script prompts for `"yes I understand"` before running. Even then, SECTION 1 (reversible: stop/deallocate) runs before SECTION 2 (destructive: delete).

The `POST /recommendations/{id}/remediate` API endpoint (when implemented) defaults to `dry_run=true`. Execute mode must be explicitly requested.

**Skip-tag safety net:** any resource tagged `env: prod` or `do-not-delete: <any value>` is skipped by all detectors regardless of signals.

---

## Presentation Deck

A 13-slide Marp deck is in `docs/deck.md`. To regenerate the PDF:

```bash
bash docs/build-deck.sh
# Requires: node 18+ with npx (@marp-team/marp-cli is fetched automatically)
# Output: docs/deck.pdf
```

The pre-built PDF is already at `docs/deck.pdf`.

---

## Running Tests

```bash
python -m pytest tests/ -q
# 274 passed in <1s
```

Test coverage:
- **`test_ingestion.py`** — AWS CUR and Azure CSV/JSON parsing, field mapping, waste-case IDs
- **`test_detectors.py`** — all 6 detectors: signal-gating, threshold logic, confidence levels, skip-tag rules
- **`test_api.py`** — remediation script generation, Jinja2 template output
- **`test_cli.py`** — all three commands (scan/report/remediate), `--format summary`, `--enrich` flag with mock and real-credential paths, edge cases
- **`test_enrich_aws.py`** — boto3 enrichment: credential check, per-resource-type fetchers, safety-omit-on-error invariant

---

## Project Structure

```
assignment2/
├── app/
│   ├── cli.py                   # Typer CLI (scan / report / remediate)
│   ├── models/schema.py         # Resource, ResourceType Pydantic models
│   ├── ingestion/               # AWS CUR + Azure parsers, auto-detect
│   ├── enrichment/              # MockProvider, AWSProvider (boto3)
│   ├── rules/                   # BaseDetector + 6 detector implementations
│   └── remediation/             # Jinja2 bash script generator
├── tests/                       # pytest suite (274 tests)
├── data/samples/                # AWS CUR and Azure sample billing exports
├── rules.yaml                   # Default thresholds and skip-tag config
├── WASTE_MANIFEST.md            # Documents planted waste in sample data
├── CLAUDE.md                    # Architecture reference (canonical)
└── requirements.txt
```
