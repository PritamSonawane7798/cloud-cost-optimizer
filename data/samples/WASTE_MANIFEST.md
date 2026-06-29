# Waste Manifest — Planted Test Cases

This file documents every deliberately wasteful resource embedded in the sample
billing exports. Use it to verify that the rule engine finds exactly these
resources and skips the prod-protected ones.

Billing period: **2026-05-01 → 2026-06-01**

---

## AWS (aws_cur_sample.csv)

### W-AWS-01 — W-AWS-04: Unattached EBS Volumes
Detector: `UnattachedDiskDetector`  
Required signal: `disk.is_attached = false`

| # | resource_id | Type | Size | Region | Tag env | Monthly cost |
|---|---|---|---|---|---|---|
| W-AWS-01 | `vol-0orph0001dead0001` | gp2 | 100 GB | us-east-1 | dev | $10.00 |
| W-AWS-02 | `vol-0orph0002dead0002` | gp3 | 200 GB | us-east-1 | dev | $16.00 |
| W-AWS-03 | `vol-0orph0003dead0003` | gp2 |  50 GB | us-west-2 | staging | $5.00 |
| W-AWS-04 | `vol-0orph0004dead0004` | gp2 |  80 GB | us-east-1 | dev | $8.00 |

**Total savings if remediated: $39.00/mo**  
Remediation: `aws ec2 delete-volume --volume-id <id> --region <region>`

---

### W-AWS-05 — W-AWS-08: Idle EC2 Instances
Detector: `IdleVMDetector`  
Required signal: `vm.avg_cpu_7d < 5%`

| # | resource_id | Type | Region | Tag env | Monthly cost |
|---|---|---|---|---|---|
| W-AWS-05 | `i-0idle00001dead0001` | t3.medium | us-east-1 | dev | $30.95 |
| W-AWS-06 | `i-0idle00002dead0002` | t3.large  | us-west-2 | dev | $61.90 |
| W-AWS-07 | `i-0idle00003dead0003` | t3.small  | us-east-1 | staging | $15.46 |
| W-AWS-08 | `i-0idle00004dead0004` | t3.medium | us-east-1 | dev | $30.95 |

**Total savings if remediated (stop): $139.26/mo**  
Remediation: `aws ec2 stop-instances --instance-ids <id> --region <region>`

---

### W-AWS-09 — W-AWS-12: Unassociated Elastic IPs
Detector: `UnusedIPDetector`  
Required signal: `ip.is_associated = false`

| # | resource_id | Region | Tag env | Monthly cost |
|---|---|---|---|---|
| W-AWS-09  | `eipalloc-0dead0001aaaa0001` | us-east-1 | dev | $3.72 |
| W-AWS-10 | `eipalloc-0dead0002bbbb0002` | us-east-1 | dev | $3.72 |
| W-AWS-11 | `eipalloc-0dead0003cccc0003` | us-west-2 | staging | $3.72 |
| W-AWS-12 | `eipalloc-0dead0004dddd0004` | us-east-1 | dev | $3.72 |

**Total savings if remediated: $14.88/mo**  
Remediation: `aws ec2 release-address --allocation-id <id> --region <region>`

---

### W-AWS-13 — W-AWS-17: Old Snapshots (>90 days)
Detector: `OldSnapshotDetector`  
Required signal: `snapshot.age_days > 90`

| # | resource_id | Size | Age | Region | Tag env | Monthly cost |
|---|---|---|---|---|---|---|
| W-AWS-13 | `snap-0old00001dead001` | 100 GB | ~150 days | us-east-1 | dev | $5.00 |
| W-AWS-14 | `snap-0old00002dead002` | 200 GB | ~200 days | us-east-1 | dev | $10.00 |
| W-AWS-15 | `snap-0old00003dead003` |  50 GB | ~130 days | us-west-2 | staging | $2.50 |
| W-AWS-16 | `snap-0old00004dead004` | 150 GB | ~150 days | us-east-1 | dev | $7.50 |
| W-AWS-17 | `snap-0old00005dead005` |  80 GB |  ~95 days | us-east-1 | dev | $4.00 |

Note: `age_days` comes from the enrichment signal (mock: seeded from resource_id
hash). The description column contains `age~Nd` as a hint for mock signal seeding.

**Total savings if remediated: $29.00/mo**  
Remediation: `aws ec2 delete-snapshot --snapshot-id <id> --region <region>`

---

### W-AWS-18 — W-AWS-19: Idle Load Balancers
Detector: `IdleLoadBalancerDetector`  
Required signal: `lb.request_count_7d = 0`

| # | resource_id (ARN) | Region | Tag env | Monthly cost |
|---|---|---|---|---|
| W-AWS-18 | `.../loadbalancer/app/idle-alb-01/...` | us-east-1 | dev | $16.74 |
| W-AWS-19 | `.../loadbalancer/app/idle-alb-02/...` | us-west-2 | dev | $16.74 |

**Total savings if remediated: $33.48/mo**  
Remediation: `aws elbv2 delete-load-balancer --load-balancer-arn <arn> --region <region>`

---

### W-AWS-20 — W-AWS-21: Idle RDS Instances
Detector: `IdleVMDetector` (scoped to RDS) or dedicated `IdleRDSDetector`  
Required signal: `vm.avg_cpu_7d < 5%` (same signal, resource_type = rds)

| # | resource_id (ARN) | Type | Region | Tag env | Monthly cost |
|---|---|---|---|---|---|
| W-AWS-20 | `.../db:db-idle-001` | db.t3.medium | us-east-1 | dev | $50.59 |
| W-AWS-21 | `.../db:db-idle-002` | db.t3.small  | us-east-1 | dev | $25.30 |

**Total savings if remediated (stop): $75.89/mo**  
Remediation: `aws rds stop-db-instance --db-instance-identifier <id> --region <region>`

---

### Prod-Protected Resources — Must NOT Be Flagged

These resources may appear wasteful by cost heuristics but carry `env=prod` and
must be skipped by all detectors.

| Resource ID | Type | Reason they look wasteful | Protection |
|---|---|---|---|
| `vol-0prod0003c3d4e5f6` | EBS 100 GB gp3 | Large standalone volume | `env=prod` |
| `snap-0prod00001aa2bb3` | Snapshot 200 GB | Has a twin (snap-0rec000025b3c4d5 also prod) | `env=prod` |
| `i-0batch0001aa2bb3cc` | EC2 m5.large | Named "batch" — may look idle | `env=prod` |

Detector contract: if `tags.get("env") == "prod"`, return `None` unconditionally.

---

## Azure (azure_cost_sample.csv / azure_cost_sample.json)

### W-AZ-01 — W-AZ-03: Unattached Managed Disks
Detector: `UnattachedDiskDetector`  
Required signal: `disk.is_attached = false`

| # | ResourceName | SKU | Size | Monthly cost |
|---|---|---|---|---|
| W-AZ-01 | `disk-orphan-01` | Premium_LRS | 128 GB | $19.71 |
| W-AZ-02 | `disk-orphan-02` | Premium_LRS | 256 GB | $38.40 |
| W-AZ-03 | `disk-orphan-03` | Standard_LRS | 256 GB | $9.61 |

**Total savings: $67.72/mo**  
Remediation: `az disk delete --ids <resource_id> --yes`

---

### W-AZ-04: Deallocated VM — Disk Still Billing
Detector: `UnattachedDiskDetector` (catches the orphaned OS disk)

| # | ResourceName | Note | Monthly cost |
|---|---|---|---|
| W-AZ-04a | `vm-deallocated-01` | VM itself: $0.00 (deallocated) | $0.00 |
| W-AZ-04b | `vm-deallocated-01-osdisk` | OS disk keeps billing | $19.71 |

The VM row costs $0 but signals the disk is orphaned. The enrichment signal
`disk.is_attached = false` will be set for `vm-deallocated-01-osdisk` by the
mock provider (it has no associated running VM).

**Savings: $19.71/mo** (delete disk or restore VM)  
Remediation: `az disk delete --ids <resource_id> --yes`

---

### W-AZ-05 — W-AZ-07: Unused Public IPs
Detector: `UnusedIPDetector`  
Required signal: `ip.is_associated = false`

| # | ResourceName | Monthly cost |
|---|---|---|
| W-AZ-05 | `pip-unused-01` | $3.65 |
| W-AZ-06 | `pip-unused-02` | $3.65 |
| W-AZ-07 | `pip-unused-03` | $3.65 |

**Total savings: $10.95/mo**  
Remediation: `az network public-ip delete --ids <resource_id>`

---

### W-AZ-08 — W-AZ-09: Old Snapshots (>90 days)
Detector: `OldSnapshotDetector`  
Required signal: `snapshot.age_days > 90` (mock: seeded from `age_note` tag)

| # | ResourceName | Age hint | Monthly cost |
|---|---|---|---|
| W-AZ-08 | `snap-old-disk-01` | ~180 days | $5.12 |
| W-AZ-09 | `snap-old-disk-02` | ~120 days | $2.56 |

**Total savings: $7.68/mo**  
Remediation: `az snapshot delete --ids <resource_id>`

---

### W-AZ-10 — W-AZ-11: Idle Load Balancers
Detector: `IdleLoadBalancerDetector`  
Required signal: `lb.request_count_7d = 0`

| # | ResourceName | Monthly cost |
|---|---|---|
| W-AZ-10 | `lb-dev-idle-01`      | $18.40 |
| W-AZ-11 | `lb-staging-idle-01`  | $18.40 |

**Total savings: $36.80/mo**  
Remediation: `az network lb delete --ids <resource_id>`

---

## Summary Table

| Provider | Detector | # Resources | Monthly Waste |
|---|---|---|---|
| AWS | UnattachedDiskDetector | 4 | $39.00 |
| AWS | IdleVMDetector (EC2) | 4 | $139.26 |
| AWS | UnusedIPDetector | 4 | $14.88 |
| AWS | OldSnapshotDetector | 5 | $29.00 |
| AWS | IdleLoadBalancerDetector | 2 | $33.48 |
| AWS | IdleVMDetector (RDS) | 2 | $75.89 |
| Azure | UnattachedDiskDetector | 4 | $87.43 |
| Azure | UnusedIPDetector | 3 | $10.95 |
| Azure | OldSnapshotDetector | 2 | $7.68 |
| Azure | IdleLoadBalancerDetector | 2 | $36.80 |
| **TOTAL** | | **32** | **$474.37/mo** |

---

## Signal Seeding Notes for MockEnrichmentProvider

The mock enrichment provider must set these signals for the specific resource
IDs above. For all other resources, use the statistical defaults (70% attached,
75% associated, etc.).

```python
FORCED_SIGNALS = {
    # Unattached EBS
    "vol-0orph0001dead0001": {"disk.is_attached": False},
    "vol-0orph0002dead0002": {"disk.is_attached": False},
    "vol-0orph0003dead0003": {"disk.is_attached": False},
    "vol-0orph0004dead0004": {"disk.is_attached": False},
    # Idle EC2
    "i-0idle00001dead0001": {"vm.avg_cpu_7d": 1.2, "vm.state": "running"},
    "i-0idle00002dead0002": {"vm.avg_cpu_7d": 0.8, "vm.state": "running"},
    "i-0idle00003dead0003": {"vm.avg_cpu_7d": 1.5, "vm.state": "running"},
    "i-0idle00004dead0004": {"vm.avg_cpu_7d": 0.5, "vm.state": "running"},
    # Unassociated EIPs
    "eipalloc-0dead0001aaaa0001": {"ip.is_associated": False},
    "eipalloc-0dead0002bbbb0002": {"ip.is_associated": False},
    "eipalloc-0dead0003cccc0003": {"ip.is_associated": False},
    "eipalloc-0dead0004dddd0004": {"ip.is_associated": False},
    # Old snapshots
    "snap-0old00001dead001": {"snapshot.age_days": 150},
    "snap-0old00002dead002": {"snapshot.age_days": 200},
    "snap-0old00003dead003": {"snapshot.age_days": 130},
    "snap-0old00004dead004": {"snapshot.age_days": 150},
    "snap-0old00005dead005": {"snapshot.age_days": 95},
    # Idle ALBs
    "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/idle-alb-01/1234567890abcdef":
        {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    "arn:aws:elasticloadbalancing:us-west-2:123456789012:loadbalancer/app/idle-alb-02/1234567890abcdef":
        {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    # Idle RDS
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-001": {"vm.avg_cpu_7d": 0.3},
    "arn:aws:rds:us-east-1:123456789012:db:db-idle-002": {"vm.avg_cpu_7d": 0.1},
    # Azure unattached disks
    "disk-orphan-01": {"disk.is_attached": False},
    "disk-orphan-02": {"disk.is_attached": False},
    "disk-orphan-03": {"disk.is_attached": False},
    "vm-deallocated-01-osdisk": {"disk.is_attached": False},
    # Azure unused PIPs
    "pip-unused-01": {"ip.is_associated": False},
    "pip-unused-02": {"ip.is_associated": False},
    "pip-unused-03": {"ip.is_associated": False},
    # Azure old snapshots
    "snap-old-disk-01": {"snapshot.age_days": 180},
    "snap-old-disk-02": {"snapshot.age_days": 120},
    # Azure idle LBs
    "lb-dev-idle-01":     {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
    "lb-staging-idle-01": {"lb.request_count_7d": 0, "lb.active_connection_count": 0},
}
```
