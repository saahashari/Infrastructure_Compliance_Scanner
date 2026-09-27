# Infrastructure Compliance Scanner

A lightweight, extensible rule engine that scans infrastructure service configurations
against codified compliance policies and reports actionable violations — grouped by
severity, with exact field-level failure details and remediation steps.

Built for the Uniphore Engineering Intern take-home assessment.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/saahashari/Infrastructure_Compliance_Scanner.git
cd Infrastructure_Compliance_Scanner

# 2. Create a virtual environment and install the single dependency
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# 3. Run a full scan (all environments, all policies)
python main.py

# 4. Export as JSON (for CI/CD or dashboards)
python main.py --output json > report.json
```

**Exit codes:** `0` = fully compliant · `1` = violations found · `2` = configuration error

Invalid YAML, malformed policies or services, duplicate policy IDs or service names,
filters that match no services, and services with no applicable policies return exit
code `2`. This prevents an incomplete scan from appearing compliant. The report
includes scanned and unscanned service counts plus the identity of every unscanned
service. `--no-fail` suppresses only the violation exit code.

Run the tests with `python -m unittest discover -s tests -q` in the virtual environment.

The engine builds a policy index in O(P) time for P policies. It uses two indexed
lookups per service (environment-specific and global policies), then evaluates
only applicable conditions. Sorting V violations costs O(V log V); condition
evaluation also depends on the depth of each field path.

---

## Project Structure

```
compliance-scanner/
│
├── main.py                     # CLI entrypoint
├── requirements.txt            # PyYAML only
├── DESIGN.md                   # Part 1: System design document
│
├── scanner/
│   ├── models.py               # Dataclasses: Service, Policy, Condition, Violation, ScanResult
│   ├── loader.py               # YAML → model parsing with robust error handling
│   ├── engine.py               # Stateless rule evaluation engine
│   └── reporter.py             # Terminal (colored) and JSON output
│
├── policies/
│   ├── security.yaml           # SEC-001 → SEC-007
│   ├── cost.yaml               # COST-001 → COST-005
│   └── operational.yaml        # OPS-001 → OPS-007
│
├── configs/
│   ├── production.yaml         # 8 services (prod DBs, compute, storage)
│   ├── staging.yaml            # 6 services (staging DBs, compute, storage)
│   └── dev.yaml                # 6 services (dev DBs, compute, storage)
│
├── example_output.json         # Full JSON report from a sample scan
└── tests/                     # Engine and CLI regression tests
    ├── test_engine.py
    ├── test_loader_cli.py
    ├── test_reporter.py
    └── test_scan_regressions.py
```

---

## CLI Usage

```
python main.py [OPTIONS]

Options:
  --policies DIR         Directory of YAML policy files  (default: policies/)
  --configs  DIR         Directory of YAML config files  (default: configs/)
  --output   FORMAT      terminal (default) | json
  --env      ENV         Filter: only scan services in this environment
  --severity SEV [SEV…]  Filter: only show violations at these severity levels
  --service  NAME        Filter: only scan a specific service by name
  --no-fail              Always exit 0 (reporting-only mode, useful in some CI pipelines)
  --verbose, -v          Enable debug logging to stderr
```

### Examples

```bash
# Scan only production services
python main.py --env production

# Show only critical violations across all environments
python main.py --severity critical

# Audit a single service in depth
python main.py --service prod-session-cache

# CI/CD: fail the build on any critical or high violation
python main.py --severity critical high
echo "Exit code: $?"   # 0 = clean, 1 = violation found

# Export JSON for a dashboard or Slack alert
python main.py --output json --env production > prod-report.json

# Use custom policy/config directories
python main.py --policies /path/to/my-policies --configs /path/to/infra-state
```

---

## Data Formats

### Infrastructure Configuration (`configs/*.yaml`)

Each file represents one environment snapshot. Services can be of any `type` —
the schema is intentionally open so it mirrors real cloud provider output.

```yaml
services:
  - name: prod-payments-db
    type: database            # Must match policy resource_type
    environment: production   # dev | staging | production (or any string)
    region: us-east-1
    owner: payments-team      # Set to "unknown" to trigger OPS-002
    tags:
      team: payments
    config:
      engine: postgres
      instance_type: db.r5.4xlarge
      backup_enabled: true
      backup_retention_days: 30
      encryption_at_rest: true
      publicly_accessible: false
      replicas: 2
      deletion_protection: true
      monitoring_enabled: true
      point_in_time_recovery: true
      min_tls_version: TLSv1.2
```

### Policy Definition (`policies/*.yaml`)

```yaml
policies:
  - id: SEC-001                          # Unique stable ID for tracking
    name: Production DB Backup Required
    description: All prod DBs need automated backups.
    severity: critical                   # critical | high | medium | low
    resource_type: database              # Matches service.type
    environment: production             # null → applies to ALL environments
    logic: AND                          # AND (default) | OR
    remediation: Enable backup_enabled in the database config.
    conditions:
      - field: config.backup_enabled    # Dot-notation path into service dict
        operator: equals
        value: true
        message: "Automated backups must be enabled."
```

### Supported Operators

| Operator | Description | Example `value` |
|---|---|---|
| `equals` | Exact equality | `true`, `"TLSv1.2"`, `7` |
| `not_equals` | Must not equal | `"unknown"` |
| `greater_than` | Numeric `>` | `2` |
| `less_than` | Numeric `<` | `100` |
| `gte` | Numeric `>=` | `7` |
| `lte` | Numeric `<=` | `500` |
| `in` | Value is in a list | `["t3.micro", "t3.small"]` |
| `not_in` | Value is not in a list | `["m5.8xlarge", "r5.4xlarge"]` |
| `exists` | Field is present | _(no value needed)_ |
| `not_exists` | Field is absent | _(no value needed)_ |
| `contains` | String contains substring | `"prod"` |
| `not_contains` | String does not contain | `"test"` |

Boolean values are distinct from numeric `0` and `1` in equality and membership
checks. Numeric comparisons reject booleans and non-finite values. JSON reports
represent a non-finite actual value as a string so the document stays valid JSON.

### Field Path Resolution

Policies use **dot-notation** to navigate nested config dicts:

```
config.backup_enabled              → service.config["backup_enabled"]
config.storage.encryption_enabled  → service.config["storage"]["encryption_enabled"]
owner                              → service.owner  (top-level attribute)
region                             → service.region
tags.team                          → service.tags["team"]
```

Missing fields return `_MISSING` internally — they fail any operator except
`not_exists`, giving clear error messages rather than silent incorrect passes.

---

## Included Policies (19 total)

### Security (`policies/security.yaml`)

| ID | Name | Severity | Scope |
|---|---|---|---|
| SEC-001 | Production DB Backup Required | critical | DB / prod |
| SEC-002 | All Databases Must Use Encryption at Rest | critical | DB / all envs |
| SEC-003 | Production DB Must Not Be Publicly Accessible | critical | DB / prod |
| SEC-004 | Production Compute Must Not Have Public IP | high | Compute / prod |
| SEC-005 | Backup Retention Must Be At Least 7 Days | high | DB / prod |
| SEC-006 | Storage Buckets Must Not Allow Public Read | critical | Storage / all envs |
| SEC-007 | TLS Version Must Be 1.2 or Higher | high | DB / all envs |

### Cost (`policies/cost.yaml`)

| ID | Name | Severity | Scope |
|---|---|---|---|
| COST-001 | Dev DB Must Use Cost-Optimized Instance Types | medium | DB / dev |
| COST-002 | Staging DB Must Use Cost-Optimized Instance Types | medium | DB / staging |
| COST-003 | Dev Compute Must Use Cost-Optimized Instance Types | medium | Compute / dev |
| COST-004 | Staging Compute Must Use Cost-Optimized Instance Types | low | Compute / staging |
| COST-005 | Storage Must Have Lifecycle Policy Enabled | low | Storage / all envs |

### Operational (`policies/operational.yaml`)

| ID | Name | Severity | Scope |
|---|---|---|---|
| OPS-001 | Production DB Must Have At Least 2 Replicas | critical | DB / prod |
| OPS-002 | Services Must Have Owner Tag | medium | DB / all envs |
| OPS-003 | Production DB Must Have Deletion Protection | high | DB / prod |
| OPS-004 | Production DB Must Have Enhanced Monitoring | medium | DB / prod |
| OPS-005 | Compute Must Have Auto Scaling in Production | high | Compute / prod |
| OPS-006 | Production DB Must Have Point-in-Time Recovery | high | DB / prod |
| OPS-007 | Storage Buckets Must Have Versioning Enabled | medium | Storage / all envs |

---

## Sample Output (Terminal)

```
══════════════════════════════════════════════════════════════════════
  INFRASTRUCTURE COMPLIANCE SCANNER
══════════════════════════════════════════════════════════════════════
  Scan time  : 2025-01-15T14:23:11.402Z
  Services   : 20
  Policies   : 19

──────────────────────────────────────────────────────────────────────
  SUMMARY
──────────────────────────────────────────────────────────────────────
  Critical:   9   High:  10   Medium:   9   Low:   4

  Total violations : 32
  Compliant svcs   : 8 / 20
  Scanned svcs     : 20 / 20
  Unscanned svcs   : 0

──────────────────────────────────────────────────────────────────────
  CRITICAL  (9 violations)
──────────────────────────────────────────────────────────────────────

  [1] SEC-002  CRITICAL  |  All Databases Must Use Encryption at Rest
      Service   : dev-payments-db
      Type      : database
      Env       : dev
      Region    : us-east-1
      Owner     : payments-team
      Conditions failed:
        ✗ config.encryption_at_rest [equals]  →  'config.encryption_at_rest' is 'False', expected 'True'.
      → Fix: Enable encryption at rest. Note: for most managed DB services this must be
        set at creation time and requires a snapshot-restore migration.
  ...

══════════════════════════════════════════════════════════════════════
  ✗ 32 violation(s) found across 20 service(s).
══════════════════════════════════════════════════════════════════════
```

See `example_output.json` for the full machine-readable report.

---

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐
│  configs/*.yaml │    │ policies/*.yaml  │
│  (infra state)  │    │ (compliance rules│
└────────┬────────┘    └────────┬────────┘
         │                      │
         ▼                      ▼
    loader.py               loader.py
  load_configs()          load_policies()
         │                      │
         └──────────┬───────────┘
                    ▼
              engine.py
          ComplianceEngine
                    │
          ┌─────────┴──────────┐
          │  Policy Index       │
          │  (resource_type,   │
          │   environment)     │
          │  → O(1) lookup     │
          └─────────┬──────────┘
                    │  for each service:
                    │    get_applicable_policies()
                    │    evaluate_policy()
                    │      evaluate_condition()  ← pure, stateless
                    ▼
              ScanResult
           (all violations)
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
   reporter.py           reporter.py
print_terminal_report  print_json_report
```

### Key Design Decisions

**Policy-as-code:** Policies live in YAML files versioned alongside the codebase.
Changes go through PR review, giving teams visibility into policy additions/modifications.

**Stateless evaluation:** `evaluate_condition()` takes a condition + service and returns
a result with no side effects. This makes the engine trivially testable and parallelizable.

**Policy indexing:** At load time, policies are indexed by `(resource_type, environment)`.
For each service, applicable policies are a direct dict lookup — O(1) regardless of how
many total policies exist. This keeps the engine fast even at thousands of services.

**Safe field resolution:** Dot-notation paths (`config.storage.encryption`) are resolved
with a sentinel `_MISSING` value (not `None`), so the engine can distinguish "field is
absent" from "field is present but false/zero." This prevents false-positive passes on
unset config keys.

**Dual output:** Terminal output with ANSI colors is piped to stdout; log messages go to
stderr. This means `python main.py --output json > report.json` cleanly captures only the
JSON with no noise.

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Compliance Scan
  run: |
    pip install -r requirements.txt
    python main.py --severity critical high
  # Exits 1 if critical/high violations found — fails the workflow
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
python main.py --severity critical --no-fail  # Warn but don't block commit
```

### Save JSON Report as Artifact

```yaml
- name: Run compliance scan
  run: python main.py --output json > compliance-report.json

- name: Upload report
  uses: actions/upload-artifact@v3
  with:
    name: compliance-report
    path: compliance-report.json
```

---

## Extending the Scanner

### Adding a New Policy

Create or edit a YAML file in `policies/`:

```yaml
policies:
  - id: SEC-008
    name: Databases Must Have SSL Enforced
    description: SSL connections must be required for all database connections.
    severity: high
    resource_type: database
    environment: null
    remediation: Set require_ssl to true in the DB parameter group.
    conditions:
      - field: config.require_ssl
        operator: equals
        value: true
        message: "require_ssl must be true."
```

No code changes needed. The loader picks up any `.yaml` file in the policies directory.

### Adding a New Service Type

Add entries to any config YAML file with a new `type` value (e.g., `type: queue`, 
`type: lambda`). Write policies that reference that resource type. Done.

### Adding a New Operator

In `scanner/engine.py`, add a new `Operator` enum value and handle it in the
`evaluate_condition()` function's if/elif chain.

### Plugging in a Live Cloud Data Source

The `loader.py` module is the only integration point. To pull live state from AWS,
implement a function with the same return signature as `load_configs()`:

```python
# scanner/aws_loader.py
import boto3
from scanner.models import Service

def load_configs_from_aws(region: str) -> list[Service]:
    rds = boto3.client("rds", region_name=region)
    instances = rds.describe_db_instances()["DBInstances"]
    return [_rds_instance_to_service(i) for i in instances]
```

Then pass the result directly to `ComplianceEngine.scan()`.

---

## Running the Tests

Unit tests are included to verify core engine behavior:

```bash
python -m unittest discover tests -v
```

> Tests cover: field resolution, all operator types (including edge cases like
> missing fields and type mismatches), AND/OR logic modes, policy scoping by
> environment, and the violation serialization format.

---

## Requirements

- Python 3.9+
- PyYAML 6.0+

No cloud credentials, no external services, no database required.

---

## What I Would Add With More Time

| Feature | Value |
|---|---|
| Live AWS/GCP/Azure adapters via cloud SDKs | True current state instead of snapshots |
| Historical scan storage (S3 + DynamoDB) | Trend tracking, regression detection |
| Slack/PagerDuty webhook on critical violations | Real-time alerting |
| Policy unit tests (pass/fail fixture per policy) | Prevent policy regressions |
| OPA/Rego integration for cross-resource rules | e.g., "DB must be in same VPC as its app" |
| Web dashboard with severity trends | Visibility for non-technical stakeholders |
| Parallel evaluation with `ThreadPoolExecutor` | Scale to thousands of services |
| Auto-remediation for safe fixes (tagging, flags) | Reduce mean-time-to-compliance |
