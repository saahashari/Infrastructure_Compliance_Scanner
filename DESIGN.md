# Infrastructure Compliance Scanner — System Design

**Author:** Saahas Hari
**Date:** March 2026 
**Scope:** Part 1 — System Design Document

---

## 1. Problem Statement

Uniphore operates hundreds of services across multi-environment cloud infrastructure
(dev, staging, production). Ensuring every service adheres to security, cost, and
operational policies manually is error-prone and does not scale. This document describes
a compliance scanning system that continuously evaluates infrastructure state against a
codified policy library and produces actionable violation reports.

---

## 2. Core Design Decisions & Assumptions

| Assumption | Rationale |
|---|---|
| Infrastructure config is represented as structured YAML/JSON | Mirrors real-world cloud provider outputs (AWS Config, Terraform state, `kubectl get -o json`) |
| Policies are stored as YAML files in version control | Human-readable, diffable, reviewable via PR — treats policy as code |
| A service has a `type`, `environment`, and nested `config` dict | Minimal but sufficient schema that maps to any cloud resource |
| The tool runs as a CLI and exits with code 1 if violations exist | Enables direct integration into CI/CD pipelines |
| Scaling to thousands of services is addressed architecturally, not implemented fully | Consistent with the 3-4 hour scope |

---

## 3. How Policies Are Defined and Stored

Policies live as YAML files in a `policies/` directory, grouped by category
(security, cost, operational). Each policy specifies:

- **`id`** — Unique, stable identifier (e.g., `SEC-001`) for tracking over time
- **`resource_type`** — Which resource type the policy targets (`database`, `compute`, `storage`)
- **`environment`** — Optional filter; `null` means the policy applies across all environments
- **`conditions`** — A list of field checks using dot-notation paths into the service config
- **`logic`** — `AND` (all must pass) or `OR` (any must pass)
- **`severity`** — `critical`, `high`, `medium`, `low` — drives prioritization in reports
- **`remediation`** — A human-readable fix suggestion included in every violation

**Example policy definition:**
```yaml
- id: SEC-001
  name: Production DB Backup Required
  severity: critical
  resource_type: database
  environment: production
  conditions:
    - field: config.backup_enabled
      operator: equals
      value: true
      message: "Automated backups must be enabled"
  remediation: "Enable automated backups in the database configuration panel."
```

**Supported operators:** `equals`, `not_equals`, `greater_than`, `less_than`,
`gte`, `lte`, `in`, `not_in`, `exists`, `not_exists`, `contains`, `not_contains`

---

## 4. Infrastructure Data Sources

**Current implementation (scoped for assessment):**
- YAML files in a `configs/` directory representing service state snapshots
- Format mirrors what you'd get from a Terraform state export or `aws rds describe-db-instances`

**Production extensions (what I would build next):**

| Source | How to Access | Notes |
|---|---|---|
| AWS Config | `boto3` + Config Rules API | Real-time resource inventory |
| Terraform state | `terraform show -json` | Works for any provider |
| Kubernetes | `kubectl get all -o json` | Pod/service configs |
| GCP Asset Inventory | `google-cloud-asset` SDK | Multi-cloud support |
| Azure Resource Graph | `azure-mgmt-resource` | |

The `loader.py` module acts as the integration boundary, so future cloud
adapters can return the same `Service` objects without changing the engine.

---

## 5. Rule Evaluation Engine

The engine follows a simple pipeline:

```
Load Policies → Load Services → Filter (type + env match) → Evaluate Conditions → Collect Violations
```

**Field resolution** uses dot-notation (`config.storage.encryption_enabled`) traversed
recursively, returning a sentinel (`_MISSING`) when a key is absent. This allows
`exists` / `not_exists` checks to distinguish missing fields from explicit falsey values.

**Condition evaluation** is pure and stateless — each condition returns a `ConditionResult`
with the actual vs. expected value, making it easy to explain exactly why a check failed.

**AND vs OR logic:** When `logic: AND`, all conditions must pass (default — conservative).
When `logic: OR`, at least one must pass (useful for "must use one of these approved instance types").

---

## 6. Reporting and Tracking Violations

The reporter outputs two formats:

**Terminal (default):** Colored, human-readable summary grouped by severity.
Each violation shows the service name, environment, rule ID, which specific field
failed, the actual vs. expected value, and the remediation step.

**JSON (`--output json`):** Machine-readable output for ingestion into dashboards,
Slack alerts, or ticketing systems like Jira. Suitable for CI/CD artifact storage.

**Exit codes:** `0` = fully compliant, `1` = one or more violations found.
This lets `make lint-infra` or a GitHub Actions step fail the build on compliance drift.

**Tracking over time (architectural extension):**
Store JSON scan results in S3 or a time-series DB (e.g., InfluxDB). Compare current
scan vs. previous to detect newly introduced violations (regressions) vs. pre-existing ones.
A violation first seen in a PR diff is far more actionable than one that has existed for months.

---

## 7. Scaling to Thousands of Services

| Challenge | Approach |
|---|---|
| Large number of services | Evaluate services in parallel using `concurrent.futures.ThreadPoolExecutor` |
| Large policy library | Pre-index policies by `(resource_type, environment)` at load time — O(1) lookup per service |
| Multiple cloud accounts | Run scanner as a distributed job; each account is an independent data source |
| Policy drift detection | Store scan results as immutable artifacts; diff consecutive scans |
| Policy authoring at scale | Policy linting/validation at PR time; schema validation via `jsonschema` |
| Real-time enforcement | Pair with AWS Config Rules or OPA/Gatekeeper for pre-admission checks |

**Bottleneck:** At thousands of services, the bottleneck shifts from evaluation logic
(which is CPU-light) to I/O — fetching infra state from cloud APIs. A caching layer
(e.g., Redis or DynamoDB with TTL) storing the last-known config per service reduces
redundant API calls on frequent scans.

---

## 8. Trade-offs and Limitations

| Trade-off | Decision | Alternative |
|---|---|---|
| YAML policies vs. OPA/Rego | YAML is simpler to author and review; Rego is more expressive for complex logic | Migrate to Rego for multi-condition interdependencies |
| Static config files vs. live cloud APIs | Static files are testable and reproducible; live APIs reflect true current state | Add cloud API adapters as the next milestone |
| AND/OR only, no nested logic | Covers ~90% of real policies with simpler code | Support `all_of` / `any_of` nesting for complex rules |
| No persistent violation database | Out of scope; scan results are ephemeral | PostgreSQL or S3 + Athena for historical trending |
| Single-process Python | Sufficient for hundreds of services | Add `asyncio` or worker queue (Celery) for thousands |

---

## 9. What I Would Add With More Time

1. **Cloud API adapters** — Pull live state from AWS (`boto3`), GCP, Azure instead of static YAML
2. **OPA/Rego integration** — For policies that require cross-resource reasoning
3. **Historical trending** — Store scan results in S3; detect regression vs. long-standing violations
4. **Slack/PagerDuty alerting** — Webhook integration for critical violations
5. **Policy unit tests** — Each policy ships with a passing and failing fixture to prevent regressions
6. **Web UI dashboard** — Violations browsable by team/environment/severity with trend graphs
7. **Auto-remediation** — For safe, low-risk fixes (e.g., enabling a tag), apply the fix via API with audit log
