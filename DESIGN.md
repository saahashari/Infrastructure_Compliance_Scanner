# Infrastructure Compliance Scanner — System Design

**Author:** Saahas Hari  
**Date:** March 2026  
**Repository:** github.com/saahashari/Infrastructure_Compliance_Scanner

---

## 1. Problem Statement

Uniphore operates hundreds of services across multi-environment cloud infrastructure
(dev, staging, production). Ensuring every service adheres to security, cost, and
operational policies manually is error-prone and does not scale. This document describes
a compliance scanning system that evaluates infrastructure state against a codified
policy library and produces actionable violation reports.

---

## 2. Core Design Decisions & Assumptions

| Assumption | Rationale |
|---|---|
| Infrastructure config is represented as structured YAML/JSON | Mirrors real-world cloud provider outputs (AWS Config, Terraform state, `kubectl get -o json`) |
| Policies are stored as YAML files in version control | Human-readable, diffable, reviewable via PR — treats policy as code |
| A service has a `type`, `environment`, and nested `config` dict | Minimal but sufficient schema that maps to any cloud resource type |
| The tool runs as a CLI and exits with code 1 if violations exist | Enables direct integration into CI/CD pipelines as a blocking gate |
| Scaling to thousands of services is addressed architecturally, not fully implemented | Consistent with the 3–4 hour assessment scope |

---

## 3. How Policies Are Defined and Stored

Policies live as YAML files in a `policies/` directory, grouped by category
(security, cost, operational). Storing policies as code means changes go through
pull request review, giving teams full visibility into what rules are being added
or modified.

Each policy specifies:

- **`id`** — Unique, stable identifier (e.g., `SEC-001`) for consistent tracking over time
- **`resource_type`** — Which resource type the policy targets (`database`, `compute`, `storage`)
- **`environment`** — Optional scope filter; `null` means the policy applies across all environments
- **`conditions`** — A list of field checks using dot-notation paths into the service config
- **`logic`** — `AND` (all conditions must pass, default) or `OR` (at least one must pass)
- **`severity`** — `critical`, `high`, `medium`, `low` — drives prioritization in violation reports
- **`remediation`** — A human-readable fix suggestion attached to every violation output

**Example policy definition:**
```yaml
policies:
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

**Current implementation (scoped for this assessment):**
- YAML files in a `configs/` directory representing point-in-time service state snapshots
- Format mirrors what you would get from a Terraform state export or
`aws rds describe-db-instances`

**Production extensions I would build next:**

| Source | How to Access | Notes |
|---|---|---|
| AWS Config | `boto3` + Config Rules API | Real-time resource inventory |
| Terraform state | `terraform show -json` | Works for any cloud provider |
| Kubernetes | `kubectl get all -o json` | Pod and service configurations |
| GCP Asset Inventory | `google-cloud-asset` SDK | Multi-cloud support |
| Azure Resource Graph | `azure-mgmt-resource` SDK | |

The `loader.py` module acts as the sole integration boundary between data sources
and the engine. Any future cloud API adapter only needs to return the same `Service`
objects — the engine works unchanged.

---

## 5. Rule Evaluation Engine

The engine follows a straightforward pipeline:
```
Load Policies → Load Services → Filter (type + env match) → Evaluate Conditions → Collect Violations
```

**Policy indexing:** At startup, policies are indexed by `(resource_type, environment)`.
For each service, applicable policies are retrieved in O(1) time regardless of how
large the policy library grows.

**Field resolution:** Dot-notation paths (e.g., `config.storage.encryption_enabled`)
are traversed recursively using a sentinel value (`_MISSING`) to distinguish a field
that is absent from one that is explicitly `False` or `0`. This is critical — a field
set to `False` should fail an `equals: true` check, but pass an `exists` check, and
these are different outcomes.

**Condition evaluation:** Each condition evaluation is pure and stateless — it takes
a condition and a service, returns a `ConditionResult` with the actual vs. expected
value, and has no side effects. This makes the engine trivially testable and safe
to parallelize.

**AND vs OR logic:** `AND` requires all conditions to pass (conservative default).
`OR` requires at least one to pass, which is useful for rules like
"TLS version must be 1.2 or 1.3."

---

## 6. Reporting and Tracking Violations

The reporter supports two output formats:

**Terminal (default):** ANSI-colored, human-readable report grouped by severity
(critical → high → medium → low). Each violation shows the service name, environment,
rule ID, the specific field that failed, the actual vs. expected value, and the
remediation step.

**JSON (`--output json`):** Fully machine-readable output suitable for ingestion
into dashboards, Slack alert webhooks, or ticketing systems like Jira. Piping stdout
keeps the output clean since all logging goes to stderr.

**Exit codes:** `0` = fully compliant, `1` = one or more violations found. This
allows a GitHub Actions step or `make lint-infra` command to fail the build
automatically on compliance drift.

**Tracking violations over time (architectural extension):** Store JSON scan results
as immutable artifacts in S3, keyed by timestamp and environment. Diffing consecutive
scans surfaces newly introduced violations (regressions from a PR) separately from
pre-existing ones. A regression caught in a PR diff is far more actionable than a
violation that has existed for months.

---

## 7. Scaling to Thousands of Services

| Challenge | Approach |
|---|---|
| Large number of services | Evaluate services in parallel using `concurrent.futures.ThreadPoolExecutor` |
| Large policy library | Pre-index policies by `(resource_type, environment)` at load time — O(1) lookup per service |
| Multiple cloud accounts | Run scanner as a distributed job; each account is an independent, isolated data source |
| Policy drift detection | Store scan results as immutable artifacts; diff consecutive scans to detect regressions |
| Policy authoring at scale | Schema validation via `jsonschema` at PR time; each policy ships with a passing and failing fixture |
| Real-time enforcement | Pair with AWS Config Rules or OPA/Gatekeeper for pre-admission checks before resources are created |

**Primary bottleneck:** At thousands of services, the bottleneck shifts from evaluation
logic (which is CPU-light) to I/O — fetching infrastructure state from cloud APIs.
A caching layer (Redis or DynamoDB with TTL) storing the last-known config per service
reduces redundant API calls on frequent scan intervals.

---

## 8. Trade-offs and Limitations

| Trade-off | Decision Made | Alternative |
|---|---|---|
| YAML policies vs. OPA/Rego | YAML is simpler to author and review; lower barrier for non-engineers | Migrate to Rego for cross-resource rules and complex interdependencies |
| Static config files vs. live cloud APIs | Static files are reproducible and fully testable without credentials | Add cloud API adapters as the immediate next milestone |
| AND/OR only, no nested logic | Covers ~90% of real-world policies with significantly simpler code | Support `all_of` / `any_of` nesting for multi-conditional rules |
| No persistent violation database | Out of scope for this assessment; scan results are ephemeral | PostgreSQL or S3 + Athena for historical trending and compliance reporting |
| Single-process Python | Sufficient for hundreds of services within the assessment scope | Add `asyncio` or a worker queue (Celery) for production scale |

---

## 9. What I Would Add With More Time

1. **Live cloud API adapters** — Pull real-time state from AWS (`boto3`), GCP, and
Azure instead of static YAML snapshots
2. **OPA/Rego integration** — For policies requiring cross-resource reasoning
(e.g., "this database must be in the same VPC as its application tier")
3. **Historical trending and regression detection** — Store scan results in S3;
diff consecutive scans to distinguish new violations from pre-existing ones
4. **Slack/PagerDuty alerting** — Webhook integration that fires immediately on
any new critical violation
5. **Policy-level unit tests** — Each policy ships with a compliant fixture and a
violating fixture to prevent silent regressions when policies are edited
6. **Web UI dashboard** — Violations browsable by team, environment, and severity
with trend graphs over time
7. **Safe auto-remediation** — For low-risk, reversible fixes (e.g., adding a
missing tag, flipping a boolean flag), apply the fix automatically via API with
a full audit log