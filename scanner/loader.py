"""
loader.py — Load infrastructure configs and compliance policies from YAML files.

Design note:
  The loader is intentionally separated from the engine. This means the engine
  never cares WHERE data comes from — only what shape it is. A future cloud API
  adapter (AWS Config, Terraform state, GCP Asset Inventory) only needs to produce
  the same Service and Policy objects; the engine works unchanged.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

from scanner.models import (
    Condition,
    LogicMode,
    Operator,
    Policy,
    Service,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require(data: Dict, key: str, context: str) -> Any:
    """Raise a clear error if a required YAML key is missing."""
    if key not in data:
        raise ValueError(f"[{context}] Missing required field: '{key}'")
    return data[key]


def _parse_operator(raw: str, context: str) -> Operator:
    """Parse an operator string into the Operator enum with a helpful error."""
    try:
        return Operator(raw)
    except ValueError:
        valid = [o.value for o in Operator]
        raise ValueError(
            f"[{context}] Unknown operator '{raw}'. Valid operators: {valid}"
        )


def _parse_severity(raw: str, context: str) -> Severity:
    try:
        return Severity(raw.lower())
    except ValueError:
        valid = [s.value for s in Severity]
        raise ValueError(
            f"[{context}] Unknown severity '{raw}'. Valid: {valid}"
        )


# ---------------------------------------------------------------------------
# Policy Loader
# ---------------------------------------------------------------------------

def _parse_condition(raw: Dict, policy_id: str, idx: int) -> Condition:
    """Parse a single condition dict from YAML into a Condition object."""
    ctx = f"policy={policy_id}, condition[{idx}]"
    field = _require(raw, "field", ctx)
    operator_str = _require(raw, "operator", ctx)
    operator = _parse_operator(operator_str, ctx)

    # EXISTS/NOT_EXISTS don't need a value
    value = raw.get("value", None)
    if operator not in (Operator.EXISTS, Operator.NOT_EXISTS) and value is None:
        # value=False and value=0 are valid — only truly absent is a problem
        if "value" not in raw:
            raise ValueError(
                f"[{ctx}] Operator '{operator.value}' requires a 'value' field."
            )

    return Condition(
        field=field,
        operator=operator,
        value=value,
        message=raw.get("message", ""),
    )


def _parse_policy(raw: Dict, source_file: str) -> Policy:
    """Parse a single policy dict from YAML into a Policy object."""
    ctx = f"file={source_file}, policy={raw.get('id', '?')}"
    policy_id = _require(raw, "id", ctx)
    name = _require(raw, "name", ctx)

    raw_conditions = _require(raw, "conditions", ctx)
    if not isinstance(raw_conditions, list) or len(raw_conditions) == 0:
        raise ValueError(f"[{ctx}] 'conditions' must be a non-empty list.")

    conditions = [
        _parse_condition(c, policy_id, i)
        for i, c in enumerate(raw_conditions)
    ]

    raw_logic = raw.get("logic", "AND").upper()
    try:
        logic = LogicMode(raw_logic)
    except ValueError:
        raise ValueError(f"[{ctx}] 'logic' must be AND or OR, got '{raw_logic}'")

    raw_environment = raw.get("environment", None)
    normalized_environment = (
        raw_environment.strip().lower()
        if isinstance(raw_environment, str)
        else None
    )

    return Policy(
        id=policy_id,
        name=name,
        description=raw.get("description", ""),
        severity=_parse_severity(_require(raw, "severity", ctx), ctx),
        resource_type=_require(raw, "resource_type", ctx).strip().lower(),
        conditions=conditions,
        environment=normalized_environment,
        logic=logic,
        remediation=raw.get("remediation", ""),
        tags=raw.get("tags", []),
    )


def load_policies(policies_dir: str) -> List[Policy]:
    """
    Load all YAML policy files from a directory.

    Each file can contain a top-level 'policies' list with one or more policies.
    Files that fail to parse are logged and skipped so one bad file doesn't
    break the entire scan.
    """
    policies_path = Path(policies_dir)
    if not policies_path.is_dir():
        raise FileNotFoundError(f"Policies directory not found: {policies_dir}")

    all_policies: List[Policy] = []
    yaml_files = sorted(policies_path.glob("*.yaml")) + sorted(policies_path.glob("*.yml"))

    if not yaml_files:
        logger.warning("No policy files found in %s", policies_dir)
        return []

    for filepath in yaml_files:
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)

            if not data or "policies" not in data:
                logger.warning("Skipping %s: no 'policies' key found.", filepath.name)
                continue

            raw_policies = data["policies"]
            if not isinstance(raw_policies, list):
                logger.warning("Skipping %s: 'policies' must be a list.", filepath.name)
                continue

            for raw_policy in raw_policies:
                try:
                    policy = _parse_policy(raw_policy, filepath.name)
                    all_policies.append(policy)
                    logger.debug("Loaded policy: %s (%s)", policy.id, policy.name)
                except (ValueError, KeyError) as e:
                    logger.error("Failed to parse policy in %s: %s", filepath.name, e)

        except yaml.YAMLError as e:
            logger.error("YAML parse error in %s: %s", filepath.name, e)
        except OSError as e:
            logger.error("Cannot read file %s: %s", filepath.name, e)

    # Check for duplicate IDs — each policy ID must be globally unique
    seen_ids: Dict[str, str] = {}
    unique_policies: List[Policy] = []
    for p in all_policies:
        if p.id in seen_ids:
            logger.warning(
                "Duplicate policy ID '%s' in '%s' (already loaded). Skipping.",
                p.id, seen_ids[p.id]
            )
        else:
            seen_ids[p.id] = p.name
            unique_policies.append(p)

    logger.info("Loaded %d policies from %d files.", len(unique_policies), len(yaml_files))
    return unique_policies


# ---------------------------------------------------------------------------
# Infrastructure Config Loader
# ---------------------------------------------------------------------------

def _parse_service(raw: Dict, source_file: str) -> Service:
    """Parse a single service dict from YAML into a Service object."""
    ctx = f"file={source_file}, service={raw.get('name', '?')}"
    name = _require(raw, "name", ctx)
    service_type = _require(raw, "type", ctx)
    environment = _require(raw, "environment", ctx)

    raw_config = raw.get("config", {})
    if not isinstance(raw_config, dict):
        raise ValueError(f"[{ctx}] 'config' must be a dict.")

    return Service(
        name=name,
        type=service_type.strip().lower(),
        environment=environment.strip().lower(),
        config=raw_config,
        region=raw.get("region", "us-east-1"),
        owner=raw.get("owner", "unknown"),
        tags=raw.get("tags", {}),
)


def load_configs(configs_dir: str) -> List[Service]:
    """
    Load all YAML infrastructure config files from a directory.

    Each file can contain a top-level 'services' list representing one
    environment's infrastructure snapshot.
    """
    configs_path = Path(configs_dir)
    if not configs_path.is_dir():
        raise FileNotFoundError(f"Configs directory not found: {configs_dir}")

    all_services: List[Service] = []
    yaml_files = sorted(configs_path.glob("*.yaml")) + sorted(configs_path.glob("*.yml"))

    if not yaml_files:
        logger.warning("No config files found in %s", configs_dir)
        return []

    for filepath in yaml_files:
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)

            if not data or "services" not in data:
                logger.warning("Skipping %s: no 'services' key found.", filepath.name)
                continue

            raw_services = data["services"]
            if not isinstance(raw_services, list):
                logger.warning("Skipping %s: 'services' must be a list.", filepath.name)
                continue

            for raw_svc in raw_services:
                try:
                    svc = _parse_service(raw_svc, filepath.name)
                    all_services.append(svc)
                    logger.debug("Loaded service: %s (%s/%s)", svc.name, svc.type, svc.environment)
                except (ValueError, KeyError) as e:
                    logger.error("Failed to parse service in %s: %s", filepath.name, e)

        except yaml.YAMLError as e:
            logger.error("YAML parse error in %s: %s", filepath.name, e)
        except OSError as e:
            logger.error("Cannot read file %s: %s", filepath.name, e)

    # Warn on duplicate service names within the same environment
    seen: Dict[str, str] = {}
    for svc in all_services:
        key = f"{svc.environment}:{svc.name}"
        if key in seen:
            logger.warning(
                "Duplicate service '%s' in environment '%s'. "
                "Both entries will be scanned; consider deduplicating the input snapshot.",
                svc.name, svc.environment
            )
        seen[key] = svc.name

    logger.info("Loaded %d services from %d files.", len(all_services), len(yaml_files))
    return all_services
