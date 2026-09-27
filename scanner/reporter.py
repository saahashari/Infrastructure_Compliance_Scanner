"""
reporter.py — Format and output compliance scan results.

Supports two output modes:
  - Terminal: colored, human-readable report grouped by severity
  - JSON: machine-readable for CI/CD artifact storage, dashboards, or alerting

ANSI color codes are used directly (no external deps) so the tool works
anywhere Python runs, including CI runners.
"""

import json
import math
import sys
from typing import Dict, List, TextIO

from scanner.models import ScanResult, Severity, Violation


# ---------------------------------------------------------------------------
# ANSI Color Codes
# ---------------------------------------------------------------------------

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    ORANGE  = "\033[33m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"

    @staticmethod
    def strip_if_no_tty(text: str, stream: TextIO) -> str:
        """Remove ANSI codes when writing to a non-terminal (e.g., piped output)."""
        if not hasattr(stream, "isatty") or not stream.isatty():
            import re
            return re.sub(r"\033\[[0-9;]*m", "", text)
        return text


def _colorize_severity(severity: Severity) -> str:
    """Return severity string formatted with the appropriate color."""
    mapping = {
        Severity.CRITICAL: Color.RED + Color.BOLD,
        Severity.HIGH:     Color.ORANGE + Color.BOLD,
        Severity.MEDIUM:   Color.YELLOW,
        Severity.LOW:      Color.CYAN,
    }
    color = mapping.get(severity, Color.WHITE)
    return f"{color}{severity.value.upper()}{Color.RESET}"


# ---------------------------------------------------------------------------
# Terminal Reporter
# ---------------------------------------------------------------------------

def _print(text: str, stream: TextIO = sys.stdout) -> None:
    print(Color.strip_if_no_tty(text, stream), file=stream)


def _divider(char: str = "─", width: int = 70) -> str:
    return Color.DIM + char * width + Color.RESET


def _print_violation(v: Violation, index: int, stream: TextIO) -> None:
    """Print a single violation with full context."""
    sev = _colorize_severity(v.severity)
    _print("", stream)
    _print(
        f"  {Color.BOLD}[{index}] {v.policy.id}{Color.RESET}  {sev}  "
        f"{Color.DIM}|{Color.RESET}  {Color.WHITE}{v.policy.name}{Color.RESET}",
        stream
    )
    _print(f"      {Color.DIM}Service   :{Color.RESET} {Color.BOLD}{v.service.name}{Color.RESET}", stream)
    _print(f"      {Color.DIM}Type      :{Color.RESET} {v.service.type}", stream)
    _print(f"      {Color.DIM}Env       :{Color.RESET} {v.service.environment}", stream)
    _print(f"      {Color.DIM}Region    :{Color.RESET} {v.service.region}", stream)
    _print(f"      {Color.DIM}Owner     :{Color.RESET} {v.service.owner}", stream)

    if v.policy.description:
        _print(f"      {Color.DIM}Policy    :{Color.RESET} {v.policy.description}", stream)

    _print(f"      {Color.DIM}Conditions failed:{Color.RESET}", stream)
    for cr in v.failed_conditions:
        indicator = f"{Color.RED}✗{Color.RESET}"
        _print(
            f"        {indicator} {Color.YELLOW}{cr.condition.field}{Color.RESET} "
            f"[{cr.condition.operator.value}]  →  {cr.message}",
            stream
        )

    if v.policy.remediation:
        _print(
            f"      {Color.CYAN}→ Fix:{Color.RESET} {v.policy.remediation}",
            stream
        )


def print_terminal_report(result: ScanResult, stream: TextIO = sys.stdout) -> None:
    """
    Print a full compliance report to the terminal.

    Structure:
      - Header with scan metadata
      - Summary statistics
      - Violations grouped by severity (critical → high → medium → low)
      - Footer with compliance status
    """
    _print("", stream)
    _print(_divider("═"), stream)
    _print(
        f"  {Color.BOLD}{Color.WHITE}INFRASTRUCTURE COMPLIANCE SCANNER{Color.RESET}",
        stream
    )
    _print(_divider("═"), stream)
    _print(f"  {Color.DIM}Scan time  :{Color.RESET} {result.scan_timestamp}", stream)
    _print(f"  {Color.DIM}Services   :{Color.RESET} {result.total_services}", stream)
    _print(f"  {Color.DIM}Policies   :{Color.RESET} {result.total_policies}", stream)
    _print("", stream)

    # --- Summary ---
    _print(_divider(), stream)
    _print(f"  {Color.BOLD}SUMMARY{Color.RESET}", stream)
    _print(_divider(), stream)

    bysev = result.violations_by_severity
    _print(
        f"  {Color.RED}Critical: {bysev['critical']:>3}{Color.RESET}   "
        f"{Color.ORANGE}High: {bysev['high']:>3}{Color.RESET}   "
        f"{Color.YELLOW}Medium: {bysev['medium']:>3}{Color.RESET}   "
        f"{Color.CYAN}Low: {bysev['low']:>3}{Color.RESET}",
        stream
    )
    _print("", stream)
    _print(f"  Total violations : {Color.BOLD}{result.total_violations}{Color.RESET}", stream)
    _print(f"  Compliant svcs   : {Color.GREEN}{result.compliant_services}{Color.RESET} / {result.total_services}", stream)
    _print(f"  Scanned svcs     : {result.scanned_services} / {result.total_services}", stream)
    _print(f"  Unscanned svcs   : {len(result.unscanned_services)}", stream)

    if result.is_compliant():
        _print("", stream)
        _print(_divider("═"), stream)
        _print(
            f"  {Color.GREEN}{Color.BOLD}✓ ALL SERVICES COMPLIANT{Color.RESET}",
            stream
        )
        _print(_divider("═"), stream)
        _print("", stream)
        return

    # --- Violations grouped by severity ---
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

    for severity in severity_order:
        group = [v for v in result.violations if v.severity == severity]
        if not group:
            continue

        _print("", stream)
        _print(_divider(), stream)
        _print(
            f"  {_colorize_severity(severity)}  ({len(group)} violation{'s' if len(group) != 1 else ''})",
            stream
        )
        _print(_divider(), stream)

        for i, violation in enumerate(group, 1):
            _print_violation(violation, i, stream)

    if result.unscanned_services:
        _print("", stream)
        _print(_divider(), stream)
        _print(f"  {Color.RED}{Color.BOLD}UNSCANNED SERVICES{Color.RESET}", stream)
        _print(_divider(), stream)
        for service in result.unscanned_services:
            _print(
                f"  {service.name} ({service.type}/{service.environment}) has no applicable policy.",
                stream,
            )

    # --- Footer ---
    _print("", stream)
    _print(_divider("═"), stream)
    status = f"{result.total_violations} violation(s) found across {result.total_services} service(s)."
    if result.unscanned_services:
        status = (
            f"{result.total_violations} violation(s) and "
            f"{len(result.unscanned_services)} unscanned service(s) "
            f"across {result.total_services} service(s)."
        )
    _print(
        f"  {Color.RED}{Color.BOLD}✗ {status}{Color.RESET}",
        stream
    )
    _print(_divider("═"), stream)
    _print("", stream)


# ---------------------------------------------------------------------------
# JSON Reporter
# ---------------------------------------------------------------------------

def _json_safe(value):
    """Preserve non-finite measurements as strings in standards-compliant JSON."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def print_json_report(result: ScanResult, stream: TextIO = sys.stdout) -> None:
    """
    Output the scan result as a formatted JSON document.

    Suitable for:
      - CI/CD artifact storage (e.g., save as compliance-report.json)
      - Dashboard ingestion
      - Diff-based regression detection
      - Slack/PagerDuty alerting webhooks
    """
    payload = result.to_dict()
    json.dump(_json_safe(payload), stream, indent=2, default=str, allow_nan=False)
    stream.write("\n")
