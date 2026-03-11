"""
SLA Tracker — Remediation SLA Compliance Module

Queries the DedupCache for open findings and checks whether they exceed
their severity-based remediation SLA windows.

SLA thresholds:
    Critical:  7 days
    High:     30 days
    Medium:   90 days
    Low:     180 days (next patch cycle)
"""

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SLA thresholds (days)
# ---------------------------------------------------------------------------
SLA_THRESHOLDS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "informational": 180,
}


def get_sla_days(severity: str) -> int:
    """Return the SLA window in days for a given severity."""
    return SLA_THRESHOLDS.get(severity.lower(), 180)


def check_sla_compliance(
    first_seen: str,
    severity: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Check whether a single finding is within its SLA window.

    Returns a dict with:
        overdue (bool): True if the SLA window has been exceeded
        days_open (int): Total days the finding has been open
        sla_days (int): The SLA window for this severity
        days_overdue (int): How many days past the SLA (0 if within SLA)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    try:
        first_seen_dt = datetime.fromisoformat(first_seen)
        if first_seen_dt.tzinfo is None:
            first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        logger.warning("Invalid first_seen timestamp: %s", first_seen)
        return {
            "overdue": False,
            "days_open": 0,
            "sla_days": get_sla_days(severity),
            "days_overdue": 0,
        }

    days_open = (now - first_seen_dt).days
    sla_days = get_sla_days(severity)
    days_overdue = max(0, days_open - sla_days)

    return {
        "overdue": days_overdue > 0,
        "days_open": days_open,
        "sla_days": sla_days,
        "days_overdue": days_overdue,
    }


def get_overdue_findings(
    cache,
    severity_map: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Query the DedupCache for all FAIL findings and return those past SLA.

    Args:
        cache: A DedupCache instance (from prowler_mapper).
        severity_map: Optional dict mapping (resource_arn, check_id) -> severity string.
                      If not provided, defaults to "medium" for unknown entries.

    Returns:
        List of dicts with: resource_arn, check_id, ciso_id, severity,
        days_open, sla_days, days_overdue, first_seen.
    """
    if severity_map is None:
        severity_map = {}

    now = datetime.now(timezone.utc)
    failing = cache.get_all_failing()
    overdue: list[dict[str, Any]] = []

    for entry in failing:
        resource_arn = entry["resource_arn"]
        check_id = entry["check_id"]
        ciso_id = entry["ciso_id"]

        # Look up the full record for first_seen
        record = cache.get(resource_arn, check_id)
        if record is None:
            continue

        key = (resource_arn, check_id)
        severity = severity_map.get(key, "medium")

        sla_result = check_sla_compliance(record["first_seen"], severity, now)

        if sla_result["overdue"]:
            overdue.append({
                "resource_arn": resource_arn,
                "check_id": check_id,
                "ciso_id": ciso_id,
                "severity": severity,
                "first_seen": record["first_seen"],
                "days_open": sla_result["days_open"],
                "sla_days": sla_result["sla_days"],
                "days_overdue": sla_result["days_overdue"],
            })

    logger.info(
        "SLA check: %d failing findings, %d overdue",
        len(failing),
        len(overdue),
    )
    return overdue
