"""
Alerter — Phase 4 Email Notification Dispatcher

Sends email alerts via AWS SNS for compliance findings.
Supports severity-based routing:
  - Critical/High: Immediate email per finding
  - Medium/Low: Daily digest summary

Also sends scan completion heartbeats and scan failure alerts.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
ALERT_ENABLED = os.getenv("ALERT_ENABLED", "true").lower() == "true"
ALERT_MIN_SEVERITY = os.getenv("ALERT_MIN_SEVERITY", "medium")
CISO_DASHBOARD_URL = os.getenv("CISO_DASHBOARD_URL", "http://localhost:8443")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def _severity_meets_threshold(severity: str) -> bool:
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(ALERT_MIN_SEVERITY, 2)


def _get_sns_client():
    return boto3.client("sns", region_name=AWS_REGION)


# ---------------------------------------------------------------------------
# Core send function
# ---------------------------------------------------------------------------
def _publish(subject: str, message: str) -> bool:
    """Publish a message to the SNS topic. Returns True on success."""
    if not ALERT_ENABLED:
        logger.debug("Alerting disabled, skipping: %s", subject)
        return False

    if not SNS_TOPIC_ARN:
        logger.warning("SNS_TOPIC_ARN not set, cannot send alert: %s", subject)
        return False

    try:
        client = _get_sns_client()
        client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject limit
            Message=message,
        )
        logger.info("Alert sent: %s", subject)
        return True
    except (BotoCoreError, ClientError):
        logger.exception("Failed to send SNS alert: %s", subject)
        return False


# ---------------------------------------------------------------------------
# Finding alerts (immediate — critical/high only)
# ---------------------------------------------------------------------------
def alert_new_finding(finding: dict, source: str = "Prowler") -> bool:
    """Send an immediate email for a new critical/high finding."""
    severity = finding.get("severity", "medium")
    if not _severity_meets_threshold(severity) or severity not in ("critical", "high"):
        return False

    subject = f"[{severity.upper()}] {source}: {finding.get('title', 'Unknown')}"

    message = (
        f"NEW {severity.upper()} FINDING DETECTED\n"
        f"{'=' * 50}\n\n"
        f"Source:      {source}\n"
        f"Check:       {finding.get('check_id', 'N/A')}\n"
        f"Title:       {finding.get('title', 'N/A')}\n"
        f"Severity:    {severity.upper()}\n"
        f"Resource:    {finding.get('resource_arn', 'N/A')}\n"
        f"Region:      {finding.get('region', 'N/A')}\n"
        f"Service:     {finding.get('service', 'N/A')}\n\n"
        f"Description:\n{finding.get('description', 'N/A')}\n\n"
        f"Remediation:\n{finding.get('remediation', 'N/A')}\n\n"
        f"Dashboard: {CISO_DASHBOARD_URL}\n"
    )

    return _publish(subject, message)


def alert_regression(finding: dict, source: str = "Prowler") -> bool:
    """Alert when a previously remediated finding regresses."""
    severity = finding.get("severity", "medium")
    subject = f"[REGRESSION] {source}: {finding.get('title', 'Unknown')}"

    message = (
        f"FINDING REGRESSION — previously remediated, now failing again\n"
        f"{'=' * 50}\n\n"
        f"Source:      {source}\n"
        f"Check:       {finding.get('check_id', 'N/A')}\n"
        f"Title:       {finding.get('title', 'N/A')}\n"
        f"Severity:    {severity.upper()}\n"
        f"Resource:    {finding.get('resource_arn', 'N/A')}\n\n"
        f"This finding was previously resolved but has reappeared.\n"
        f"Investigate immediately.\n\n"
        f"Dashboard: {CISO_DASHBOARD_URL}\n"
    )

    return _publish(subject, message)


def alert_remediation(finding: dict, source: str = "Prowler") -> bool:
    """Send a positive notification when a critical/high finding is remediated."""
    severity = finding.get("severity", "medium")
    if severity not in ("critical", "high"):
        return False

    subject = f"[REMEDIATED] {source}: {finding.get('title', 'Unknown')}"

    message = (
        f"FINDING REMEDIATED\n"
        f"{'=' * 50}\n\n"
        f"Source:      {source}\n"
        f"Check:       {finding.get('check_id', 'N/A')}\n"
        f"Title:       {finding.get('title', 'N/A')}\n"
        f"Severity:    {severity.upper()}\n"
        f"Resource:    {finding.get('resource_arn', 'N/A')}\n\n"
        f"This finding has been successfully remediated.\n\n"
        f"Dashboard: {CISO_DASHBOARD_URL}\n"
    )

    return _publish(subject, message)


# ---------------------------------------------------------------------------
# Scan summary (completion heartbeat)
# ---------------------------------------------------------------------------
def alert_scan_complete(stats: dict, scan_type: str = "delta") -> bool:
    """Send scan completion summary email (heartbeat)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_new = stats.get("new", 0)
    total_remediated = stats.get("remediated", 0)
    total_errors = stats.get("errors", 0)

    subject = f"[SCAN COMPLETE] {scan_type.title()} scan — {now}"

    message = (
        f"PROWLER SCAN COMPLETED\n"
        f"{'=' * 50}\n\n"
        f"Scan type:     {scan_type}\n"
        f"Completed at:  {now}\n"
        f"Input file:    {stats.get('input_file', 'N/A')}\n\n"
        f"RESULTS:\n"
        f"  Total findings processed: {stats.get('total_findings', 0)}\n"
        f"  New findings:             {total_new}\n"
        f"  Updated (unchanged):      {stats.get('updated', 0)}\n"
        f"  Remediated:               {total_remediated}\n"
        f"  Skipped:                  {stats.get('skipped', 0)}\n"
        f"  Errors:                   {total_errors}\n\n"
    )

    if total_new > 0:
        message += f"ACTION REQUIRED: {total_new} new finding(s) need attention.\n"
    if total_remediated > 0:
        message += f"GOOD NEWS: {total_remediated} finding(s) were remediated.\n"
    if total_errors > 0:
        message += f"WARNING: {total_errors} error(s) during import.\n"

    message += f"\nDashboard: {CISO_DASHBOARD_URL}\n"

    return _publish(subject, message)


# ---------------------------------------------------------------------------
# Scan failure alert
# ---------------------------------------------------------------------------
def alert_scan_failure(error_message: str, scan_type: str = "delta") -> bool:
    """Alert when a Prowler or Wazuh scan fails."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    subject = f"[SCAN FAILURE] {scan_type.title()} scan failed — {now}"

    message = (
        f"SCAN FAILURE ALERT\n"
        f"{'=' * 50}\n\n"
        f"Scan type:   {scan_type}\n"
        f"Failed at:   {now}\n\n"
        f"Error:\n{error_message}\n\n"
        f"Investigate immediately. The compliance scan did not complete.\n"
        f"Check container logs: docker compose logs prowler glue-mapper\n"
    )

    return _publish(subject, message)


# ---------------------------------------------------------------------------
# Wazuh alert forwarding
# ---------------------------------------------------------------------------
def alert_wazuh_finding(finding: dict) -> bool:
    """Send an immediate email for a critical/high Wazuh alert."""
    severity = finding.get("severity", "medium")
    if severity not in ("critical", "high"):
        return False

    level = finding.get("level", 0)
    subject = f"[WAZUH {severity.upper()}] Level {level}: {finding.get('title', 'Unknown')}"

    message = (
        f"WAZUH SECURITY ALERT\n"
        f"{'=' * 50}\n\n"
        f"Alert Level: {level} ({severity.upper()})\n"
        f"Rule:        {finding.get('check_id', 'N/A')}\n"
        f"Title:       {finding.get('title', 'N/A')}\n"
        f"Agent:       {finding.get('agent_name', 'N/A')}\n"
        f"Resource:    {finding.get('resource_arn', 'N/A')}\n\n"
        f"Description:\n{finding.get('description', 'N/A')}\n\n"
    )

    if finding.get("fim_path"):
        message += f"FIM Path: {finding['fim_path']}\n\n"

    if finding.get("detail"):
        message += f"Log excerpt:\n{finding['detail'][:1000]}\n\n"

    message += f"Dashboard: {CISO_DASHBOARD_URL}\n"

    return _publish(subject, message)


# ---------------------------------------------------------------------------
# Daily digest (called by cron, reads scan summary file)
# ---------------------------------------------------------------------------
def send_daily_digest(summary_path: str) -> bool:
    """Send a daily digest email summarizing the latest scan results."""
    try:
        with open(summary_path) as f:
            stats = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logger.warning("No scan summary found at %s, skipping digest", summary_path)
        return False

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"[DAILY DIGEST] ISO 27001 Compliance Summary — {now}"

    message = (
        f"DAILY COMPLIANCE DIGEST\n"
        f"{'=' * 50}\n\n"
        f"Date: {now}\n"
        f"Last scan: {stats.get('timestamp', 'N/A')}\n\n"
        f"FINDINGS SUMMARY:\n"
        f"  Total processed: {stats.get('total_findings', 0)}\n"
        f"  New:             {stats.get('new', 0)}\n"
        f"  Updated:         {stats.get('updated', 0)}\n"
        f"  Remediated:      {stats.get('remediated', 0)}\n"
        f"  Errors:          {stats.get('errors', 0)}\n\n"
        f"Review the full dashboard: {CISO_DASHBOARD_URL}\n"
    )

    return _publish(subject, message)
