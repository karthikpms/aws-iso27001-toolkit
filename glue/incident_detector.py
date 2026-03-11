#!/usr/bin/env python3
"""
Incident Auto-Detection and Logging

Polls GuardDuty, CloudTrail, and SecurityHub for security incidents,
maps them to ISO 27001 controls, and creates findings in CISO Assistant.

Usage:
    python incident_detector.py
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from alerter import (
    alert_new_finding,
    alert_scan_complete,
    alert_scan_failure,
)
from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("incident_detector")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
LAST_RUN_PATH = os.getenv(
    "INCIDENT_LAST_RUN_PATH", "/data/glue/incident_detector_last_run.json"
)
SCAN_SUMMARY_PATH = os.getenv(
    "INCIDENT_SUMMARY_PATH", "/data/glue/incident_detector_summary.json"
)
RULES_FILE = Path(__file__).parent / "mappings" / "incident_rules.json"
FINDINGS_ASSESSMENT_NAME = "Security Incidents"

# ---------------------------------------------------------------------------
# Rules loader
# ---------------------------------------------------------------------------


def load_rules(rules_file: Path) -> dict:
    """Load the incident detection rules."""
    with open(rules_file) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Last-run timestamp tracking
# ---------------------------------------------------------------------------


def load_last_run() -> datetime:
    """Load the last run timestamp, defaulting to 15 minutes ago."""
    try:
        with open(LAST_RUN_PATH) as f:
            data = json.load(f)
        ts = data.get("last_run")
        if ts:
            return datetime.fromisoformat(ts)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        pass
    return datetime.now(timezone.utc) - timedelta(minutes=15)


def save_last_run(ts: datetime) -> None:
    """Persist the last run timestamp."""
    os.makedirs(os.path.dirname(LAST_RUN_PATH), exist_ok=True)
    with open(LAST_RUN_PATH, "w") as f:
        json.dump({"last_run": ts.isoformat()}, f)


# ---------------------------------------------------------------------------
# Severity helpers (mirrors prowler_mapper.py)
# ---------------------------------------------------------------------------

_SEVERITY_TO_PRIORITY = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "informational": 4,
}

_SEVERITY_TO_FINDING_SEVERITY = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


def _guardduty_severity_to_label(numeric: float) -> str:
    """Map GuardDuty numeric severity to a label."""
    if numeric >= 7.0:
        return "critical"
    elif numeric >= 4.0:
        return "high"
    elif numeric >= 1.0:
        return "medium"
    return "low"


def _should_alert_immediately(severity_label: str, gd_severity: float | None = None) -> bool:
    """Return True if the finding warrants an immediate SNS alert."""
    if gd_severity is not None and gd_severity >= 7.0:
        return True
    return severity_label in ("critical", "high")


# ---------------------------------------------------------------------------
# CISO Assistant integration (same patterns as prowler_mapper.py)
# ---------------------------------------------------------------------------


def ensure_project(client: CISOClient, name: str) -> str:
    """Get or create the CISO Assistant project (folder)."""
    projects = client.list_projects()
    for p in projects:
        if p.get("name") == name:
            logger.info("Using existing project: %s (id=%s)", name, p["id"])
            return p["id"]
    project = client.create_project(name)
    logger.info("Created project: %s (id=%s)", name, project["id"])
    return project["id"]


def ensure_findings_assessment(
    client: CISOClient, folder_id: str, name: str = FINDINGS_ASSESSMENT_NAME
) -> str:
    """Get or create a findings assessment for security incidents."""
    assessments = client.list_findings_assessments()
    for a in assessments:
        if a.get("name") == name:
            logger.info(
                "Using existing findings assessment: %s (id=%s)", name, a["id"]
            )
            return a["id"]
    assessment = client.create_findings_assessment(
        {
            "name": name,
            "description": "Automated incident findings from GuardDuty, CloudTrail, and SecurityHub",
            "folder": folder_id,
            "category": "audit",
        }
    )
    logger.info("Created findings assessment: %s (id=%s)", name, assessment["id"])
    return assessment["id"]


# ---------------------------------------------------------------------------
# GuardDuty Polling
# ---------------------------------------------------------------------------


def _get_guardduty_detector(gd_client: Any) -> str | None:
    """Get the existing GuardDuty detector ID, or None if not enabled."""
    try:
        resp = gd_client.list_detectors()
        detector_ids = resp.get("DetectorIds", [])
        if detector_ids:
            return detector_ids[0]
        logger.info("No GuardDuty detector found — skipping GuardDuty polling")
        return None
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list GuardDuty detectors — skipping")
        return None


def poll_guardduty(since: datetime, rules: dict) -> list[dict]:
    """Poll GuardDuty for findings updated since the given timestamp."""
    gd_client = boto3.client("guardduty", region_name=AWS_REGION)

    detector_id = _get_guardduty_detector(gd_client)
    if not detector_id:
        return []

    since_ms = int(since.timestamp() * 1000)
    finding_criteria = {
        "Criterion": {
            "updatedAt": {
                "GreaterThanOrEqual": since_ms,
            }
        }
    }

    # Paginate through finding IDs
    all_finding_ids: list[str] = []
    next_token = ""
    try:
        while True:
            kwargs: dict[str, Any] = {
                "DetectorId": detector_id,
                "FindingCriteria": finding_criteria,
                "MaxResults": 50,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = gd_client.list_findings(**kwargs)
            all_finding_ids.extend(resp.get("FindingIds", []))
            next_token = resp.get("NextToken", "")
            if not next_token:
                break
    except (BotoCoreError, ClientError):
        logger.exception("Error listing GuardDuty findings")
        return []

    if not all_finding_ids:
        logger.info("No new GuardDuty findings since %s", since.isoformat())
        return []

    logger.info("Found %d GuardDuty finding IDs", len(all_finding_ids))

    # Fetch details in batches of 50
    normalized: list[dict] = []
    gd_rules = rules.get("guardduty", {})
    iso_controls_cfg = gd_rules.get("iso_controls", {})
    default_controls = iso_controls_cfg.get("default", ["A.5.24", "A.5.25", "A.5.26", "A.5.28"])
    type_overrides = iso_controls_cfg.get("type_overrides", {})

    for i in range(0, len(all_finding_ids), 50):
        batch = all_finding_ids[i : i + 50]
        try:
            resp = gd_client.get_findings(
                DetectorId=detector_id, FindingIds=batch
            )
        except (BotoCoreError, ClientError):
            logger.exception("Error fetching GuardDuty finding details batch %d", i)
            continue

        for f in resp.get("Findings", []):
            gd_severity = f.get("Severity", 0)
            severity_label = _guardduty_severity_to_label(gd_severity)
            finding_type = f.get("Type", "Unknown")

            # Determine ISO controls based on finding type prefix
            type_prefix = finding_type.split(":")[0] if ":" in finding_type else finding_type.split("/")[0]
            controls = type_overrides.get(type_prefix, default_controls)

            resource = f.get("Resource", {})
            resource_type = resource.get("ResourceType", "Unknown")
            resource_arn = "unknown"
            if resource_type == "Instance":
                instance = resource.get("InstanceDetails", {})
                resource_arn = instance.get("InstanceId", "unknown")
            elif resource_type == "AccessKey":
                ak = resource.get("AccessKeyDetails", {})
                resource_arn = ak.get("PrincipalId", ak.get("UserName", "unknown"))
            elif resource_type == "S3Bucket":
                s3 = resource.get("S3BucketDetails", [{}])
                if s3:
                    resource_arn = s3[0].get("Arn", s3[0].get("Name", "unknown"))
            else:
                resource_arn = f.get("Arn", "unknown")

            normalized.append(
                {
                    "source": "GuardDuty",
                    "source_id": f.get("Id", ""),
                    "dedup_key": (resource_arn, f"guardduty:{f.get('Id', '')}"),
                    "title": f"[GuardDuty] {finding_type}",
                    "description": f.get("Description", ""),
                    "severity": severity_label,
                    "gd_severity": gd_severity,
                    "resource_arn": resource_arn,
                    "region": f.get("Region", AWS_REGION),
                    "iso_controls": controls,
                    "raw_type": finding_type,
                    "updated_at": f.get("UpdatedAt", ""),
                }
            )

    logger.info("Normalized %d GuardDuty findings", len(normalized))
    return normalized


# ---------------------------------------------------------------------------
# CloudTrail Event Polling
# ---------------------------------------------------------------------------


def _is_root_event(event: dict) -> bool:
    """Check if the event was performed by the root account."""
    username = event.get("Username", "")
    return username == "root" or username.endswith(":root")


def _is_admin_policy(event: dict) -> bool:
    """Check if an AttachUserPolicy/AttachRolePolicy event grants admin access."""
    detail = event.get("CloudTrailEvent", "")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except json.JSONDecodeError:
            return False
    req_params = detail.get("requestParameters", {}) if isinstance(detail, dict) else {}
    policy_arn = req_params.get("policyArn", "")
    admin_policies = [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
    ]
    return any(p in policy_arn for p in admin_policies)


def _is_open_sg_rule(event: dict) -> bool:
    """Check if AuthorizeSecurityGroupIngress opens sensitive ports to 0.0.0.0/0."""
    detail = event.get("CloudTrailEvent", "")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except json.JSONDecodeError:
            return False
    req_params = detail.get("requestParameters", {}) if isinstance(detail, dict) else {}
    ip_permissions = req_params.get("ipPermissions", {}).get("items", [])
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 6379, 27017, 9200}

    for perm in ip_permissions:
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 0)
        ip_ranges = perm.get("ipRanges", {}).get("items", [])
        for ip_range in ip_ranges:
            cidr = ip_range.get("cidrIp", "")
            if cidr == "0.0.0.0/0":
                for port in sensitive_ports:
                    if from_port <= port <= to_port:
                        return True
    return False


def _passes_filter(event: dict, event_name: str, filter_type: str) -> bool:
    """Apply the filter logic defined in incident_rules.json."""
    if filter_type == "always":
        return True
    if filter_type == "root_only":
        return _is_root_event(event)
    if filter_type == "admin_access":
        return _is_admin_policy(event)
    if filter_type == "open_access":
        return _is_open_sg_rule(event)
    if filter_type == "public_access":
        # PutBucketPolicy — always flag for review
        return True
    if filter_type == "disabled_block":
        return True
    return True


def poll_cloudtrail(since: datetime, rules: dict) -> list[dict]:
    """Poll CloudTrail for suspicious events since the given timestamp."""
    ct_client = boto3.client("cloudtrail", region_name=AWS_REGION)
    ct_rules = rules.get("cloudtrail", {})
    monitored = ct_rules.get("monitored_events", {})

    if not monitored:
        logger.info("No CloudTrail events configured for monitoring")
        return []

    normalized: list[dict] = []

    for event_name, event_cfg in monitored.items():
        try:
            events: list[dict] = []
            next_token = ""

            while True:
                kwargs: dict[str, Any] = {
                    "LookupAttributes": [
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    "StartTime": since,
                    "EndTime": datetime.now(timezone.utc),
                    "MaxResults": 50,
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                resp = ct_client.lookup_events(**kwargs)
                events.extend(resp.get("Events", []))
                next_token = resp.get("NextToken", "")
                if not next_token:
                    break

            for event in events:
                if not _passes_filter(event, event_name, event_cfg.get("filter", "always")):
                    continue

                event_id = event.get("EventId", "")
                event_source = event.get("EventSource", "cloudtrail")
                resource_arn = "unknown"
                ct_resources = event.get("Resources", [])
                if ct_resources:
                    resource_arn = ct_resources[0].get("ResourceName", "unknown")

                normalized.append(
                    {
                        "source": "CloudTrail",
                        "source_id": event_id,
                        "dedup_key": (event_source, f"cloudtrail:{event_id}"),
                        "title": f"[CloudTrail] {event_cfg['description']}",
                        "description": (
                            f"Event: {event_name}\n"
                            f"Source: {event_source}\n"
                            f"User: {event.get('Username', 'N/A')}\n"
                            f"Time: {event.get('EventTime', 'N/A')}\n"
                            f"Resource: {resource_arn}"
                        ),
                        "severity": event_cfg.get("severity", "medium"),
                        "gd_severity": None,
                        "resource_arn": resource_arn,
                        "region": AWS_REGION,
                        "iso_controls": event_cfg.get("iso_controls", ["A.5.24", "A.8.15"]),
                        "raw_type": event_name,
                        "updated_at": str(event.get("EventTime", "")),
                    }
                )

        except (BotoCoreError, ClientError):
            logger.exception("Error polling CloudTrail for event: %s", event_name)

    logger.info("Normalized %d CloudTrail findings", len(normalized))
    return normalized


# ---------------------------------------------------------------------------
# SecurityHub Polling
# ---------------------------------------------------------------------------


def poll_securityhub(since: datetime, rules: dict) -> list[dict]:
    """Poll SecurityHub for CRITICAL/HIGH findings not already from GuardDuty."""
    sh_client = boto3.client("securityhub", region_name=AWS_REGION)
    sh_rules = rules.get("securityhub", {})
    severity_filter = sh_rules.get("severity_filter", ["CRITICAL", "HIGH"])
    controls_by_type = sh_rules.get("iso_controls_by_type", {})
    default_controls = sh_rules.get("default_iso_controls", ["A.5.24", "A.5.25"])

    filters: dict[str, Any] = {
        "SeverityLabel": [{"Value": s, "Comparison": "EQUALS"} for s in severity_filter],
        "UpdatedAt": [
            {"Start": since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "DateRange": None}
        ],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        # Exclude GuardDuty findings (already captured separately)
        "ProductName": [{"Value": "GuardDuty", "Comparison": "NOT_EQUALS"}],
    }
    # Fix: UpdatedAt needs proper filter format
    filters["UpdatedAt"] = [
        {
            "Start": since.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "End": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
    ]

    normalized: list[dict] = []

    try:
        next_token = ""
        while True:
            kwargs: dict[str, Any] = {
                "Filters": filters,
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = sh_client.get_findings(**kwargs)

            for f in resp.get("Findings", []):
                finding_id = f.get("Id", "")
                severity_label_raw = f.get("Severity", {}).get("Label", "MEDIUM")
                severity_label = severity_label_raw.lower()
                if severity_label == "informational":
                    severity_label = "informational"

                # Get resource ARN
                resources = f.get("Resources", [{}])
                resource_arn = resources[0].get("Id", "unknown") if resources else "unknown"

                # Map to ISO controls based on finding type
                finding_types = f.get("Types", [])
                controls = default_controls
                for ft in finding_types:
                    category = ft.split("/")[0] if "/" in ft else ft
                    if category in controls_by_type:
                        controls = controls_by_type[category]
                        break

                title_raw = f.get("Title", "Unknown SecurityHub Finding")

                normalized.append(
                    {
                        "source": "SecurityHub",
                        "source_id": finding_id,
                        "dedup_key": (resource_arn, f"securityhub:{finding_id}"),
                        "title": f"[SecurityHub] {title_raw}"[:200],
                        "description": (
                            f"Product: {f.get('ProductName', 'N/A')}\n"
                            f"Type: {', '.join(finding_types)}\n"
                            f"Resource: {resource_arn}\n\n"
                            f"{f.get('Description', '')}"
                        ),
                        "severity": severity_label,
                        "gd_severity": None,
                        "resource_arn": resource_arn,
                        "region": f.get("Region", AWS_REGION),
                        "iso_controls": controls,
                        "raw_type": ", ".join(finding_types),
                        "updated_at": f.get("UpdatedAt", ""),
                    }
                )

            next_token = resp.get("NextToken", "")
            if not next_token:
                break

    except (BotoCoreError, ClientError):
        logger.exception("Error polling SecurityHub findings")

    logger.info("Normalized %d SecurityHub findings", len(normalized))
    return normalized


# ---------------------------------------------------------------------------
# Process incidents into CISO Assistant
# ---------------------------------------------------------------------------


def process_incidents(
    client: CISOClient,
    incidents: list[dict],
    cache: DedupCache,
    findings_assessment_id: str,
) -> dict:
    """Create/update incident findings in CISO Assistant with deduplication."""
    stats = {"new": 0, "updated": 0, "skipped": 0, "errors": 0, "alerts_sent": 0}

    for incident in incidents:
        dedup_key = incident["dedup_key"]
        resource_arn, check_id = dedup_key
        cached = cache.get(resource_arn, check_id)

        severity = incident["severity"]

        if cached is not None:
            # Already tracked — update timestamp only
            cache.upsert(resource_arn, check_id, cached["ciso_id"], "FAIL")
            stats["updated"] += 1
            logger.debug("Already tracked incident: %s", dedup_key)
            continue

        # New incident — create finding in CISO Assistant
        control_labels = ", ".join(incident["iso_controls"])
        description = (
            f"**Source:** {incident['source']}\n"
            f"**Resource:** {incident['resource_arn']}\n"
            f"**Region:** {incident['region']}\n"
            f"**ISO 27001 Controls:** {control_labels}\n\n"
            f"{incident['description']}"
        )

        payload: dict[str, Any] = {
            "name": incident["title"][:200],
            "description": description,
            "findings_assessment": findings_assessment_id,
            "severity": _SEVERITY_TO_FINDING_SEVERITY.get(severity, 2),
            "status": "identified",
            "ref_id": f"{incident['source']}:{incident['source_id']}"[:100],
        }

        if incident.get("iso_controls"):
            payload["observation"] = (
                f"**Detected:** {incident.get('updated_at', 'N/A')}\n"
                f"**Type:** {incident.get('raw_type', 'N/A')}\n"
                f"**Mapped ISO Controls:** {control_labels}"
            )

        priority = _SEVERITY_TO_PRIORITY.get(severity)
        if priority is not None:
            payload["priority"] = priority

        try:
            result = client.create_finding(payload)
            ciso_id = str(result["id"])
            cache.upsert(resource_arn, check_id, ciso_id, "FAIL")
            stats["new"] += 1
            logger.info("Created incident finding: %s (ciso_id=%s)", dedup_key, ciso_id)

            # Alert based on escalation rules
            if _should_alert_immediately(severity, incident.get("gd_severity")):
                alert_data = {
                    "check_id": f"{incident['source']}:{incident['source_id']}",
                    "title": incident["title"],
                    "severity": severity,
                    "resource_arn": incident["resource_arn"],
                    "region": incident["region"],
                    "description": incident["description"],
                    "service": incident["source"],
                }
                if alert_new_finding(alert_data, source=incident["source"]):
                    stats["alerts_sent"] += 1

        except CISOClientError:
            logger.exception("Error creating incident finding: %s", dedup_key)
            stats["errors"] += 1

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    run_start = datetime.now(timezone.utc)

    # Load rules
    rules = load_rules(RULES_FILE)
    logger.info("Loaded incident detection rules from %s", RULES_FILE)

    # Load last run timestamp
    since = load_last_run()
    logger.info("Polling for incidents since %s", since.isoformat())

    # Poll all three sources
    all_incidents: list[dict] = []

    logger.info("=== Polling GuardDuty ===")
    gd_incidents = poll_guardduty(since, rules)
    all_incidents.extend(gd_incidents)

    logger.info("=== Polling CloudTrail ===")
    ct_incidents = poll_cloudtrail(since, rules)
    all_incidents.extend(ct_incidents)

    logger.info("=== Polling SecurityHub ===")
    sh_incidents = poll_securityhub(since, rules)
    all_incidents.extend(sh_incidents)

    logger.info(
        "Total incidents found: %d (GuardDuty=%d, CloudTrail=%d, SecurityHub=%d)",
        len(all_incidents),
        len(gd_incidents),
        len(ct_incidents),
        len(sh_incidents),
    )

    if not all_incidents:
        logger.info("No new incidents detected. Saving timestamp and exiting.")
        save_last_run(run_start)
        # Write empty summary
        os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
        with open(SCAN_SUMMARY_PATH, "w") as f:
            json.dump(
                {
                    "timestamp": run_start.isoformat(),
                    "total_incidents": 0,
                    "new": 0,
                    "updated": 0,
                    "errors": 0,
                    "alerts_sent": 0,
                    "sources": {
                        "guardduty": len(gd_incidents),
                        "cloudtrail": len(ct_incidents),
                        "securityhub": len(sh_incidents),
                    },
                },
                f,
                indent=2,
            )
        return

    # Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # Ensure project and findings assessment
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)

    # Open dedup cache
    cache = DedupCache(DB_PATH)

    try:
        stats = process_incidents(client, all_incidents, cache, fa_id)
    finally:
        cache.close()

    # Save last run timestamp
    save_last_run(run_start)

    # Print summary
    logger.info("=" * 60)
    logger.info("INCIDENT DETECTION SUMMARY")
    logger.info("=" * 60)
    logger.info("  New incidents:       %d", stats["new"])
    logger.info("  Already tracked:     %d", stats["updated"])
    logger.info("  Skipped:             %d", stats["skipped"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("  Alerts sent:         %d", stats["alerts_sent"])
    logger.info("=" * 60)

    # Write summary JSON
    summary = {
        "timestamp": run_start.isoformat(),
        "total_incidents": len(all_incidents),
        "sources": {
            "guardduty": len(gd_incidents),
            "cloudtrail": len(ct_incidents),
            "securityhub": len(sh_incidents),
        },
        **stats,
    }
    os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
    with open(SCAN_SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    # Send scan completion alert
    alert_scan_complete(
        {
            "input_file": "incident_detector",
            "total_findings": len(all_incidents),
            **stats,
        },
        scan_type="incident-detection",
    )

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        alert_scan_failure(str(e), scan_type="incident-detection")
        raise
