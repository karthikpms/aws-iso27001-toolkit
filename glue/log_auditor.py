#!/usr/bin/env python3
"""
Log Completeness Verification — Automation 12

Verifies that all required logging sources are enabled and functioning:
  - CloudTrail: multi-region, log file validation, S3 delivery
  - VPC Flow Logs: enabled on all VPCs
  - S3 access logging: enabled on sensitive buckets
  - ELB access logs: enabled on all load balancers
  - RDS audit logging: enabled on all database instances
  - CloudWatch Logs: required log groups exist and are active
  - Lambda function logging: all functions have log groups
  - GuardDuty: enabled and active
  - AWS Config: recorder running

Creates findings in CISO Assistant for any missing/broken logging and
uploads a log completeness evidence report.

ISO 27001 Controls: A.8.15 (Logging), A.8.16 (Monitoring), A.8.17 (Clock Sync)

Usage:
    python log_auditor.py
"""

import json
import logging
import os
import re
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from alerter import alert_new_finding, alert_scan_complete, alert_scan_failure
from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("log_auditor")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
SCAN_SUMMARY_PATH = os.getenv(
    "LOG_AUDIT_SUMMARY_PATH", "/data/glue/log_audit_summary.json"
)
CONFIG_FILE = Path(__file__).parent / "mappings" / "required_logging.json"
FINDINGS_ASSESSMENT_NAME = "Log Completeness Audit"

_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_PRIORITY_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict:
    """Load the required logging configuration."""
    with open(config_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CISO Assistant integration
# ---------------------------------------------------------------------------


def ensure_project(client: CISOClient, name: str) -> str:
    """Get or create the CISO Assistant project (folder)."""
    for p in client.list_projects():
        if p.get("name") == name:
            return p["id"]
    return client.create_project(name)["id"]


def ensure_findings_assessment(
    client: CISOClient, folder_id: str, name: str = FINDINGS_ASSESSMENT_NAME
) -> str:
    """Get or create a findings assessment for log auditing."""
    for a in client.list_findings_assessments():
        if a.get("name") == name:
            return a["id"]
    assessment = client.create_findings_assessment(
        {
            "name": name,
            "description": "Automated log completeness verification — ISO 27001 A.8.15/A.8.16/A.8.17",
            "folder": folder_id,
            "category": "audit",
        }
    )
    return assessment["id"]


# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------


def _client(service: str) -> Any:
    return boto3.client(service, region_name=AWS_REGION)


# ---------------------------------------------------------------------------
# Check: CloudTrail
# ---------------------------------------------------------------------------


def check_cloudtrail(config: dict) -> list[dict]:
    """Verify CloudTrail is enabled with required settings."""
    findings: list[dict] = []
    ct = _client("cloudtrail")
    checks = config.get("checks", {})

    try:
        trails = ct.describe_trails().get("trailList", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe CloudTrail trails")
        findings.append({
            "check_id": "log-ct-api-error",
            "title": "CloudTrail API Error",
            "description": "Unable to query CloudTrail API. Check IAM permissions.",
            "severity": config.get("severity", "critical"),
            "resource_arn": "cloudtrail",
            "iso_controls": config.get("iso_controls", []),
        })
        return findings

    if not trails:
        findings.append({
            "check_id": "log-ct-no-trail",
            "title": "No CloudTrail Trail Configured",
            "description": "No CloudTrail trails found. All API activity must be logged per A.8.15.",
            "severity": "critical",
            "resource_arn": "cloudtrail",
            "iso_controls": config.get("iso_controls", []),
        })
        return findings

    has_multi_region = False
    for trail in trails:
        trail_arn = trail.get("TrailARN", "unknown")
        trail_name = trail.get("Name", "unknown")

        if trail.get("IsMultiRegionTrail"):
            has_multi_region = True

        if checks.get("log_file_validation") and not trail.get("LogFileValidationEnabled"):
            findings.append({
                "check_id": "log-ct-no-validation",
                "title": f"CloudTrail Log File Validation Disabled: {trail_name}",
                "description": f"Trail '{trail_name}' does not have log file validation enabled. "
                "This is required to ensure log integrity per A.8.15.",
                "severity": config.get("severity", "critical"),
                "resource_arn": trail_arn,
                "iso_controls": config.get("iso_controls", []),
            })

        # Check delivery status
        if checks.get("s3_delivery"):
            try:
                status = ct.get_trail_status(Name=trail_arn)
                last_delivery = status.get("LatestDeliveryTime")
                if last_delivery:
                    max_gap = checks.get("max_delivery_gap_hours", 1)
                    gap = datetime.now(timezone.utc) - last_delivery.replace(tzinfo=timezone.utc)
                    if gap > timedelta(hours=max_gap):
                        findings.append({
                            "check_id": "log-ct-delivery-gap",
                            "title": f"CloudTrail Delivery Gap: {trail_name}",
                            "description": (
                                f"Trail '{trail_name}' last delivered logs {gap.total_seconds() / 3600:.1f} hours ago "
                                f"(threshold: {max_gap}h). Possible log delivery failure."
                            ),
                            "severity": "high",
                            "resource_arn": trail_arn,
                            "iso_controls": config.get("iso_controls", []),
                        })
                last_error = status.get("LatestDeliveryError")
                if last_error:
                    findings.append({
                        "check_id": "log-ct-delivery-error",
                        "title": f"CloudTrail Delivery Error: {trail_name}",
                        "description": f"Trail '{trail_name}' has a delivery error: {last_error}",
                        "severity": "critical",
                        "resource_arn": trail_arn,
                        "iso_controls": config.get("iso_controls", []),
                    })
            except (BotoCoreError, ClientError):
                logger.exception("Failed to get trail status for %s", trail_name)

    if checks.get("multi_region") and not has_multi_region:
        findings.append({
            "check_id": "log-ct-no-multiregion",
            "title": "No Multi-Region CloudTrail Trail",
            "description": "No multi-region CloudTrail trail found. A multi-region trail is required "
            "to capture API activity across all regions per A.8.15.",
            "severity": "high",
            "resource_arn": "cloudtrail",
            "iso_controls": config.get("iso_controls", []),
        })

    return findings


# ---------------------------------------------------------------------------
# Check: VPC Flow Logs
# ---------------------------------------------------------------------------


def check_vpc_flow_logs(config: dict) -> list[dict]:
    """Verify VPC Flow Logs are enabled on all VPCs."""
    findings: list[dict] = []
    ec2 = _client("ec2")

    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe VPCs")
        return [{
            "check_id": "log-vpc-api-error",
            "title": "VPC API Error",
            "description": "Unable to query VPC API. Check IAM permissions.",
            "severity": config.get("severity", "high"),
            "resource_arn": "vpc",
            "iso_controls": config.get("iso_controls", []),
        }]

    if not vpcs:
        logger.info("No VPCs found — skipping VPC Flow Log check")
        return findings

    try:
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe flow logs")
        return findings

    # Map VPC IDs with active flow logs
    vpcs_with_logs = {
        fl["ResourceId"]
        for fl in flow_logs
        if fl.get("FlowLogStatus") == "ACTIVE"
    }

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        if vpc_id not in vpcs_with_logs:
            vpc_name = ""
            for tag in vpc.get("Tags", []):
                if tag["Key"] == "Name":
                    vpc_name = tag["Value"]
                    break
            label = f"{vpc_id} ({vpc_name})" if vpc_name else vpc_id
            findings.append({
                "check_id": f"log-vpc-no-flowlog-{vpc_id}",
                "title": f"VPC Flow Logs Not Enabled: {label}",
                "description": f"VPC {label} does not have flow logs enabled. "
                "Network traffic logging is required per A.8.15.",
                "severity": config.get("severity", "high"),
                "resource_arn": vpc_id,
                "iso_controls": config.get("iso_controls", []),
            })

    return findings


# ---------------------------------------------------------------------------
# Check: S3 Access Logging
# ---------------------------------------------------------------------------


def check_s3_access_logging(config: dict) -> list[dict]:
    """Verify S3 access logging is enabled on buckets (excluding log-destination buckets)."""
    findings: list[dict] = []
    s3 = _client("s3")
    checks = config.get("checks", {})
    skip_patterns = [re.compile(p) for p in checks.get("skip_patterns", [])]

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list S3 buckets")
        return [{
            "check_id": "log-s3-api-error",
            "title": "S3 API Error",
            "description": "Unable to list S3 buckets. Check IAM permissions.",
            "severity": config.get("severity", "medium"),
            "resource_arn": "s3",
            "iso_controls": config.get("iso_controls", []),
        }]

    for bucket in buckets:
        name = bucket["Name"]

        # Skip known log-destination buckets
        if any(p.search(name) for p in skip_patterns):
            logger.debug("Skipping log-destination bucket: %s", name)
            continue

        try:
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if not logging_cfg.get("LoggingEnabled"):
                findings.append({
                    "check_id": f"log-s3-no-logging-{name}",
                    "title": f"S3 Access Logging Disabled: {name}",
                    "description": f"Bucket '{name}' does not have access logging enabled.",
                    "severity": config.get("severity", "medium"),
                    "resource_arn": f"arn:aws:s3:::{name}",
                    "iso_controls": config.get("iso_controls", []),
                })
        except (BotoCoreError, ClientError):
            logger.warning("Failed to check logging for bucket: %s", name)

    return findings


# ---------------------------------------------------------------------------
# Check: ELB Access Logs
# ---------------------------------------------------------------------------


def check_elb_access_logs(config: dict) -> list[dict]:
    """Verify access logs are enabled on all load balancers (ALB/NLB)."""
    findings: list[dict] = []
    elbv2 = _client("elbv2")

    try:
        lbs = elbv2.describe_load_balancers().get("LoadBalancers", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe load balancers")
        return []

    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb.get("LoadBalancerName", lb_arn)

        try:
            attrs = elbv2.describe_load_balancer_attributes(
                LoadBalancerArn=lb_arn
            ).get("Attributes", [])
            logging_enabled = False
            for attr in attrs:
                if attr["Key"] == "access_logs.s3.enabled" and attr["Value"] == "true":
                    logging_enabled = True
                    break

            if not logging_enabled:
                findings.append({
                    "check_id": f"log-elb-no-logging-{lb_name}",
                    "title": f"ELB Access Logs Disabled: {lb_name}",
                    "description": f"Load balancer '{lb_name}' does not have access logging enabled.",
                    "severity": config.get("severity", "medium"),
                    "resource_arn": lb_arn,
                    "iso_controls": config.get("iso_controls", []),
                })
        except (BotoCoreError, ClientError):
            logger.warning("Failed to check attributes for LB: %s", lb_name)

    return findings


# ---------------------------------------------------------------------------
# Check: RDS Audit Logging
# ---------------------------------------------------------------------------


def check_rds_audit_logging(config: dict) -> list[dict]:
    """Verify audit logging is enabled on all RDS instances."""
    findings: list[dict] = []
    rds = _client("rds")
    checks = config.get("checks", {})
    required_by_engine = checks.get("required_logs_by_engine", {})

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe RDS instances")
        return []

    for db in instances:
        db_id = db["DBInstanceIdentifier"]
        db_arn = db.get("DBInstanceArn", db_id)
        engine = db.get("Engine", "unknown")
        enabled_logs = db.get("EnabledCloudwatchLogsExports", [])

        # Find the required logs for this engine
        required_logs = None
        for engine_key, logs in required_by_engine.items():
            if engine.startswith(engine_key):
                required_logs = logs
                break

        if required_logs is None:
            # Unknown engine — just check that some logging is enabled
            if not enabled_logs:
                findings.append({
                    "check_id": f"log-rds-no-logging-{db_id}",
                    "title": f"RDS No CloudWatch Logs Exports: {db_id}",
                    "description": f"RDS instance '{db_id}' (engine: {engine}) has no CloudWatch log exports enabled.",
                    "severity": config.get("severity", "medium"),
                    "resource_arn": db_arn,
                    "iso_controls": config.get("iso_controls", []),
                })
        else:
            missing = [log for log in required_logs if log not in enabled_logs]
            if missing:
                findings.append({
                    "check_id": f"log-rds-missing-logs-{db_id}",
                    "title": f"RDS Missing Log Exports: {db_id}",
                    "description": (
                        f"RDS instance '{db_id}' (engine: {engine}) is missing "
                        f"required log exports: {', '.join(missing)}. "
                        f"Enabled: {', '.join(enabled_logs) if enabled_logs else 'none'}."
                    ),
                    "severity": config.get("severity", "medium"),
                    "resource_arn": db_arn,
                    "iso_controls": config.get("iso_controls", []),
                })

    return findings


# ---------------------------------------------------------------------------
# Check: CloudWatch Log Groups
# ---------------------------------------------------------------------------


def check_cloudwatch_log_groups(config: dict) -> list[dict]:
    """Verify required log groups exist and check for stale groups."""
    findings: list[dict] = []
    logs_client = _client("logs")
    checks = config.get("checks", {})
    required_groups = checks.get("required_log_groups", [])
    stale_days = checks.get("stale_threshold_days", 7)
    stale_threshold = datetime.now(timezone.utc) - timedelta(days=stale_days)

    try:
        # Paginate through all log groups
        all_groups: list[dict] = []
        next_token = None
        while True:
            kwargs: dict[str, Any] = {"limit": 50}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = logs_client.describe_log_groups(**kwargs)
            all_groups.extend(resp.get("logGroups", []))
            next_token = resp.get("nextToken")
            if not next_token:
                break
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe CloudWatch log groups")
        return [{
            "check_id": "log-cw-api-error",
            "title": "CloudWatch Logs API Error",
            "description": "Unable to query CloudWatch Logs API.",
            "severity": config.get("severity", "medium"),
            "resource_arn": "cloudwatch-logs",
            "iso_controls": config.get("iso_controls", []),
        }]

    group_names = {g["logGroupName"] for g in all_groups}

    # Check required log groups exist
    for required in required_groups:
        if required not in group_names:
            findings.append({
                "check_id": f"log-cw-missing-group-{required}",
                "title": f"Required CloudWatch Log Group Missing: {required}",
                "description": f"The required log group '{required}' does not exist.",
                "severity": "high",
                "resource_arn": f"log-group:{required}",
                "iso_controls": config.get("iso_controls", []),
            })

    # Check for stale log groups (no recent events)
    stale_count = 0
    for group in all_groups:
        name = group["logGroupName"]
        # storedBytes == 0 and no recent ingestion → stale
        last_ingestion = group.get("creationTime", 0)
        # Try to get most recent log stream
        try:
            streams = logs_client.describe_log_streams(
                logGroupName=name,
                orderBy="LastEventTime",
                descending=True,
                limit=1,
            ).get("logStreams", [])
            if streams:
                last_event_ms = streams[0].get("lastEventTimestamp")
                if last_event_ms:
                    last_event = datetime.fromtimestamp(last_event_ms / 1000, tz=timezone.utc)
                    if last_event < stale_threshold:
                        stale_count += 1
                        logger.debug("Stale log group: %s (last event: %s)", name, last_event)
            elif group.get("storedBytes", 0) == 0:
                stale_count += 1
        except (BotoCoreError, ClientError):
            logger.debug("Could not check streams for log group: %s", name)

    if stale_count > 0:
        findings.append({
            "check_id": "log-cw-stale-groups",
            "title": f"{stale_count} Stale CloudWatch Log Groups Detected",
            "description": (
                f"{stale_count} CloudWatch log group(s) have not received events "
                f"in the last {stale_days} days. This may indicate dead services or "
                "broken log pipelines."
            ),
            "severity": "low",
            "resource_arn": "cloudwatch-logs",
            "iso_controls": config.get("iso_controls", []),
        })

    return findings


# ---------------------------------------------------------------------------
# Check: Lambda Logging
# ---------------------------------------------------------------------------


def check_lambda_logging(config: dict) -> list[dict]:
    """Verify all Lambda functions have CloudWatch log groups."""
    findings: list[dict] = []
    lam = _client("lambda")
    logs_client = _client("logs")

    try:
        functions: list[dict] = []
        marker = None
        while True:
            kwargs: dict[str, Any] = {"MaxItems": 50}
            if marker:
                kwargs["Marker"] = marker
            resp = lam.list_functions(**kwargs)
            functions.extend(resp.get("Functions", []))
            marker = resp.get("NextMarker")
            if not marker:
                break
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list Lambda functions")
        return []

    if not functions:
        logger.info("No Lambda functions found — skipping Lambda logging check")
        return findings

    missing_count = 0
    missing_names: list[str] = []

    for fn in functions:
        fn_name = fn["FunctionName"]
        log_group = f"/aws/lambda/{fn_name}"
        try:
            resp = logs_client.describe_log_groups(logGroupNamePrefix=log_group, limit=1)
            groups = resp.get("logGroups", [])
            if not any(g["logGroupName"] == log_group for g in groups):
                missing_count += 1
                missing_names.append(fn_name)
        except (BotoCoreError, ClientError):
            logger.debug("Could not check log group for Lambda: %s", fn_name)

    if missing_count > 0:
        sample = ", ".join(missing_names[:5])
        if missing_count > 5:
            sample += f" (and {missing_count - 5} more)"
        findings.append({
            "check_id": "log-lambda-missing-logs",
            "title": f"{missing_count} Lambda Functions Without Log Groups",
            "description": (
                f"{missing_count} Lambda function(s) do not have CloudWatch log groups. "
                f"Functions: {sample}. This may indicate functions that have never been "
                "invoked or have logging misconfigured."
            ),
            "severity": config.get("severity", "low"),
            "resource_arn": "lambda",
            "iso_controls": config.get("iso_controls", []),
        })

    return findings


# ---------------------------------------------------------------------------
# Check: GuardDuty
# ---------------------------------------------------------------------------


def check_guardduty(config: dict) -> list[dict]:
    """Verify GuardDuty is enabled and active."""
    findings: list[dict] = []
    gd = _client("guardduty")

    try:
        detectors = gd.list_detectors().get("DetectorIds", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list GuardDuty detectors")
        return [{
            "check_id": "log-gd-api-error",
            "title": "GuardDuty API Error",
            "description": "Unable to query GuardDuty API. Check IAM permissions.",
            "severity": config.get("severity", "critical"),
            "resource_arn": "guardduty",
            "iso_controls": config.get("iso_controls", []),
        }]

    if not detectors:
        findings.append({
            "check_id": "log-gd-not-enabled",
            "title": "GuardDuty Not Enabled",
            "description": "GuardDuty is not enabled in this region. Threat detection "
            "is required per A.8.16.",
            "severity": "critical",
            "resource_arn": "guardduty",
            "iso_controls": config.get("iso_controls", []),
        })
        return findings

    for detector_id in detectors:
        try:
            det = gd.get_detector(DetectorId=detector_id)
            status = det.get("Status", "DISABLED")
            if status != "ENABLED":
                findings.append({
                    "check_id": f"log-gd-disabled-{detector_id}",
                    "title": f"GuardDuty Detector Disabled: {detector_id}",
                    "description": f"GuardDuty detector '{detector_id}' has status '{status}'. "
                    "It must be ENABLED for continuous threat detection.",
                    "severity": "critical",
                    "resource_arn": f"guardduty:{detector_id}",
                    "iso_controls": config.get("iso_controls", []),
                })
        except (BotoCoreError, ClientError):
            logger.exception("Failed to get GuardDuty detector: %s", detector_id)

    return findings


# ---------------------------------------------------------------------------
# Check: AWS Config Recorder
# ---------------------------------------------------------------------------


def check_config_recorder(config: dict) -> list[dict]:
    """Verify AWS Config recorder is running."""
    findings: list[dict] = []
    cfg = _client("config")

    try:
        recorders = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe Config recorder status")
        return [{
            "check_id": "log-config-api-error",
            "title": "AWS Config API Error",
            "description": "Unable to query AWS Config API. Check IAM permissions.",
            "severity": config.get("severity", "high"),
            "resource_arn": "config",
            "iso_controls": config.get("iso_controls", []),
        }]

    if not recorders:
        findings.append({
            "check_id": "log-config-no-recorder",
            "title": "AWS Config Recorder Not Configured",
            "description": "No AWS Config recorder found. Configuration recording "
            "is required for continuous compliance monitoring per A.8.15.",
            "severity": "high",
            "resource_arn": "config",
            "iso_controls": config.get("iso_controls", []),
        })
        return findings

    for rec in recorders:
        name = rec.get("name", "unknown")
        recording = rec.get("recording", False)
        last_status = rec.get("lastStatus", "UNKNOWN")

        if not recording:
            findings.append({
                "check_id": f"log-config-not-recording-{name}",
                "title": f"AWS Config Recorder Stopped: {name}",
                "description": f"Config recorder '{name}' is not recording. "
                f"Last status: {last_status}.",
                "severity": "high",
                "resource_arn": f"config:{name}",
                "iso_controls": config.get("iso_controls", []),
            })
        elif last_status == "FAILURE":
            findings.append({
                "check_id": f"log-config-failure-{name}",
                "title": f"AWS Config Recorder Failure: {name}",
                "description": f"Config recorder '{name}' reports a delivery failure.",
                "severity": "high",
                "resource_arn": f"config:{name}",
                "iso_controls": config.get("iso_controls", []),
            })

    return findings


# ---------------------------------------------------------------------------
# Evidence report generation
# ---------------------------------------------------------------------------


def generate_report(
    all_findings: list[dict],
    check_results: dict[str, list[dict]],
    run_time: datetime,
) -> str:
    """Generate a text-based log completeness evidence report."""
    lines = [
        "=" * 70,
        "LOG COMPLETENESS VERIFICATION REPORT",
        f"Generated: {run_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Region: {AWS_REGION}",
        f"ISO 27001 Controls: A.8.15, A.8.16, A.8.17",
        "=" * 70,
        "",
    ]

    # Summary
    total_checks = len(check_results)
    checks_pass = sum(1 for f in check_results.values() if not f)
    checks_fail = total_checks - checks_pass

    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Log sources checked:  {total_checks}")
    lines.append(f"  Passing:              {checks_pass}")
    lines.append(f"  Failing:              {checks_fail}")
    lines.append(f"  Total findings:       {len(all_findings)}")
    lines.append("")

    # Per-source results
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for source_name, source_findings in check_results.items():
        status = "PASS" if not source_findings else "FAIL"
        lines.append(f"[{status}] {source_name}")
        if source_findings:
            sorted_findings = sorted(
                source_findings, key=lambda f: severity_order.get(f.get("severity", "low"), 9)
            )
            for f in sorted_findings:
                lines.append(f"       [{f['severity'].upper()}] {f['title']}")
        lines.append("")

    # Detailed findings
    if all_findings:
        lines.append("")
        lines.append("DETAILED FINDINGS")
        lines.append("=" * 70)
        sorted_all = sorted(
            all_findings, key=lambda f: severity_order.get(f.get("severity", "low"), 9)
        )
        for i, f in enumerate(sorted_all, 1):
            lines.append(f"\n--- Finding {i} ---")
            lines.append(f"  Check ID:     {f['check_id']}")
            lines.append(f"  Title:        {f['title']}")
            lines.append(f"  Severity:     {f['severity'].upper()}")
            lines.append(f"  Resource:     {f['resource_arn']}")
            lines.append(f"  ISO Controls: {', '.join(f.get('iso_controls', []))}")
            lines.append(f"  Description:  {f['description']}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Process findings into CISO Assistant
# ---------------------------------------------------------------------------


def process_findings(
    client: CISOClient,
    all_findings: list[dict],
    cache: DedupCache,
    findings_assessment_id: str,
    folder_id: str,
    report_text: str,
    run_time: datetime,
) -> dict:
    """Create/update log audit findings in CISO Assistant and upload evidence."""
    stats = {"new": 0, "updated": 0, "errors": 0, "alerts_sent": 0}

    for finding in all_findings:
        check_id = finding["check_id"]
        resource_arn = finding["resource_arn"]
        severity = finding["severity"]
        cached = cache.get(resource_arn, check_id)

        if cached is not None:
            # Already tracked — update timestamp
            cache.upsert(resource_arn, check_id, cached["ciso_id"], "FAIL")
            stats["updated"] += 1
            continue

        # New finding
        control_labels = ", ".join(finding.get("iso_controls", []))
        description = (
            f"**Source:** Log Completeness Audit\n"
            f"**Resource:** {resource_arn}\n"
            f"**ISO 27001 Controls:** {control_labels}\n\n"
            f"{finding['description']}"
        )

        payload: dict[str, Any] = {
            "name": finding["title"][:200],
            "description": description,
            "findings_assessment": findings_assessment_id,
            "severity": _SEVERITY_MAP.get(severity, 2),
            "status": "identified",
            "ref_id": check_id[:100],
        }

        priority = _PRIORITY_MAP.get(severity)
        if priority is not None:
            payload["priority"] = priority

        try:
            result = client.create_finding(payload)
            ciso_id = str(result["id"])
            cache.upsert(resource_arn, check_id, ciso_id, "FAIL")
            stats["new"] += 1
            logger.info("Created log audit finding: %s (ciso_id=%s)", check_id, ciso_id)

            # Alert for critical/high findings
            if severity in ("critical", "high"):
                alert_data = {
                    "check_id": check_id,
                    "title": finding["title"],
                    "severity": severity,
                    "resource_arn": resource_arn,
                    "region": AWS_REGION,
                    "description": finding["description"],
                    "service": "Log Audit",
                }
                if alert_new_finding(alert_data, source="Log Audit"):
                    stats["alerts_sent"] += 1

        except CISOClientError:
            logger.exception("Error creating finding: %s", check_id)
            stats["errors"] += 1

    # Upload evidence report
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="log_audit_", delete=False
        ) as tmp:
            tmp.write(report_text)
            tmp_path = tmp.name

        report_name = f"Log Completeness Report — {run_time.strftime('%Y-%m-%d')}"
        client.upload_evidence(report_name, tmp_path, folder_id)
        logger.info("Uploaded log audit evidence report")
        os.unlink(tmp_path)
    except (CISOClientError, OSError):
        logger.exception("Failed to upload evidence report")
        stats["errors"] += 1

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    run_start = datetime.now(timezone.utc)

    # Load config
    config = load_config(CONFIG_FILE)
    log_sources = config.get("log_sources", {})
    logger.info("Loaded log audit config with %d log sources", len(log_sources))

    # Run all checks
    check_dispatch = {
        "cloudtrail": check_cloudtrail,
        "vpc_flow_logs": check_vpc_flow_logs,
        "s3_access_logging": check_s3_access_logging,
        "elb_access_logs": check_elb_access_logs,
        "rds_audit_logging": check_rds_audit_logging,
        "cloudwatch_log_groups": check_cloudwatch_log_groups,
        "lambda_logging": check_lambda_logging,
        "guardduty": check_guardduty,
        "config_recorder": check_config_recorder,
    }

    check_results: dict[str, list[dict]] = {}
    all_findings: list[dict] = []

    for source_name, source_config in log_sources.items():
        if not source_config.get("enabled", True):
            logger.info("Skipping disabled log source: %s", source_name)
            continue

        check_fn = check_dispatch.get(source_name)
        if not check_fn:
            logger.warning("No check function for log source: %s", source_name)
            continue

        logger.info("=== Checking: %s ===", source_name)
        try:
            source_findings = check_fn(source_config)
            check_results[source_name] = source_findings
            all_findings.extend(source_findings)
            if source_findings:
                logger.info("  Found %d issue(s)", len(source_findings))
            else:
                logger.info("  PASS — no issues")
        except Exception:
            logger.exception("Unexpected error checking %s", source_name)
            check_results[source_name] = [{
                "check_id": f"log-{source_name}-unexpected-error",
                "title": f"Unexpected Error Checking {source_name}",
                "description": f"An unexpected error occurred while checking {source_name}.",
                "severity": "medium",
                "resource_arn": source_name,
                "iso_controls": source_config.get("iso_controls", []),
            }]
            all_findings.extend(check_results[source_name])

    # Generate evidence report
    report_text = generate_report(all_findings, check_results, run_start)

    # Log summary to console
    logger.info("=" * 60)
    logger.info("LOG COMPLETENESS AUDIT SUMMARY")
    logger.info("=" * 60)
    sources_checked = len(check_results)
    sources_pass = sum(1 for f in check_results.values() if not f)
    logger.info("  Sources checked:     %d", sources_checked)
    logger.info("  Sources passing:     %d", sources_pass)
    logger.info("  Sources failing:     %d", sources_checked - sources_pass)
    logger.info("  Total findings:      %d", len(all_findings))
    logger.info("=" * 60)

    # Connect to CISO Assistant and process
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)

    cache = DedupCache(DB_PATH)
    try:
        stats = process_findings(
            client, all_findings, cache, fa_id, folder_id, report_text, run_start
        )
    finally:
        cache.close()

    # Write summary JSON
    summary = {
        "timestamp": run_start.isoformat(),
        "region": AWS_REGION,
        "sources_checked": sources_checked,
        "sources_passing": sources_pass,
        "sources_failing": sources_checked - sources_pass,
        "total_findings": len(all_findings),
        "findings_by_severity": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ("critical", "high", "medium", "low")
        },
        **stats,
    }
    os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
    with open(SCAN_SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    # Send scan completion alert
    alert_scan_complete(
        {
            "input_file": "log_auditor",
            "total_findings": len(all_findings),
            **stats,
        },
        scan_type="log-completeness-audit",
    )

    logger.info("  New findings:        %d", stats["new"])
    logger.info("  Already tracked:     %d", stats["updated"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("  Alerts sent:         %d", stats["alerts_sent"])

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        alert_scan_failure(str(e), scan_type="log-completeness-audit")
        raise
