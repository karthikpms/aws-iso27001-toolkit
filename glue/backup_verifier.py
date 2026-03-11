#!/usr/bin/env python3
"""
Backup Verification & Restore Testing — Automation 4

Verifies that all expected backups exist and are recent:
  - RDS automated backups enabled and within retention window
  - EBS snapshots exist and are recent (< 25 hours old)
  - S3 versioning enabled on critical buckets
  - CISO Assistant nightly export exists in S3

Performs automated restore tests (monthly, with --restore-test flag):
  - Restore latest RDS snapshot to a temporary instance, verify connectivity, tear down
  - Create an EBS volume from latest snapshot, verify, tear down

Creates findings in CISO Assistant for any failures and uploads an evidence report.

ISO 27001 Controls: A.8.13 (Information Backup), A.8.14 (Redundancy)

Usage:
    python backup_verifier.py                  # Daily verification checks
    python backup_verifier.py --restore-test   # Monthly restore tests
    python backup_verifier.py --cleanup        # Safety-net cleanup of stale test resources
"""

import argparse
import json
import logging
import os
import re
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, WaiterError

from alerter import alert_new_finding, alert_scan_complete, alert_scan_failure
from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("backup_verifier")

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
    "BACKUP_SUMMARY_PATH", "/data/glue/backup_verifier_summary.json"
)
CONFIG_FILE = Path(__file__).parent / "mappings" / "backup_config.json"
FINDINGS_ASSESSMENT_NAME = "Backup Verification"
BACKUP_S3_BUCKET = os.getenv("BACKUP_S3_BUCKET", "")

RESTORE_TEST_TAG = {"Key": "Purpose", "Value": "iso27001-restore-test"}

_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_PRIORITY_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict:
    """Load the backup verification configuration."""
    with open(config_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# AWS client helpers
# ---------------------------------------------------------------------------


def _client(service: str) -> Any:
    return boto3.client(service, region_name=AWS_REGION)


def _resource(service: str) -> Any:
    return boto3.resource(service, region_name=AWS_REGION)


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
    """Get or create a findings assessment for backup verification."""
    for a in client.list_findings_assessments():
        if a.get("name") == name:
            return a["id"]
    assessment = client.create_findings_assessment(
        {
            "name": name,
            "description": "Automated backup verification and restore testing — ISO 27001 A.8.13/A.8.14",
            "folder": folder_id,
            "category": "audit",
        }
    )
    return assessment["id"]


# ---------------------------------------------------------------------------
# Check: RDS Backups
# ---------------------------------------------------------------------------


def check_rds_backups(config: dict, thresholds: dict) -> list[dict]:
    """Verify RDS automated backups are enabled and recent."""
    findings: list[dict] = []
    rds = _client("rds")
    min_retention = config.get("min_retention_days", 7)
    max_age_hours = thresholds.get("rds_backup_max_age_hours", 25)
    iso_controls = ["A.8.13", "A.8.14"]

    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe RDS instances")
        return [{
            "check_id": "backup-rds-api-error",
            "title": "RDS API Error",
            "description": "Unable to query RDS API. Check IAM permissions.",
            "severity": config.get("severity", "critical"),
            "resource_arn": "rds",
            "iso_controls": iso_controls,
        }]

    if not instances:
        logger.info("No RDS instances found — skipping RDS backup check")
        return findings

    for db in instances:
        db_id = db["DBInstanceIdentifier"]
        db_arn = db.get("DBInstanceArn", db_id)
        retention = db.get("BackupRetentionPeriod", 0)
        latest_restorable = db.get("LatestRestorableTime")

        # Skip restore-test temp instances
        if db_id.startswith("iso27001-restore-test-"):
            continue

        # Check backup retention period
        if retention < min_retention:
            findings.append({
                "check_id": f"backup-rds-low-retention-{db_id}",
                "title": f"RDS Backup Retention Too Low: {db_id}",
                "description": (
                    f"RDS instance '{db_id}' has backup retention set to {retention} days "
                    f"(minimum required: {min_retention} days). Increase retention period "
                    "to comply with A.8.13."
                ),
                "severity": "critical" if retention == 0 else "high",
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })

        if retention == 0:
            findings.append({
                "check_id": f"backup-rds-disabled-{db_id}",
                "title": f"RDS Automated Backups Disabled: {db_id}",
                "description": (
                    f"RDS instance '{db_id}' has automated backups disabled "
                    "(retention period = 0). This violates A.8.13."
                ),
                "severity": "critical",
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })
            continue

        # Check latest restorable time
        if latest_restorable:
            age = datetime.now(timezone.utc) - latest_restorable.replace(tzinfo=timezone.utc)
            age_hours = age.total_seconds() / 3600
            if age_hours > max_age_hours:
                findings.append({
                    "check_id": f"backup-rds-stale-{db_id}",
                    "title": f"RDS Backup Stale: {db_id}",
                    "description": (
                        f"RDS instance '{db_id}' latest restorable time is "
                        f"{age_hours:.1f} hours ago (threshold: {max_age_hours}h). "
                        "This may indicate a backup failure."
                    ),
                    "severity": config.get("severity", "critical"),
                    "resource_arn": db_arn,
                    "iso_controls": iso_controls,
                })
        else:
            findings.append({
                "check_id": f"backup-rds-no-restorable-{db_id}",
                "title": f"RDS No Restorable Time: {db_id}",
                "description": (
                    f"RDS instance '{db_id}' has no LatestRestorableTime despite backups "
                    "being enabled. Backup process may be failing."
                ),
                "severity": config.get("severity", "critical"),
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })

    return findings


# ---------------------------------------------------------------------------
# Check: EBS Snapshots
# ---------------------------------------------------------------------------


def check_ebs_snapshots(config: dict, thresholds: dict) -> list[dict]:
    """Verify EBS snapshots exist and are recent for all volumes."""
    findings: list[dict] = []
    ec2 = _client("ec2")
    max_age_hours = thresholds.get("ebs_snapshot_max_age_hours", 25)
    iso_controls = ["A.8.13", "A.8.14"]

    try:
        # Get all in-use EBS volumes
        volumes = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["in-use"]}]
        ).get("Volumes", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe EBS volumes")
        return [{
            "check_id": "backup-ebs-api-error",
            "title": "EBS API Error",
            "description": "Unable to query EBS API. Check IAM permissions.",
            "severity": config.get("severity", "critical"),
            "resource_arn": "ebs",
            "iso_controls": iso_controls,
        }]

    if not volumes:
        logger.info("No in-use EBS volumes found — skipping EBS snapshot check")
        return findings

    now = datetime.now(timezone.utc)

    for vol in volumes:
        vol_id = vol["VolumeId"]
        vol_name = ""
        for tag in vol.get("Tags", []):
            if tag["Key"] == "Name":
                vol_name = tag["Value"]
                break

        # Skip restore-test volumes
        for tag in vol.get("Tags", []):
            if tag["Key"] == RESTORE_TEST_TAG["Key"] and tag["Value"] == RESTORE_TEST_TAG["Value"]:
                continue

        label = f"{vol_id} ({vol_name})" if vol_name else vol_id

        try:
            snapshots = ec2.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [vol_id]}],
                OwnerIds=["self"],
            ).get("Snapshots", [])
        except (BotoCoreError, ClientError):
            logger.warning("Failed to describe snapshots for volume: %s", vol_id)
            continue

        if not snapshots:
            findings.append({
                "check_id": f"backup-ebs-no-snapshot-{vol_id}",
                "title": f"No EBS Snapshots: {label}",
                "description": (
                    f"EBS volume {label} has no snapshots. All data volumes must "
                    "have regular snapshots per A.8.13."
                ),
                "severity": config.get("severity", "critical"),
                "resource_arn": vol_id,
                "iso_controls": iso_controls,
            })
            continue

        # Check latest snapshot age
        latest = max(snapshots, key=lambda s: s.get("StartTime", datetime.min.replace(tzinfo=timezone.utc)))
        start_time = latest["StartTime"]
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        age = now - start_time
        age_hours = age.total_seconds() / 3600

        if age_hours > max_age_hours:
            findings.append({
                "check_id": f"backup-ebs-stale-snapshot-{vol_id}",
                "title": f"EBS Snapshot Stale: {label}",
                "description": (
                    f"Latest snapshot for EBS volume {label} is {age_hours:.1f} hours old "
                    f"(threshold: {max_age_hours}h). Snapshot ID: {latest['SnapshotId']}."
                ),
                "severity": config.get("severity", "critical"),
                "resource_arn": vol_id,
                "iso_controls": iso_controls,
            })

        # Check snapshot state
        if latest.get("State") != "completed":
            findings.append({
                "check_id": f"backup-ebs-incomplete-snapshot-{vol_id}",
                "title": f"EBS Snapshot Not Completed: {label}",
                "description": (
                    f"Latest snapshot {latest['SnapshotId']} for volume {label} "
                    f"has state '{latest.get('State', 'unknown')}' instead of 'completed'."
                ),
                "severity": "high",
                "resource_arn": vol_id,
                "iso_controls": iso_controls,
            })

    return findings


# ---------------------------------------------------------------------------
# Check: S3 Versioning
# ---------------------------------------------------------------------------


def check_s3_versioning(config: dict) -> list[dict]:
    """Verify S3 versioning is enabled on critical buckets."""
    findings: list[dict] = []
    s3 = _client("s3")
    iso_controls = ["A.8.13"]
    patterns = [re.compile(p) for p in config.get("critical_bucket_patterns", [])]

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list S3 buckets")
        return [{
            "check_id": "backup-s3-api-error",
            "title": "S3 API Error",
            "description": "Unable to list S3 buckets. Check IAM permissions.",
            "severity": config.get("severity", "high"),
            "resource_arn": "s3",
            "iso_controls": iso_controls,
        }]

    for bucket in buckets:
        name = bucket["Name"]

        # Only check buckets matching critical patterns
        if patterns and not any(p.search(name) for p in patterns):
            continue

        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                findings.append({
                    "check_id": f"backup-s3-no-versioning-{name}",
                    "title": f"S3 Versioning Not Enabled: {name}",
                    "description": (
                        f"Critical bucket '{name}' does not have versioning enabled "
                        f"(status: {status}). Versioning is required for data "
                        "protection per A.8.13."
                    ),
                    "severity": config.get("severity", "high"),
                    "resource_arn": f"arn:aws:s3:::{name}",
                    "iso_controls": iso_controls,
                })
        except (BotoCoreError, ClientError):
            logger.warning("Failed to check versioning for bucket: %s", name)

    return findings


# ---------------------------------------------------------------------------
# Check: S3 Export (CISO Assistant nightly export)
# ---------------------------------------------------------------------------


def check_s3_export(config: dict, thresholds: dict) -> list[dict]:
    """Verify CISO Assistant nightly export exists in S3."""
    findings: list[dict] = []
    iso_controls = ["A.8.13"]
    max_age_hours = thresholds.get("s3_export_max_age_hours", 25)

    bucket = BACKUP_S3_BUCKET or os.getenv("BACKUP_S3_BUCKET", "")
    if not bucket:
        logger.info("BACKUP_S3_BUCKET not set — skipping S3 export check")
        return findings

    prefix = config.get("export_prefix", "ciso-export/")
    s3 = _client("s3")

    try:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=10)
        objects = resp.get("Contents", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list objects in bucket: %s", bucket)
        return [{
            "check_id": "backup-s3-export-api-error",
            "title": f"S3 Export Check Failed: {bucket}",
            "description": f"Unable to list objects in bucket '{bucket}'. Check permissions.",
            "severity": config.get("severity", "high"),
            "resource_arn": f"arn:aws:s3:::{bucket}",
            "iso_controls": iso_controls,
        }]

    if not objects:
        findings.append({
            "check_id": "backup-s3-no-export",
            "title": f"No CISO Export Found in S3: {bucket}",
            "description": (
                f"No export files found in s3://{bucket}/{prefix}. "
                "The nightly CISO Assistant export may not be running."
            ),
            "severity": config.get("severity", "high"),
            "resource_arn": f"arn:aws:s3:::{bucket}/{prefix}",
            "iso_controls": iso_controls,
        })
        return findings

    # Check latest export age
    latest = max(objects, key=lambda o: o.get("LastModified", datetime.min.replace(tzinfo=timezone.utc)))
    last_modified = latest["LastModified"]
    if last_modified.tzinfo is None:
        last_modified = last_modified.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - last_modified
    age_hours = age.total_seconds() / 3600

    if age_hours > max_age_hours:
        findings.append({
            "check_id": "backup-s3-export-stale",
            "title": f"CISO Export Stale: {bucket}",
            "description": (
                f"Latest export in s3://{bucket}/{prefix} is {age_hours:.1f} hours old "
                f"(threshold: {max_age_hours}h). Key: {latest['Key']}. "
                "The nightly backup may have failed."
            ),
            "severity": config.get("severity", "high"),
            "resource_arn": f"arn:aws:s3:::{bucket}/{prefix}",
            "iso_controls": iso_controls,
        })

    return findings


# ---------------------------------------------------------------------------
# Restore Test: RDS
# ---------------------------------------------------------------------------


def restore_test_rds(config: dict) -> list[dict]:
    """Restore latest RDS snapshot to a temp instance, verify connectivity, tear down."""
    findings: list[dict] = []
    rds = _client("rds")
    iso_controls = ["A.8.13", "A.8.14"]
    prefix = config.get("temp_instance_prefix", "iso27001-restore-test-")
    instance_class = config.get("temp_instance_class", "db.t3.micro")
    timeout_min = config.get("timeout_minutes", 30)

    # Find RDS instances and their snapshots
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe RDS instances for restore test")
        return [{
            "check_id": "backup-restore-rds-api-error",
            "title": "RDS Restore Test API Error",
            "description": "Unable to query RDS API for restore test.",
            "severity": "high",
            "resource_arn": "rds",
            "iso_controls": iso_controls,
        }]

    # Filter out test instances
    prod_instances = [
        db for db in instances
        if not db["DBInstanceIdentifier"].startswith(prefix)
    ]

    if not prod_instances:
        logger.info("No RDS instances found for restore testing")
        return findings

    for db in prod_instances:
        db_id = db["DBInstanceIdentifier"]
        db_arn = db.get("DBInstanceArn", db_id)

        # Get latest automated snapshot
        try:
            snapshots = rds.describe_db_snapshots(
                DBInstanceIdentifier=db_id,
                SnapshotType="automated",
            ).get("DBSnapshots", [])
        except (BotoCoreError, ClientError):
            logger.exception("Failed to list snapshots for %s", db_id)
            findings.append({
                "check_id": f"backup-restore-rds-no-snapshots-{db_id}",
                "title": f"RDS Restore Test Failed — No Snapshots: {db_id}",
                "description": f"Could not list automated snapshots for RDS instance '{db_id}'.",
                "severity": "high",
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })
            continue

        available_snapshots = [s for s in snapshots if s.get("Status") == "available"]
        if not available_snapshots:
            findings.append({
                "check_id": f"backup-restore-rds-no-available-{db_id}",
                "title": f"RDS No Available Snapshots: {db_id}",
                "description": f"No available automated snapshots found for RDS instance '{db_id}'.",
                "severity": "high",
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })
            continue

        latest_snapshot = max(
            available_snapshots,
            key=lambda s: s.get("SnapshotCreateTime", datetime.min.replace(tzinfo=timezone.utc)),
        )
        snapshot_id = latest_snapshot["DBSnapshotIdentifier"]
        temp_id = f"{prefix}{db_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}"
        # RDS identifier max 63 chars
        temp_id = temp_id[:63]

        logger.info("Restoring RDS snapshot %s to temp instance %s", snapshot_id, temp_id)

        try:
            rds.restore_db_instance_from_db_snapshot(
                DBInstanceIdentifier=temp_id,
                DBSnapshotIdentifier=snapshot_id,
                DBInstanceClass=instance_class,
                Tags=[
                    RESTORE_TEST_TAG,
                    {"Key": "Name", "Value": temp_id},
                    {"Key": "AutoCleanup", "Value": "true"},
                ],
                MultiAZ=False,
                PubliclyAccessible=False,
            )

            # Wait for instance to become available
            logger.info("Waiting for temp instance %s to become available (timeout: %d min)", temp_id, timeout_min)
            waiter = rds.get_waiter("db_instance_available")
            try:
                waiter.wait(
                    DBInstanceIdentifier=temp_id,
                    WaiterConfig={"Delay": 30, "MaxAttempts": timeout_min * 2},
                )
                logger.info("Temp RDS instance %s is available — restore test PASSED", temp_id)
            except WaiterError:
                logger.error("Temp RDS instance %s did not become available within timeout", temp_id)
                findings.append({
                    "check_id": f"backup-restore-rds-timeout-{db_id}",
                    "title": f"RDS Restore Test Timeout: {db_id}",
                    "description": (
                        f"Restored RDS instance '{temp_id}' from snapshot '{snapshot_id}' "
                        f"did not become available within {timeout_min} minutes."
                    ),
                    "severity": "high",
                    "resource_arn": db_arn,
                    "iso_controls": iso_controls,
                })

            # Verify the instance endpoint exists (connectivity check)
            try:
                resp = rds.describe_db_instances(DBInstanceIdentifier=temp_id)
                temp_instances = resp.get("DBInstances", [])
                if temp_instances:
                    endpoint = temp_instances[0].get("Endpoint")
                    status = temp_instances[0].get("DBInstanceStatus")
                    if endpoint and status == "available":
                        logger.info(
                            "RDS restore test PASSED for %s — endpoint: %s:%s",
                            db_id, endpoint.get("Address"), endpoint.get("Port"),
                        )
                    else:
                        logger.warning(
                            "RDS restore test: instance %s status=%s, endpoint=%s",
                            temp_id, status, endpoint,
                        )
            except (BotoCoreError, ClientError):
                logger.warning("Could not verify temp instance %s status", temp_id)

        except (BotoCoreError, ClientError) as e:
            logger.exception("RDS restore test failed for %s", db_id)
            findings.append({
                "check_id": f"backup-restore-rds-failed-{db_id}",
                "title": f"RDS Restore Test Failed: {db_id}",
                "description": (
                    f"Failed to restore RDS snapshot '{snapshot_id}' to temp instance. "
                    f"Error: {e}"
                ),
                "severity": "critical",
                "resource_arn": db_arn,
                "iso_controls": iso_controls,
            })
            continue
        finally:
            # Always attempt cleanup
            _cleanup_rds_instance(rds, temp_id)

    return findings


def _cleanup_rds_instance(rds: Any, instance_id: str) -> None:
    """Delete a temporary RDS instance (skip final snapshot)."""
    try:
        rds.delete_db_instance(
            DBInstanceIdentifier=instance_id,
            SkipFinalSnapshot=True,
            DeleteAutomatedBackups=True,
        )
        logger.info("Initiated deletion of temp RDS instance: %s", instance_id)
    except (BotoCoreError, ClientError):
        logger.exception("Failed to delete temp RDS instance: %s — manual cleanup needed", instance_id)


# ---------------------------------------------------------------------------
# Restore Test: EBS
# ---------------------------------------------------------------------------


def restore_test_ebs(config: dict) -> list[dict]:
    """Create a volume from latest EBS snapshot, verify it, tear down."""
    findings: list[dict] = []
    ec2 = _client("ec2")
    iso_controls = ["A.8.13", "A.8.14"]
    timeout_min = config.get("timeout_minutes", 15)

    try:
        # Get all in-use volumes (excluding restore-test volumes)
        volumes = ec2.describe_volumes(
            Filters=[{"Name": "status", "Values": ["in-use"]}]
        ).get("Volumes", [])
    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe EBS volumes for restore test")
        return [{
            "check_id": "backup-restore-ebs-api-error",
            "title": "EBS Restore Test API Error",
            "description": "Unable to query EBS API for restore test.",
            "severity": "high",
            "resource_arn": "ebs",
            "iso_controls": iso_controls,
        }]

    # Filter out test resources
    prod_volumes = []
    for vol in volumes:
        is_test = False
        for tag in vol.get("Tags", []):
            if tag["Key"] == RESTORE_TEST_TAG["Key"] and tag["Value"] == RESTORE_TEST_TAG["Value"]:
                is_test = True
                break
        if not is_test:
            prod_volumes.append(vol)

    if not prod_volumes:
        logger.info("No EBS volumes found for restore testing")
        return findings

    for vol in prod_volumes:
        vol_id = vol["VolumeId"]
        vol_az = vol["AvailabilityZone"]
        vol_name = ""
        for tag in vol.get("Tags", []):
            if tag["Key"] == "Name":
                vol_name = tag["Value"]
                break
        label = f"{vol_id} ({vol_name})" if vol_name else vol_id

        # Get latest snapshot
        try:
            snapshots = ec2.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [vol_id]}],
                OwnerIds=["self"],
            ).get("Snapshots", [])
        except (BotoCoreError, ClientError):
            logger.warning("Failed to list snapshots for volume: %s", vol_id)
            continue

        completed_snapshots = [s for s in snapshots if s.get("State") == "completed"]
        if not completed_snapshots:
            logger.info("No completed snapshots for volume %s — skipping restore test", label)
            continue

        latest = max(
            completed_snapshots,
            key=lambda s: s.get("StartTime", datetime.min.replace(tzinfo=timezone.utc)),
        )
        snapshot_id = latest["SnapshotId"]

        logger.info("Creating test volume from snapshot %s (source volume: %s)", snapshot_id, label)

        temp_vol_id = None
        try:
            resp = ec2.create_volume(
                AvailabilityZone=vol_az,
                SnapshotId=snapshot_id,
                VolumeType="gp3",
                TagSpecifications=[{
                    "ResourceType": "volume",
                    "Tags": [
                        RESTORE_TEST_TAG,
                        {"Key": "Name", "Value": f"iso27001-restore-test-{vol_id}"},
                        {"Key": "AutoCleanup", "Value": "true"},
                        {"Key": "SourceVolume", "Value": vol_id},
                    ],
                }],
            )
            temp_vol_id = resp["VolumeId"]

            # Wait for volume to become available
            logger.info("Waiting for test volume %s to become available", temp_vol_id)
            waiter = ec2.get_waiter("volume_available")
            try:
                waiter.wait(
                    VolumeIds=[temp_vol_id],
                    WaiterConfig={"Delay": 10, "MaxAttempts": timeout_min * 6},
                )
                # Verify the volume
                vol_resp = ec2.describe_volumes(VolumeIds=[temp_vol_id])
                test_vols = vol_resp.get("Volumes", [])
                if test_vols and test_vols[0].get("State") == "available":
                    test_size = test_vols[0].get("Size", 0)
                    logger.info(
                        "EBS restore test PASSED for %s — test volume %s (%d GiB) is available",
                        label, temp_vol_id, test_size,
                    )
                else:
                    findings.append({
                        "check_id": f"backup-restore-ebs-state-{vol_id}",
                        "title": f"EBS Restore Test: Volume Not Available: {label}",
                        "description": (
                            f"Test volume created from snapshot '{snapshot_id}' "
                            "did not reach 'available' state."
                        ),
                        "severity": "high",
                        "resource_arn": vol_id,
                        "iso_controls": iso_controls,
                    })
            except WaiterError:
                logger.error("Test volume %s did not become available within timeout", temp_vol_id)
                findings.append({
                    "check_id": f"backup-restore-ebs-timeout-{vol_id}",
                    "title": f"EBS Restore Test Timeout: {label}",
                    "description": (
                        f"Test volume from snapshot '{snapshot_id}' did not become "
                        f"available within {timeout_min} minutes."
                    ),
                    "severity": "high",
                    "resource_arn": vol_id,
                    "iso_controls": iso_controls,
                })

        except (BotoCoreError, ClientError) as e:
            logger.exception("EBS restore test failed for %s", label)
            findings.append({
                "check_id": f"backup-restore-ebs-failed-{vol_id}",
                "title": f"EBS Restore Test Failed: {label}",
                "description": (
                    f"Failed to create test volume from snapshot '{snapshot_id}'. "
                    f"Error: {e}"
                ),
                "severity": "critical",
                "resource_arn": vol_id,
                "iso_controls": iso_controls,
            })
        finally:
            if temp_vol_id:
                _cleanup_ebs_volume(ec2, temp_vol_id)

    return findings


def _cleanup_ebs_volume(ec2: Any, volume_id: str) -> None:
    """Delete a temporary EBS volume."""
    try:
        # Wait briefly for any pending operations
        time.sleep(5)
        ec2.delete_volume(VolumeId=volume_id)
        logger.info("Deleted temp EBS volume: %s", volume_id)
    except (BotoCoreError, ClientError):
        logger.exception("Failed to delete temp EBS volume: %s — manual cleanup needed", volume_id)


# ---------------------------------------------------------------------------
# Safety-net cleanup
# ---------------------------------------------------------------------------


def cleanup_stale_resources(config: dict) -> None:
    """Delete any restore-test resources older than the max age threshold."""
    max_age_hours = config.get("max_age_hours", 2)
    tag_key = config.get("tag_key", "Purpose")
    tag_value = config.get("tag_value", "iso27001-restore-test")
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

    logger.info("Cleaning up stale restore-test resources older than %d hours", max_age_hours)

    # Cleanup RDS instances
    rds = _client("rds")
    try:
        instances = rds.describe_db_instances().get("DBInstances", [])
        for db in instances:
            db_id = db["DBInstanceIdentifier"]
            tags = rds.list_tags_for_resource(
                ResourceName=db.get("DBInstanceArn", "")
            ).get("TagList", [])
            is_test = any(
                t["Key"] == tag_key and t["Value"] == tag_value for t in tags
            )
            if is_test:
                create_time = db.get("InstanceCreateTime")
                if create_time and create_time.replace(tzinfo=timezone.utc) < cutoff:
                    logger.warning("Cleaning up stale RDS test instance: %s", db_id)
                    _cleanup_rds_instance(rds, db_id)
    except (BotoCoreError, ClientError):
        logger.exception("Error during RDS cleanup sweep")

    # Cleanup EBS volumes
    ec2 = _client("ec2")
    try:
        volumes = ec2.describe_volumes(
            Filters=[
                {"Name": f"tag:{tag_key}", "Values": [tag_value]},
                {"Name": "status", "Values": ["available"]},
            ]
        ).get("Volumes", [])
        for vol in volumes:
            create_time = vol.get("CreateTime")
            if create_time and create_time.replace(tzinfo=timezone.utc) < cutoff:
                logger.warning("Cleaning up stale EBS test volume: %s", vol["VolumeId"])
                _cleanup_ebs_volume(ec2, vol["VolumeId"])
    except (BotoCoreError, ClientError):
        logger.exception("Error during EBS cleanup sweep")


# ---------------------------------------------------------------------------
# Evidence report generation
# ---------------------------------------------------------------------------


def generate_report(
    all_findings: list[dict],
    check_results: dict[str, list[dict]],
    run_time: datetime,
    restore_test_run: bool,
    restore_results: dict[str, list[dict]] | None = None,
) -> str:
    """Generate a text-based backup verification evidence report."""
    lines = [
        "=" * 70,
        "BACKUP VERIFICATION REPORT",
        f"Generated: {run_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Region: {AWS_REGION}",
        f"ISO 27001 Controls: A.8.13, A.8.14",
        f"Restore tests included: {'Yes' if restore_test_run else 'No'}",
        "=" * 70,
        "",
    ]

    # Summary
    total_checks = len(check_results)
    checks_pass = sum(1 for f in check_results.values() if not f)
    checks_fail = total_checks - checks_pass

    lines.append("VERIFICATION SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Backup sources checked: {total_checks}")
    lines.append(f"  Passing:                {checks_pass}")
    lines.append(f"  Failing:                {checks_fail}")
    lines.append(f"  Total findings:         {len(all_findings)}")
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

    # Restore test results
    if restore_test_run and restore_results:
        lines.append("")
        lines.append("RESTORE TEST RESULTS")
        lines.append("-" * 40)
        for test_name, test_findings in restore_results.items():
            status = "PASS" if not test_findings else "FAIL"
            lines.append(f"[{status}] {test_name}")
            for f in test_findings:
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
    """Create/update backup findings in CISO Assistant and upload evidence."""
    stats = {"new": 0, "updated": 0, "errors": 0, "alerts_sent": 0}

    for finding in all_findings:
        check_id = finding["check_id"]
        resource_arn = finding["resource_arn"]
        severity = finding["severity"]
        cached = cache.get(resource_arn, check_id)

        if cached is not None:
            cache.upsert(resource_arn, check_id, cached["ciso_id"], "FAIL")
            stats["updated"] += 1
            continue

        control_labels = ", ".join(finding.get("iso_controls", []))
        description = (
            f"**Source:** Backup Verification\n"
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
            logger.info("Created backup finding: %s (ciso_id=%s)", check_id, ciso_id)

            if severity in ("critical", "high"):
                alert_data = {
                    "check_id": check_id,
                    "title": finding["title"],
                    "severity": severity,
                    "resource_arn": resource_arn,
                    "region": AWS_REGION,
                    "description": finding["description"],
                    "service": "Backup Verification",
                }
                if alert_new_finding(alert_data, source="Backup Verification"):
                    stats["alerts_sent"] += 1

        except CISOClientError:
            logger.exception("Error creating finding: %s", check_id)
            stats["errors"] += 1

    # Upload evidence report
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="backup_verify_", delete=False
        ) as tmp:
            tmp.write(report_text)
            tmp_path = tmp.name

        report_name = f"Backup Verification Report — {run_time.strftime('%Y-%m-%d')}"
        client.upload_evidence(report_name, tmp_path, folder_id)
        logger.info("Uploaded backup verification evidence report")
        os.unlink(tmp_path)
    except (CISOClientError, OSError):
        logger.exception("Failed to upload evidence report")
        stats["errors"] += 1

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Backup Verification & Restore Testing")
    parser.add_argument(
        "--restore-test", action="store_true",
        help="Run monthly restore tests (RDS snapshot restore, EBS volume restore)",
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Safety-net cleanup of stale restore-test resources",
    )
    args = parser.parse_args()

    run_start = datetime.now(timezone.utc)

    # Load config
    config = load_config(CONFIG_FILE)
    checks_cfg = config.get("checks", {})
    thresholds = config.get("thresholds", {})
    logger.info("Loaded backup verification config")

    # Cleanup-only mode
    if args.cleanup:
        cleanup_stale_resources(config.get("cleanup", {}))
        logger.info("Cleanup complete")
        return

    # Run verification checks
    check_results: dict[str, list[dict]] = {}
    all_findings: list[dict] = []

    check_dispatch: list[tuple[str, str, Any]] = [
        ("rds_backups", "RDS Backups", lambda cfg: check_rds_backups(cfg, thresholds)),
        ("ebs_snapshots", "EBS Snapshots", lambda cfg: check_ebs_snapshots(cfg, thresholds)),
        ("s3_versioning", "S3 Versioning", lambda cfg: check_s3_versioning(cfg)),
        ("s3_export", "S3 Export (CISO)", lambda cfg: check_s3_export(cfg, thresholds)),
    ]

    for check_key, check_name, check_fn in check_dispatch:
        check_cfg = checks_cfg.get(check_key, {})
        if not check_cfg.get("enabled", True):
            logger.info("Skipping disabled check: %s", check_name)
            continue

        logger.info("=== Checking: %s ===", check_name)
        try:
            source_findings = check_fn(check_cfg)
            check_results[check_name] = source_findings
            all_findings.extend(source_findings)
            if source_findings:
                logger.info("  Found %d issue(s)", len(source_findings))
            else:
                logger.info("  PASS — no issues")
        except Exception:
            logger.exception("Unexpected error checking %s", check_name)
            check_results[check_name] = [{
                "check_id": f"backup-{check_key}-unexpected-error",
                "title": f"Unexpected Error Checking {check_name}",
                "description": f"An unexpected error occurred while checking {check_name}.",
                "severity": "medium",
                "resource_arn": check_key,
                "iso_controls": ["A.8.13"],
            }]
            all_findings.extend(check_results[check_name])

    # Run restore tests if requested
    restore_results: dict[str, list[dict]] = {}
    if args.restore_test:
        logger.info("=" * 60)
        logger.info("RUNNING MONTHLY RESTORE TESTS")
        logger.info("=" * 60)

        restore_cfg = config.get("restore_tests", {})

        if restore_cfg.get("rds", {}).get("enabled", True):
            logger.info("=== Restore Test: RDS ===")
            rds_results = restore_test_rds(restore_cfg.get("rds", {}))
            restore_results["RDS Restore Test"] = rds_results
            all_findings.extend(rds_results)
            if rds_results:
                logger.info("  RDS restore test: %d issue(s)", len(rds_results))
            else:
                logger.info("  RDS restore test: PASSED")

        if restore_cfg.get("ebs", {}).get("enabled", True):
            logger.info("=== Restore Test: EBS ===")
            ebs_results = restore_test_ebs(restore_cfg.get("ebs", {}))
            restore_results["EBS Restore Test"] = ebs_results
            all_findings.extend(ebs_results)
            if ebs_results:
                logger.info("  EBS restore test: %d issue(s)", len(ebs_results))
            else:
                logger.info("  EBS restore test: PASSED")

        # Run safety-net cleanup after restore tests
        cleanup_stale_resources(config.get("cleanup", {}))

    # Generate evidence report
    report_text = generate_report(
        all_findings, check_results, run_start, args.restore_test, restore_results
    )

    # Log summary
    logger.info("=" * 60)
    logger.info("BACKUP VERIFICATION SUMMARY")
    logger.info("=" * 60)
    sources_checked = len(check_results)
    sources_pass = sum(1 for f in check_results.values() if not f)
    logger.info("  Sources checked:     %d", sources_checked)
    logger.info("  Sources passing:     %d", sources_pass)
    logger.info("  Sources failing:     %d", sources_checked - sources_pass)
    logger.info("  Total findings:      %d", len(all_findings))
    if args.restore_test:
        tests_pass = sum(1 for f in restore_results.values() if not f)
        logger.info("  Restore tests run:   %d", len(restore_results))
        logger.info("  Restore tests pass:  %d", tests_pass)
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
    summary: dict[str, Any] = {
        "timestamp": run_start.isoformat(),
        "region": AWS_REGION,
        "sources_checked": sources_checked,
        "sources_passing": sources_pass,
        "sources_failing": sources_checked - sources_pass,
        "total_findings": len(all_findings),
        "restore_test_run": args.restore_test,
        "findings_by_severity": {
            sev: sum(1 for f in all_findings if f.get("severity") == sev)
            for sev in ("critical", "high", "medium", "low")
        },
        **stats,
    }
    if args.restore_test:
        summary["restore_tests"] = {
            name: "PASS" if not findings else "FAIL"
            for name, findings in restore_results.items()
        }

    os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
    with open(SCAN_SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    # Send scan completion alert
    scan_type = "backup-verification-with-restore" if args.restore_test else "backup-verification"
    alert_scan_complete(
        {
            "input_file": "backup_verifier",
            "total_findings": len(all_findings),
            **stats,
        },
        scan_type=scan_type,
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
        alert_scan_failure(str(e), scan_type="backup-verification")
        raise
