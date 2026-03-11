#!/usr/bin/env python3
"""
Asset Inventory Sync — AWS Resource Inventory for ISO 27001

Pulls AWS resource inventory using boto3 and the Resource Groups Tagging API,
checks required tag compliance, and pushes tag violation findings into
CISO Assistant. Generates a summary asset inventory report as evidence.

Usage:
    python asset_inventory.py                # Full inventory scan
    python asset_inventory.py --region us-east-1  # Specific region

ISO 27001 Controls:
    A.5.9  — Inventory of Information and Other Associated Assets
    A.5.12 — Classification of Information
    A.8.9  — Configuration Management
"""

import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from alerter import alert_new_finding, alert_scan_complete, alert_scan_failure
from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("asset_inventory")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
MAPPING_FILE = Path(__file__).parent / "mappings" / "required_tags.json"
REPORT_DIR = os.getenv("ASSET_REPORT_DIR", "/data/glue/reports")
CHECK_ID = "tag_compliance"


# ---------------------------------------------------------------------------
# Mapping Loader
# ---------------------------------------------------------------------------
def load_tag_mappings(mapping_file: Path) -> dict:
    """Load the required tags configuration."""
    with open(mapping_file) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Severity helpers (matching prowler_mapper.py conventions)
# ---------------------------------------------------------------------------
def _severity_to_priority(severity: str) -> int:
    """Map severity to CISO Assistant priority (P1-P4)."""
    return {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "informational": 4,
    }.get(severity, 3)


def _severity_to_finding_severity(severity: str) -> int:
    """Map severity string to CISO Assistant Finding severity integer."""
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }.get(severity, 2)


# ---------------------------------------------------------------------------
# AWS Resource Collectors
# ---------------------------------------------------------------------------
def _get_session(region: str) -> boto3.Session:
    """Create a boto3 session for the given region."""
    return boto3.Session(region_name=region)


def _safe_api_call(func, *args, **kwargs):
    """Wrapper for boto3 calls with error handling."""
    try:
        return func(*args, **kwargs)
    except (BotoCoreError, ClientError) as e:
        logger.warning("API call failed: %s — %s", func.__name__, e)
        return None


def collect_ec2_resources(session: boto3.Session) -> list[dict]:
    """Collect EC2 instances, volumes, snapshots, AMIs, and Elastic IPs."""
    ec2 = session.client("ec2")
    resources = []

    # Instances
    resp = _safe_api_call(ec2.describe_instances)
    if resp:
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                resources.append({
                    "arn": f"arn:aws:ec2:{session.region_name}:{inst.get('OwnerId', 'unknown')}:instance/{inst['InstanceId']}",
                    "resource_id": inst["InstanceId"],
                    "resource_type": "ec2:instance",
                    "service": "ec2",
                    "tags": tags,
                    "metadata": {
                        "state": inst.get("State", {}).get("Name"),
                        "instance_type": inst.get("InstanceType"),
                        "launch_time": inst.get("LaunchTime", "").isoformat() if inst.get("LaunchTime") else "",
                        "private_ip": inst.get("PrivateIpAddress"),
                        "public_ip": inst.get("PublicIpAddress"),
                    },
                })

    # Volumes
    resp = _safe_api_call(ec2.describe_volumes)
    if resp:
        for vol in resp.get("Volumes", []):
            tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:unknown:volume/{vol['VolumeId']}",
                "resource_id": vol["VolumeId"],
                "resource_type": "ec2:volume",
                "service": "ec2",
                "tags": tags,
                "metadata": {
                    "state": vol.get("State"),
                    "size_gb": vol.get("Size"),
                    "encrypted": vol.get("Encrypted", False),
                    "volume_type": vol.get("VolumeType"),
                },
            })

    # Snapshots (owned by self)
    resp = _safe_api_call(ec2.describe_snapshots, OwnerIds=["self"])
    if resp:
        for snap in resp.get("Snapshots", []):
            tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:{snap.get('OwnerId', 'unknown')}:snapshot/{snap['SnapshotId']}",
                "resource_id": snap["SnapshotId"],
                "resource_type": "ec2:snapshot",
                "service": "ec2",
                "tags": tags,
                "metadata": {
                    "state": snap.get("State"),
                    "volume_size_gb": snap.get("VolumeSize"),
                    "encrypted": snap.get("Encrypted", False),
                },
            })

    # AMIs (owned by self)
    resp = _safe_api_call(ec2.describe_images, Owners=["self"])
    if resp:
        for img in resp.get("Images", []):
            tags = {t["Key"]: t["Value"] for t in img.get("Tags", [])}
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:{img.get('OwnerId', 'unknown')}:image/{img['ImageId']}",
                "resource_id": img["ImageId"],
                "resource_type": "ec2:image",
                "service": "ec2",
                "tags": tags,
                "metadata": {
                    "name": img.get("Name"),
                    "state": img.get("State"),
                    "creation_date": img.get("CreationDate"),
                },
            })

    # Elastic IPs
    resp = _safe_api_call(ec2.describe_addresses)
    if resp:
        for addr in resp.get("Addresses", []):
            tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
            alloc_id = addr.get("AllocationId", "unknown")
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:unknown:elastic-ip/{alloc_id}",
                "resource_id": alloc_id,
                "resource_type": "ec2:elastic-ip",
                "service": "ec2",
                "tags": tags,
                "metadata": {
                    "public_ip": addr.get("PublicIp"),
                    "associated_instance": addr.get("InstanceId"),
                    "domain": addr.get("Domain"),
                },
            })

    return resources


def collect_s3_resources(session: boto3.Session) -> list[dict]:
    """Collect S3 buckets with encryption, public access, and versioning status."""
    s3 = session.client("s3")
    resources = []

    resp = _safe_api_call(s3.list_buckets)
    if not resp:
        return resources

    for bucket in resp.get("Buckets", []):
        name = bucket["Name"]

        # Get tags
        tags = {}
        tag_resp = _safe_api_call(s3.get_bucket_tagging, Bucket=name)
        if tag_resp:
            tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagSet", [])}

        # Encryption status
        encryption = "none"
        enc_resp = _safe_api_call(s3.get_bucket_encryption, Bucket=name)
        if enc_resp:
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                encryption = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "none")

        # Public access block
        public_access = "unknown"
        pab_resp = _safe_api_call(s3.get_public_access_block, Bucket=name)
        if pab_resp:
            config = pab_resp.get("PublicAccessBlockConfiguration", {})
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            public_access = "blocked" if all_blocked else "partially_open"
        else:
            public_access = "no_block_configured"

        # Versioning
        versioning = "disabled"
        ver_resp = _safe_api_call(s3.get_bucket_versioning, Bucket=name)
        if ver_resp:
            versioning = ver_resp.get("Status", "disabled").lower()

        resources.append({
            "arn": f"arn:aws:s3:::{name}",
            "resource_id": name,
            "resource_type": "s3:bucket",
            "service": "s3",
            "tags": tags,
            "metadata": {
                "encryption": encryption,
                "public_access": public_access,
                "versioning": versioning,
                "creation_date": bucket.get("CreationDate", "").isoformat() if bucket.get("CreationDate") else "",
            },
        })

    return resources


def collect_rds_resources(session: boto3.Session) -> list[dict]:
    """Collect RDS DB instances and clusters."""
    rds = session.client("rds")
    resources = []

    # DB instances
    resp = _safe_api_call(rds.describe_db_instances)
    if resp:
        for db in resp.get("DBInstances", []):
            # RDS tags require a separate call
            tags = {}
            tag_resp = _safe_api_call(rds.list_tags_for_resource, ResourceName=db["DBInstanceArn"])
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagList", [])}

            resources.append({
                "arn": db["DBInstanceArn"],
                "resource_id": db["DBInstanceIdentifier"],
                "resource_type": "rds:db-instance",
                "service": "rds",
                "tags": tags,
                "metadata": {
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "instance_class": db.get("DBInstanceClass"),
                    "storage_encrypted": db.get("StorageEncrypted", False),
                    "multi_az": db.get("MultiAZ", False),
                    "publicly_accessible": db.get("PubliclyAccessible", False),
                    "status": db.get("DBInstanceStatus"),
                },
            })

    # DB clusters
    resp = _safe_api_call(rds.describe_db_clusters)
    if resp:
        for cluster in resp.get("DBClusters", []):
            tags = {}
            tag_resp = _safe_api_call(rds.list_tags_for_resource, ResourceName=cluster["DBClusterArn"])
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagList", [])}

            resources.append({
                "arn": cluster["DBClusterArn"],
                "resource_id": cluster["DBClusterIdentifier"],
                "resource_type": "rds:cluster",
                "service": "rds",
                "tags": tags,
                "metadata": {
                    "engine": cluster.get("Engine"),
                    "engine_version": cluster.get("EngineVersion"),
                    "storage_encrypted": cluster.get("StorageEncrypted", False),
                    "multi_az": cluster.get("MultiAZ", False),
                    "status": cluster.get("Status"),
                },
            })

    return resources


def collect_lambda_resources(session: boto3.Session) -> list[dict]:
    """Collect Lambda functions."""
    lam = session.client("lambda")
    resources = []

    resp = _safe_api_call(lam.list_functions)
    if resp:
        for func in resp.get("Functions", []):
            # Lambda tags are returned inline
            tags = func.get("Tags", {}) or {}
            resources.append({
                "arn": func["FunctionArn"],
                "resource_id": func["FunctionName"],
                "resource_type": "lambda:function",
                "service": "lambda",
                "tags": tags,
                "metadata": {
                    "runtime": func.get("Runtime"),
                    "handler": func.get("Handler"),
                    "memory_mb": func.get("MemorySize"),
                    "timeout_sec": func.get("Timeout"),
                    "last_modified": func.get("LastModified"),
                },
            })

    return resources


def collect_iam_resources(session: boto3.Session) -> list[dict]:
    """Collect IAM users and roles."""
    iam = session.client("iam")
    resources = []

    # Users
    resp = _safe_api_call(iam.list_users)
    if resp:
        for user in resp.get("Users", []):
            tags = {}
            tag_resp = _safe_api_call(iam.list_user_tags, UserName=user["UserName"])
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}

            resources.append({
                "arn": user["Arn"],
                "resource_id": user["UserName"],
                "resource_type": "iam:user",
                "service": "iam",
                "tags": tags,
                "metadata": {
                    "create_date": user.get("CreateDate", "").isoformat() if user.get("CreateDate") else "",
                    "password_last_used": user.get("PasswordLastUsed", "").isoformat() if user.get("PasswordLastUsed") else "",
                    "path": user.get("Path"),
                },
            })

    # Roles (skip service-linked roles)
    resp = _safe_api_call(iam.list_roles)
    if resp:
        for role in resp.get("Roles", []):
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            tags = {}
            tag_resp = _safe_api_call(iam.list_role_tags, RoleName=role["RoleName"])
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}

            resources.append({
                "arn": role["Arn"],
                "resource_id": role["RoleName"],
                "resource_type": "iam:role",
                "service": "iam",
                "tags": tags,
                "metadata": {
                    "create_date": role.get("CreateDate", "").isoformat() if role.get("CreateDate") else "",
                    "path": role.get("Path"),
                    "max_session_duration": role.get("MaxSessionDuration"),
                },
            })

    return resources


def collect_vpc_resources(session: boto3.Session) -> list[dict]:
    """Collect VPCs, subnets, and security groups."""
    ec2 = session.client("ec2")
    resources = []

    # VPCs
    resp = _safe_api_call(ec2.describe_vpcs)
    if resp:
        for vpc in resp.get("Vpcs", []):
            tags = {t["Key"]: t["Value"] for t in vpc.get("Tags", [])}
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:{vpc.get('OwnerId', 'unknown')}:vpc/{vpc['VpcId']}",
                "resource_id": vpc["VpcId"],
                "resource_type": "ec2:vpc",
                "service": "vpc",
                "tags": tags,
                "metadata": {
                    "cidr_block": vpc.get("CidrBlock"),
                    "state": vpc.get("State"),
                    "is_default": vpc.get("IsDefault", False),
                },
            })

    # Subnets
    resp = _safe_api_call(ec2.describe_subnets)
    if resp:
        for subnet in resp.get("Subnets", []):
            tags = {t["Key"]: t["Value"] for t in subnet.get("Tags", [])}
            resources.append({
                "arn": subnet.get("SubnetArn", f"arn:aws:ec2:{session.region_name}:unknown:subnet/{subnet['SubnetId']}"),
                "resource_id": subnet["SubnetId"],
                "resource_type": "ec2:subnet",
                "service": "vpc",
                "tags": tags,
                "metadata": {
                    "vpc_id": subnet.get("VpcId"),
                    "cidr_block": subnet.get("CidrBlock"),
                    "availability_zone": subnet.get("AvailabilityZone"),
                    "map_public_ip": subnet.get("MapPublicIpOnLaunch", False),
                },
            })

    # Security Groups
    resp = _safe_api_call(ec2.describe_security_groups)
    if resp:
        for sg in resp.get("SecurityGroups", []):
            tags = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
            resources.append({
                "arn": f"arn:aws:ec2:{session.region_name}:{sg.get('OwnerId', 'unknown')}:security-group/{sg['GroupId']}",
                "resource_id": sg["GroupId"],
                "resource_type": "ec2:security-group",
                "service": "vpc",
                "tags": tags,
                "metadata": {
                    "group_name": sg.get("GroupName"),
                    "vpc_id": sg.get("VpcId"),
                    "description": sg.get("Description"),
                    "ingress_rules_count": len(sg.get("IpPermissions", [])),
                    "egress_rules_count": len(sg.get("IpPermissionsEgress", [])),
                },
            })

    return resources


def collect_ecs_eks_resources(session: boto3.Session) -> list[dict]:
    """Collect ECS and EKS clusters."""
    resources = []

    # ECS clusters
    ecs = session.client("ecs")
    resp = _safe_api_call(ecs.list_clusters)
    if resp and resp.get("clusterArns"):
        detail_resp = _safe_api_call(ecs.describe_clusters, clusters=resp["clusterArns"], include=["TAGS"])
        if detail_resp:
            for cluster in detail_resp.get("clusters", []):
                tags = {t["key"]: t["value"] for t in cluster.get("tags", [])}
                resources.append({
                    "arn": cluster["clusterArn"],
                    "resource_id": cluster["clusterName"],
                    "resource_type": "ecs:cluster",
                    "service": "ecs",
                    "tags": tags,
                    "metadata": {
                        "status": cluster.get("status"),
                        "running_tasks": cluster.get("runningTasksCount", 0),
                        "active_services": cluster.get("activeServicesCount", 0),
                    },
                })

    # EKS clusters
    eks = session.client("eks")
    resp = _safe_api_call(eks.list_clusters)
    if resp:
        for cluster_name in resp.get("clusters", []):
            detail_resp = _safe_api_call(eks.describe_cluster, name=cluster_name)
            if detail_resp:
                cluster = detail_resp.get("cluster", {})
                tags = cluster.get("tags", {}) or {}
                resources.append({
                    "arn": cluster.get("arn", f"arn:aws:eks:{session.region_name}:unknown:cluster/{cluster_name}"),
                    "resource_id": cluster_name,
                    "resource_type": "eks:cluster",
                    "service": "eks",
                    "tags": tags,
                    "metadata": {
                        "status": cluster.get("status"),
                        "version": cluster.get("version"),
                        "platform_version": cluster.get("platformVersion"),
                    },
                })

    return resources


def collect_route53_resources(session: boto3.Session) -> list[dict]:
    """Collect Route 53 hosted zones."""
    r53 = session.client("route53")
    resources = []

    resp = _safe_api_call(r53.list_hosted_zones)
    if resp:
        for zone in resp.get("HostedZones", []):
            zone_id = zone["Id"].split("/")[-1]
            # Route 53 tags require a separate call
            tags = {}
            tag_resp = _safe_api_call(r53.list_tags_for_resource, ResourceType="hostedzone", ResourceId=zone_id)
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("ResourceTagSet", {}).get("Tags", [])}

            resources.append({
                "arn": f"arn:aws:route53:::hostedzone/{zone_id}",
                "resource_id": zone_id,
                "resource_type": "route53:hostedzone",
                "service": "route53",
                "tags": tags,
                "metadata": {
                    "name": zone.get("Name"),
                    "record_count": zone.get("ResourceRecordSetCount", 0),
                    "private": zone.get("Config", {}).get("PrivateZone", False),
                },
            })

    return resources


def collect_cloudfront_resources(session: boto3.Session) -> list[dict]:
    """Collect CloudFront distributions."""
    cf = session.client("cloudfront")
    resources = []

    resp = _safe_api_call(cf.list_distributions)
    if resp:
        dist_list = resp.get("DistributionList", {})
        for dist in dist_list.get("Items", []):
            # CloudFront tags require a separate call
            arn = dist["ARN"]
            tags = {}
            tag_resp = _safe_api_call(cf.list_tags_for_resource, Resource=arn)
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", {}).get("Items", [])}

            resources.append({
                "arn": arn,
                "resource_id": dist["Id"],
                "resource_type": "cloudfront:distribution",
                "service": "cloudfront",
                "tags": tags,
                "metadata": {
                    "domain_name": dist.get("DomainName"),
                    "status": dist.get("Status"),
                    "enabled": dist.get("Enabled", False),
                    "http_version": dist.get("HttpVersion"),
                },
            })

    return resources


def collect_sns_sqs_resources(session: boto3.Session) -> list[dict]:
    """Collect SNS topics and SQS queues."""
    resources = []

    # SNS topics
    sns = session.client("sns")
    resp = _safe_api_call(sns.list_topics)
    if resp:
        for topic in resp.get("Topics", []):
            arn = topic["TopicArn"]
            tags = {}
            tag_resp = _safe_api_call(sns.list_tags_for_resource, ResourceArn=arn)
            if tag_resp:
                tags = {t["Key"]: t["Value"] for t in tag_resp.get("Tags", [])}

            topic_name = arn.split(":")[-1]
            resources.append({
                "arn": arn,
                "resource_id": topic_name,
                "resource_type": "sns:topic",
                "service": "sns",
                "tags": tags,
                "metadata": {"topic_name": topic_name},
            })

    # SQS queues
    sqs = session.client("sqs")
    resp = _safe_api_call(sqs.list_queues)
    if resp:
        for queue_url in resp.get("QueueUrls", []):
            # Get queue attributes for ARN
            attr_resp = _safe_api_call(sqs.get_queue_attributes, QueueUrl=queue_url, AttributeNames=["QueueArn"])
            queue_arn = "unknown"
            if attr_resp:
                queue_arn = attr_resp.get("Attributes", {}).get("QueueArn", "unknown")

            tags = {}
            tag_resp = _safe_api_call(sqs.list_queue_tags, QueueUrl=queue_url)
            if tag_resp:
                tags = tag_resp.get("Tags", {})

            queue_name = queue_url.split("/")[-1]
            resources.append({
                "arn": queue_arn,
                "resource_id": queue_name,
                "resource_type": "sqs:queue",
                "service": "sqs",
                "tags": tags,
                "metadata": {"queue_url": queue_url},
            })

    return resources


def collect_secrets_manager_resources(session: boto3.Session) -> list[dict]:
    """Collect Secrets Manager secrets (metadata only)."""
    sm = session.client("secretsmanager")
    resources = []

    resp = _safe_api_call(sm.list_secrets)
    if resp:
        for secret in resp.get("SecretList", []):
            tags = {t["Key"]: t["Value"] for t in secret.get("Tags", [])}
            resources.append({
                "arn": secret["ARN"],
                "resource_id": secret["Name"],
                "resource_type": "secretsmanager:secret",
                "service": "secretsmanager",
                "tags": tags,
                "metadata": {
                    "last_accessed": secret.get("LastAccessedDate", "").isoformat() if secret.get("LastAccessedDate") else "",
                    "last_rotated": secret.get("LastRotatedDate", "").isoformat() if secret.get("LastRotatedDate") else "",
                    "rotation_enabled": secret.get("RotationEnabled", False),
                },
            })

    return resources


def collect_kms_resources(session: boto3.Session) -> list[dict]:
    """Collect KMS keys with rotation status."""
    kms = session.client("kms")
    resources = []

    resp = _safe_api_call(kms.list_keys)
    if resp:
        for key_entry in resp.get("Keys", []):
            key_id = key_entry["KeyId"]

            # Get key metadata
            desc_resp = _safe_api_call(kms.describe_key, KeyId=key_id)
            if not desc_resp:
                continue
            key_meta = desc_resp.get("KeyMetadata", {})

            # Skip AWS-managed keys
            if key_meta.get("KeyManager") == "AWS":
                continue

            # Get tags
            tags = {}
            tag_resp = _safe_api_call(kms.list_resource_tags, KeyId=key_id)
            if tag_resp:
                tags = {t["TagKey"]: t["TagValue"] for t in tag_resp.get("Tags", [])}

            # Get rotation status
            rotation_enabled = False
            rot_resp = _safe_api_call(kms.get_key_rotation_status, KeyId=key_id)
            if rot_resp:
                rotation_enabled = rot_resp.get("KeyRotationEnabled", False)

            resources.append({
                "arn": key_meta.get("Arn", key_entry.get("KeyArn", "")),
                "resource_id": key_id,
                "resource_type": "kms:key",
                "service": "kms",
                "tags": tags,
                "metadata": {
                    "key_state": key_meta.get("KeyState"),
                    "key_usage": key_meta.get("KeyUsage"),
                    "origin": key_meta.get("Origin"),
                    "rotation_enabled": rotation_enabled,
                    "creation_date": key_meta.get("CreationDate", "").isoformat() if key_meta.get("CreationDate") else "",
                },
            })

    return resources


def collect_tagged_resources(session: boto3.Session) -> dict[str, dict]:
    """Use Resource Groups Tagging API as primary tag source.

    Returns a dict mapping resource ARN -> {tags dict}.
    """
    tagging = session.client("resourcegroupstaggingapi")
    arn_tags: dict[str, dict] = {}

    try:
        paginator = tagging.get_paginator("get_resources")
        for page in paginator.paginate():
            for resource in page.get("ResourceTagMappingList", []):
                arn = resource.get("ResourceARN", "")
                tags = {t["Key"]: t["Value"] for t in resource.get("Tags", [])}
                arn_tags[arn] = tags
    except (BotoCoreError, ClientError) as e:
        logger.warning("Resource Groups Tagging API failed: %s", e)

    return arn_tags


# ---------------------------------------------------------------------------
# Full inventory collection
# ---------------------------------------------------------------------------
def collect_all_resources(region: str) -> list[dict]:
    """Collect resources from all supported AWS services."""
    session = _get_session(region)
    all_resources: list[dict] = []

    collectors = [
        ("EC2", collect_ec2_resources),
        ("S3", collect_s3_resources),
        ("RDS", collect_rds_resources),
        ("Lambda", collect_lambda_resources),
        ("IAM", collect_iam_resources),
        ("VPC", collect_vpc_resources),
        ("ECS/EKS", collect_ecs_eks_resources),
        ("Route53", collect_route53_resources),
        ("CloudFront", collect_cloudfront_resources),
        ("SNS/SQS", collect_sns_sqs_resources),
        ("Secrets Manager", collect_secrets_manager_resources),
        ("KMS", collect_kms_resources),
    ]

    for name, collector in collectors:
        logger.info("Collecting %s resources...", name)
        try:
            resources = collector(session)
            logger.info("  Found %d %s resources", len(resources), name)
            all_resources.extend(resources)
        except Exception:
            logger.exception("Error collecting %s resources", name)

    # Enrich with Resource Groups Tagging API
    logger.info("Enriching tags via Resource Groups Tagging API...")
    tagging_tags = collect_tagged_resources(session)
    enriched = 0
    for resource in all_resources:
        arn = resource.get("arn", "")
        if arn in tagging_tags:
            # Tagging API is authoritative — merge, preferring its values
            merged = {**resource.get("tags", {}), **tagging_tags[arn]}
            if merged != resource.get("tags", {}):
                enriched += 1
            resource["tags"] = merged
    logger.info("  Enriched tags for %d resources from Tagging API", enriched)

    return all_resources


# ---------------------------------------------------------------------------
# Tag Compliance Checker
# ---------------------------------------------------------------------------
def check_tag_compliance(
    resources: list[dict], tag_config: dict
) -> tuple[list[dict], list[dict]]:
    """Check resources against required tag policies.

    Returns (violations, compliant) where each entry has resource info
    plus missing_tags and severity fields.
    """
    global_required = tag_config.get("global_required_tags", [])
    overrides = tag_config.get("resource_type_overrides", {})

    violations = []
    compliant = []

    for resource in resources:
        rtype = resource.get("resource_type", "")
        tags = resource.get("tags", {})

        # Determine required tags for this resource type
        if rtype in overrides:
            override = overrides[rtype]
            required = override.get("required_tags", global_required)
            severity = override.get("severity", "medium")
        else:
            required = global_required
            severity = "medium"

        # Find missing tags
        missing = [tag for tag in required if tag not in tags]

        entry = {
            **resource,
            "required_tags": required,
            "missing_tags": missing,
            "severity": severity,
            "compliant": len(missing) == 0,
        }

        if missing:
            violations.append(entry)
        else:
            compliant.append(entry)

    return violations, compliant


# ---------------------------------------------------------------------------
# CISO Assistant Integration
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
    client: CISOClient, folder_id: str, name: str = "AWS Asset Inventory — Tag Compliance"
) -> str:
    """Get or create a findings assessment for asset inventory results."""
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
            "description": "Automated findings from AWS asset inventory tag compliance scans",
            "folder": folder_id,
            "category": "audit",
        }
    )
    logger.info(
        "Created findings assessment: %s (id=%s)", name, assessment["id"]
    )
    return assessment["id"]


def build_tag_violation_payload(
    resource: dict,
    findings_assessment_id: str,
    annex_labels: dict,
) -> dict:
    """Build a CISO Assistant Finding payload for a tag compliance violation."""
    severity = resource.get("severity", "medium")
    missing = resource.get("missing_tags", [])
    rtype = resource.get("resource_type", "unknown")
    arn = resource.get("arn", "unknown")

    controls = ["A.5.9", "A.5.12", "A.8.9"]
    control_labels = [f"{c}: {annex_labels.get(c, '')}" for c in controls]

    description = (
        f"**Resource:** {arn}\n"
        f"**Resource Type:** {rtype}\n"
        f"**Service:** {resource.get('service', 'unknown')}\n"
        f"**ISO 27001 Controls:** {', '.join(control_labels)}\n\n"
        f"**Missing Required Tags:** {', '.join(missing)}\n\n"
        f"This resource is missing {len(missing)} required tag(s) for ISO 27001 "
        f"asset inventory compliance (A.5.9) and information classification (A.5.12).\n\n"
        f"**Current Tags:** {json.dumps(resource.get('tags', {}), indent=2)}"
    )

    observation = (
        f"**Remediation:** Add the following tags to resource {arn}:\n"
        + "\n".join(f"  - `{tag}`" for tag in missing)
    )

    payload: dict = {
        "name": f"[TAG_COMPLIANCE] {rtype}: {resource.get('resource_id', 'unknown')} — missing {', '.join(missing)}"[:200],
        "description": description,
        "findings_assessment": findings_assessment_id,
        "severity": _severity_to_finding_severity(severity),
        "status": "identified",
        "ref_id": f"tag_compliance:{rtype}:{resource.get('resource_id', 'unknown')}"[:100],
        "observation": observation,
        "priority": _severity_to_priority(severity),
    }

    return payload


def process_violations(
    client: CISOClient,
    violations: list[dict],
    cache: DedupCache,
    findings_assessment_id: str,
    annex_labels: dict,
) -> dict:
    """Process tag violations: create/update findings in CISO Assistant with dedup."""
    stats = {"new": 0, "updated": 0, "resolved": 0, "errors": 0}

    for resource in violations:
        arn = resource.get("arn", "unknown")
        key = (arn, CHECK_ID)
        cached = cache.get(*key)

        try:
            payload = build_tag_violation_payload(
                resource, findings_assessment_id, annex_labels
            )

            if cached is None:
                # New violation
                result = client.create_finding(payload)
                cache.upsert(*key, ciso_id=str(result["id"]), status="FAIL")
                stats["new"] += 1
                logger.debug("Created tag violation finding: %s", arn)

                # Alert on critical/high untagged resources
                alert_finding = {
                    "severity": resource.get("severity", "medium"),
                    "title": f"Missing tags on {resource.get('resource_type')}: {resource.get('resource_id')}",
                    "check_id": CHECK_ID,
                    "resource_arn": arn,
                    "region": AWS_REGION,
                    "service": resource.get("service", "unknown"),
                    "description": f"Missing required tags: {', '.join(resource.get('missing_tags', []))}",
                    "remediation": f"Add required tags: {', '.join(resource.get('missing_tags', []))}",
                }
                alert_new_finding(alert_finding, source="AssetInventory")

            else:
                # Existing violation — update
                client.update_finding(cached["ciso_id"], payload)
                cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
                stats["updated"] += 1

        except CISOClientError:
            logger.exception("Error processing tag violation for: %s", arn)
            stats["errors"] += 1

    return stats


def resolve_compliant_resources(
    client: CISOClient,
    compliant: list[dict],
    cache: DedupCache,
) -> int:
    """Mark previously-violated resources as resolved if now compliant."""
    resolved_count = 0

    for resource in compliant:
        arn = resource.get("arn", "unknown")
        key = (arn, CHECK_ID)
        cached = cache.get(*key)

        if cached and cached["status"] == "FAIL":
            try:
                client.update_finding(
                    cached["ciso_id"],
                    {
                        "status": "resolved",
                        "observation": (
                            f"**RESOLVED** on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                            f"**Resource:** {arn}\n"
                            f"All required tags are now present."
                        ),
                    },
                )
                cache.upsert(*key, ciso_id=cached["ciso_id"], status="PASS")
                resolved_count += 1
                logger.info("Resolved tag violation: %s", arn)
            except CISOClientError:
                logger.exception("Error resolving tag violation for: %s", arn)

    return resolved_count


# ---------------------------------------------------------------------------
# Asset Sync — push resources into CISO Assistant Asset Management
# ---------------------------------------------------------------------------
ASSET_TYPE_MAP = {
    # Maps AWS service to CISO Assistant asset type
    # "PR" = Primary (business process/function), "SP" = Supporting (technical)
    "ec2": "SP",
    "s3": "SP",
    "rds": "SP",
    "lambda": "SP",
    "iam": "SP",
    "vpc": "SP",
    "ecs": "SP",
    "eks": "SP",
    "route53": "SP",
    "cloudfront": "SP",
    "sns": "SP",
    "sqs": "SP",
    "secretsmanager": "SP",
    "kms": "SP",
}


def sync_assets_to_ciso(
    client: CISOClient,
    resources: list[dict],
    folder_id: str,
) -> dict:
    """Create or update assets in CISO Assistant's Asset Management.

    Returns stats dict with counts of created/updated/errors.
    """
    stats = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}

    # Fetch existing assets to avoid duplicates (keyed by ref_id)
    existing = {}
    try:
        for asset in client.list_assets():
            ref = asset.get("ref_id", "")
            if ref:
                existing[ref] = asset
    except CISOClientError:
        logger.warning("Could not list existing assets, will create all")

    for resource in resources:
        arn = resource.get("arn", "")
        rid = resource.get("resource_id", "unknown")
        rtype = resource.get("resource_type", "unknown")
        service = resource.get("service", "unknown")
        tags = resource.get("tags", {})
        meta = resource.get("metadata", {})

        # Use ARN as the unique ref_id
        ref_id = arn[:100] if arn else f"{rtype}:{rid}"[:100]

        # Build a human-readable name
        name_tag = tags.get("Name", "")
        display_name = f"{name_tag} ({rid})" if name_tag else rid
        asset_name = f"[{rtype}] {display_name}"[:200]

        # Build description with metadata
        desc_parts = [
            f"**ARN:** `{arn}`",
            f"**Type:** {rtype}",
            f"**Service:** {service}",
            f"**Region:** {resource.get('region', AWS_REGION)}",
        ]
        if tags:
            desc_parts.append(f"**Tags:** {json.dumps(tags, indent=2)}")
        if meta:
            meta_lines = [f"  - {k}: {v}" for k, v in meta.items() if v]
            if meta_lines:
                desc_parts.append("**Metadata:**\n" + "\n".join(meta_lines))
        description = "\n".join(desc_parts)

        asset_type = ASSET_TYPE_MAP.get(service, "SP")

        payload = {
            "name": asset_name,
            "description": description,
            "folder": folder_id,
            "type": asset_type,
            "ref_id": ref_id,
        }

        try:
            if ref_id in existing:
                # Update existing asset
                client.update_asset(existing[ref_id]["id"], payload)
                stats["updated"] += 1
            else:
                client.create_asset(payload)
                stats["created"] += 1
        except CISOClientError:
            logger.debug("Error syncing asset: %s", arn)
            stats["errors"] += 1

    logger.info(
        "Asset sync: %d created, %d updated, %d errors",
        stats["created"], stats["updated"], stats["errors"],
    )
    return stats


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------
def generate_inventory_report(
    resources: list[dict],
    violations: list[dict],
    compliant: list[dict],
    stats: dict,
    region: str,
) -> str:
    """Generate a JSON asset inventory report and save to disk."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(REPORT_DIR, f"asset_inventory_{timestamp}.json")

    # Build service-level summary
    service_summary: dict[str, dict] = {}
    for r in resources:
        svc = r.get("service", "unknown")
        rtype = r.get("resource_type", "unknown")
        if svc not in service_summary:
            service_summary[svc] = {"total": 0, "types": {}}
        service_summary[svc]["total"] += 1
        service_summary[svc]["types"][rtype] = service_summary[svc]["types"].get(rtype, 0) + 1

    # Build violation summary by severity
    violation_by_severity: dict[str, int] = {}
    for v in violations:
        sev = v.get("severity", "medium")
        violation_by_severity[sev] = violation_by_severity.get(sev, 0) + 1

    report = {
        "report_type": "aws_asset_inventory",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "summary": {
            "total_resources": len(resources),
            "total_compliant": len(compliant),
            "total_violations": len(violations),
            "compliance_rate_pct": round(
                len(compliant) / len(resources) * 100, 1
            ) if resources else 0,
            "violations_by_severity": violation_by_severity,
            "service_summary": service_summary,
        },
        "processing_stats": stats,
        "violations": [
            {
                "arn": v["arn"],
                "resource_id": v.get("resource_id"),
                "resource_type": v.get("resource_type"),
                "service": v.get("service"),
                "severity": v.get("severity"),
                "missing_tags": v.get("missing_tags"),
                "current_tags": v.get("tags", {}),
            }
            for v in violations
        ],
        "resources": [
            {
                "arn": r["arn"],
                "resource_id": r.get("resource_id"),
                "resource_type": r.get("resource_type"),
                "service": r.get("service"),
                "tags": r.get("tags", {}),
                "metadata": r.get("metadata", {}),
            }
            for r in resources
        ],
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    logger.info("Asset inventory report written to %s", report_path)
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # Parse region from CLI args
    region = AWS_REGION
    if len(sys.argv) > 1 and sys.argv[1] == "--region" and len(sys.argv) > 2:
        region = sys.argv[2]

    logger.info("Starting AWS asset inventory scan for region: %s", region)

    # Load tag configuration
    tag_config = load_tag_mappings(MAPPING_FILE)
    annex_labels = tag_config.get("annex_a_controls", {})
    logger.info(
        "Loaded tag config: %d global required tags, %d resource type overrides",
        len(tag_config.get("global_required_tags", [])),
        len(tag_config.get("resource_type_overrides", {})),
    )

    # Collect all resources
    resources = collect_all_resources(region)
    logger.info("Collected %d total resources", len(resources))

    if not resources:
        logger.warning("No resources found. Exiting.")
        return

    # Check tag compliance
    violations, compliant = check_tag_compliance(resources, tag_config)
    logger.info(
        "Tag compliance: %d violations, %d compliant (%.1f%% compliance rate)",
        len(violations),
        len(compliant),
        len(compliant) / len(resources) * 100 if resources else 0,
    )

    # Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # Ensure project and findings assessment exist
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)

    # Sync resources as CISO Assistant assets
    logger.info("Syncing %d resources to CISO Assistant Asset Management...", len(resources))
    asset_stats = sync_assets_to_ciso(client, resources, folder_id)

    # Open dedup cache
    cache = DedupCache(DB_PATH)

    try:
        # Process violations
        stats = process_violations(client, violations, cache, fa_id, annex_labels)

        # Resolve previously-violated resources that are now compliant
        resolved = resolve_compliant_resources(client, compliant, cache)
        stats["resolved"] = resolved

    finally:
        cache.close()

    # Generate and upload evidence report
    report_path = generate_inventory_report(resources, violations, compliant, stats, region)

    try:
        client.upload_evidence(
            name=f"AWS Asset Inventory Report — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
            file_path=report_path,
            folder_id=folder_id,
        )
        logger.info("Uploaded inventory report as evidence to CISO Assistant")
    except CISOClientError:
        logger.exception("Failed to upload inventory report as evidence")

    # Print summary
    logger.info("=" * 60)
    logger.info("ASSET INVENTORY SCAN SUMMARY")
    logger.info("=" * 60)
    logger.info("  Total resources:       %d", len(resources))
    logger.info("  Compliant:             %d", len(compliant))
    logger.info("  Violations:            %d", len(violations))
    logger.info("  Assets created:        %d", asset_stats["created"])
    logger.info("  Assets updated:        %d", asset_stats["updated"])
    logger.info("  New findings:          %d", stats["new"])
    logger.info("  Updated findings:      %d", stats["updated"])
    logger.info("  Resolved:              %d", stats["resolved"])
    logger.info("  Errors:                %d", stats["errors"])
    logger.info("  Compliance rate:       %.1f%%",
                len(compliant) / len(resources) * 100 if resources else 0)
    logger.info("=" * 60)

    # Write summary for cron/digest pickup
    summary_path = os.getenv("ASSET_SUMMARY_PATH", "/data/glue/last_asset_scan_summary.json")
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "region": region,
                "total_resources": len(resources),
                "total_compliant": len(compliant),
                "total_violations": len(violations),
                **stats,
            },
            f,
            indent=2,
        )

    # Send scan completion alert
    summary = {
        "total_findings": len(violations),
        "new": stats["new"],
        "updated": stats["updated"],
        "remediated": stats["resolved"],
        "errors": stats["errors"],
        "skipped": 0,
        "input_file": report_path,
    }
    alert_scan_complete(summary, scan_type="asset_inventory")

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        alert_scan_failure(str(e), scan_type="asset_inventory")
        raise
