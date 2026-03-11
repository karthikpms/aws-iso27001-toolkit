#!/usr/bin/env python3
"""
Network Security Monitoring — Automation 9

Real-time monitoring of security group and NACL changes via EventBridge/SNS,
plus weekly VPC Flow Log analysis via Athena.

Detects:
  - Security groups opened to 0.0.0.0/0 on risky ports (SSH, RDP, DB ports)
  - NACL rules allowing unrestricted inbound traffic
  - VPC peering connections created
  - Route table modifications
  - Unusual outbound traffic patterns (via Flow Logs + Athena)

Optionally auto-remediates overly permissive security group rules.

ISO 27001 Controls: A.8.20 (Network Security), A.8.21 (Security of Network Services)

Usage:
    # Process a real-time EventBridge event (called by webhook_server.py)
    from network_monitor import process_network_event

    # Run weekly VPC Flow Log analysis
    python network_monitor.py --flow-analysis

    # Run a one-time scan of all current security group rules
    python network_monitor.py --scan-all
"""

import argparse
import json
import logging
import os
import sys
import tempfile
import time
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
logger = logging.getLogger("network_monitor")

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
    "NETWORK_MONITOR_SUMMARY_PATH", "/data/glue/network_monitor_summary.json"
)
CONFIG_FILE = Path(__file__).parent / "mappings" / "risky_ports.json"
FINDINGS_ASSESSMENT_NAME = "Network Security Monitoring"

# Auto-remediation (default: OFF — alert only)
AUTO_REMEDIATE_SG = os.getenv("AUTO_REMEDIATE_SG", "false").lower() == "true"

# Athena config for VPC Flow Log analysis
ATHENA_DATABASE = os.getenv("ATHENA_DATABASE", "iso27001_vpc_flow_logs")
ATHENA_TABLE = os.getenv("ATHENA_TABLE", "flow_logs")
ATHENA_WORKGROUP = os.getenv("ATHENA_WORKGROUP", "iso27001-toolkit")
ATHENA_OUTPUT_BUCKET = os.getenv(
    "ATHENA_OUTPUT_BUCKET", ""
)

_SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
_PRIORITY_MAP = {"critical": 1, "high": 2, "medium": 3, "low": 4}
ISO_CONTROLS = ["A.8.20", "A.8.21"]


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> dict:
    """Load the risky ports configuration."""
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
    """Get or create a findings assessment for network monitoring."""
    for a in client.list_findings_assessments():
        if a.get("name") == name:
            return a["id"]
    assessment = client.create_findings_assessment(
        {
            "name": name,
            "description": "Automated network security monitoring — ISO 27001 A.8.20/A.8.21",
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


def _safe_api_call(func, *args, **kwargs):
    """Call an AWS API with error handling."""
    try:
        return func(*args, **kwargs)
    except (BotoCoreError, ClientError):
        logger.exception("AWS API call failed: %s", func.__name__)
        return None


# ---------------------------------------------------------------------------
# Real-time event processing (EventBridge → SNS → Webhook)
# ---------------------------------------------------------------------------


def process_network_event(
    event: dict,
    client: CISOClient,
    cache: DedupCache,
    findings_assessment_id: str,
    config: dict,
) -> dict:
    """
    Process a CloudTrail event received via EventBridge → SNS → Webhook.

    Returns dict with status: "finding_created", "remediated", "skipped", "error".
    """
    event_name = event.get("detail", {}).get("eventName", "")
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    user_identity = detail.get("userIdentity", {})
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    source_ip = detail.get("sourceIPAddress", "unknown")
    user_arn = user_identity.get("arn", user_identity.get("principalId", "unknown"))
    account_id = event.get("account", detail.get("recipientAccountId", "unknown"))

    logger.info("Processing network event: %s by %s from %s", event_name, user_arn, source_ip)

    handlers = {
        "AuthorizeSecurityGroupIngress": _handle_sg_ingress,
        "AuthorizeSecurityGroupEgress": _handle_sg_egress,
        "CreateNetworkAclEntry": _handle_nacl_entry,
        "CreateVpcPeeringConnection": _handle_vpc_peering,
        "CreateRoute": _handle_route_change,
        "ReplaceRoute": _handle_route_change,
        "DeleteRoute": _handle_route_change,
    }

    handler = handlers.get(event_name)
    if not handler:
        logger.debug("Unhandled event type: %s", event_name)
        return {"status": "skipped", "reason": f"unhandled event: {event_name}"}

    findings = handler(event_name, request_params, config, user_arn, source_ip, event_time, account_id)

    if not findings:
        return {"status": "skipped", "reason": "no risky changes detected"}

    result = {"status": "finding_created", "findings": []}
    for finding in findings:
        push_result = _push_finding(client, finding, cache, findings_assessment_id)
        result["findings"].append({"check_id": finding["check_id"], "result": push_result})

        # Auto-remediate if enabled and applicable
        if AUTO_REMEDIATE_SG and finding.get("remediation_action"):
            remediation = _auto_remediate(finding)
            if remediation["success"]:
                result["status"] = "remediated"
                finding["description"] += (
                    f"\n\n**Auto-Remediation:** Rule was automatically revoked. "
                    f"Action: {remediation['action']}"
                )

    return result


def _handle_sg_ingress(
    event_name: str,
    params: dict,
    config: dict,
    user_arn: str,
    source_ip: str,
    event_time: str,
    account_id: str,
) -> list[dict]:
    """Check if an ingress rule opens risky ports to the world."""
    findings = []
    risky_ports = config.get("risky_ports", {})
    sg_id = params.get("groupId", "unknown")
    ip_permissions = params.get("ipPermissions", {}).get("items", [])

    for perm in ip_permissions:
        from_port = perm.get("fromPort", 0)
        to_port = perm.get("toPort", 65535)
        protocol = perm.get("ipProtocol", "tcp")

        # Check for 0.0.0.0/0 or ::/0 in CIDR ranges
        cidr_ranges = []
        for ip_range in perm.get("ipRanges", {}).get("items", []):
            cidr = ip_range.get("cidrIp", "")
            if cidr in ("0.0.0.0/0", "::/0"):
                cidr_ranges.append(cidr)
        for ip_range in perm.get("ipv6Ranges", {}).get("items", []):
            cidr = ip_range.get("cidrIpv6", "")
            if cidr == "::/0":
                cidr_ranges.append(cidr)

        if not cidr_ranges:
            continue

        # Check if any risky port falls in the range
        matched_ports = []
        for port_str, service_name in risky_ports.items():
            port = int(port_str)
            if from_port <= port <= to_port:
                matched_ports.append((port, service_name))

        if matched_ports:
            port_list = ", ".join(f"{p} ({s})" for p, s in matched_ports)
            severity = "critical"
            findings.append({
                "check_id": f"net-sg-open-{sg_id}-{from_port}-{to_port}",
                "title": f"Security Group {sg_id} Opened to Internet on Risky Ports",
                "description": (
                    f"Security group `{sg_id}` was modified to allow inbound traffic from "
                    f"{', '.join(cidr_ranges)} on ports {from_port}-{to_port}.\n\n"
                    f"**Risky ports exposed:** {port_list}\n"
                    f"**Protocol:** {protocol}\n"
                    f"**Changed by:** {user_arn}\n"
                    f"**Source IP:** {source_ip}\n"
                    f"**Time:** {event_time}\n"
                    f"**Account:** {account_id}\n\n"
                    f"Opening these ports to the internet violates network security policy (A.8.20)."
                ),
                "severity": severity,
                "resource_arn": f"sg:{sg_id}",
                "iso_controls": ISO_CONTROLS,
                "remediation_action": {
                    "type": "revoke_sg_ingress",
                    "sg_id": sg_id,
                    "ip_permissions": [perm],
                },
            })
        elif config.get("alert_on_any_0000_rule"):
            # Alert on any 0.0.0.0/0 rule even if port isn't in risky list
            findings.append({
                "check_id": f"net-sg-open-wide-{sg_id}-{from_port}-{to_port}",
                "title": f"Security Group {sg_id} Opened to Internet (0.0.0.0/0)",
                "description": (
                    f"Security group `{sg_id}` was modified to allow inbound traffic from "
                    f"{', '.join(cidr_ranges)} on ports {from_port}-{to_port}.\n\n"
                    f"**Protocol:** {protocol}\n"
                    f"**Changed by:** {user_arn}\n"
                    f"**Source IP:** {source_ip}\n"
                    f"**Time:** {event_time}"
                ),
                "severity": "medium",
                "resource_arn": f"sg:{sg_id}",
                "iso_controls": ISO_CONTROLS,
            })

    return findings


def _handle_sg_egress(
    event_name: str,
    params: dict,
    config: dict,
    user_arn: str,
    source_ip: str,
    event_time: str,
    account_id: str,
) -> list[dict]:
    """Check if an egress rule is overly permissive (all ports, all protocols)."""
    findings = []
    sg_id = params.get("groupId", "unknown")
    ip_permissions = params.get("ipPermissions", {}).get("items", [])

    for perm in ip_permissions:
        protocol = perm.get("ipProtocol", "")
        if protocol != "-1":
            continue  # Only flag "all traffic" egress rules

        for ip_range in perm.get("ipRanges", {}).get("items", []):
            cidr = ip_range.get("cidrIp", "")
            if cidr == "0.0.0.0/0":
                # This is the default egress rule — skip if it already exists
                # Only flag if it's a NEW unrestricted egress being added
                findings.append({
                    "check_id": f"net-sg-egress-open-{sg_id}",
                    "title": f"Security Group {sg_id} Unrestricted Egress Added",
                    "description": (
                        f"Security group `{sg_id}` had an unrestricted egress rule added "
                        f"(all traffic to 0.0.0.0/0).\n\n"
                        f"**Changed by:** {user_arn}\n"
                        f"**Source IP:** {source_ip}\n"
                        f"**Time:** {event_time}"
                    ),
                    "severity": "low",
                    "resource_arn": f"sg:{sg_id}",
                    "iso_controls": ISO_CONTROLS,
                })

    return findings


def _handle_nacl_entry(
    event_name: str,
    params: dict,
    config: dict,
    user_arn: str,
    source_ip: str,
    event_time: str,
    account_id: str,
) -> list[dict]:
    """Check if a NACL rule allows unrestricted inbound traffic."""
    findings = []
    nacl_id = params.get("networkAclId", "unknown")
    cidr = params.get("cidrBlock", "")
    rule_action = params.get("ruleAction", "")
    egress = params.get("egress", False)
    protocol = params.get("protocol", "")
    rule_number = params.get("ruleNumber", "unknown")

    # Only flag inbound allow rules with 0.0.0.0/0
    if egress or rule_action != "allow" or cidr != "0.0.0.0/0":
        return findings

    port_range = params.get("portRange", {})
    from_port = port_range.get("from", 0)
    to_port = port_range.get("to", 65535)

    severity = "high" if protocol == "-1" else "medium"

    findings.append({
        "check_id": f"net-nacl-open-{nacl_id}-rule{rule_number}",
        "title": f"NACL {nacl_id} Allows Unrestricted Inbound Traffic",
        "description": (
            f"Network ACL `{nacl_id}` rule #{rule_number} allows inbound traffic from "
            f"0.0.0.0/0.\n\n"
            f"**Protocol:** {protocol} ('-1' = all)\n"
            f"**Port range:** {from_port}-{to_port}\n"
            f"**Changed by:** {user_arn}\n"
            f"**Source IP:** {source_ip}\n"
            f"**Time:** {event_time}"
        ),
        "severity": severity,
        "resource_arn": f"nacl:{nacl_id}",
        "iso_controls": ISO_CONTROLS,
    })

    return findings


def _handle_vpc_peering(
    event_name: str,
    params: dict,
    config: dict,
    user_arn: str,
    source_ip: str,
    event_time: str,
    account_id: str,
) -> list[dict]:
    """Alert on VPC peering connection creation."""
    requester_vpc = params.get("vpcId", "unknown")
    peer_vpc = params.get("peerVpcId", "unknown")
    peer_account = params.get("peerOwnerId", account_id)
    peer_region = params.get("peerRegion", AWS_REGION)

    cross_account = peer_account != account_id
    severity = "high" if cross_account else "medium"

    return [{
        "check_id": f"net-vpc-peering-{requester_vpc}-{peer_vpc}",
        "title": f"VPC Peering Connection Created: {requester_vpc} → {peer_vpc}",
        "description": (
            f"A VPC peering connection was created between `{requester_vpc}` and "
            f"`{peer_vpc}`.\n\n"
            f"**Peer account:** {peer_account} ({'CROSS-ACCOUNT' if cross_account else 'same account'})\n"
            f"**Peer region:** {peer_region}\n"
            f"**Created by:** {user_arn}\n"
            f"**Source IP:** {source_ip}\n"
            f"**Time:** {event_time}\n\n"
            f"VPC peering changes must be reviewed per network security policy (A.8.20)."
        ),
        "severity": severity,
        "resource_arn": f"vpc-peering:{requester_vpc}-{peer_vpc}",
        "iso_controls": ISO_CONTROLS,
    }]


def _handle_route_change(
    event_name: str,
    params: dict,
    config: dict,
    user_arn: str,
    source_ip: str,
    event_time: str,
    account_id: str,
) -> list[dict]:
    """Alert on route table modifications."""
    rtb_id = params.get("routeTableId", "unknown")
    dest_cidr = params.get("destinationCidrBlock", params.get("destinationIpv6CidrBlock", "unknown"))
    gateway_id = params.get("gatewayId", params.get("natGatewayId", params.get("vpcPeeringConnectionId", "unknown")))

    return [{
        "check_id": f"net-route-change-{rtb_id}-{event_name}",
        "title": f"Route Table Modified: {rtb_id} ({event_name})",
        "description": (
            f"Route table `{rtb_id}` was modified ({event_name}).\n\n"
            f"**Destination CIDR:** {dest_cidr}\n"
            f"**Target:** {gateway_id}\n"
            f"**Changed by:** {user_arn}\n"
            f"**Source IP:** {source_ip}\n"
            f"**Time:** {event_time}\n\n"
            f"Route table changes affect network segmentation and must be reviewed (A.8.20)."
        ),
        "severity": "medium",
        "resource_arn": f"rtb:{rtb_id}",
        "iso_controls": ISO_CONTROLS,
    }]


# ---------------------------------------------------------------------------
# Auto-remediation (optional)
# ---------------------------------------------------------------------------


def _auto_remediate(finding: dict) -> dict:
    """
    Revoke an overly permissive security group rule.

    Only runs when AUTO_REMEDIATE_SG=true.
    """
    action = finding.get("remediation_action", {})
    if action.get("type") != "revoke_sg_ingress":
        return {"success": False, "reason": "unsupported action type"}

    sg_id = action["sg_id"]
    ip_permissions = action["ip_permissions"]

    try:
        ec2 = _client("ec2")
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=ip_permissions,
        )
        logger.warning(
            "AUTO-REMEDIATION: Revoked ingress rule on %s — ports %s from 0.0.0.0/0",
            sg_id,
            ip_permissions,
        )
        return {"success": True, "action": f"revoked ingress on {sg_id}"}
    except (BotoCoreError, ClientError):
        logger.exception("Auto-remediation failed for %s", sg_id)
        return {"success": False, "reason": "API call failed"}


# ---------------------------------------------------------------------------
# Full scan of all current security groups
# ---------------------------------------------------------------------------


def scan_all_security_groups(config: dict) -> list[dict]:
    """Scan all existing security groups for risky rules (one-time or periodic check)."""
    findings = []
    risky_ports = config.get("risky_ports", {})
    ec2 = _client("ec2")

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "")
                vpc_id = sg.get("VpcId", "unknown")

                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    protocol = perm.get("IpProtocol", "tcp")

                    # Skip "all traffic" protocol check for port matching
                    if protocol == "-1":
                        from_port = 0
                        to_port = 65535

                    open_cidrs = []
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                            open_cidrs.append(ip_range["CidrIp"])
                    for ip_range in perm.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            open_cidrs.append(ip_range["CidrIpv6"])

                    if not open_cidrs:
                        continue

                    matched_ports = []
                    for port_str, service_name in risky_ports.items():
                        port = int(port_str)
                        if from_port <= port <= to_port:
                            matched_ports.append((port, service_name))

                    if matched_ports:
                        port_list = ", ".join(f"{p} ({s})" for p, s in matched_ports)
                        findings.append({
                            "check_id": f"net-sg-existing-{sg_id}-{from_port}-{to_port}",
                            "title": f"Security Group {sg_id} ({sg_name}) Open to Internet on Risky Ports",
                            "description": (
                                f"Security group `{sg_id}` (`{sg_name}`) in VPC `{vpc_id}` "
                                f"allows inbound traffic from {', '.join(open_cidrs)} on "
                                f"ports {from_port}-{to_port}.\n\n"
                                f"**Risky ports exposed:** {port_list}\n"
                                f"**Protocol:** {protocol}\n\n"
                                f"This violates network security policy (A.8.20). "
                                f"Restrict access to specific IP ranges."
                            ),
                            "severity": "critical",
                            "resource_arn": f"sg:{sg_id}",
                            "iso_controls": ISO_CONTROLS,
                            "remediation_action": {
                                "type": "revoke_sg_ingress",
                                "sg_id": sg_id,
                                "ip_permissions": [perm],
                            },
                        })

    except (BotoCoreError, ClientError):
        logger.exception("Failed to describe security groups")
        findings.append({
            "check_id": "net-sg-scan-api-error",
            "title": "Security Group Scan API Error",
            "description": "Unable to describe security groups. Check IAM permissions.",
            "severity": "high",
            "resource_arn": "ec2",
            "iso_controls": ISO_CONTROLS,
        })

    return findings


# ---------------------------------------------------------------------------
# VPC Flow Log Analysis via Athena
# ---------------------------------------------------------------------------


def run_flow_log_analysis(config: dict) -> list[dict]:
    """
    Run Athena queries on VPC Flow Logs to detect anomalous traffic patterns.

    Requires Athena database/table to be set up with VPC Flow Logs data.
    """
    findings = []
    flow_config = config.get("flow_log_analysis", {})

    if not flow_config.get("enabled", False):
        logger.info("Flow log analysis disabled in config")
        return findings

    if not ATHENA_OUTPUT_BUCKET:
        logger.warning("ATHENA_OUTPUT_BUCKET not set — skipping flow log analysis")
        return findings

    athena = _client("athena")
    lookback_days = flow_config.get("lookback_days", 7)
    start_date = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).strftime("%Y-%m-%d")

    # Query 1: Top outbound data transfers (potential exfiltration)
    threshold_gb = flow_config.get("unusual_outbound_threshold_gb", 10)
    outbound_query = f"""
        SELECT dstaddr, SUM(bytes) as total_bytes, COUNT(*) as flow_count
        FROM {ATHENA_DATABASE}.{ATHENA_TABLE}
        WHERE action = 'ACCEPT'
          AND flowdirection = 'egress'
          AND date >= '{start_date}'
          AND dstaddr NOT LIKE '10.%'
          AND dstaddr NOT LIKE '172.16.%'
          AND dstaddr NOT LIKE '192.168.%'
        GROUP BY dstaddr
        HAVING SUM(bytes) > {threshold_gb * 1024 * 1024 * 1024}
        ORDER BY total_bytes DESC
        LIMIT 20
    """

    outbound_results = _run_athena_query(athena, outbound_query)
    if outbound_results:
        for row in outbound_results:
            dst_ip = row[0]
            total_gb = int(row[1]) / (1024 ** 3)
            flow_count = row[2]
            findings.append({
                "check_id": f"net-flow-high-egress-{dst_ip}",
                "title": f"Unusual Outbound Traffic: {total_gb:.1f} GB to {dst_ip}",
                "description": (
                    f"Detected {total_gb:.1f} GB of outbound traffic to `{dst_ip}` "
                    f"over the past {lookback_days} days ({flow_count} flows).\n\n"
                    f"This exceeds the threshold of {threshold_gb} GB and may indicate "
                    f"data exfiltration. Investigate the destination and source instances."
                ),
                "severity": "high",
                "resource_arn": f"flow-log:egress:{dst_ip}",
                "iso_controls": ISO_CONTROLS,
            })

    # Query 2: Traffic on unexpected ports
    unexpected_ports = flow_config.get("unexpected_ports", [])
    if unexpected_ports:
        port_list = ", ".join(str(p) for p in unexpected_ports)
        port_query = f"""
            SELECT srcaddr, dstaddr, dstport, protocol, COUNT(*) as flow_count,
                   SUM(bytes) as total_bytes
            FROM {ATHENA_DATABASE}.{ATHENA_TABLE}
            WHERE action = 'ACCEPT'
              AND dstport IN ({port_list})
              AND date >= '{start_date}'
            GROUP BY srcaddr, dstaddr, dstport, protocol
            ORDER BY flow_count DESC
            LIMIT 50
        """

        port_results = _run_athena_query(athena, port_query)
        if port_results:
            findings.append({
                "check_id": "net-flow-unexpected-ports",
                "title": f"Traffic Detected on {len(port_results)} Unexpected Port Combinations",
                "description": (
                    f"Traffic was detected on ports commonly associated with "
                    f"suspicious activity: {port_list}.\n\n"
                    f"**Connections detected:** {len(port_results)} unique src/dst/port combinations "
                    f"over the past {lookback_days} days.\n\n"
                    f"Review these connections to determine if they are legitimate."
                ),
                "severity": "medium",
                "resource_arn": "flow-log:unexpected-ports",
                "iso_controls": ISO_CONTROLS,
            })

    # Query 3: Rejected traffic volume (potential scanning/probing)
    rejected_query = f"""
        SELECT srcaddr, COUNT(*) as reject_count
        FROM {ATHENA_DATABASE}.{ATHENA_TABLE}
        WHERE action = 'REJECT'
          AND date >= '{start_date}'
          AND srcaddr NOT LIKE '10.%'
          AND srcaddr NOT LIKE '172.16.%'
          AND srcaddr NOT LIKE '192.168.%'
        GROUP BY srcaddr
        HAVING COUNT(*) > 1000
        ORDER BY reject_count DESC
        LIMIT 20
    """

    rejected_results = _run_athena_query(athena, rejected_query)
    if rejected_results:
        top_sources = ", ".join(f"{row[0]} ({row[1]} rejects)" for row in rejected_results[:5])
        findings.append({
            "check_id": "net-flow-high-reject-volume",
            "title": f"High Rejected Traffic from {len(rejected_results)} External IPs",
            "description": (
                f"Detected high volumes of rejected traffic from {len(rejected_results)} "
                f"external IP addresses over the past {lookback_days} days.\n\n"
                f"**Top sources:** {top_sources}\n\n"
                f"This may indicate port scanning, brute force attempts, or reconnaissance."
            ),
            "severity": "medium",
            "resource_arn": "flow-log:rejected-traffic",
            "iso_controls": ISO_CONTROLS,
        })

    return findings


def _run_athena_query(athena_client, query: str) -> list[list[str]] | None:
    """Execute an Athena query and return results as a list of rows."""
    try:
        response = athena_client.start_query_execution(
            QueryString=query,
            WorkGroup=ATHENA_WORKGROUP,
            ResultConfiguration={
                "OutputLocation": f"s3://{ATHENA_OUTPUT_BUCKET}/athena-results/"
            },
        )
        query_id = response["QueryExecutionId"]

        # Poll for completion (max 5 minutes)
        for _ in range(60):
            status = athena_client.get_query_execution(QueryExecutionId=query_id)
            state = status["QueryExecution"]["Status"]["State"]
            if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(5)

        if state != "SUCCEEDED":
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", "unknown")
            logger.error("Athena query failed: %s — %s", state, reason)
            return None

        # Fetch results
        results = athena_client.get_query_results(QueryExecutionId=query_id)
        rows = results.get("ResultSet", {}).get("Rows", [])
        if len(rows) <= 1:  # Header only
            return None

        # Skip header row, extract data
        data = []
        for row in rows[1:]:
            data.append([col.get("VarCharValue", "") for col in row.get("Data", [])])
        return data

    except (BotoCoreError, ClientError):
        logger.exception("Athena query execution failed")
        return None


# ---------------------------------------------------------------------------
# Finding push to CISO Assistant
# ---------------------------------------------------------------------------


def _push_finding(
    client: CISOClient,
    finding: dict,
    cache: DedupCache,
    findings_assessment_id: str,
) -> str:
    """Create or update a finding in CISO Assistant. Returns 'new', 'updated', or 'error'."""
    check_id = finding["check_id"]
    resource_arn = finding["resource_arn"]
    severity = finding["severity"]
    cached = cache.get(resource_arn, check_id)

    if cached is not None:
        cache.upsert(resource_arn, check_id, cached["ciso_id"], "FAIL")
        return "updated"

    control_labels = ", ".join(finding.get("iso_controls", []))
    description = (
        f"**Source:** Network Security Monitor\n"
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
        logger.info("Created network finding: %s (ciso_id=%s)", check_id, ciso_id)

        if severity in ("critical", "high"):
            alert_data = {
                "check_id": check_id,
                "title": finding["title"],
                "severity": severity,
                "resource_arn": resource_arn,
                "region": AWS_REGION,
                "description": finding["description"],
                "service": "Network Monitor",
            }
            alert_new_finding(alert_data, source="Network Monitor")

        return "new"
    except CISOClientError:
        logger.exception("Error creating finding: %s", check_id)
        return "error"


# ---------------------------------------------------------------------------
# Evidence report
# ---------------------------------------------------------------------------


def generate_report(
    all_findings: list[dict],
    mode: str,
    run_time: datetime,
) -> str:
    """Generate a text-based network security evidence report."""
    lines = [
        "=" * 70,
        "NETWORK SECURITY MONITORING REPORT",
        f"Generated: {run_time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Region: {AWS_REGION}",
        f"Mode: {mode}",
        f"ISO 27001 Controls: A.8.20, A.8.21",
        f"Auto-remediation: {'ENABLED' if AUTO_REMEDIATE_SG else 'DISABLED'}",
        "=" * 70,
        "",
    ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    # Summary
    by_severity: dict[str, int] = {}
    for f in all_findings:
        s = f.get("severity", "medium")
        by_severity[s] = by_severity.get(s, 0) + 1

    lines.append("SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Total findings: {len(all_findings)}")
    for sev in ["critical", "high", "medium", "low", "informational"]:
        count = by_severity.get(sev, 0)
        if count:
            lines.append(f"  {sev.upper()}: {count}")
    lines.append("")

    # Detailed findings
    if all_findings:
        lines.append("FINDINGS")
        lines.append("=" * 70)
        sorted_findings = sorted(
            all_findings, key=lambda f: severity_order.get(f.get("severity", "medium"), 9)
        )
        for i, f in enumerate(sorted_findings, 1):
            lines.append(f"\n--- Finding {i} ---")
            lines.append(f"  Check ID:     {f['check_id']}")
            lines.append(f"  Title:        {f['title']}")
            lines.append(f"  Severity:     {f['severity'].upper()}")
            lines.append(f"  Resource:     {f['resource_arn']}")
            lines.append(f"  ISO Controls: {', '.join(f.get('iso_controls', []))}")
            lines.append(f"  Description:  {f['description'][:500]}")
    else:
        lines.append("No findings — all checks passed.")

    lines.append("")
    lines.append("=" * 70)
    lines.append("END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Security Monitor")
    parser.add_argument(
        "--flow-analysis", action="store_true",
        help="Run weekly VPC Flow Log analysis via Athena",
    )
    parser.add_argument(
        "--scan-all", action="store_true",
        help="Scan all existing security groups for risky rules",
    )
    args = parser.parse_args()

    run_start = datetime.now(timezone.utc)
    config = load_config(CONFIG_FILE)

    if not args.flow_analysis and not args.scan_all:
        logger.error("Specify --flow-analysis or --scan-all")
        sys.exit(1)

    mode = "flow-analysis" if args.flow_analysis else "scan-all"
    logger.info("Starting network security monitor — mode: %s", mode)

    # Collect findings
    all_findings: list[dict] = []

    if args.scan_all:
        logger.info("=== Scanning all security groups ===")
        all_findings.extend(scan_all_security_groups(config))

    if args.flow_analysis:
        logger.info("=== Running VPC Flow Log analysis ===")
        all_findings.extend(run_flow_log_analysis(config))

    # Generate report
    report_text = generate_report(all_findings, mode, run_start)

    # Log summary
    logger.info("=" * 60)
    logger.info("NETWORK SECURITY MONITOR SUMMARY")
    logger.info("=" * 60)
    logger.info("  Mode:            %s", mode)
    logger.info("  Total findings:  %d", len(all_findings))
    logger.info("=" * 60)

    # Connect to CISO Assistant and process
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)
    cache = DedupCache(DB_PATH)

    stats = {"new": 0, "updated": 0, "errors": 0, "alerts_sent": 0}
    try:
        for finding in all_findings:
            result = _push_finding(client, finding, cache, fa_id)
            stats[result if result in stats else "errors"] += 1

            # Auto-remediate if enabled
            if AUTO_REMEDIATE_SG and finding.get("remediation_action"):
                _auto_remediate(finding)

        # Upload evidence report
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", prefix="network_monitor_", delete=False
            ) as tmp:
                tmp.write(report_text)
                tmp_path = tmp.name

            report_name = f"Network Security Report — {run_start.strftime('%Y-%m-%d')}"
            client.upload_evidence(report_name, tmp_path, folder_id)
            logger.info("Uploaded network security evidence report")
            os.unlink(tmp_path)
        except (CISOClientError, OSError):
            logger.exception("Failed to upload evidence report")
            stats["errors"] += 1

    finally:
        cache.close()

    # Write summary JSON
    summary = {
        "timestamp": run_start.isoformat(),
        "region": AWS_REGION,
        "mode": mode,
        "total_findings": len(all_findings),
        "auto_remediation_enabled": AUTO_REMEDIATE_SG,
        **stats,
    }

    try:
        os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
        with open(SCAN_SUMMARY_PATH, "w") as f:
            json.dump(summary, f, indent=2)
        logger.info("Summary written to %s", SCAN_SUMMARY_PATH)
    except OSError:
        logger.exception("Failed to write summary")

    # Send scan-complete alert
    alert_scan_complete(summary, scan_type="Network Security Monitor")

    if stats["errors"] > 0:
        logger.warning("Completed with %d error(s)", stats["errors"])
    else:
        logger.info("Network security monitor completed successfully")


if __name__ == "__main__":
    main()
