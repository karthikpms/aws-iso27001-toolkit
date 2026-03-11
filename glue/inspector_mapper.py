#!/usr/bin/env python3
"""
Inspector Mapper — AWS Inspector Vulnerability Management

Pulls active findings from AWS Inspector v2, deduplicates against a local
SQLite cache, and pushes findings into CISO Assistant.

Maps Inspector CVE findings to ISO 27001 control A.8.8 (Management of
Technical Vulnerabilities) and network reachability findings to A.8.20
(Network Security).

Tracks SLA compliance and creates additional findings for breaches.

Usage:
    python inspector_mapper.py
"""

import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
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
from prowler_mapper import (
    DedupCache,
    _severity_to_finding_severity,
    _severity_to_priority,
    ensure_findings_assessment,
    ensure_project,
)
from sla_tracker import check_sla_compliance, get_sla_days

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("inspector_mapper")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
AWS_REGION = os.getenv("AWS_REGION", "ap-south-1")
MAPPING_FILE = Path(__file__).parent / "mappings" / "inspector_iso27001_map.json"
FINDINGS_ASSESSMENT_NAME = "AWS Inspector Vulnerabilities"
SCAN_SUMMARY_PATH = os.getenv(
    "INSPECTOR_SUMMARY_PATH", "/data/glue/last_inspector_summary.json"
)

# ---------------------------------------------------------------------------
# Severity mapping (Inspector uses uppercase)
# ---------------------------------------------------------------------------
INSPECTOR_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "informational",
    "UNTRIAGED": "medium",
}


def normalize_severity(inspector_severity: str) -> str:
    """Map Inspector severity to normalized lowercase severity."""
    return INSPECTOR_SEVERITY_MAP.get(inspector_severity.upper(), "medium")


# ---------------------------------------------------------------------------
# Mapping Loader
# ---------------------------------------------------------------------------
def load_mappings(mapping_file: Path) -> dict:
    """Load the Inspector finding type -> Annex A control mapping."""
    with open(mapping_file) as f:
        return json.load(f)


def resolve_controls(finding: dict, mappings: dict) -> list[str]:
    """Resolve ISO 27001 Annex A controls for an Inspector finding."""
    finding_type = finding.get("type", "PACKAGE_VULNERABILITY")

    # Check network reachability overrides first
    if finding_type == "NETWORK_REACHABILITY":
        nr = finding.get("networkReachabilityDetails", {})
        protocol = nr.get("protocol", "")
        overrides = mappings.get("network_reachability_overrides", {})
        # Check for specific network reachability subtypes
        open_port = nr.get("openPortRange", {})
        if open_port:
            for key in ("RECOGNIZED_PORT_WITH_LISTENER", "OPEN_PORT"):
                if key in overrides:
                    return overrides[key]
        return overrides.get("NETWORK_EXPOSURE", ["A.8.20"])

    # Check CVE-specific overrides
    vuln = finding.get("packageVulnerabilityDetails", {})
    cve_id = vuln.get("vulnerabilityId", "")
    cve_overrides = mappings.get("cve_severity_overrides", {})
    if cve_id in cve_overrides:
        return cve_overrides[cve_id]["controls"]

    # Check finding type defaults
    type_defaults = mappings.get("finding_type_defaults", {})
    if finding_type in type_defaults:
        return type_defaults[finding_type]

    # Check resource type defaults
    resources = finding.get("resources", [{}])
    resource_type = resources[0].get("type", "") if resources else ""
    resource_defaults = mappings.get("resource_type_defaults", {})
    if resource_type in resource_defaults:
        return resource_defaults[resource_type]

    # Fallback: vulnerability management
    return ["A.8.8"]


# ---------------------------------------------------------------------------
# Inspector Client
# ---------------------------------------------------------------------------
def get_inspector_client():
    """Create a boto3 Inspector2 client."""
    return boto3.client("inspector2", region_name=AWS_REGION)


def check_inspector_enabled(client) -> bool:
    """Check if Inspector is enabled in this account. Returns False if not."""
    try:
        resp = client.batch_get_account_status(
            accountIds=[]  # empty = current account
        )
        accounts = resp.get("accounts", [])
        if not accounts:
            return False
        state = accounts[0].get("state", {}).get("status", "")
        return state in ("ENABLED", "ENABLING")
    except (BotoCoreError, ClientError) as e:
        logger.warning("Could not check Inspector status: %s", e)
        return False


def fetch_active_findings(client) -> list[dict]:
    """Fetch all ACTIVE findings from Inspector using pagination."""
    findings: list[dict] = []

    try:
        paginator = client.get_paginator("list_findings")
        page_iterator = paginator.paginate(
            filterCriteria={
                "findingStatus": [
                    {"comparison": "EQUALS", "value": "ACTIVE"}
                ]
            },
            maxResults=100,
        )

        for page in page_iterator:
            findings.extend(page.get("findings", []))

    except (BotoCoreError, ClientError) as e:
        logger.error("Error fetching Inspector findings: %s", e)
        raise

    logger.info("Fetched %d active findings from Inspector", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Finding normalization
# ---------------------------------------------------------------------------
def normalize_finding(raw: dict) -> dict:
    """Normalize an Inspector finding into a standard format."""
    finding_arn = raw.get("findingArn", "")
    finding_type = raw.get("type", "PACKAGE_VULNERABILITY")

    # Extract resource info
    resources = raw.get("resources", [{}])
    resource = resources[0] if resources else {}
    resource_arn = resource.get("id", finding_arn)
    resource_type = resource.get("type", "UNKNOWN")
    resource_region = resource.get("region", AWS_REGION)

    # Severity
    inspector_severity = raw.get("severity", "MEDIUM")
    severity = normalize_severity(inspector_severity)

    # Extract vulnerability details
    vuln = raw.get("packageVulnerabilityDetails", {})
    cve_id = vuln.get("vulnerabilityId", "")
    cvss_score = 0.0
    cvss_list = vuln.get("cvss", [])
    if cvss_list:
        # Use the highest CVSS score available
        cvss_score = max(s.get("baseScore", 0.0) for s in cvss_list)

    # Affected packages
    affected_packages = vuln.get("vulnerablePackages", [])
    package_names = [
        f"{p.get('name', '?')}:{p.get('version', '?')}"
        for p in affected_packages[:5]  # Limit to 5
    ]

    # Fixed version info
    fixed_versions = []
    for pkg in affected_packages[:5]:
        fixed = pkg.get("fixedInVersion", "")
        if fixed:
            fixed_versions.append(f"{pkg.get('name', '?')}:{fixed}")

    # Build title
    if cve_id:
        title = f"{cve_id}: {vuln.get('source', '')} vulnerability"
        if package_names:
            title += f" in {package_names[0]}"
        check_id = cve_id
    elif finding_type == "NETWORK_REACHABILITY":
        nr = raw.get("networkReachabilityDetails", {})
        port_range = nr.get("openPortRange", {})
        port_str = ""
        if port_range:
            port_str = f" port {port_range.get('begin', '?')}"
        title = f"Network reachability{port_str} on {resource_type}"
        check_id = f"NR-{resource_arn.split(':')[-1][:40]}" if resource_arn else finding_arn
    else:
        title = raw.get("title", finding_type)
        check_id = finding_arn.split("/")[-1] if "/" in finding_arn else finding_arn

    # Description
    description = raw.get("description", "")
    if not description and vuln.get("sourceUrl"):
        description = f"See: {vuln['sourceUrl']}"

    # Remediation
    remediation_raw = raw.get("remediation", {})
    remediation = ""
    if isinstance(remediation_raw, dict):
        rec = remediation_raw.get("recommendation", {})
        if isinstance(rec, dict):
            remediation = rec.get("text", "")
            url = rec.get("Url", rec.get("url", ""))
            if url:
                remediation += f"\nReference: {url}"
        elif isinstance(rec, str):
            remediation = rec

    if fixed_versions:
        remediation += f"\n\nFixed versions: {', '.join(fixed_versions)}"

    return {
        "finding_arn": finding_arn,
        "check_id": check_id,
        "type": finding_type,
        "status": "FAIL",  # All ACTIVE Inspector findings are failures
        "resource_arn": resource_arn,
        "resource_type": resource_type,
        "region": resource_region,
        "severity": severity,
        "inspector_severity": inspector_severity,
        "title": title[:200],
        "description": description,
        "remediation": remediation,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "package_names": package_names,
        "first_observed": raw.get("firstObservedAt", ""),
        "last_observed": raw.get("lastObservedAt", ""),
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# CISO Assistant Integration
# ---------------------------------------------------------------------------
def build_finding_payload(
    finding: dict,
    controls: list[str],
    annex_labels: dict,
    findings_assessment_id: str,
) -> dict:
    """Build a CISO Assistant Finding payload from a normalized Inspector finding."""
    control_labels = [
        f"{c}: {annex_labels.get(c, '')}" for c in controls
    ]
    severity = finding["severity"]

    desc_parts = [
        f"**Resource:** {finding['resource_arn']}",
        f"**Resource Type:** {finding['resource_type']}",
        f"**Region:** {finding['region']}",
        f"**ISO 27001 Controls:** {', '.join(control_labels)}",
    ]

    if finding.get("cve_id"):
        desc_parts.append(f"**CVE:** {finding['cve_id']}")
    if finding.get("cvss_score"):
        desc_parts.append(f"**CVSS Score:** {finding['cvss_score']}")
    if finding.get("package_names"):
        desc_parts.append(f"**Affected Packages:** {', '.join(finding['package_names'])}")

    desc_parts.append("")
    desc_parts.append(finding.get("description", ""))

    description = "\n".join(desc_parts)

    observation = finding.get("remediation", "")

    payload: dict = {
        "name": f"[Inspector] {finding['title']}"[:200],
        "description": description,
        "findings_assessment": findings_assessment_id,
        "severity": _severity_to_finding_severity(severity),
        "status": "identified",
        "ref_id": finding["check_id"][:100],
    }

    if observation:
        payload["observation"] = f"**Remediation:** {observation}"

    priority = _severity_to_priority(severity)
    if priority is not None:
        payload["priority"] = priority

    return payload


def build_sla_breach_payload(
    overdue_finding: dict,
    annex_labels: dict,
    findings_assessment_id: str,
) -> dict:
    """Build a CISO Assistant Finding payload for an SLA breach."""
    severity = overdue_finding["severity"]
    sla_days = overdue_finding["sla_days"]
    days_overdue = overdue_finding["days_overdue"]
    days_open = overdue_finding["days_open"]

    description = (
        f"**SLA BREACH — Remediation window exceeded**\n\n"
        f"**Resource:** {overdue_finding['resource_arn']}\n"
        f"**Finding:** {overdue_finding['check_id']}\n"
        f"**Severity:** {severity.upper()}\n"
        f"**SLA Window:** {sla_days} days\n"
        f"**Days Open:** {days_open}\n"
        f"**Days Overdue:** {days_overdue}\n"
        f"**First Seen:** {overdue_finding['first_seen']}\n\n"
        f"**ISO 27001 Controls:** A.8.8: {annex_labels.get('A.8.8', '')}\n\n"
        f"This vulnerability has exceeded its remediation SLA. "
        f"Immediate action is required to maintain ISO 27001 compliance."
    )

    return {
        "name": f"[SLA BREACH] {overdue_finding['check_id']} ({days_overdue}d overdue)"[:200],
        "description": description,
        "findings_assessment": findings_assessment_id,
        "severity": _severity_to_finding_severity(severity),
        "status": "identified",
        "ref_id": f"SLA-{overdue_finding['check_id']}"[:100],
        "priority": 1,  # SLA breaches always P1
    }


# ---------------------------------------------------------------------------
# SLA Breach Alerting
# ---------------------------------------------------------------------------
def alert_sla_breach(overdue_finding: dict) -> None:
    """Send an alert for an SLA breach via the alerter module."""
    from alerter import _publish

    subject = (
        f"[SLA BREACH] {overdue_finding['severity'].upper()}: "
        f"{overdue_finding['check_id']} ({overdue_finding['days_overdue']}d overdue)"
    )

    message = (
        f"SLA BREACH — REMEDIATION WINDOW EXCEEDED\n"
        f"{'=' * 50}\n\n"
        f"Resource:     {overdue_finding['resource_arn']}\n"
        f"Finding:      {overdue_finding['check_id']}\n"
        f"Severity:     {overdue_finding['severity'].upper()}\n"
        f"SLA Window:   {overdue_finding['sla_days']} days\n"
        f"Days Open:    {overdue_finding['days_open']}\n"
        f"Days Overdue: {overdue_finding['days_overdue']}\n"
        f"First Seen:   {overdue_finding['first_seen']}\n\n"
        f"This vulnerability has exceeded its remediation SLA.\n"
        f"Immediate action is required to maintain ISO 27001 compliance.\n"
    )

    _publish(subject, message)


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------
def process_findings(
    client: CISOClient,
    findings: list[dict],
    mappings: dict,
    cache: DedupCache,
    findings_assessment_id: str,
) -> dict[str, Any]:
    """Process normalized Inspector findings: create/update in CISO Assistant."""
    annex_labels = mappings.get("annex_a_controls", {})

    stats: dict[str, Any] = {
        "new": 0,
        "updated": 0,
        "remediated": 0,
        "skipped": 0,
        "errors": 0,
        "sla_breaches": 0,
        "by_severity": defaultdict(int),
        "by_type": defaultdict(int),
    }

    # Track severity for SLA checking later
    severity_map: dict[tuple[str, str], str] = {}

    # Group findings by resource ARN for efficient processing
    by_resource: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_resource[f["resource_arn"]].append(f)

    logger.info(
        "Processing %d findings across %d resources",
        len(findings),
        len(by_resource),
    )

    for resource_arn, resource_findings in by_resource.items():
        for finding in resource_findings:
            key = (finding["resource_arn"], finding["check_id"])
            severity = finding["severity"]
            stats["by_severity"][severity] += 1
            stats["by_type"][finding["type"]] += 1
            severity_map[key] = severity

            controls = resolve_controls(finding.get("raw", {}), mappings)
            cached = cache.get(*key)

            try:
                if cached is None:
                    # New finding
                    payload = build_finding_payload(
                        finding, controls, annex_labels, findings_assessment_id
                    )
                    result = client.create_finding(payload)
                    cache.upsert(*key, ciso_id=str(result["id"]), status="FAIL")
                    stats["new"] += 1
                    logger.debug("Created finding: %s", key)
                    alert_new_finding(finding, source="Inspector")

                elif cached["status"] == "FAIL":
                    # Still failing — update timestamp
                    payload = build_finding_payload(
                        finding, controls, annex_labels, findings_assessment_id
                    )
                    client.update_finding(cached["ciso_id"], payload)
                    cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
                    stats["updated"] += 1

                elif cached["status"] == "PASS":
                    # Regression: was remediated, now failing again
                    payload = build_finding_payload(
                        finding, controls, annex_labels, findings_assessment_id
                    )
                    payload["status"] = "identified"
                    client.update_finding(cached["ciso_id"], payload)
                    cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
                    stats["new"] += 1
                    logger.warning("Regression detected: %s", key)

                    from alerter import alert_regression
                    alert_regression(finding, source="Inspector")

            except CISOClientError:
                logger.exception("Error processing finding: %s", key)
                stats["errors"] += 1

    # --- SLA Breach Processing ---
    logger.info("Checking SLA compliance for Inspector findings...")
    now = datetime.now(timezone.utc)

    from sla_tracker import get_overdue_findings

    overdue = get_overdue_findings(cache, severity_map)

    for overdue_finding in overdue:
        # Only process SLA breaches for Inspector findings (check_id matches)
        if not any(
            overdue_finding["check_id"] == f["check_id"]
            for f in findings
        ):
            continue

        sla_key = (
            overdue_finding["resource_arn"],
            f"SLA-{overdue_finding['check_id']}",
        )
        cached_sla = cache.get(*sla_key)

        if cached_sla is None:
            try:
                payload = build_sla_breach_payload(
                    overdue_finding, annex_labels, findings_assessment_id
                )
                result = client.create_finding(payload)
                cache.upsert(
                    *sla_key, ciso_id=str(result["id"]), status="FAIL"
                )
                stats["sla_breaches"] += 1
                logger.warning(
                    "SLA breach: %s — %d days overdue",
                    overdue_finding["check_id"],
                    overdue_finding["days_overdue"],
                )
                alert_sla_breach(overdue_finding)
            except CISOClientError:
                logger.exception(
                    "Error creating SLA breach finding: %s", sla_key
                )
                stats["errors"] += 1

    # Convert defaultdicts to regular dicts for JSON serialization
    stats["by_severity"] = dict(stats["by_severity"])
    stats["by_type"] = dict(stats["by_type"])

    return stats


def remediate_resolved(
    client: CISOClient,
    active_findings: list[dict],
    cache: DedupCache,
) -> int:
    """Mark findings as remediated if they no longer appear in Inspector.

    Compares active finding keys against cache entries. Any cached FAIL
    entry whose key is not in the active set gets marked resolved.

    Returns the count of remediated findings.
    """
    active_keys = {
        (f["resource_arn"], f["check_id"]) for f in active_findings
    }

    all_failing = cache.get_all_failing()
    remediated_count = 0

    for entry in all_failing:
        key = (entry["resource_arn"], entry["check_id"])

        # Skip SLA breach findings
        if entry["check_id"].startswith("SLA-"):
            continue

        # Only remediate Inspector findings (skip Prowler/Wazuh entries)
        # Inspector findings use CVE IDs or NR- prefixes
        check_id = entry["check_id"]
        is_inspector = (
            check_id.startswith("CVE-")
            or check_id.startswith("NR-")
            or check_id.startswith("GHSA-")
        )
        if not is_inspector:
            continue

        if key not in active_keys:
            try:
                client.update_finding(
                    entry["ciso_id"],
                    {
                        "status": "resolved",
                        "observation": (
                            f"**REMEDIATED** on "
                            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                            f"**Resource:** {entry['resource_arn']}\n"
                            f"**Finding:** {entry['check_id']}\n\n"
                            f"This finding is no longer reported by AWS Inspector."
                        ),
                    },
                )
                cache.upsert(*key, ciso_id=entry["ciso_id"], status="PASS")
                remediated_count += 1
                logger.info("Remediated (no longer in Inspector): %s", key)

                # Also resolve the SLA breach if one exists
                sla_key = (entry["resource_arn"], f"SLA-{entry['check_id']}")
                sla_cached = cache.get(*sla_key)
                if sla_cached and sla_cached["status"] == "FAIL":
                    client.update_finding(
                        sla_cached["ciso_id"],
                        {"status": "resolved"},
                    )
                    cache.upsert(
                        *sla_key, ciso_id=sla_cached["ciso_id"], status="PASS"
                    )

            except CISOClientError:
                logger.exception(
                    "Error remediating finding: %s", key
                )

    return remediated_count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    logger.info("Starting AWS Inspector vulnerability scan import")

    # Check Inspector is enabled
    inspector = get_inspector_client()
    if not check_inspector_enabled(inspector):
        logger.warning(
            "AWS Inspector is not enabled in region %s. "
            "Enable Inspector in the AWS console or via Terraform. Exiting.",
            AWS_REGION,
        )
        return

    # Fetch active findings from Inspector
    raw_findings = fetch_active_findings(inspector)

    if not raw_findings:
        logger.info("No active findings from Inspector. Nothing to process.")
        # Still write summary
        summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": 0,
            "new": 0,
            "updated": 0,
            "remediated": 0,
            "errors": 0,
            "sla_breaches": 0,
        }
        os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
        with open(SCAN_SUMMARY_PATH, "w") as f:
            json.dump(summary, f, indent=2)
        return

    # Normalize findings
    findings = [normalize_finding(r) for r in raw_findings]
    logger.info("Normalized %d Inspector findings", len(findings))

    # Load mapping
    mappings = load_mappings(MAPPING_FILE)
    logger.info("Loaded Inspector ISO 27001 control mappings")

    # Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # Ensure project and findings assessment exist
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(
        client, folder_id, name=FINDINGS_ASSESSMENT_NAME
    )

    # Open dedup cache
    cache = DedupCache(DB_PATH)

    try:
        # Process active findings
        stats = process_findings(client, findings, mappings, cache, fa_id)

        # Mark findings no longer in Inspector as remediated
        remediated_count = remediate_resolved(client, findings, cache)
        stats["remediated"] = remediated_count

    finally:
        cache.close()

    # Print summary
    logger.info("=" * 60)
    logger.info("INSPECTOR SCAN IMPORT SUMMARY")
    logger.info("=" * 60)
    logger.info("  Total findings:      %d", len(findings))
    logger.info("  New findings:        %d", stats["new"])
    logger.info("  Updated findings:    %d", stats["updated"])
    logger.info("  Remediated:          %d", stats["remediated"])
    logger.info("  SLA breaches:        %d", stats["sla_breaches"])
    logger.info("  Errors:              %d", stats["errors"])
    if stats["by_severity"]:
        logger.info("  By severity:         %s", stats["by_severity"])
    if stats["by_type"]:
        logger.info("  By type:             %s", stats["by_type"])
    logger.info("=" * 60)

    # Write scan summary JSON for daily digest
    os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
    with open(SCAN_SUMMARY_PATH, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "aws_inspector",
                "total_findings": len(findings),
                **stats,
            },
            f,
            indent=2,
        )

    # Send scan completion heartbeat
    alert_scan_complete(
        {
            "total_findings": len(findings),
            **stats,
        },
        scan_type="inspector",
    )

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        alert_scan_failure(str(e), scan_type="inspector")
        raise
