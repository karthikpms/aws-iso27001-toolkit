#!/usr/bin/env python3
"""
Prowler Mapper — Phase 2 Glue Layer

Parses Prowler JSON-OCSF output, deduplicates against a local SQLite cache,
and pushes findings into CISO Assistant via its API.

Usage:
    python prowler_mapper.py                        # Process latest scan
    python prowler_mapper.py /path/to/output.json   # Process specific file
"""

import glob
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from alerter import alert_new_finding, alert_regression, alert_remediation, alert_scan_complete, alert_scan_failure
from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("prowler_mapper")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
PROWLER_OUTPUT_DIR = os.getenv("PROWLER_OUTPUT_DIR", "/home/prowler/output")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
MAPPING_FILE = Path(__file__).parent / "mappings" / "prowler_iso27001_map.json"
CONCURRENT_REQUESTS = int(os.getenv("CISO_CONCURRENT_REQUESTS", "5"))



# ---------------------------------------------------------------------------
# Mapping Loader
# ---------------------------------------------------------------------------
def load_mappings(mapping_file: Path) -> dict:
    """Load the Prowler check -> Annex A control mapping."""
    with open(mapping_file) as f:
        return json.load(f)


def resolve_controls(
    check_id: str, service: str, mappings: dict
) -> list[str]:
    """Resolve Annex A controls for a Prowler check ID."""
    overrides = mappings.get("check_overrides", {})
    if check_id in overrides:
        return overrides[check_id]

    defaults = mappings.get("service_defaults", {})
    service_lower = service.lower()
    if service_lower in defaults:
        return defaults[service_lower]

    return ["A.8.9"]  # Fallback: Configuration Management


# ---------------------------------------------------------------------------
# Prowler Output Parser
# ---------------------------------------------------------------------------
def find_latest_output(output_dir: str) -> str | None:
    """Find the most recent Prowler JSON-OCSF output file."""
    patterns = [
        os.path.join(output_dir, "**", "*.ocsf.json"),
        os.path.join(output_dir, "**", "*.json"),
    ]
    files: list[str] = []
    for pattern in patterns:
        files.extend(glob.glob(pattern, recursive=True))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def parse_prowler_output(file_path: str) -> list[dict]:
    """Parse Prowler JSON-OCSF output into normalized findings."""
    with open(file_path) as f:
        content = f.read().strip()

    # Handle both JSON array and newline-delimited JSON
    if content.startswith("["):
        raw_findings = json.loads(content)
    else:
        raw_findings = [json.loads(line) for line in content.splitlines() if line.strip()]

    findings = []
    for item in raw_findings:
        # OCSF format fields
        status_code = item.get("status_code", item.get("status", ""))
        if isinstance(status_code, str):
            status = status_code.upper()
        else:
            status = str(status_code)

        # Extract check metadata
        finding = item.get("finding_info", item.get("finding", {}))
        check_id = (
            finding.get("uid", "")
            or item.get("metadata", {}).get("event_code", "")
            or item.get("check_id", "")
        )

        # Extract resource info
        resources = item.get("resources", [{}])
        resource = resources[0] if resources else {}
        resource_arn = resource.get("uid", item.get("resource_arn", "unknown"))
        service = resource.get("group", {}).get("name", "")
        if not service:
            service = item.get("service_name", check_id.split("_")[0] if check_id else "unknown")

        region = resource.get("region", item.get("region", ""))

        severity = item.get("severity", item.get("severity_id", ""))
        if isinstance(severity, int):
            severity_map = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}
            severity = severity_map.get(severity, "medium")
        elif isinstance(severity, str):
            severity = severity.lower()

        title = finding.get("title", item.get("check_title", check_id))
        description = (
            finding.get("desc", "")
            or item.get("status_detail", "")
            or item.get("description", "")
        )
        remediation = item.get("remediation", {})
        remediation_text = ""
        if isinstance(remediation, dict):
            remediation_text = remediation.get("desc", remediation.get("recommendation", ""))
        elif isinstance(remediation, str):
            remediation_text = remediation

        findings.append(
            {
                "check_id": check_id,
                "status": status,
                "resource_arn": resource_arn,
                "service": service,
                "region": region,
                "severity": severity,
                "title": title,
                "description": description,
                "remediation": remediation_text,
                "raw": item,
            }
        )

    return findings


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
    client: CISOClient, folder_id: str, name: str = "Prowler AWS Scan"
) -> str:
    """Get or create a findings assessment for Prowler scan results."""
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
            "description": "Automated findings from Prowler AWS security scans",
            "folder": folder_id,
            "category": "audit",
        }
    )
    logger.info(
        "Created findings assessment: %s (id=%s)", name, assessment["id"]
    )
    return assessment["id"]


def resolve_csf_function(controls: list[str]) -> str:
    """Map ISO 27001 Annex A controls to NIST CSF functions.

    A.5.x (Organizational)  → govern/identify depending on sub-control
    A.6.x (People)          → govern
    A.7.x (Physical)        → protect
    A.8.x (Technological)   → protect/detect depending on sub-control
    """
    csf_map = {
        # A.5 — Organizational controls
        "A.5.1": "govern", "A.5.2": "govern", "A.5.3": "govern",
        "A.5.4": "govern", "A.5.5": "govern", "A.5.6": "govern",
        "A.5.7": "identify", "A.5.8": "identify",
        "A.5.9": "identify", "A.5.10": "protect",
        "A.5.11": "protect", "A.5.12": "identify",
        "A.5.13": "protect", "A.5.14": "protect",
        "A.5.15": "protect", "A.5.16": "protect",
        "A.5.17": "protect", "A.5.18": "protect",
        "A.5.19": "govern", "A.5.20": "govern",
        "A.5.21": "govern", "A.5.22": "govern",
        "A.5.23": "protect", "A.5.24": "respond",
        "A.5.25": "respond", "A.5.26": "respond",
        "A.5.27": "recover", "A.5.28": "detect",
        "A.5.29": "recover", "A.5.30": "recover",
        # A.8 — Technological controls
        "A.8.1": "identify", "A.8.2": "protect",
        "A.8.3": "protect", "A.8.4": "protect",
        "A.8.5": "protect", "A.8.6": "protect",
        "A.8.7": "protect", "A.8.8": "identify",
        "A.8.9": "protect", "A.8.10": "protect",
        "A.8.11": "protect", "A.8.12": "protect",
        "A.8.13": "protect", "A.8.14": "protect",
        "A.8.15": "detect", "A.8.16": "detect",
        "A.8.17": "protect", "A.8.18": "protect",
        "A.8.19": "protect", "A.8.20": "protect",
        "A.8.21": "protect", "A.8.22": "protect",
        "A.8.23": "protect", "A.8.24": "protect",
        "A.8.25": "protect", "A.8.26": "protect",
        "A.8.27": "protect", "A.8.28": "protect",
    }
    # Use the first control that has a mapping
    for c in controls:
        if c in csf_map:
            return csf_map[c]
    # Fallback by prefix
    if controls:
        prefix = controls[0].split(".")[0] + "." + controls[0].split(".")[1]
        prefix_map = {"A.5": "govern", "A.6": "govern", "A.7": "protect", "A.8": "protect"}
        return prefix_map.get(prefix, "protect")
    return "protect"


def _severity_to_priority(severity: str) -> int | None:
    """Map Prowler severity to CISO Assistant priority (P1-P4)."""
    return {
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 4,
        "informational": 4,
    }.get(severity)


def _severity_to_effort(severity: str) -> str | None:
    """Estimate remediation effort from severity (T-shirt sizing)."""
    return {
        "critical": "L",
        "high": "M",
        "medium": "S",
        "low": "XS",
        "informational": "XS",
    }.get(severity)


def _severity_to_impact(severity: str) -> int | None:
    """Map Prowler severity to CISO Assistant impact (1-5)."""
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }.get(severity)


def _severity_to_finding_severity(severity: str) -> int:
    """Map Prowler severity string to CISO Assistant Finding severity integer."""
    return {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }.get(severity, 2)


def _finding_status(prowler_status: str) -> str:
    """Map Prowler status to CISO Assistant Finding status."""
    return "identified" if prowler_status == "FAIL" else "resolved"


def build_finding_payload(
    finding: dict,
    controls: list[str],
    annex_labels: dict,
    findings_assessment_id: str,
) -> dict:
    """Build a CISO Assistant Finding payload from a Prowler finding."""
    control_labels = [
        f"{c}: {annex_labels.get(c, '')}" for c in controls
    ]
    severity = finding["severity"]

    description = (
        f"**Resource:** {finding['resource_arn']}\n"
        f"**Region:** {finding['region']}\n"
        f"**ISO 27001 Controls:** {', '.join(control_labels)}\n\n"
        f"{finding['description']}"
    )

    observation = finding.get("remediation", "")

    payload: dict = {
        "name": f"[{finding['check_id']}] {finding['title']}"[:200],
        "description": description,
        "findings_assessment": findings_assessment_id,
        "severity": _severity_to_finding_severity(severity),
        "status": _finding_status(finding["status"]),
        "ref_id": finding["check_id"][:100],
    }

    if observation:
        payload["observation"] = f"**Remediation:** {observation}"

    priority = _severity_to_priority(severity)
    if priority is not None:
        payload["priority"] = priority

    return payload


def process_findings(
    client: CISOClient,
    findings: list[dict],
    mappings: dict,
    cache: DedupCache,
    findings_assessment_id: str,
) -> dict:
    """Process parsed findings: create/update in CISO Assistant with dedup."""
    annex_labels = mappings.get("annex_a_controls", {})

    stats = {"new": 0, "updated": 0, "remediated": 0, "skipped": 0, "errors": 0}

    # Track which (resource_arn, check_id) we see in this scan
    seen_keys: set[tuple[str, str]] = set()

    # --- Process FAIL findings ---
    fail_findings = [f for f in findings if f["status"] == "FAIL"]
    pass_findings = [f for f in findings if f["status"] == "PASS"]

    logger.info(
        "Processing %d FAIL and %d PASS findings",
        len(fail_findings),
        len(pass_findings),
    )

    for finding in fail_findings:
        key = (finding["resource_arn"], finding["check_id"])
        seen_keys.add(key)

        controls = resolve_controls(finding["check_id"], finding["service"], mappings)
        cached = cache.get(*key)

        try:
            if cached is None:
                # New finding
                payload = build_finding_payload(finding, controls, annex_labels, findings_assessment_id)
                result = client.create_finding(payload)
                cache.upsert(*key, ciso_id=str(result["id"]), status="FAIL")
                stats["new"] += 1
                logger.debug("Created finding: %s", key)
                alert_new_finding(finding, source="Prowler")

            elif cached["status"] == "FAIL":
                # Existing, still failing — update timestamp
                payload = build_finding_payload(finding, controls, annex_labels, findings_assessment_id)
                client.update_finding(cached["ciso_id"], payload)
                cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
                stats["updated"] += 1

            elif cached["status"] == "PASS":
                # Regression: was remediated, now failing again
                payload = build_finding_payload(finding, controls, annex_labels, findings_assessment_id)
                payload["status"] = "identified"
                client.update_finding(cached["ciso_id"], payload)
                cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
                stats["new"] += 1
                logger.warning("Regression detected: %s", key)
                alert_regression(finding, source="Prowler")

        except CISOClientError as e:
            if "permission" in str(e).lower() and stats["new"] == 0:
                # Retry once — folder permissions may not be ready yet
                import time
                time.sleep(2)
                try:
                    result = client.create_finding(payload)
                    cache.upsert(*key, ciso_id=str(result["id"]), status="FAIL")
                    stats["new"] += 1
                    alert_new_finding(finding, source="Prowler")
                    continue
                except CISOClientError:
                    pass
            logger.exception("Error processing finding: %s", key)
            stats["errors"] += 1

    # --- Process PASS findings (mark remediated) ---
    for finding in pass_findings:
        key = (finding["resource_arn"], finding["check_id"])
        seen_keys.add(key)
        cached = cache.get(*key)

        if cached and cached["status"] == "FAIL":
            try:
                client.update_finding(
                    cached["ciso_id"],
                    {
                        "status": "resolved",
                        "observation": (
                            f"**REMEDIATED** on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                            f"**Resource:** {finding['resource_arn']}\n"
                            f"**Check:** {finding['check_id']}"
                        ),
                    },
                )
                cache.upsert(*key, ciso_id=cached["ciso_id"], status="PASS")
                stats["remediated"] += 1
                logger.info("Remediated: %s", key)
                alert_remediation(finding, source="Prowler")
            except CISOClientError:
                logger.exception("Error remediating finding: %s", key)
                stats["errors"] += 1
        else:
            stats["skipped"] += 1

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    # Determine input file
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = find_latest_output(PROWLER_OUTPUT_DIR)

    if not output_file or not os.path.exists(output_file):
        logger.error("No Prowler output found in %s", PROWLER_OUTPUT_DIR)
        sys.exit(1)

    logger.info("Processing Prowler output: %s", output_file)

    # Load mapping
    mappings = load_mappings(MAPPING_FILE)
    logger.info(
        "Loaded %d check overrides, %d service defaults",
        len(mappings.get("check_overrides", {})),
        len(mappings.get("service_defaults", {})),
    )

    # Parse findings
    findings = parse_prowler_output(output_file)
    logger.info("Parsed %d total findings from Prowler output", len(findings))

    if not findings:
        logger.warning("No findings to process. Exiting.")
        return

    # Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # Ensure project and findings assessment exist
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)

    # Open dedup cache
    cache = DedupCache(DB_PATH)

    try:
        stats = process_findings(client, findings, mappings, cache, fa_id)
    finally:
        cache.close()

    # Print summary
    logger.info("=" * 60)
    logger.info("SCAN IMPORT SUMMARY")
    logger.info("=" * 60)
    logger.info("  New findings:        %d", stats["new"])
    logger.info("  Updated findings:    %d", stats["updated"])
    logger.info("  Remediated:          %d", stats["remediated"])
    logger.info("  Skipped (no change): %d", stats["skipped"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("=" * 60)

    # Write summary to a file for run_scan.sh to pick up
    summary_path = os.getenv("SCAN_SUMMARY_PATH", "/data/glue/last_scan_summary.json")
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "input_file": output_file,
                "total_findings": len(findings),
                **stats,
            },
            f,
            indent=2,
        )

    # Send scan completion heartbeat
    scan_type = os.getenv("SCAN_TYPE", "delta")
    summary = {
        "input_file": output_file,
        "total_findings": len(findings),
        **stats,
    }
    alert_scan_complete(summary, scan_type=scan_type)

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        scan_type = os.getenv("SCAN_TYPE", "delta")
        alert_scan_failure(str(e), scan_type=scan_type)
        raise
