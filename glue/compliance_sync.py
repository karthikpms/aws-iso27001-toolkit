#!/usr/bin/env python3
"""
Compliance Sync — Wires Prowler scan results into CISO Assistant's compliance framework.

Loads the ISO 27001:2022 framework, creates a compliance assessment, maps Prowler
findings to requirement assessments, updates their statuses, and uploads scan
evidence.

Usage:
    python compliance_sync.py                        # Process latest scan
    python compliance_sync.py /path/to/output.json   # Process specific file
"""

import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ciso_client import CISOClient, CISOClientError
from prowler_mapper import (
    find_latest_output,
    load_mappings,
    parse_prowler_output,
    resolve_controls,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("compliance_sync")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
PROWLER_OUTPUT_DIR = os.getenv("PROWLER_OUTPUT_DIR", "/home/prowler/output")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")
MAPPING_FILE = Path(__file__).parent / "mappings" / "prowler_iso27001_map.json"

ISO27001_LIBRARY_URN = "urn:intuitem:risk:library:iso27001-2022"
COMPLIANCE_ASSESSMENT_NAME = "ISO 27001:2022 — AWS Controls"


# ---------------------------------------------------------------------------
# Framework & Assessment Setup
# ---------------------------------------------------------------------------
def ensure_framework_loaded(client: CISOClient) -> str:
    """Load ISO 27001:2022 framework if not already loaded. Returns framework ID."""
    # Check if already loaded
    fw = client.get_framework_by_name("27001")
    if fw:
        logger.info("Framework already loaded: %s (id=%s)", fw["name"], fw["id"])
        return fw["id"]

    # Find the stored library
    logger.info("ISO 27001 framework not loaded. Searching stored libraries...")
    libraries = client.list_stored_libraries("27001")
    library = None
    for lib in libraries:
        urn = lib.get("urn", "")
        if urn == ISO27001_LIBRARY_URN:
            library = lib
            break
        # Fallback: match any iso27001-2022 library
        if "iso27001" in urn and "2022" in urn and "mapping" not in urn:
            library = lib

    if not library:
        logger.error(
            "ISO 27001:2022 library not found in stored libraries. "
            "Import it manually via CISO Assistant UI → Governance → Libraries."
        )
        sys.exit(1)

    # Import the library
    logger.info("Importing library: %s (id=%s)", library["name"], library["id"])
    client.import_stored_library(library["id"])

    # Fetch the newly created framework
    fw = client.get_framework_by_name("27001")
    if not fw:
        logger.error("Framework not found after library import.")
        sys.exit(1)

    logger.info("Framework loaded: %s (id=%s)", fw["name"], fw["id"])
    return fw["id"]


def ensure_project(client: CISOClient, name: str) -> str:
    """Get or create the CISO Assistant project folder."""
    projects = client.list_projects()
    for p in projects:
        if p.get("name") == name:
            return p["id"]
    project = client.create_project(name)
    logger.info("Created project: %s (id=%s)", name, project["id"])
    return project["id"]


def ensure_compliance_assessment(
    client: CISOClient, framework_id: str, project_id: str
) -> str:
    """Get or create the ISO 27001 compliance assessment."""
    assessments = client.list_compliance_assessments()
    for a in assessments:
        if a.get("name") == COMPLIANCE_ASSESSMENT_NAME:
            logger.info(
                "Using existing compliance assessment: %s (id=%s)",
                a["name"],
                a["id"],
            )
            return a["id"]

    assessment = client.create_compliance_assessment(
        COMPLIANCE_ASSESSMENT_NAME, framework_id, project_id
    )
    logger.info(
        "Created compliance assessment: %s (id=%s)",
        COMPLIANCE_ASSESSMENT_NAME,
        assessment["id"],
    )
    return assessment["id"]


# ---------------------------------------------------------------------------
# Requirement Mapping
# ---------------------------------------------------------------------------
def build_requirement_map(
    client: CISOClient, compliance_assessment_id: str
) -> dict[str, list[dict]]:
    """Build a map of Annex A control ref_id -> requirement assessment objects.

    The requirement assessments contain a nested 'requirement' field with ref_id.
    We normalize ref_ids to match our mapping format (e.g., "A.5.15").
    """
    requirement_assessments = client.list_requirement_assessments(
        compliance_assessment_id
    )
    logger.info(
        "Fetched %d requirement assessments", len(requirement_assessments)
    )

    # Map ref_id -> list of requirement assessment dicts
    ra_map: dict[str, list[dict]] = defaultdict(list)

    for ra in requirement_assessments:
        # The ref_id may be in the requirement_assessment directly or nested
        ref_id = ra.get("ref_id", "")
        if not ref_id:
            # Try nested requirement object
            req = ra.get("requirement", {})
            if isinstance(req, dict):
                ref_id = req.get("ref_id", "")

        if not ref_id:
            continue

        # Normalize: ensure "A." prefix for Annex A controls
        normalized = _normalize_ref_id(ref_id)
        if normalized:
            ra_map[normalized].append(ra)

    logger.info(
        "Mapped %d unique control ref_ids to requirement assessments",
        len(ra_map),
    )
    return dict(ra_map)


def _normalize_ref_id(ref_id: str) -> str:
    """Normalize requirement ref_id to match our Annex A format (e.g., 'A.5.15')."""
    ref_id = ref_id.strip()

    # Already in our format
    if ref_id.startswith("A."):
        return ref_id

    # Some libraries use "5.15" without the "A." prefix
    parts = ref_id.split(".")
    if len(parts) >= 2 and parts[0].isdigit():
        section = int(parts[0])
        # Annex A controls are sections 5-8
        if 5 <= section <= 8:
            return f"A.{ref_id}"

    return ref_id


# ---------------------------------------------------------------------------
# Prowler Results Aggregation
# ---------------------------------------------------------------------------
def aggregate_prowler_results(
    prowler_output_path: str, mappings: dict
) -> dict[str, dict]:
    """Aggregate Prowler findings by Annex A control.

    Returns: {control_id: {"pass": N, "fail": N, "checks": [...]}}
    """
    findings = parse_prowler_output(prowler_output_path)
    logger.info("Parsed %d findings for compliance aggregation", len(findings))

    control_results: dict[str, dict] = defaultdict(
        lambda: {"pass": 0, "fail": 0, "checks": []}
    )

    for finding in findings:
        controls = resolve_controls(
            finding["check_id"], finding["service"], mappings
        )
        status = finding["status"]

        for control in controls:
            if status == "FAIL":
                control_results[control]["fail"] += 1
                control_results[control]["checks"].append(
                    {
                        "check_id": finding["check_id"],
                        "status": "FAIL",
                        "resource": finding["resource_arn"],
                        "title": finding["title"],
                    }
                )
            elif status == "PASS":
                control_results[control]["pass"] += 1

    logger.info(
        "Aggregated results for %d Annex A controls", len(control_results)
    )
    return dict(control_results)


# ---------------------------------------------------------------------------
# Requirement Status Updates
# ---------------------------------------------------------------------------
def update_requirement_statuses(
    client: CISOClient,
    ra_map: dict[str, list[dict]],
    control_results: dict[str, dict],
) -> dict:
    """Update requirement assessment results based on aggregated Prowler results.

    CISO Assistant uses two separate fields:
    - status: workflow state (to_do, in_progress, in_review, done)
    - result: compliance result (not_assessed, compliant, partially_compliant,
              non_compliant, not_applicable)
    """
    stats = {"compliant": 0, "partially_compliant": 0, "non_compliant": 0, "skipped": 0, "errors": 0}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for control_id, ra_list in ra_map.items():
        results = control_results.get(control_id)
        if not results:
            # No automated checks for this control — skip
            stats["skipped"] += 1
            continue

        # Determine compliance result
        if results["fail"] == 0 and results["pass"] > 0:
            result = "compliant"
            stats["compliant"] += 1
        elif results["fail"] > 0 and results["pass"] > 0:
            result = "partially_compliant"
            stats["partially_compliant"] += 1
        else:
            result = "non_compliant"
            stats["non_compliant"] += 1

        # Build observation text
        observation = (
            f"**Automated assessment** — {now}\n\n"
            f"**Pass:** {results['pass']} | **Fail:** {results['fail']}\n"
        )
        if results["fail"] > 0:
            observation += "\n**Failing checks:**\n"
            for check in results["checks"][:10]:  # Limit to 10
                observation += f"- `{check['check_id']}`: {check['title']}\n"
            if len(results["checks"]) > 10:
                observation += f"- ... and {len(results['checks']) - 10} more\n"

        # Update each requirement assessment for this control
        for ra in ra_list:
            try:
                client.update_requirement_assessment(
                    ra["id"],
                    {
                        "result": result,
                        "status": "done",
                        "observation": observation,
                    },
                )
            except CISOClientError as e:
                logger.error(
                    "Failed to update requirement %s: %s", control_id, e
                )
                stats["errors"] += 1

    return stats


# ---------------------------------------------------------------------------
# Evidence Upload
# ---------------------------------------------------------------------------
def upload_scan_evidence(
    client: CISOClient, folder_id: str, prowler_output_path: str
) -> None:
    """Upload Prowler scan output as evidence."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    name = f"Prowler Full Scan — {timestamp}"
    try:
        result = client.upload_evidence(
            name=name,
            file_path=prowler_output_path,
            folder_id=folder_id,
        )
        logger.info("Uploaded evidence: %s (id=%s)", name, result.get("id"))
    except CISOClientError as e:
        logger.error("Failed to upload evidence: %s", e)


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

    # Connect to CISO Assistant
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # 1. Load framework
    framework_id = ensure_framework_loaded(client)

    # 2. Ensure project exists
    folder_id = ensure_project(client, PROJECT_NAME)

    # 3. Create compliance assessment
    ca_id = ensure_compliance_assessment(client, framework_id, folder_id)

    # 4. Build requirement map
    ra_map = build_requirement_map(client, ca_id)

    # 5. Aggregate Prowler results by Annex A control
    mappings = load_mappings(MAPPING_FILE)
    control_results = aggregate_prowler_results(output_file, mappings)

    # Log which controls we can assess
    mapped_controls = set(ra_map.keys()) & set(control_results.keys())
    unmapped_controls = set(control_results.keys()) - set(ra_map.keys())
    logger.info(
        "Controls with both requirements and scan results: %d",
        len(mapped_controls),
    )
    if unmapped_controls:
        logger.warning(
            "Controls with scan results but no matching requirements: %s",
            sorted(unmapped_controls),
        )

    # 6. Update requirement statuses
    stats = update_requirement_statuses(client, ra_map, control_results)

    # 7. Upload evidence
    upload_scan_evidence(client, folder_id, output_file)

    # Summary
    logger.info("=" * 60)
    logger.info("COMPLIANCE SYNC SUMMARY")
    logger.info("=" * 60)
    logger.info("  Compliant:           %d", stats["compliant"])
    logger.info("  Partially compliant: %d", stats["partially_compliant"])
    logger.info("  Non-compliant:       %d", stats["non_compliant"])
    logger.info("  Skipped (no checks): %d", stats["skipped"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
