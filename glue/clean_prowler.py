#!/usr/bin/env python3
"""
Clean Prowler Data — Removes only Prowler-inserted findings from CISO Assistant.

Deletes all findings under the "Prowler AWS Scan" findings assessment and clears
the corresponding entries from the dedup cache. Leaves all other data (manually
uploaded findings, account details, compliance assessments, etc.) untouched.

Usage:
    python clean_prowler.py                # Dry run (shows what would be deleted)
    python clean_prowler.py --confirm      # Actually delete
    python clean_prowler.py --keep-assessment --confirm  # Delete findings but keep the assessment
"""

import argparse
import logging
import os
import sys

from ciso_client import CISOClient, CISOClientError
from dedup_cache import DedupCache

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("clean_prowler")

CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
ASSESSMENT_NAME = "Prowler AWS Scan"


def list_all_findings(client: CISOClient, assessment_id: str) -> list[dict]:
    """List all findings for a findings assessment, handling pagination."""
    results = []
    url = f"/findings/?findings_assessment={assessment_id}"
    while url:
        resp = client._request("GET", url).json()
        results.extend(resp.get("results", []))
        next_url = resp.get("next")
        if next_url:
            url = next_url.replace(client.api_url, "")
        else:
            url = None
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove Prowler-inserted findings from CISO Assistant"
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Actually delete (without this flag, runs in dry-run mode)",
    )
    parser.add_argument(
        "--keep-assessment",
        action="store_true",
        help="Keep the findings assessment container, only delete findings inside it",
    )
    args = parser.parse_args()

    dry_run = not args.confirm
    if dry_run:
        logger.info("DRY RUN — pass --confirm to actually delete")

    # Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)

    # Find the Prowler findings assessment
    assessments = client.list_findings_assessments()
    prowler_assessment = None
    for a in assessments:
        if a.get("name") == ASSESSMENT_NAME:
            prowler_assessment = a
            break

    if not prowler_assessment:
        logger.info("No '%s' findings assessment found. Nothing to clean.", ASSESSMENT_NAME)
        return

    assessment_id = prowler_assessment["id"]
    logger.info("Found assessment: %s (id=%s)", ASSESSMENT_NAME, assessment_id)

    # List all findings under this assessment
    findings = list_all_findings(client, assessment_id)
    logger.info("Found %d findings to delete", len(findings))

    if not findings and not dry_run and not args.keep_assessment:
        logger.info("No findings. Deleting empty assessment...")
        client.delete_findings_assessment(assessment_id)
        logger.info("Assessment deleted.")
        _clear_dedup_cache(dry_run)
        return

    # Delete findings
    deleted = 0
    errors = 0
    for finding in findings:
        fid = finding["id"]
        fname = finding.get("name", "unknown")
        if dry_run:
            logger.info("  [DRY RUN] Would delete: %s — %s", fid, fname)
        else:
            try:
                client.delete_finding(fid)
                deleted += 1
                if deleted % 50 == 0:
                    logger.info("  Deleted %d / %d findings...", deleted, len(findings))
            except CISOClientError as e:
                logger.error("  Failed to delete %s: %s", fid, e)
                errors += 1

    if not dry_run:
        logger.info("Deleted %d findings (%d errors)", deleted, errors)

    # Delete the assessment itself (unless --keep-assessment)
    if not args.keep_assessment:
        if dry_run:
            logger.info("[DRY RUN] Would delete assessment: %s", ASSESSMENT_NAME)
        else:
            try:
                client.delete_findings_assessment(assessment_id)
                logger.info("Deleted assessment: %s", ASSESSMENT_NAME)
            except CISOClientError as e:
                logger.error("Failed to delete assessment: %s", e)

    # Clear dedup cache
    _clear_dedup_cache(dry_run)

    # Summary
    logger.info("=" * 50)
    if dry_run:
        logger.info("DRY RUN SUMMARY")
        logger.info("  Would delete %d findings", len(findings))
        logger.info("  Would clear dedup cache")
        logger.info("Run with --confirm to execute.")
    else:
        logger.info("CLEANUP COMPLETE")
        logger.info("  Findings deleted: %d", deleted)
        logger.info("  Errors: %d", errors)
    logger.info("=" * 50)


def _clear_dedup_cache(dry_run: bool) -> None:
    """Clear all entries from the dedup SQLite cache."""
    if not os.path.exists(DB_PATH):
        logger.info("No dedup cache found at %s — skipping", DB_PATH)
        return

    cache = DedupCache(DB_PATH)
    try:
        if dry_run:
            count = cache.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            logger.info("[DRY RUN] Would clear %d entries from dedup cache", count)
        else:
            count = cache.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            cache.conn.execute("DELETE FROM findings")
            cache.conn.commit()
            logger.info("Cleared %d entries from dedup cache", count)
    finally:
        cache.close()


if __name__ == "__main__":
    main()
