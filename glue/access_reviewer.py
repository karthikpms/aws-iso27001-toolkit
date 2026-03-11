#!/usr/bin/env python3
"""
IAM Access Review Reports

Generates periodic IAM access review reports for audit evidence.
Identifies non-compliant users/roles (no MFA, stale keys, excessive privileges)
and creates findings in CISO Assistant.

Usage:
    python access_reviewer.py
"""

import csv
import io
import json
import logging
import os
import sys
import tempfile
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
logger = logging.getLogger("access_reviewer")

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
    "ACCESS_REVIEW_SUMMARY_PATH", "/data/glue/access_review_summary.json"
)
REPORT_OUTPUT_DIR = os.getenv("ACCESS_REVIEW_REPORT_DIR", "/data/glue/reports")
FINDINGS_ASSESSMENT_NAME = "IAM Access Reviews"

# Configurable thresholds
MAX_KEY_AGE_DAYS = int(os.getenv("IAM_MAX_KEY_AGE_DAYS", "90"))
MAX_UNUSED_KEY_DAYS = int(os.getenv("IAM_MAX_UNUSED_KEY_DAYS", "90"))
MAX_INACTIVE_CONSOLE_DAYS = int(os.getenv("IAM_MAX_INACTIVE_CONSOLE_DAYS", "90"))
PROHIBITED_POLICIES = [
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
]

# ISO 27001 control mappings
ISO_CONTROLS = {
    "no_mfa": ["A.5.17", "A.8.5"],
    "stale_key": ["A.5.18", "A.8.2"],
    "unused_key": ["A.5.18", "A.8.2"],
    "inactive_console": ["A.5.18"],
    "overly_permissive_user": ["A.5.15", "A.5.18", "A.8.2"],
    "overly_permissive_role": ["A.5.15", "A.5.18", "A.8.2"],
    "wildcard_policy": ["A.5.15", "A.5.18", "A.8.2"],
    "cross_account_trust": ["A.5.15", "A.8.2"],
    "dual_access": ["A.5.15", "A.5.18"],
    "root_no_mfa": ["A.5.17", "A.8.2", "A.8.5"],
    "root_has_keys": ["A.5.17", "A.8.2"],
}

# ---------------------------------------------------------------------------
# Severity helpers (mirrors incident_detector.py)
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


# ---------------------------------------------------------------------------
# CISO Assistant integration (same patterns as incident_detector.py)
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
    """Get or create a findings assessment for IAM access reviews."""
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
            "description": "Automated IAM access review findings — A.5.15, A.5.18, A.8.2",
            "folder": folder_id,
            "category": "audit",
        }
    )
    logger.info("Created findings assessment: %s (id=%s)", name, assessment["id"])
    return assessment["id"]


# ---------------------------------------------------------------------------
# IAM Data Collection
# ---------------------------------------------------------------------------
def generate_credential_report(iam_client: Any) -> list[dict]:
    """Generate and parse the IAM credential report."""
    # Request report generation
    try:
        resp = iam_client.generate_credential_report()
        logger.info("Credential report state: %s", resp.get("State"))
    except (BotoCoreError, ClientError):
        logger.exception("Failed to initiate credential report generation")
        return []

    # Poll until ready (usually takes a few seconds)
    import time

    for _ in range(30):
        try:
            resp = iam_client.get_credential_report()
            break
        except iam_client.exceptions.CredentialReportNotReadyException:
            time.sleep(2)
        except (BotoCoreError, ClientError):
            logger.exception("Failed to get credential report")
            return []
    else:
        logger.error("Credential report not ready after 60 seconds")
        return []

    # Parse CSV
    content = resp["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def get_user_policies(iam_client: Any, username: str) -> dict:
    """Get all policies attached to a user (managed + inline)."""
    attached = []
    inline = []

    try:
        paginator = iam_client.get_paginator("list_attached_user_policies")
        for page in paginator.paginate(UserName=username):
            attached.extend(page.get("AttachedPolicies", []))
    except (BotoCoreError, ClientError):
        logger.warning("Failed to list attached policies for user: %s", username)

    try:
        paginator = iam_client.get_paginator("list_user_policies")
        for page in paginator.paginate(UserName=username):
            inline.extend(page.get("PolicyNames", []))
    except (BotoCoreError, ClientError):
        logger.warning("Failed to list inline policies for user: %s", username)

    return {"attached": attached, "inline": inline}


def get_user_groups(iam_client: Any, username: str) -> list[dict]:
    """Get groups a user belongs to."""
    groups = []
    try:
        paginator = iam_client.get_paginator("list_groups_for_user")
        for page in paginator.paginate(UserName=username):
            groups.extend(page.get("Groups", []))
    except (BotoCoreError, ClientError):
        logger.warning("Failed to list groups for user: %s", username)
    return groups


def get_inline_policy_document(
    iam_client: Any, username: str, policy_name: str
) -> dict | None:
    """Get an inline policy document for a user."""
    try:
        resp = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
        return resp.get("PolicyDocument", {})
    except (BotoCoreError, ClientError):
        logger.warning(
            "Failed to get inline policy %s for user %s", policy_name, username
        )
        return None


def get_managed_policy_document(iam_client: Any, policy_arn: str) -> dict | None:
    """Get the default version document for a managed policy."""
    try:
        resp = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = resp["Policy"]["DefaultVersionId"]
        version_resp = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        return version_resp.get("PolicyVersion", {}).get("Document", {})
    except (BotoCoreError, ClientError):
        logger.warning("Failed to get policy document for: %s", policy_arn)
        return None


def has_wildcard_permissions(policy_doc: dict) -> bool:
    """Check if a policy document grants *:* (full admin)."""
    if not policy_doc:
        return False
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def list_roles_with_details(iam_client: Any) -> list[dict]:
    """List all IAM roles with their trust policies and attached policies."""
    roles = []
    try:
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                # Get attached policies
                attached = []
                try:
                    pol_paginator = iam_client.get_paginator(
                        "list_attached_role_policies"
                    )
                    for pol_page in pol_paginator.paginate(
                        RoleName=role["RoleName"]
                    ):
                        attached.extend(pol_page.get("AttachedPolicies", []))
                except (BotoCoreError, ClientError):
                    logger.warning(
                        "Failed to list policies for role: %s", role["RoleName"]
                    )

                role["attached_policies"] = attached
                roles.append(role)
    except (BotoCoreError, ClientError):
        logger.exception("Failed to list IAM roles")
    return roles


# ---------------------------------------------------------------------------
# Analysis — produce findings from collected data
# ---------------------------------------------------------------------------
def _parse_date(date_str: str) -> datetime | None:
    """Parse a date string from the credential report."""
    if not date_str or date_str in ("N/A", "no_information", "not_supported"):
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _days_since(dt: datetime | None) -> int | None:
    """Calculate days since a given datetime."""
    if dt is None:
        return None
    delta = datetime.now(timezone.utc) - dt
    return delta.days


def analyze_credential_report(
    cred_report: list[dict], iam_client: Any
) -> tuple[list[dict], list[dict]]:
    """
    Analyze the credential report and per-user policies.

    Returns:
        (findings, user_summaries)
        - findings: list of non-compliance issues to push to CISO Assistant
        - user_summaries: list of user data for the HTML report
    """
    now = datetime.now(timezone.utc)
    findings: list[dict] = []
    user_summaries: list[dict] = []

    for row in cred_report:
        username = row.get("user", "")
        arn = row.get("arn", "")
        is_root = username == "<root_account>"

        summary: dict[str, Any] = {
            "username": username,
            "arn": arn,
            "is_root": is_root,
            "mfa_active": row.get("mfa_active") == "true",
            "password_enabled": row.get("password_enabled") == "true",
            "access_key_1_active": row.get("access_key_1_active") == "true",
            "access_key_2_active": row.get("access_key_2_active") == "true",
            "issues": [],
        }

        # --- Root account checks ---
        if is_root:
            if not summary["mfa_active"]:
                findings.append(
                    {
                        "check_id": "iam_root_no_mfa",
                        "title": "Root account does not have MFA enabled",
                        "description": (
                            "The AWS root account does not have multi-factor "
                            "authentication enabled. This is the highest-privilege "
                            "account and must be protected with MFA."
                        ),
                        "severity": "critical",
                        "resource_arn": arn,
                        "iso_controls": ISO_CONTROLS["root_no_mfa"],
                    }
                )
                summary["issues"].append("Root: No MFA")

            if summary["access_key_1_active"] or summary["access_key_2_active"]:
                findings.append(
                    {
                        "check_id": "iam_root_has_access_keys",
                        "title": "Root account has active access keys",
                        "description": (
                            "The AWS root account has active access keys. "
                            "Root access keys should be deleted — use IAM users "
                            "or roles for programmatic access."
                        ),
                        "severity": "critical",
                        "resource_arn": arn,
                        "iso_controls": ISO_CONTROLS["root_has_keys"],
                    }
                )
                summary["issues"].append("Root: Has access keys")

            user_summaries.append(summary)
            continue

        # --- MFA check (for console users) ---
        if summary["password_enabled"] and not summary["mfa_active"]:
            findings.append(
                {
                    "check_id": "iam_user_no_mfa",
                    "title": f"IAM user '{username}' has console access without MFA",
                    "description": (
                        f"User '{username}' has console password enabled but MFA "
                        f"is not active. All console users must have MFA enabled."
                    ),
                    "severity": "high",
                    "resource_arn": arn,
                    "iso_controls": ISO_CONTROLS["no_mfa"],
                }
            )
            summary["issues"].append("No MFA")

        # --- Access key age checks ---
        for key_num in ("1", "2"):
            active_field = f"access_key_{key_num}_active"
            rotated_field = f"access_key_{key_num}_last_rotated"
            used_field = f"access_key_{key_num}_last_used_date"

            if row.get(active_field) != "true":
                continue

            # Key age
            rotated_dt = _parse_date(row.get(rotated_field, ""))
            key_age = _days_since(rotated_dt)
            summary[f"key_{key_num}_age_days"] = key_age

            if key_age is not None and key_age > MAX_KEY_AGE_DAYS:
                findings.append(
                    {
                        "check_id": f"iam_user_stale_key_{key_num}",
                        "title": (
                            f"IAM user '{username}' access key {key_num} is "
                            f"{key_age} days old (max {MAX_KEY_AGE_DAYS})"
                        ),
                        "description": (
                            f"Access key {key_num} for user '{username}' was last "
                            f"rotated {key_age} days ago. Keys must be rotated "
                            f"every {MAX_KEY_AGE_DAYS} days."
                        ),
                        "severity": "high",
                        "resource_arn": arn,
                        "iso_controls": ISO_CONTROLS["stale_key"],
                    }
                )
                summary["issues"].append(f"Key {key_num}: {key_age}d old")

            # Key unused
            used_dt = _parse_date(row.get(used_field, ""))
            unused_days = _days_since(used_dt)
            summary[f"key_{key_num}_unused_days"] = unused_days

            if used_dt is None:
                # Key never used
                if key_age is not None and key_age > MAX_UNUSED_KEY_DAYS:
                    findings.append(
                        {
                            "check_id": f"iam_user_never_used_key_{key_num}",
                            "title": (
                                f"IAM user '{username}' access key {key_num} "
                                f"has never been used ({key_age} days old)"
                            ),
                            "description": (
                                f"Access key {key_num} for user '{username}' "
                                f"was created {key_age} days ago and has never "
                                f"been used. Unused keys should be deactivated."
                            ),
                            "severity": "medium",
                            "resource_arn": arn,
                            "iso_controls": ISO_CONTROLS["unused_key"],
                        }
                    )
                    summary["issues"].append(f"Key {key_num}: Never used")
            elif unused_days is not None and unused_days > MAX_UNUSED_KEY_DAYS:
                findings.append(
                    {
                        "check_id": f"iam_user_unused_key_{key_num}",
                        "title": (
                            f"IAM user '{username}' access key {key_num} "
                            f"unused for {unused_days} days"
                        ),
                        "description": (
                            f"Access key {key_num} for user '{username}' has not "
                            f"been used for {unused_days} days (max "
                            f"{MAX_UNUSED_KEY_DAYS}). Inactive keys should be "
                            f"deactivated or deleted."
                        ),
                        "severity": "medium",
                        "resource_arn": arn,
                        "iso_controls": ISO_CONTROLS["unused_key"],
                    }
                )
                summary["issues"].append(f"Key {key_num}: Unused {unused_days}d")

        # --- Inactive console user ---
        if summary["password_enabled"]:
            last_login = _parse_date(row.get("password_last_used", ""))
            inactive_days = _days_since(last_login)
            summary["console_inactive_days"] = inactive_days

            if last_login is None and _days_since(_parse_date(row.get("user_creation_time", ""))) is not None:
                creation_days = _days_since(_parse_date(row.get("user_creation_time", "")))
                if creation_days is not None and creation_days > MAX_INACTIVE_CONSOLE_DAYS:
                    findings.append(
                        {
                            "check_id": "iam_user_never_logged_in",
                            "title": (
                                f"IAM user '{username}' has never logged in "
                                f"({creation_days} days since creation)"
                            ),
                            "description": (
                                f"User '{username}' has console access enabled but "
                                f"has never logged in. Account created {creation_days} "
                                f"days ago. Unused console access should be removed."
                            ),
                            "severity": "medium",
                            "resource_arn": arn,
                            "iso_controls": ISO_CONTROLS["inactive_console"],
                        }
                    )
                    summary["issues"].append("Console: Never logged in")
            elif inactive_days is not None and inactive_days > MAX_INACTIVE_CONSOLE_DAYS:
                findings.append(
                    {
                        "check_id": "iam_user_inactive_console",
                        "title": (
                            f"IAM user '{username}' has not logged in for "
                            f"{inactive_days} days"
                        ),
                        "description": (
                            f"User '{username}' has not used console login for "
                            f"{inactive_days} days (max {MAX_INACTIVE_CONSOLE_DAYS}). "
                            f"Inactive console access should be removed."
                        ),
                        "severity": "medium",
                        "resource_arn": arn,
                        "iso_controls": ISO_CONTROLS["inactive_console"],
                    }
                )
                summary["issues"].append(f"Console: Inactive {inactive_days}d")

        # --- Dual access (console + programmatic) ---
        has_console = summary["password_enabled"]
        has_keys = summary["access_key_1_active"] or summary["access_key_2_active"]
        summary["dual_access"] = has_console and has_keys
        if has_console and has_keys:
            findings.append(
                {
                    "check_id": "iam_user_dual_access",
                    "title": (
                        f"IAM user '{username}' has both console and "
                        f"programmatic access"
                    ),
                    "description": (
                        f"User '{username}' has both console password and active "
                        f"access keys. This increases the attack surface. Review "
                        f"whether both access methods are needed."
                    ),
                    "severity": "low",
                    "resource_arn": arn,
                    "iso_controls": ISO_CONTROLS["dual_access"],
                }
            )
            summary["issues"].append("Dual access")

        # --- Policy checks (overly permissive) ---
        if not is_root:
            policies = get_user_policies(iam_client, username)
            summary["attached_policies"] = [
                p["PolicyName"] for p in policies["attached"]
            ]
            summary["inline_policies"] = policies["inline"]

            # Check for prohibited managed policies
            for pol in policies["attached"]:
                if pol.get("PolicyArn") in PROHIBITED_POLICIES:
                    findings.append(
                        {
                            "check_id": "iam_user_overly_permissive",
                            "title": (
                                f"IAM user '{username}' has prohibited policy: "
                                f"{pol['PolicyName']}"
                            ),
                            "description": (
                                f"User '{username}' has the '{pol['PolicyName']}' "
                                f"policy directly attached. Highly privileged "
                                f"policies should not be attached to users — use "
                                f"roles with temporary credentials instead."
                            ),
                            "severity": "high",
                            "resource_arn": arn,
                            "iso_controls": ISO_CONTROLS["overly_permissive_user"],
                        }
                    )
                    summary["issues"].append(f"Policy: {pol['PolicyName']}")

            # Check inline policies for wildcard
            for pol_name in policies["inline"]:
                doc = get_inline_policy_document(iam_client, username, pol_name)
                if has_wildcard_permissions(doc):
                    findings.append(
                        {
                            "check_id": "iam_user_wildcard_inline",
                            "title": (
                                f"IAM user '{username}' has inline policy "
                                f"'{pol_name}' with *:* permissions"
                            ),
                            "description": (
                                f"User '{username}' has an inline policy "
                                f"'{pol_name}' granting Action:* on Resource:*. "
                                f"This is effectively full admin access."
                            ),
                            "severity": "high",
                            "resource_arn": arn,
                            "iso_controls": ISO_CONTROLS["wildcard_policy"],
                        }
                    )
                    summary["issues"].append(f"Wildcard: {pol_name}")

        user_summaries.append(summary)

    return findings, user_summaries


def analyze_roles(roles: list[dict]) -> list[dict]:
    """Analyze IAM roles for overly permissive policies and cross-account trusts."""
    findings: list[dict] = []
    account_id = None

    for role in roles:
        role_name = role.get("RoleName", "")
        role_arn = role.get("Arn", "")

        # Extract account ID from role ARN
        if account_id is None and role_arn:
            parts = role_arn.split(":")
            if len(parts) >= 5:
                account_id = parts[4]

        # Skip AWS service-linked roles
        if role.get("Path", "").startswith("/aws-service-role/"):
            continue

        # Check for prohibited attached policies
        for pol in role.get("attached_policies", []):
            if pol.get("PolicyArn") in PROHIBITED_POLICIES:
                findings.append(
                    {
                        "check_id": "iam_role_overly_permissive",
                        "title": (
                            f"IAM role '{role_name}' has prohibited policy: "
                            f"{pol['PolicyName']}"
                        ),
                        "description": (
                            f"Role '{role_name}' has the '{pol['PolicyName']}' "
                            f"policy attached. Review whether this level of "
                            f"access is necessary and apply least privilege."
                        ),
                        "severity": "medium",
                        "resource_arn": role_arn,
                        "iso_controls": ISO_CONTROLS["overly_permissive_role"],
                    }
                )

        # Check trust policy for cross-account principals
        trust = role.get("AssumeRolePolicyDocument", {})
        statements = trust.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            # Principal can be a string "*" or a dict
            if principal == "*":
                findings.append(
                    {
                        "check_id": "iam_role_open_trust",
                        "title": (
                            f"IAM role '{role_name}' trusts all AWS principals"
                        ),
                        "description": (
                            f"Role '{role_name}' has a trust policy with "
                            f"Principal: *. Any AWS account can assume this role."
                        ),
                        "severity": "critical",
                        "resource_arn": role_arn,
                        "iso_controls": ISO_CONTROLS["cross_account_trust"],
                    }
                )
                continue

            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]

            for p in aws_principals:
                if p == "*":
                    findings.append(
                        {
                            "check_id": "iam_role_open_trust",
                            "title": (
                                f"IAM role '{role_name}' trusts all AWS principals"
                            ),
                            "description": (
                                f"Role '{role_name}' has a trust policy with "
                                f"Principal AWS:*. Any AWS account can assume "
                                f"this role."
                            ),
                            "severity": "critical",
                            "resource_arn": role_arn,
                            "iso_controls": ISO_CONTROLS["cross_account_trust"],
                        }
                    )
                elif account_id and account_id not in p:
                    # External account
                    findings.append(
                        {
                            "check_id": "iam_role_cross_account_trust",
                            "title": (
                                f"IAM role '{role_name}' has cross-account trust"
                            ),
                            "description": (
                                f"Role '{role_name}' trusts an external "
                                f"principal: {p}. Verify this cross-account "
                                f"trust is authorized and documented."
                            ),
                            "severity": "medium",
                            "resource_arn": role_arn,
                            "iso_controls": ISO_CONTROLS["cross_account_trust"],
                        }
                    )

    return findings


# ---------------------------------------------------------------------------
# HTML Report Generation
# ---------------------------------------------------------------------------
def generate_html_report(
    user_summaries: list[dict],
    user_findings: list[dict],
    role_findings: list[dict],
    report_date: str,
) -> str:
    """Generate an HTML access review report using Jinja2."""
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:
        logger.warning("Jinja2 not available, generating plain text report instead")
        return _generate_plain_report(
            user_summaries, user_findings, role_findings, report_date
        )

    template_dir = Path(__file__).parent / "templates"
    if not (template_dir / "access_review.html").exists():
        logger.warning("HTML template not found, generating plain text report")
        return _generate_plain_report(
            user_summaries, user_findings, role_findings, report_date
        )

    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    template = env.get_template("access_review.html")

    # Summary stats
    total_users = len([u for u in user_summaries if not u.get("is_root")])
    root_summary = next((u for u in user_summaries if u.get("is_root")), None)
    users_with_issues = len(
        [u for u in user_summaries if u.get("issues") and not u.get("is_root")]
    )
    total_findings = len(user_findings) + len(role_findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in user_findings + role_findings:
        sev = f.get("severity", "medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return template.render(
        report_date=report_date,
        total_users=total_users,
        users_with_issues=users_with_issues,
        total_findings=total_findings,
        severity_counts=severity_counts,
        root_summary=root_summary,
        user_summaries=[u for u in user_summaries if not u.get("is_root")],
        user_findings=user_findings,
        role_findings=role_findings,
        max_key_age_days=MAX_KEY_AGE_DAYS,
        max_unused_key_days=MAX_UNUSED_KEY_DAYS,
        max_inactive_console_days=MAX_INACTIVE_CONSOLE_DAYS,
    )


def _generate_plain_report(
    user_summaries: list[dict],
    user_findings: list[dict],
    role_findings: list[dict],
    report_date: str,
) -> str:
    """Fallback plain-text report when Jinja2 is not available."""
    lines = [
        f"IAM Access Review Report — {report_date}",
        "=" * 60,
        "",
        f"Total users: {len(user_summaries)}",
        f"Total findings: {len(user_findings) + len(role_findings)}",
        "",
        "USER FINDINGS:",
        "-" * 40,
    ]
    for f in user_findings:
        lines.append(
            f"  [{f['severity'].upper()}] {f['title']}"
        )
    lines.extend(["", "ROLE FINDINGS:", "-" * 40])
    for f in role_findings:
        lines.append(
            f"  [{f['severity'].upper()}] {f['title']}"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Process findings into CISO Assistant
# ---------------------------------------------------------------------------
def process_findings(
    client: CISOClient,
    all_findings: list[dict],
    cache: DedupCache,
    findings_assessment_id: str,
) -> dict:
    """Create/update findings in CISO Assistant with deduplication."""
    stats = {"new": 0, "updated": 0, "skipped": 0, "errors": 0, "alerts_sent": 0}

    for finding in all_findings:
        resource_arn = finding["resource_arn"]
        check_id = f"access_review:{finding['check_id']}"
        cached = cache.get(resource_arn, check_id)
        severity = finding["severity"]

        if cached is not None:
            # Already tracked — update timestamp
            cache.upsert(resource_arn, check_id, cached["ciso_id"], "FAIL")
            stats["updated"] += 1
            logger.debug("Already tracked: %s / %s", resource_arn, check_id)
            continue

        # New finding — create in CISO Assistant
        control_labels = ", ".join(finding["iso_controls"])
        description = (
            f"**Resource:** {resource_arn}\n"
            f"**ISO 27001 Controls:** {control_labels}\n\n"
            f"{finding['description']}"
        )

        payload: dict[str, Any] = {
            "name": finding["title"][:200],
            "description": description,
            "findings_assessment": findings_assessment_id,
            "severity": _SEVERITY_TO_FINDING_SEVERITY.get(severity, 2),
            "status": "identified",
            "ref_id": check_id[:100],
        }

        priority = _SEVERITY_TO_PRIORITY.get(severity)
        if priority is not None:
            payload["priority"] = priority

        try:
            result = client.create_finding(payload)
            ciso_id = str(result["id"])
            cache.upsert(resource_arn, check_id, ciso_id, "FAIL")
            stats["new"] += 1
            logger.info(
                "Created finding: %s / %s (ciso_id=%s)",
                resource_arn,
                check_id,
                ciso_id,
            )

            # Immediate alert for critical/high
            if severity in ("critical", "high"):
                alert_data = {
                    "check_id": check_id,
                    "title": finding["title"],
                    "severity": severity,
                    "resource_arn": resource_arn,
                    "region": AWS_REGION,
                    "description": finding["description"],
                    "service": "IAM",
                }
                if alert_new_finding(alert_data, source="IAM Access Review"):
                    stats["alerts_sent"] += 1

        except CISOClientError:
            logger.exception(
                "Error creating finding: %s / %s", resource_arn, check_id
            )
            stats["errors"] += 1

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    run_start = datetime.now(timezone.utc)
    report_date = run_start.strftime("%Y-%m-%d")

    logger.info("=== IAM Access Review starting ===")
    logger.info(
        "Thresholds: key_age=%dd, unused_key=%dd, inactive_console=%dd",
        MAX_KEY_AGE_DAYS,
        MAX_UNUSED_KEY_DAYS,
        MAX_INACTIVE_CONSOLE_DAYS,
    )

    iam_client = boto3.client("iam", region_name=AWS_REGION)

    # 1. Generate and parse credential report
    logger.info("Generating IAM credential report...")
    cred_report = generate_credential_report(iam_client)
    if not cred_report:
        logger.error("Failed to generate credential report — aborting")
        alert_scan_failure(
            "Failed to generate IAM credential report",
            scan_type="access-review",
        )
        sys.exit(1)

    logger.info("Credential report contains %d entries", len(cred_report))

    # 2. Analyze users
    logger.info("Analyzing user credentials and policies...")
    user_findings, user_summaries = analyze_credential_report(cred_report, iam_client)
    logger.info(
        "User analysis: %d users, %d findings",
        len(user_summaries),
        len(user_findings),
    )

    # 3. Analyze roles
    logger.info("Analyzing IAM roles...")
    roles = list_roles_with_details(iam_client)
    role_findings = analyze_roles(roles)
    logger.info("Role analysis: %d roles, %d findings", len(roles), len(role_findings))

    all_findings = user_findings + role_findings

    # 4. Generate HTML report
    logger.info("Generating access review report...")
    report_html = generate_html_report(
        user_summaries, user_findings, role_findings, report_date
    )

    # Save report to disk
    os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
    report_filename = f"iam_access_review_{report_date}.html"
    report_path = os.path.join(REPORT_OUTPUT_DIR, report_filename)
    with open(report_path, "w") as f:
        f.write(report_html)
    logger.info("Report saved to %s", report_path)

    # 5. Connect to CISO Assistant
    logger.info("Connecting to CISO Assistant at %s", CISO_URL)
    client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)
    folder_id = ensure_project(client, PROJECT_NAME)
    fa_id = ensure_findings_assessment(client, folder_id)

    # 6. Upload report as evidence
    logger.info("Uploading access review report as evidence...")
    try:
        client.upload_evidence(
            name=f"IAM Access Review — {report_date}",
            file_path=report_path,
            folder_id=folder_id,
        )
        logger.info("Evidence uploaded successfully")
    except CISOClientError:
        logger.exception("Failed to upload evidence report")

    # 7. Process findings with dedup
    cache = DedupCache(DB_PATH)
    try:
        stats = process_findings(client, all_findings, cache, fa_id)
    finally:
        cache.close()

    # 8. Print summary
    logger.info("=" * 60)
    logger.info("IAM ACCESS REVIEW SUMMARY")
    logger.info("=" * 60)
    logger.info("  Users analyzed:      %d", len(user_summaries))
    logger.info("  Roles analyzed:      %d", len(roles))
    logger.info("  Total findings:      %d", len(all_findings))
    logger.info("  New findings:        %d", stats["new"])
    logger.info("  Already tracked:     %d", stats["updated"])
    logger.info("  Errors:              %d", stats["errors"])
    logger.info("  Alerts sent:         %d", stats["alerts_sent"])
    logger.info("=" * 60)

    # 9. Write summary JSON
    summary = {
        "timestamp": run_start.isoformat(),
        "report_path": report_path,
        "users_analyzed": len(user_summaries),
        "roles_analyzed": len(roles),
        "total_findings": len(all_findings),
        "user_findings": len(user_findings),
        "role_findings": len(role_findings),
        **stats,
    }
    os.makedirs(os.path.dirname(SCAN_SUMMARY_PATH), exist_ok=True)
    with open(SCAN_SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    # 10. Send completion alert with review summary
    alert_scan_complete(
        {
            "input_file": "access_reviewer",
            "total_findings": len(all_findings),
            **stats,
        },
        scan_type="access-review",
    )

    if stats["errors"] > 0:
        logger.warning("Completed with %d errors", stats["errors"])
        sys.exit(1)

    logger.info("IAM Access Review complete")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        alert_scan_failure(str(e), scan_type="access-review")
        raise
