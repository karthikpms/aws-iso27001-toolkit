"""
Wazuh Mapper — Phase 3 Glue Layer

Transforms Wazuh alerts into CISO Assistant findings.
Called by the webhook server when Wazuh forwards alerts above the
configured severity threshold (default: level 7+).

Uses the same DedupCache and CISOClient as prowler_mapper.py.
"""

import logging
import os
from datetime import datetime, timezone

from ciso_client import CISOClient, CISOClientError
from prowler_mapper import (
    DedupCache,
    _severity_to_priority,
    _severity_to_finding_severity,
    ensure_project,
    ensure_findings_assessment,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wazuh alert rule group → ISO 27001 Annex A control mapping
# ---------------------------------------------------------------------------
WAZUH_CONTROL_MAP: dict[str, list[str]] = {
    # File Integrity Monitoring
    "syscheck": ["A.8.9"],
    "fim": ["A.8.9"],
    # Rootkit / Malware detection
    "rootcheck": ["A.8.7"],
    "rootkit": ["A.8.7"],
    # Vulnerability detection
    "vulnerability-detector": ["A.8.8"],
    "vulnerability": ["A.8.8"],
    # Authentication / brute-force
    "authentication_failed": ["A.5.17", "A.8.5"],
    "authentication_failures": ["A.5.17", "A.8.5"],
    "pam": ["A.5.17", "A.8.5"],
    "sshd": ["A.5.17", "A.8.5"],
    "win_authentication_failed": ["A.5.17", "A.8.5"],
    # Web attacks
    "web": ["A.8.20", "A.8.21"],
    "attack": ["A.8.20"],
    # SCA (Security Configuration Assessment)
    "sca": ["A.8.9"],
    # System audit / policy
    "audit": ["A.8.15"],
    "policy_changed": ["A.8.9"],
    # Logging
    "syslog": ["A.8.15"],
    "ossec": ["A.8.16"],
    # Network
    "firewall": ["A.8.20"],
    "ids": ["A.8.16"],
    # Docker / container
    "docker": ["A.8.9"],
    # AWS (CloudTrail via Wazuh)
    "aws": ["A.8.15", "A.8.16"],
    "amazon": ["A.8.15", "A.8.16"],
}

ANNEX_A_LABELS: dict[str, str] = {
    "A.5.17": "Authentication Information",
    "A.8.5": "Secure Authentication",
    "A.8.7": "Protection Against Malware",
    "A.8.8": "Management of Technical Vulnerabilities",
    "A.8.9": "Configuration Management",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring Activities",
    "A.8.20": "Network Security",
    "A.8.21": "Security of Network Services",
}

SEVERITY_THRESHOLD = int(os.getenv("WAZUH_ALERT_THRESHOLD", "7"))


def resolve_wazuh_controls(groups: list[str], rule_id: str) -> list[str]:
    """Resolve Annex A controls from Wazuh rule groups."""
    controls: set[str] = set()
    for group in groups:
        group_lower = group.lower()
        if group_lower in WAZUH_CONTROL_MAP:
            controls.update(WAZUH_CONTROL_MAP[group_lower])
    if not controls:
        controls.add("A.8.16")  # Default: Monitoring Activities
    return sorted(controls)


def parse_wazuh_alert(alert: dict) -> dict | None:
    """Parse a single Wazuh alert JSON into a normalized finding.

    Returns None if the alert is below severity threshold.
    """
    rule = alert.get("rule", {})
    level = rule.get("level", 0)

    if level < SEVERITY_THRESHOLD:
        return None

    rule_id = str(rule.get("id", "unknown"))
    description = rule.get("description", "")
    groups = rule.get("groups", [])

    agent = alert.get("agent", {})
    agent_name = agent.get("name", "unknown")
    agent_id = agent.get("id", "000")

    # Build a stable resource identifier for dedup
    # Use agent + rule_id combo; for FIM, include the affected path
    syscheck = alert.get("syscheck", {})
    fim_path = syscheck.get("path", "")
    if fim_path:
        resource_id = f"agent:{agent_id}:{fim_path}"
    else:
        resource_id = f"agent:{agent_id}"

    # Map severity
    if level >= 12:
        severity = "critical"
    elif level >= 10:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    else:
        severity = "low"

    full_log = alert.get("full_log", "")
    timestamp = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

    controls = resolve_wazuh_controls(groups, rule_id)

    return {
        "check_id": f"wazuh-{rule_id}",
        "resource_arn": resource_id,
        "title": f"[Wazuh {rule_id}] {description}",
        "description": (
            f"**Agent:** {agent_name} (ID: {agent_id})\n"
            f"**Rule:** {rule_id} — {description}\n"
            f"**Level:** {level} ({severity})\n"
            f"**Groups:** {', '.join(groups)}\n"
            f"**Timestamp:** {timestamp}\n"
        ),
        "detail": full_log[:2000] if full_log else "",
        "severity": severity,
        "level": level,
        "controls": controls,
        "groups": groups,
        "agent_name": agent_name,
        "fim_path": fim_path,
    }


def push_wazuh_finding(
    client: CISOClient,
    finding: dict,
    cache: DedupCache,
    findings_assessment_id: str,
) -> str:
    """Push a single Wazuh finding to CISO Assistant with dedup.

    Returns: 'new', 'updated', or 'error'.
    """
    key = (finding["resource_arn"], finding["check_id"])
    cached = cache.get(*key)

    control_labels = [
        f"{c}: {ANNEX_A_LABELS.get(c, '')}" for c in finding["controls"]
    ]

    severity = finding["severity"]

    payload: dict = {
        "name": finding["title"][:200],
        "description": (
            f"{finding['description']}\n"
            f"**ISO 27001 Controls:** {', '.join(control_labels)}"
        ),
        "findings_assessment": findings_assessment_id,
        "severity": _severity_to_finding_severity(severity),
        "status": "identified",
        "ref_id": finding["check_id"][:100],
    }

    if finding.get("detail"):
        payload["observation"] = f"```\n{finding['detail'][:2000]}\n```"

    priority = _severity_to_priority(severity)
    if priority is not None:
        payload["priority"] = priority

    try:
        if cached is None:
            result = client.create_finding(payload)
            cache.upsert(*key, ciso_id=str(result["id"]), status="FAIL")
            logger.info("Created Wazuh finding: %s", key)
            return "new"
        else:
            client.update_finding(cached["ciso_id"], payload)
            cache.upsert(*key, ciso_id=cached["ciso_id"], status="FAIL")
            logger.debug("Updated Wazuh finding: %s", key)
            return "updated"
    except CISOClientError:
        logger.exception("Error pushing Wazuh finding: %s", key)
        return "error"
