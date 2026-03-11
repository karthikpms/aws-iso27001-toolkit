# ISO 27001 Automation Plan

**Project:** AWS ISO 27001 Infrastructure Readiness Toolkit
**Prepared by:** Pyramidions
**Date:** March 11, 2026

---

## Current State

The toolkit already automates:

| Automation | Status | Annex A Controls |
|------------|--------|-----------------|
| AWS infrastructure scanning (Prowler) | Live | A.5.15, A.5.17, A.8.2, A.8.5, A.8.8–A.8.10, A.8.13–A.8.16, A.8.20–A.8.21, A.8.24 |
| Host intrusion detection & FIM (Wazuh) | Live | A.8.7, A.8.9, A.8.15, A.8.16 |
| Finding dedup + CISO Assistant import (Glue Layer) | Live | — |
| Email alerting via SNS | Live | — |
| Nightly CISO Assistant data export to S3 | Live | A.8.13 |
| CloudWatch instance monitoring + alarms | Live | A.8.16 |

Everything below is **new automation** to be added.

---

## Automation 1: AWS Asset Inventory Sync — DONE

**Status:** Implemented — `glue/asset_inventory.py`, `glue/mappings/required_tags.json`, `glue/dedup_cache.py` (shared module). Cron: daily 03:00 UTC. IAM permissions added to Terraform.

**ISO 27001 Controls:** A.5.9 (Information Security in Project Management), A.5.10 (Acceptable Use of Information), A.5.11 (Return of Assets), A.5.12 (Classification of Information), A.5.13 (Labelling of Information), A.5.14 (Information Transfer)

**What it does:**
- Pulls a complete inventory of AWS resources using AWS Config and the Resource Groups Tagging API
- Syncs resources into CISO Assistant as managed assets with ownership, classification, and tags
- Detects drift: new resources created without required tags (Owner, Classification, Environment)
- Flags orphaned resources (untagged, no owner) as findings
- Runs daily after Prowler delta scans

**Resources covered:**

| AWS Service | Resource Types |
|-------------|---------------|
| EC2 | Instances, AMIs, EBS volumes, snapshots, Elastic IPs |
| S3 | Buckets (with size, encryption status, public access) |
| RDS | DB instances, clusters, snapshots |
| Lambda | Functions (with runtime, last invoked) |
| IAM | Users, roles, policies (with last used date) |
| VPC | VPCs, subnets, security groups, NACLs |
| ECS/EKS | Clusters, services, task definitions |
| Route 53 | Hosted zones, records |
| CloudFront | Distributions |
| SNS/SQS | Topics, queues |
| Secrets Manager | Secrets (metadata only, not values) |
| KMS | Keys (with rotation status) |

**Architecture:**

```
AWS Config Aggregator ──→ asset_inventory.py ──→ CISO Assistant (Assets)
                                │
Resource Groups Tagging API ────┘
                                │
                                ├──→ Tag compliance findings
                                └──→ Alerter (orphaned resource alerts)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Asset collector | `glue/asset_inventory.py` | New script. Calls AWS Config `list_discovered_resources` and `get_resource_config_history` for each resource type. Falls back to service-specific APIs (ec2.describe_instances, s3.list_buckets, etc.) if Config is not enabled. |
| Tag policy | `glue/mappings/required_tags.json` | Defines required tags per resource type (Owner, Classification, Environment, CostCenter). |
| CISO client extension | `glue/ciso_client.py` | Add `create_asset()`, `update_asset()`, `list_assets()` methods. CISO Assistant's asset model supports: name, description, type, owner, classification, parent folder. |
| Cron entry | `terraform/user_data.sh.tpl` | Daily at 03:00 UTC: `python asset_inventory.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| AWS Config enabled | Must be enabled in the target account with a recorder covering all resource types. If not already enabled, add `aws_config_configuration_recorder` and `aws_config_delivery_channel` to Terraform. | Already enabled (continuous recording, all resource types) |
| IAM permissions | Add `config:ListDiscoveredResources`, `config:GetResourceConfigHistory`, `tag:GetResources`, `tag:GetTagKeys` to the EC2 instance role. | Added to `terraform/main.tf` |
| CISO Assistant asset API | Verify the community edition API supports asset CRUD. Test endpoints: `GET/POST /api/assets/`. | Using findings model instead |
| Tag policy defined | Agree on mandatory tags with the team (Owner, Classification, Environment at minimum). | Defined in `glue/mappings/required_tags.json` |

**Effort estimate:** 3–4 days

---

## Automation 2: AWS Inspector Vulnerability Management — DONE

**Status:** Implemented — `glue/inspector_mapper.py`, `glue/sla_tracker.py`, `glue/mappings/inspector_iso27001_map.json`. Cron: daily 02:30 UTC. Inspector v2 enabler + IAM permissions added to Terraform.

**ISO 27001 Controls:** A.8.8 (Management of Technical Vulnerabilities)

**What it does:**
- Enables AWS Inspector v2 for continuous vulnerability scanning of EC2, ECR images, and Lambda functions
- Pulls Inspector findings via API and imports them into CISO Assistant as findings
- Tracks remediation SLAs per severity:
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days
  - Low: next patch cycle
- Alerts on SLA breaches (finding open beyond its remediation window)
- Deduplicates using the same SQLite cache pattern as Prowler

**Architecture:**

```
AWS Inspector v2 (continuous scanning)
        │
        ▼
inspector_mapper.py ──→ DedupCache ──→ CISO Assistant (Findings)
        │                                      │
        ├──→ Alerter (new CVEs, SLA breaches)  │
        └──→ SLA tracker (age vs threshold)    │
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Inspector mapper | `glue/inspector_mapper.py` | New script. Calls `inspector2.list_findings()` with filters for ACTIVE status. Maps CVE severity to CISO priority. Groups findings by resource ARN. |
| SLA tracker | `glue/sla_tracker.py` | New module. Queries dedup cache for finding age, compares against SLA thresholds, generates overdue findings list. |
| Control mapping | `glue/mappings/inspector_iso27001_map.json` | Maps Inspector finding types → A.8.8 (primary), with secondary mappings for network reachability findings → A.8.20. |
| Terraform | `terraform/main.tf` | Add `aws_inspector2_enabler` resource for EC2, ECR, Lambda scan types. Add IAM permissions for `inspector2:ListFindings`, `inspector2:DescribeFindings`. |
| Cron entry | `terraform/user_data.sh.tpl` | Daily at 02:30 UTC (between delta scan and asset inventory): `python inspector_mapper.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| AWS Inspector v2 available | Inspector v2 must be available in `ap-south-1`. It is supported in Mumbai. | OK |
| IAM permissions | Add `inspector2:ListFindings`, `inspector2:DescribeFindings`, `inspector2:ListCoverage`, `inspector2:BatchGetAccountStatus` to EC2 instance role. | Added to `terraform/main.tf` |
| SSM Agent on EC2 targets | Inspector v2 requires SSM Agent running on EC2 instances for OS-level vulnerability detection. Amazon Linux 2/2023 and Ubuntu 20.04+ include it by default. | Verify on target instances |
| ECR image scanning | If using ECR, enhanced scanning must be enabled at the registry level. | Check if applicable |
| SLA thresholds agreed | Confirm remediation SLA windows with security/management. | Defaults set in `glue/sla_tracker.py` (C:7d, H:30d, M:90d, L:180d) |
| boto3 >= 1.26 | Inspector v2 client available in boto3 1.26+. Current requirements.txt uses `boto3>=1.28` — OK. | OK |

**Effort estimate:** 3–4 days

---

## Automation 3: IAM Access Review Reports — DONE

**Status:** Implemented — `glue/access_reviewer.py`, `glue/templates/access_review.html`. Cron: monthly 1st at 06:00 UTC. Jinja2 added to requirements.txt.

**ISO 27001 Controls:** A.5.15 (Access Control), A.5.18 (Access Rights), A.8.2 (Privileged Access Rights)

**What it does:**
- Generates periodic IAM access review reports for audit evidence
- Identifies and flags:
  - Users with no MFA enabled
  - Access keys older than 90 days
  - Access keys never used or unused for 90+ days
  - Users with console access but no recent login (90+ days)
  - Roles with overly permissive policies (AdminAccess, PowerUserAccess, `*:*`)
  - Cross-account role trusts (external principals)
  - Service-linked roles vs custom roles breakdown
  - Users with both console and programmatic access (higher risk)
- Produces a structured report uploaded as evidence to CISO Assistant
- Creates findings for each non-compliant user/role requiring remediation
- Sends summary to security team for sign-off (the human review step auditors require)

**Architecture:**

```
IAM API (generate_credential_report, list_users, list_roles, etc.)
        │
        ▼
access_reviewer.py ──→ Report (JSON + HTML) ──→ CISO Assistant (Evidence)
        │                                              │
        ├──→ Non-compliance findings ──→ CISO Assistant (Findings)
        └──→ Alerter (summary for sign-off)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Access reviewer | `glue/access_reviewer.py` | New script. Calls `iam.generate_credential_report()`, `iam.list_users()`, `iam.list_roles()`, `iam.list_attached_user_policies()`, `iam.list_user_policies()`. Analyzes and produces structured report. |
| Report template | `glue/templates/access_review.html` | Jinja2 HTML template for human-readable report. Table of all users with status indicators. |
| CISO client extension | `glue/ciso_client.py` | Use existing `upload_evidence()` to attach report as evidence to the access control requirement assessment. |
| Cron entry | `terraform/user_data.sh.tpl` | Monthly on the 1st at 06:00 UTC: `python access_reviewer.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| IAM permissions | Already have `SecurityAudit` and `ViewOnlyAccess` on the instance role — these cover all IAM read APIs including `GenerateCredentialReport`. | OK |
| Jinja2 | Add `jinja2>=3.1` to `glue/requirements.txt` for HTML report generation. | Add to requirements |
| Access review policy | Define what constitutes non-compliance: max key age, max inactive days, prohibited policies. Make configurable via environment variables. | Decision needed |
| Review sign-off process | Decide who receives the report and how they sign off (email reply, CISO Assistant comment, etc.). | Decision needed |

**Effort estimate:** 2–3 days

---

## Automation 4: Backup Verification & Restore Testing — DONE

**Status:** Implemented — `glue/backup_verifier.py`, `glue/mappings/backup_config.json`. Cron: daily 05:00 UTC (verification), monthly 1st 07:00 UTC (restore tests), every 3h (cleanup). IAM permissions added to Terraform.

**ISO 27001 Controls:** A.8.13 (Information Backup), A.8.14 (Redundancy of Information Processing Facilities)

**What it does:**
- Verifies that all expected backups exist and are recent:
  - RDS automated backups enabled and within retention window
  - EBS snapshots exist and are recent (< 25 hours old)
  - S3 versioning enabled on critical buckets
  - CISO Assistant nightly export exists in S3
- Performs automated restore tests:
  - Monthly: restore latest RDS snapshot to a temporary instance, run a connectivity check, tear down
  - Monthly: create an EBS volume from latest snapshot, mount it on a temp instance, verify file checksums, tear down
- Logs all verification and restore test results as evidence in CISO Assistant
- Alerts on: missing backups, failed restore tests, backup age exceeding threshold

**Architecture:**

```
backup_verifier.py
    ├──→ Check RDS backup status (describe_db_instances → BackupRetentionPeriod, LatestRestorableTime)
    ├──→ Check EBS snapshot age (describe_snapshots → StartTime)
    ├──→ Check S3 versioning (get_bucket_versioning)
    ├──→ Check S3 export file age (list_objects_v2 → LastModified)
    │
    ├──→ Monthly: restore_test_rds() → create temp instance → verify → delete
    ├──→ Monthly: restore_test_ebs() → create temp volume → attach → verify → delete
    │
    ├──→ CISO Assistant (Evidence: verification report)
    ├──→ CISO Assistant (Findings: failed checks)
    └──→ Alerter (failures + monthly restore test results)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Backup verifier | `glue/backup_verifier.py` | New script. Verification checks run daily. Restore tests run monthly (controlled by `--restore-test` flag). |
| Terraform additions | `terraform/main.tf` | Add IAM permissions for `rds:RestoreDBInstanceFromDBSnapshot`, `rds:DeleteDBInstance`, `ec2:CreateVolume`, `ec2:DeleteVolume`, `ec2:AttachVolume` (scoped to temp resources with tag conditions). |
| Cron entries | `terraform/user_data.sh.tpl` | Daily at 05:00 UTC: `python backup_verifier.py`. Monthly 1st at 07:00 UTC: `python backup_verifier.py --restore-test` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| IAM permissions for restore tests | Instance role needs `rds:RestoreDBInstanceFromDBSnapshot`, `rds:DeleteDBInstance` (scoped to `iso27001-restore-test-*` instance names), `ec2:CreateVolume`, `ec2:AttachVolume`, `ec2:DeleteVolume`, `ec2:DetachVolume` (scoped to tagged resources). | Add to Terraform |
| RDS in use | Only relevant if the product uses RDS. If no RDS, skip that check. | Verify |
| Temp resource cleanup safety | Restore test resources are created with a `Purpose=iso27001-restore-test` tag and deleted immediately after verification. Add a cleanup cron as a safety net (delete any resources with this tag older than 2 hours). | Implement |
| Cost awareness | Each RDS restore test creates a temporary db.t3.micro instance (~$0.02/hour, runs for ~10 minutes). Monthly cost: negligible. | OK |
| VPC/subnet for temp instances | Restore test instances need a subnet. Use the toolkit's own subnet or a designated test subnet. | Decision needed |

**Effort estimate:** 4–5 days

---

## Automation 5: Change Management Evidence from CI/CD

**ISO 27001 Controls:** A.8.32 (Change Management), A.8.9 (Configuration Management), A.8.25 (Secure Development Life Cycle)

**What it does:**
- Hooks into GitHub (or GitLab/Bitbucket) to automatically capture evidence of controlled change management for every production deployment
- For each merged PR to production branches, records:
  - PR title, description, and URL
  - Author and reviewers/approvers
  - Whether it was peer-reviewed (at least one approval)
  - CI/CD pipeline status (tests passed before merge)
  - Deployment timestamp
  - Files changed (summary, not full diff)
- Pushes each deployment record as evidence to CISO Assistant against A.8.32
- Creates findings for policy violations:
  - PR merged without review
  - PR merged with failing CI checks
  - Direct commits to production branch (no PR)
  - Force pushes to protected branches

**Architecture:**

```
GitHub Webhooks (push, pull_request, deployment)
        │
        ▼
change_tracker.py (webhook endpoint on glue-webhook)
        │
        ├──→ Parse event, extract change metadata
        ├──→ Check for policy violations
        ├──→ CISO Assistant (Evidence: change record)
        ├──→ CISO Assistant (Findings: violations)
        └──→ Alerter (violations only)
```

**Alternative (polling mode — no webhook needed):**

```
GitHub API (list merged PRs since last check)
        │
        ▼
change_tracker.py (cron, polls every 6 hours)
        │
        └──→ Same downstream as above
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Change tracker | `glue/change_tracker.py` | New script. Supports both webhook mode (added as route to `webhook_server.py`) and polling mode (cron). Polling mode uses GitHub API: `GET /repos/{owner}/{repo}/pulls?state=closed&sort=updated&base=main`. |
| Webhook route | `glue/webhook_server.py` | Add `/github` endpoint. Verify webhook signature using `GITHUB_WEBHOOK_SECRET`. |
| Change policy | `glue/mappings/change_policy.json` | Configurable rules: required reviewers count, required CI checks, protected branches list. |
| Control mapping | Hardcoded | A.8.32 (Change Management), A.8.25 (Secure Development Life Cycle) |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| GitHub API token | A Personal Access Token (classic) or GitHub App token with `repo` scope (read access to PRs, commits, deployments). Store in Secrets Manager as `github_api_token`. | Create token |
| Repository list | Define which repositories to monitor. Configure via environment variable: `GITHUB_REPOS=org/repo1,org/repo2`. | Decision needed |
| GitHub webhook (optional) | If using webhook mode: configure webhook on each repo pointing to `https://<toolkit-ip>:9000/github` with content type `application/json` and a shared secret. Requires toolkit to be reachable from GitHub (public IP or GitHub Actions runner with VPN). | Network decision |
| Branch protection rules | For this to be meaningful, branch protection should already be enabled on production branches (require PRs, require reviews, require status checks). This automation detects violations, not prevents them. | Verify |
| PyGithub or requests | Polling mode uses raw `requests` (already in requirements). No additional dependency needed. | OK |
| Port exposure | If webhook mode: port 9000 must be reachable from GitHub IPs (or use a reverse proxy). The security group currently only exposes 9000 internally. | Terraform change if webhook mode |

**Effort estimate:** 3–4 days

---

## Automation 6: Policy Review Lifecycle Tracker

**ISO 27001 Controls:** A.5.1 (Policies for Information Security), A.5.2 (Information Security Roles and Responsibilities)

**What it does:**
- Tracks all information security policies stored in CISO Assistant with their review dates
- Automatically creates findings/tasks when policies are overdue for review
- Sends reminder emails to policy owners at configurable intervals before due date:
  - 30 days before: first reminder
  - 14 days before: second reminder
  - 7 days before: urgent reminder
  - Overdue: daily reminders + finding created
- Generates a policy compliance dashboard summary:
  - Total policies, up-to-date count, due soon, overdue
  - Per-owner breakdown
- Uploads policy compliance status as evidence to CISO Assistant quarterly

**Architecture:**

```
CISO Assistant API (list applied_controls where category=policy)
        │
        ▼
policy_tracker.py
    ├──→ Check review dates against current date
    ├──→ Send reminders (via Alerter/SNS)
    ├──→ Create overdue findings in CISO Assistant
    └──→ Generate quarterly evidence report
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Policy tracker | `glue/policy_tracker.py` | New script. Queries CISO Assistant for applied controls tagged as policies. Compares `eta` (review date) field against current date. |
| Policy config | `glue/mappings/policy_owners.json` | Maps policy names → owner email addresses and review cadence (annual, semi-annual). |
| Cron entry | `terraform/user_data.sh.tpl` | Daily at 08:00 UTC: `python policy_tracker.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| Policies loaded in CISO Assistant | All information security policies must be created as applied controls in CISO Assistant with `eta` (review date) set. | Manual setup |
| Policy owner mapping | Need a mapping of policy name → owner email. Can be stored in CISO Assistant custom fields or in a local JSON config. | Decision needed |
| SNS subscriptions | Policy owners' email addresses must be subscribed to the SNS topic (or use a separate topic for policy reminders). | Terraform/manual |
| CISO Assistant API fields | Verify that applied controls expose `eta`, `status`, and `description` fields via API. Test with: `GET /api/applied-controls/`. | Verify |

**Effort estimate:** 2 days

---

## Automation 7: Training Compliance Tracker

**ISO 27001 Controls:** A.6.3 (Information Security Awareness, Education and Training)

**What it does:**
- Integrates with training platform APIs to pull security awareness training completion status
- Supported platforms (implement one, design for extensibility):
  - **Google Workspace** (Admin SDK → Reports API for course completions)
  - **KnowBe4** (Reporting API for training campaigns)
  - **Custom LMS** (generic CSV/API adapter)
- Compares completion list against employee roster (pulled from HR system or static CSV)
- Creates findings for employees who:
  - Haven't completed mandatory annual training
  - Are more than 30 days past their training due date
  - Are new hires who haven't completed onboarding security training within 14 days
- Uploads completion evidence (training report) to CISO Assistant quarterly
- Sends reminders to non-compliant employees and their managers

**Architecture:**

```
Training Platform API ──→ training_tracker.py ──→ Compare against employee roster
        │                                                    │
Employee Roster (CSV/API) ──────────────────────────────────┘
        │
        ├──→ CISO Assistant (Evidence: training completion report)
        ├──→ CISO Assistant (Findings: non-compliant employees)
        └──→ Alerter (reminders to employees + managers)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Training tracker | `glue/training_tracker.py` | New script. Abstract `TrainingProvider` class with implementations for KnowBe4 / Google Workspace / CSV. |
| Employee roster | `glue/data/employee_roster.csv` | CSV with: name, email, department, manager_email, hire_date. Updated manually or synced from HR system. Gitignored. |
| Cron entry | `terraform/user_data.sh.tpl` | Weekly on Monday at 08:00 UTC: `python training_tracker.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| Training platform selected | Must have a training platform with an API. KnowBe4 is common for security awareness. If no platform, use a manual CSV upload approach. | Decision needed |
| API credentials | Training platform API key/OAuth credentials. Store in Secrets Manager. | Create after platform selected |
| Employee roster source | Either a static CSV (maintained manually) or an API integration with HR system (BambooHR, Google Workspace Directory, etc.). | Decision needed |
| Training policy defined | What training is mandatory, how often, grace period for new hires. | Decision needed |
| Privacy considerations | Training compliance data contains employee PII. Ensure handling complies with internal privacy policies. | Review |

**Effort estimate:** 3–5 days (varies by training platform)

---

## Automation 8: Incident Auto-Detection and Logging — DONE

**Status:** Implemented — `glue/incident_detector.py`, `glue/mappings/incident_rules.json`. Cron: every 15 minutes. IAM permissions for GuardDuty, CloudTrail, SecurityHub added to Terraform.

**ISO 27001 Controls:** A.5.24 (Information Security Incident Management Planning), A.5.25 (Assessment and Decision on Information Security Events), A.5.26 (Response to Information Security Incidents), A.5.28 (Collection of Evidence)

**What it does:**
- Automatically detects security incidents from multiple AWS sources and creates incident records in CISO Assistant
- Detection sources:
  - **GuardDuty findings** — threat detection (recon, credential compromise, crypto mining, data exfil)
  - **CloudTrail anomalies** — root logins, unauthorized API calls, console logins from unusual IPs/countries
  - **SecurityHub findings** — aggregated findings from multiple AWS services
  - **Wazuh critical alerts** — already partially implemented; this extends it with richer incident records
- Creates structured incident records with:
  - Incident title and description
  - Severity and category (malware, unauthorized access, data breach, etc.)
  - Affected resources (ARNs)
  - Detection timestamp
  - Raw evidence (JSON payload)
  - Status: Open (manual investigation required for response actions, root cause, and closure)
- Escalation rules:
  - Critical (GuardDuty severity 7+): immediate alert to security team + management
  - High: alert within 1 hour
  - Medium/Low: included in daily digest

**Architecture:**

```
GuardDuty ──────────┐
CloudTrail Events ──┤
SecurityHub ────────┼──→ incident_detector.py ──→ CISO Assistant (Incidents)
Wazuh (critical) ───┘              │
                                   ├──→ Alerter (escalation)
                                   └──→ Evidence attachment (raw JSON)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Incident detector | `glue/incident_detector.py` | New script. Polls GuardDuty (`list_findings` + `get_findings`), CloudTrail (`lookup_events` for specific event names), SecurityHub (`get_findings`). |
| Incident rules | `glue/mappings/incident_rules.json` | Defines which GuardDuty finding types and CloudTrail events constitute incidents, with severity mappings. |
| CloudTrail events of interest | Embedded in config | `ConsoleLogin` (root or from new IP), `StopLogging`, `DeleteTrail`, `CreateUser` (outside IaC), `AttachUserPolicy` (AdminAccess), `PutBucketPolicy` (public), `AuthorizeSecurityGroupIngress` (0.0.0.0/0). |
| CISO client extension | `glue/ciso_client.py` | Verify incident model support. If CISO Assistant doesn't have a native incident model, use findings with a category tag. |
| Cron entry | `terraform/user_data.sh.tpl` | Every 15 minutes: `python incident_detector.py` (lightweight API poll, no heavy compute). |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| GuardDuty enabled | Must be enabled in the target account. Add `aws_guardduty_detector` to Terraform if not already enabled. | Already enabled (detector `e2ce6b7298f19bda2b71e4d6c8db56b8`) |
| SecurityHub enabled (optional) | Provides aggregated view. Not strictly required if using GuardDuty + CloudTrail directly. | Already enabled |
| IAM permissions | Add `guardduty:ListFindings`, `guardduty:GetFindings`, `guardduty:ListDetectors`, `cloudtrail:LookupEvents`, `securityhub:GetFindings` to EC2 instance role. | Added to `terraform/main.tf` |
| CloudTrail enabled | Must have at least one trail with management events enabled. Prowler already checks for this. | Already enabled (multi-region, KMS-encrypted, log validation on) |
| Incident response procedure | Define severity thresholds, escalation contacts, and expected response times. The automation detects — humans still investigate and respond. | Defaults set in `glue/mappings/incident_rules.json` |
| CISO Assistant incident model | Verify how to model incidents. Options: use findings with `incident` tag, or use risk scenarios. Test the API. | Using findings model under "Security Incidents" assessment |

**Effort estimate:** 4–5 days

---

## Automation 9: Network Security Monitoring (Real-time) — DONE

**Status:** Implemented — `glue/network_monitor.py`, `glue/mappings/risky_ports.json`, `glue/webhook_server.py` (added `/network-event` endpoint). EventBridge rules + Athena workgroup added to Terraform. Cron: weekly Sunday 05:30 UTC (SG scan) + 06:00 UTC (Flow Log analysis). Real-time via EventBridge → SNS → webhook.

**ISO 27001 Controls:** A.8.20 (Network Security), A.8.21 (Security of Network Services)

**What it does:**
- Monitors security group and NACL changes in real-time via CloudTrail EventBridge rules
- Detects and alerts on risky changes:
  - Security group opened to `0.0.0.0/0` on sensitive ports (SSH, RDP, database ports)
  - NACL rules allowing unrestricted inbound traffic
  - VPC peering connections created
  - VPN/Direct Connect changes
  - Route table modifications
- Optionally auto-remediates (with approval):
  - Automatically revokes overly permissive security group rules
  - Creates a finding in CISO Assistant with the original rule and remediation action
- Analyzes VPC Flow Logs (weekly) for:
  - Unusual outbound traffic patterns (potential data exfiltration)
  - Connections to known-bad IP ranges
  - Traffic on unexpected ports

**Architecture:**

```
CloudTrail ──→ EventBridge Rule ──→ SNS ──→ Glue Webhook (/network-event)
                                                    │
                                                    ▼
                                          network_monitor.py
                                              │
                                              ├──→ Risk assessment
                                              ├──→ CISO Assistant (Finding)
                                              ├──→ Alerter (immediate for critical)
                                              └──→ Auto-remediate (optional, with config flag)

VPC Flow Logs ──→ Athena (weekly query) ──→ network_monitor.py --flow-analysis
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Network monitor | `glue/network_monitor.py` | New script. Handles both real-time events (via webhook) and periodic flow log analysis (via Athena). |
| Webhook route | `glue/webhook_server.py` | Add `/network-event` endpoint for EventBridge → SNS notifications. |
| EventBridge rules | `terraform/main.tf` | Add `aws_cloudwatch_event_rule` for `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, `CreateNetworkAclEntry`, `CreateVpcPeeringConnection`. Target: SNS topic → webhook. |
| Athena setup | `terraform/main.tf` | Add Athena workgroup, S3 results bucket, and VPC Flow Logs table DDL for weekly analysis. |
| Risky ports config | `glue/mappings/risky_ports.json` | List of ports that should never be open to 0.0.0.0/0: 22, 3389, 3306, 5432, 27017, 6379, 9200, 11211. |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| EventBridge access | Default event bus receives CloudTrail management events automatically. No additional config needed. | OK |
| SNS topic for events | Can reuse existing `iso27001-alerts` topic or create a dedicated one. Webhook endpoint must be subscribed. | Terraform |
| VPC Flow Logs enabled | Must be enabled on all VPCs, publishing to S3 (for Athena) or CloudWatch Logs. Add to Terraform if not enabled. | Check |
| Athena (for flow analysis) | Need an Athena workgroup, query results S3 bucket, and the VPC Flow Logs Athena table. | Add to Terraform |
| IAM permissions | Add `ec2:RevokeSecurityGroupIngress` (only if auto-remediation enabled), `athena:StartQueryExecution`, `athena:GetQueryResults`, `s3:GetObject` (flow logs bucket). | Add to Terraform |
| Auto-remediation policy | Must explicitly decide whether auto-remediation is enabled. Default should be OFF (alert only). Controlled via `AUTO_REMEDIATE_SG=false` env var. | Decision needed |
| Webhook reachability | EventBridge → SNS → HTTPS subscription requires the webhook to have a valid HTTPS endpoint (or use SNS → Lambda → internal call). | Architecture decision |

**Effort estimate:** 5–6 days

---

## Automation 10: Vendor Security Posture Monitoring

**ISO 27001 Controls:** A.5.19 (Information Security in Supplier Relationships), A.5.20 (Addressing Information Security Within Supplier Agreements), A.5.21 (Managing Information Security in the ICT Supply Chain), A.5.22 (Monitoring, Review and Change Management of Supplier Services)

**What it does:**
- Continuously monitors the security posture of third-party vendors/suppliers
- Two data sources:
  - **SecurityScorecard / UpGuard / BitSight API** — automated vendor security ratings (paid service)
  - **Breach monitoring** — checks vendor domains against public breach databases (Have I Been Pwned, breach notification feeds)
- Tracks vendor risk score over time
- Alerts when:
  - A vendor's security score drops below threshold
  - A vendor appears in a data breach notification
  - A vendor's score has decreased by more than 10 points since last check
- Creates findings in CISO Assistant for vendors requiring reassessment
- Generates quarterly vendor risk summary report as evidence

**Architecture:**

```
SecurityScorecard API ──┐
                        ├──→ vendor_monitor.py ──→ CISO Assistant (Findings + Evidence)
Breach Feeds (HIBP) ───┘              │
                                      ├──→ Alerter (score drops, breaches)
                                      └──→ Quarterly report
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Vendor monitor | `glue/vendor_monitor.py` | New script. Abstract `VendorScoreProvider` with implementations for SecurityScorecard, UpGuard, or a manual CSV-based approach. |
| Vendor registry | `glue/data/vendors.json` | List of monitored vendors: name, domain, criticality tier (critical/high/medium/low), minimum acceptable score. |
| Breach checker | `glue/breach_checker.py` | Checks vendor domains against HIBP breach API (`GET /api/v3/breaches?domain=vendor.com`). |
| Cron entry | `terraform/user_data.sh.tpl` | Weekly on Wednesday at 10:00 UTC: `python vendor_monitor.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| Vendor scoring service (optional) | SecurityScorecard, UpGuard, or BitSight subscription. Has cost ($$$). Can start without one using manual score entry. | Decision needed (budget) |
| HIBP API key | Have I Been Pwned API key for breach domain search. $3.50/month for the `hibp-enterprise` plan. | Purchase |
| Vendor list | Complete list of vendors with domains and criticality ratings. Likely already exists as part of vendor management process. | Compile list |
| Score thresholds | Define minimum acceptable score per vendor tier: critical vendors ≥ 80, high ≥ 70, medium ≥ 60, low ≥ 50 (example). | Decision needed |
| requests library | Already in requirements.txt. | OK |

**Effort estimate:** 3–4 days (without paid scoring service), 5–6 days (with API integration)

---

## Automation 11: Encryption Compliance Verification — DONE

**Status:** Implemented — `glue/encryption_auditor.py`. IAM permissions added to Terraform. Cron: weekly Sunday 05:00 UTC.

**ISO 27001 Controls:** A.8.24 (Use of Cryptography)

**What it does:**
- Comprehensive encryption-at-rest and in-transit verification across all AWS services
- Goes beyond Prowler's checks with deeper analysis:
  - **At rest:** EBS volumes, RDS instances, S3 buckets, DynamoDB tables, EFS filesystems, Elasticsearch domains, Redshift clusters, SQS queues, SNS topics, Kinesis streams, Backup vaults
  - **In transit:** CloudFront HTTPS enforcement, ALB/NLB listener protocols, API Gateway TLS, RDS SSL enforcement
  - **Key management:** KMS key rotation status, key policies (who has decrypt access), CMK vs AWS-managed key usage, key age
- Produces an encryption posture report
- Identifies resources using AWS-managed keys that should use CMKs (per policy)
- Tracks encryption coverage percentage over time

**Architecture:**

```
AWS APIs (describe calls across services)
        │
        ▼
encryption_auditor.py ──→ Encryption posture report
        │
        ├──→ CISO Assistant (Evidence: quarterly encryption report)
        ├──→ CISO Assistant (Findings: unencrypted resources, weak TLS)
        └──→ Alerter (new unencrypted resources found)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Encryption auditor | `glue/encryption_auditor.py` | New script. Service-by-service encryption check. Uses existing AWS API permissions from SecurityAudit policy. |
| Cron entry | `terraform/user_data.sh.tpl` | Weekly on Sunday at 05:00 UTC (after full Prowler scan): `python encryption_auditor.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| IAM permissions | `SecurityAudit` + `ViewOnlyAccess` already covers most describe APIs. May need `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus`, `kms:GetKeyPolicy`. | Verify, likely OK |
| Encryption policy | Define which services must use CMKs vs AWS-managed keys. Define minimum TLS version (1.2). | Decision needed |
| Service inventory | Need to know which AWS services are in use to scope the audit. Can auto-discover via AWS Config or the asset inventory (Automation 1). | Depends on Automation 1 |

**Effort estimate:** 3 days

---

## Automation 12: Log Completeness Verification — DONE

**Status:** Implemented — `glue/log_auditor.py`, `glue/mappings/required_logging.json`. Cron: daily 06:00 UTC. IAM permissions added to Terraform.

**ISO 27001 Controls:** A.8.15 (Logging), A.8.16 (Monitoring Activities), A.8.17 (Clock Synchronization)

**What it does:**
- Verifies that all required logging is enabled and functioning:
  - CloudTrail: enabled in all regions, multi-region trail, log file validation, S3 delivery
  - VPC Flow Logs: enabled on all VPCs
  - S3 access logging: enabled on sensitive buckets
  - ELB access logs: enabled on all load balancers
  - RDS audit logging: enabled on all database instances
  - CloudWatch Logs: log groups exist for all services, no expired/missing log streams
  - Lambda function logging: all functions have CloudWatch log groups
  - GuardDuty: enabled and exporting findings
  - AWS Config: recorder running
- Checks for log delivery gaps:
  - CloudTrail digest: last delivery timestamp vs expected (should be within 1 hour)
  - VPC Flow Logs: last event timestamp per VPC
  - CloudWatch log groups: identifies groups with no recent events (possibly dead services)
- Verifies NTP synchronization on Wazuh-monitored hosts (via Wazuh SCA)

**Architecture:**

```
AWS APIs (CloudTrail, VPC, S3, ELB, RDS, CloudWatch, etc.)
        │
        ▼
log_auditor.py ──→ Log completeness report
        │
        ├──→ CISO Assistant (Evidence: log audit report)
        ├──→ CISO Assistant (Findings: missing/broken logging)
        └──→ Alerter (critical: CloudTrail/GuardDuty disabled)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Log auditor | `glue/log_auditor.py` | New script. Checks each logging source for enabled status and recent activity. |
| Expected logging config | `glue/mappings/required_logging.json` | Defines which log sources are mandatory, per-service expectations. |
| Cron entry | `terraform/user_data.sh.tpl` | Daily at 06:00 UTC: `python log_auditor.py` |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| IAM permissions | Covered by `SecurityAudit` + `ViewOnlyAccess`. Need `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `cloudtrail:GetTrailStatus`, `elasticloadbalancing:DescribeLoadBalancerAttributes`. | Likely OK |
| Logging policy | Define which log sources are mandatory for the environment. | Decision needed |

**Effort estimate:** 2–3 days

---

## Automation 13: Compliance Report Generator

**ISO 27001 Controls:** All (cross-cutting)

**What it does:**
- Generates audit-ready compliance reports on demand or on schedule
- Report types:
  - **Executive summary**: single-page compliance score, trend, top risks
  - **Full compliance report**: all 93 Annex A controls with status, evidence links, and gap analysis
  - **Service-level report**: per-AWS-service compliance breakdown
  - **Remediation tracker**: all open findings sorted by severity and age, with SLA status
  - **Audit evidence pack**: ZIP file containing all evidence attachments for a specific control or time period
- Output formats: HTML (primary), PDF (via WeasyPrint), JSON (machine-readable)
- Stores generated reports in S3 with a permalink for sharing
- Sends report links to stakeholders on schedule

**Architecture:**

```
CISO Assistant API (all data)
        │
        ▼
report_generator.py ──→ Jinja2 templates ──→ HTML/PDF
        │
        ├──→ S3 upload (with presigned URL for sharing)
        ├──→ CISO Assistant (Evidence: report attachment)
        └──→ Alerter (report ready notification with link)
```

**Implementation:**

| Component | File | Description |
|-----------|------|-------------|
| Report generator | `glue/report_generator.py` | New script. Pulls all data from CISO Assistant API, renders templates, uploads to S3. |
| Report templates | `glue/templates/` | Jinja2 HTML templates for each report type. |
| Cron entry | `terraform/user_data.sh.tpl` | Monthly 1st at 09:00 UTC: `python report_generator.py --type full`. Weekly Monday at 09:00 UTC: `python report_generator.py --type executive`. |

**Pre-requisites:**

| Requirement | Details | Status |
|-------------|---------|--------|
| Jinja2 | Add to requirements.txt (shared with Automation 3). | Add |
| WeasyPrint (for PDF) | Add `weasyprint>=60` to requirements.txt. Requires system dependencies: `libpango`, `libcairo`, `libgdk-pixbuf`. Add to Dockerfile. | Add to Dockerfile |
| S3 bucket for reports | Can reuse the backup bucket or create a dedicated `pyramidions-iso27001-reports` bucket. Reports should be encrypted and access-controlled. | Terraform |
| Report recipients | List of stakeholders who receive reports. Configure via env var or JSON config. | Decision needed |
| CISO Assistant data populated | Reports are only useful once there's enough data in CISO Assistant (after a few weeks of scanning). | Timing |

**Effort estimate:** 4–5 days

---

## Implementation Priority Matrix

| Priority | Automation | Effort | Impact | Dependencies | Status |
|----------|-----------|--------|--------|-------------|--------|
| **P1** | 1. Asset Inventory Sync | 3–4 days | High | AWS Config | **DONE** |
| **P1** | 2. Inspector Vulnerability Mgmt | 3–4 days | High | AWS Inspector v2 | **DONE** |
| **P1** | 8. Incident Auto-Detection | 4–5 days | High | GuardDuty | **DONE** |
| **P2** | 3. IAM Access Review Reports | 2–3 days | High | None (permissions already exist) | **DONE** |
| **P2** | 5. Change Management Evidence | 3–4 days | High | GitHub API token | Pending |
| **P2** | 12. Log Completeness Verification | 2–3 days | Medium | None | **DONE** |
| **P2** | 4. Backup Verification | 4–5 days | Medium | RDS/EBS in use | **Done** |
| **P3** | 11. Encryption Compliance | 3 days | Medium | Encryption policy defined | **DONE** |
| **P3** | 6. Policy Review Tracker | 2 days | Medium | Policies in CISO Assistant | Pending |
| **P3** | 13. Compliance Report Generator | 4–5 days | Medium | Jinja2, WeasyPrint | Pending |
| **P4** | 9. Network Security Monitoring | 5–6 days | Medium | EventBridge, Athena | **DONE** |
| **P4** | 7. Training Compliance Tracker | 3–5 days | Low–Med | Training platform API | Pending |
| **P4** | 10. Vendor Security Monitoring | 3–6 days | Low–Med | Vendor scoring service (paid) | Pending |

---

## Suggested Implementation Phases

### Phase 5: Core Automation (Weeks 9–12)

| Week | Automations | Combined Effort |
|------|------------|----------------|
| 9–10 | Asset Inventory Sync (1) + Inspector Vuln Mgmt (2) | 6–8 days |
| 11–12 | Incident Auto-Detection (8) + IAM Access Review (3) | 6–8 days |

**Outcome:** Automated asset management, vulnerability management, incident detection, and access reviews. Covers A.5.9–A.5.14, A.5.15, A.5.18, A.5.24–A.5.28, A.8.2, A.8.8.

### Phase 6: Evidence Automation (Weeks 13–15)

| Week | Automations | Combined Effort |
|------|------------|----------------|
| 13 | Change Management Evidence (5) + Log Completeness (12) | 5–7 days |
| 14–15 | Backup Verification (4) + Policy Review Tracker (6) | 6–7 days |

**Outcome:** Continuous audit evidence generation for change management, logging, backups, and policy lifecycle. Covers A.5.1, A.8.13, A.8.15, A.8.32.

### Phase 7: Advanced Monitoring (Weeks 16–19)

| Week | Automations | Combined Effort |
|------|------------|----------------|
| 16 | Encryption Compliance (11) | 3 days |
| 17–18 | Network Security Monitoring (9) | 5–6 days |
| 19 | Compliance Report Generator (13) | 4–5 days |

**Outcome:** Deep encryption auditing, real-time network monitoring, and automated report generation. Covers A.8.20, A.8.21, A.8.24.

### Phase 8: External Integrations (Weeks 20–22)

| Week | Automations | Combined Effort |
|------|------------|----------------|
| 20–21 | Training Compliance Tracker (7) | 3–5 days |
| 21–22 | Vendor Security Monitoring (10) | 3–6 days |

**Outcome:** Automated tracking of people and supplier controls. Covers A.5.19–A.5.22, A.6.3.

---

## Cumulative Annex A Coverage After Full Implementation

| Control Domain | Controls | Automated | Manual Only |
|---------------|----------|-----------|-------------|
| **A.5 Organizational** (37 controls) | A.5.1, A.5.2, A.5.9–A.5.15, A.5.17–A.5.22, A.5.24–A.5.28 | 20 | 17 |
| **A.6 People** (8 controls) | A.6.3 | 1 | 7 |
| **A.7 Physical** (14 controls) | — | 0 | 14 |
| **A.8 Technological** (34 controls) | A.8.2, A.8.5, A.8.7–A.8.10, A.8.13–A.8.17, A.8.20–A.8.21, A.8.24–A.8.25, A.8.32 | 18 | 16 |
| **Total** | **93 controls** | **39 (42%)** | **54 (58%)** |

> The 54 manual controls are primarily physical security (A.7), HR processes (A.6), legal/contractual (parts of A.5), and controls that inherently require human judgment. 42% automation is a strong coverage for ISO 27001 — most organizations achieve 20–30%.

---

## Shared Pre-requisites (All Automations)

| Requirement | Details |
|-------------|---------|
| Glue Layer Docker image rebuild | Each new script must be added to the Docker image. Update `glue/Dockerfile` to include new `.py` files. |
| Secrets Manager updates | New API keys (GitHub, training platform, HIBP, vendor scoring) must be added to the Secrets Manager secret and `init-secrets.sh`. |
| CISO Assistant API capacity | More frequent API calls from additional automations. May need to adjust rate limiting in `ciso_client.py` (currently 100ms delay). Monitor CISO backend CPU/memory. |
| Instance sizing | Additional automations increase memory usage during peak (multiple scripts running concurrently). Monitor and consider upgrading to t3.xlarge (16 GB) if needed. Current t3.large (8 GB) should suffice for Phases 5–6. |
| Cron schedule coordination | All cron entries must be staggered to avoid concurrent execution. See the scheduling section in each automation for proposed times. |
| Testing | Each automation should have unit tests in `tests/` covering: mapping logic, deduplication, error handling. Integration tests should verify end-to-end flow against a test CISO Assistant instance. |
