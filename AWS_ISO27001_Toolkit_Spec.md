# AWS ISO 27001 Infrastructure Readiness Toolkit

**Project Specification v3.0**
Integrating Prowler + CISO Assistant + Wazuh

Prepared by: Pyramidions
Date: March 10, 2026

---

## 1. Executive Summary

This document specifies an internal toolkit that scans Pyramidions' AWS infrastructure against ISO 27001 (Annex A) and SOC 2 controls, tracks compliance posture over time, and generates actionable remediation recommendations.

**Primary Goal:** Continuous infrastructure-level compliance monitoring of our own AWS account, running on a schedule, producing a clear picture of our ISO 27001 readiness from a technical controls perspective.

**Secondary Goal:** Use CISO Assistant as a centralized ISMS tracker for non-infrastructure ISO 27001 requirements — including policy management, vendor assessments, incident tracking, asset inventory, and HR-related controls. These are tracked manually within CISO Assistant rather than through automated scanning.

**Note:** The automated scanning (Prowler + Wazuh) covers technical Annex A controls verifiable through AWS APIs. The non-infrastructure controls require manual input but are managed in the same CISO Assistant instance for a single-pane-of-glass view.

---

## 2. System Architecture

### 2.1 Component Overview

| Component | Role | Description |
|-----------|------|-------------|
| Prowler | Infrastructure security scanner | Scans our AWS resources against ISO 27001/SOC 2 controls. Outputs JSON findings on a configurable schedule. |
| CISO Assistant | GRC and compliance tracker | Tracks control implementation status, stores evidence, maps gaps to Annex A controls. |
| Wazuh | Endpoint monitoring & SIEM | Host intrusion detection, file integrity monitoring, centralized logging for our hosts and containers. |
| Glue Layer | Integration pipeline | Transforms Prowler/Wazuh outputs and pushes findings into CISO Assistant via API. Handles deduplication and delta tracking. |

### 2.2 Data Flow

- Prowler runs on schedule (daily/weekly) against our AWS account using an IAM role with read-only permissions.
- Prowler outputs findings as JSON, each tagged with the AWS service, resource ARN, ISO 27001 control mapping, and severity.
- The Glue Layer picks up new findings, deduplicates against previous runs, computes deltas, and pushes them to CISO Assistant via its API.
- CISO Assistant stores findings as evidence against the relevant Annex A controls and updates the compliance dashboard.
- Wazuh forwards host-level alerts to the Glue Layer, which maps them to the appropriate controls and pushes to CISO Assistant.
- Reports are generated on demand or on schedule from CISO Assistant's API.

### 2.3 Deployment Architecture

The toolkit supports two deployment modes: **Local** (for development and testing) and **AWS** (for persistent monitoring).

#### Option A: Local Machine (Development / Testing)

All components run on your local machine via Docker Compose. Use this for:
- Initial setup and testing before deploying to AWS
- Running one-off scans and reviewing results
- Developing and debugging the Glue Layer

**Requirements:**
- Docker Desktop (macOS/Windows) or Docker Engine (Linux)
- Minimum 8 GB RAM allocated to Docker (16 GB system RAM recommended)
- 20 GB free disk space
- AWS CLI configured with credentials for our account

**How it works:**
- Same `docker-compose.yml` as production.
- Prowler uses your local `~/.aws/credentials` or environment variables to authenticate.
- Data is persisted in Docker volumes on your local disk.
- Access CISO Assistant dashboard at `http://localhost:8443` and Wazuh dashboard at `https://localhost:5601`.
- Scans are triggered manually.

#### Option B: AWS (Persistent Monitoring)

All components run on a single EC2 t3.large instance (2 vCPUs, 8GB RAM) using Docker Compose in our AWS account.

- **Host:** Single t3.large EC2 instance running Docker Compose with all services.
- **Prowler:** Runs as a scheduled container via cron. Spins up, scans, writes output to a shared volume, and exits.
- **CISO Assistant:** Always-running container. Data persisted on a dedicated EBS volume.
- **Wazuh:** Always-running container (manager, indexer, dashboard). Data persisted on a dedicated EBS volume. Wazuh agents installed on our hosts.
- **Glue Layer:** Python scripts triggered by cron after Prowler completes, or by Wazuh webhook alerts.
- **Storage:** Separate EBS volume mounted for persistent data (Wazuh indexes, CISO Assistant database, Prowler scan history).

**Approximate memory allocation (t3.large — 8 GB):**

| Service | RAM |
|---------|-----|
| Wazuh (manager + indexer + dashboard) | ~3 GB |
| CISO Assistant | ~1 GB |
| Prowler (during scan windows only) | ~512 MB |
| Glue Layer (during processing) | ~256 MB |
| OS + Docker overhead | ~1 GB |
| **Headroom** | **~2 GB** |

### 2.4 Authentication

Prowler runs in the same AWS account it scans. No cross-account role is needed. It authenticates using:

- **Local:** Your AWS CLI credentials (`~/.aws/credentials` or environment variables).
- **AWS deployment:** An IAM instance profile attached to the EC2 instance with the `SecurityAudit` managed policy plus additional read permissions for services not covered by SecurityAudit. No write permissions.

---

## 3. Prowler Scan Coverage

Prowler will scan the following AWS services, mapped to ISO 27001:2022 Annex A controls:

| Service | ISO 27001 Controls | Key Checks |
|---------|-------------------|------------|
| IAM | A.5.15 - Access Control, A.5.17 - Authentication | MFA enforcement, password policy, unused credentials, overly permissive policies, root account usage |
| S3 | A.8.10 - Information Deletion, A.8.24 - Cryptography | Public access blocks, encryption at rest, bucket policies, versioning, access logging |
| EC2/VPC | A.8.20 - Network Security, A.8.21 - Web Filtering | Security group rules, open ports, VPC flow logs, default VPC usage, public IP exposure |
| CloudTrail | A.8.15 - Logging, A.8.16 - Monitoring | Trail enabled in all regions, log file validation, S3 bucket access logging, CloudWatch integration |
| RDS | A.8.24 - Cryptography, A.8.13 - Backup | Encryption at rest, public accessibility, automated backups, multi-AZ deployment |
| KMS | A.8.24 - Cryptography | Key rotation enabled, key policies, CMK usage vs AWS-managed keys |
| Lambda | A.8.9 - Configuration Management | Runtime versions, environment variable encryption, VPC attachment, resource policies |
| ECS/EKS | A.8.9 - Configuration Management | Task role permissions, image scanning, secrets management, network policies |
| GuardDuty | A.8.16 - Monitoring Activities | Enabled status, finding export configuration, threat detection coverage |
| Config | A.8.9 - Configuration Management | Recorder status, conformance packs, rule compliance tracking |

### 3.1 Scan Scheduling

- **Full scan:** Weekly (recommended Sunday 02:00 UTC). Covers all services and all regions.
- **Delta scan:** Daily. Covers high-priority services only (IAM, S3, CloudTrail, Security Groups).
- **On-demand scan:** Triggered manually via CLI for ad-hoc assessments.
- **Retention:** Scan results stored with 12-month retention for audit trail.

---

## 4. CISO Assistant Integration

### 4.1 Baseline Configuration

The deployment starts with a pre-loaded ISO 27001:2022 framework containing all 93 Annex A controls. The Glue Layer maps Prowler finding categories to specific controls using a maintained mapping file (JSON). This mapping file is the single source of truth for which Prowler checks correspond to which Annex A controls.

### 4.2 Finding Import Pipeline

The Glue Layer performs the following steps when processing Prowler output:

1. Parse Prowler JSON output and extract findings with FAIL status.
2. For each finding, look up the corresponding Annex A control(s) from the mapping file.
3. Check CISO Assistant for existing findings on the same resource. If found, update the timestamp and status. If new, create a new evidence entry.
4. For findings that previously existed but now PASS, mark them as remediated with the remediation date.
5. Generate a scan summary with counts of new findings, remediated findings, and unchanged findings.

### 4.3 Dashboard Requirements

CISO Assistant should be configured to display:

- Overall compliance score as a percentage of Annex A controls with no open findings.
- Trend chart showing compliance score over time (minimum 6 months of history).
- Breakdown by control domain (Organizational, People, Physical, Technological).
- Top 10 most critical open findings sorted by severity and age.
- Per-service compliance summary (e.g., IAM: 85%, S3: 92%, EC2: 78%).

---

## 5. Non-Infrastructure ISMS Tracking via CISO Assistant

CISO Assistant serves double duty: it receives automated findings from Prowler and Wazuh, and it also acts as the central tracker for all non-infrastructure ISO 27001 requirements. The following areas are managed manually within CISO Assistant.

### 5.1 Policy Management (A.5.1 - Policies for Information Security)

- Create a control entry for each required policy (Information Security Policy, Acceptable Use Policy, Access Control Policy, Incident Response Policy, etc.).
- Upload the policy document as evidence. Set a review date (typically annual).
- CISO Assistant tracks policy review status and flags overdue reviews on the dashboard.

### 5.2 Vendor / Third-Party Risk (A.5.19 - A.5.22)

- Create a control framework for vendor assessments within CISO Assistant.
- For each vendor, create an assessment record with: vendor name, services provided, data access level, last assessment date, risk rating.
- Attach vendor questionnaire responses and due diligence documents as evidence.
- Set review cadence (annual for critical vendors, biennial for low-risk).

### 5.3 HR & People Controls (A.6.1 - A.6.8)

- Track security awareness training completion per employee. Upload training records or completion certificates as evidence against A.6.3.
- Track NDA and confidentiality agreement status for all staff (A.6.6).
- Document joiner/mover/leaver procedures and attach evidence of process execution (A.6.1, A.6.5).
- Track background verification records where applicable (A.6.1).

### 5.4 Incident Management (A.5.24 - A.5.28)

- Log security incidents directly in CISO Assistant with: incident description, date, severity, affected assets, response actions, root cause, and lessons learned.
- Attach incident reports and post-mortem documents as evidence.
- Track incident response metrics (time to detect, time to respond, time to resolve).

### 5.5 Asset Management (A.5.9 - A.5.14)

- Maintain an asset inventory within CISO Assistant, covering: hardware (laptops, servers, network equipment), software (applications, licenses), data assets (databases, file stores, backups), and cloud resources (auto-populated from Prowler scans).
- Assign ownership for each asset. Track asset classification and handling requirements.

### 5.6 Business Continuity (A.5.29 - A.5.30)

- Upload Business Continuity Plan (BCP) and Disaster Recovery Plan (DRP) documents as evidence.
- Track BCP/DRP test execution: date, scope, results, and follow-up actions.
- Set review cadence for plans (typically annual or after significant changes).

---

## 6. Wazuh Integration

Wazuh provides host-level intrusion detection, log management, and continuous compliance monitoring for our infrastructure.

### 6.1 What Wazuh Covers

- **File Integrity Monitoring (FIM):** Detects unauthorized changes to critical system files. Maps to A.8.9 (Configuration Management).
- **Rootkit Detection:** Scans for known rootkits and suspicious kernel modules. Maps to A.8.7 (Protection Against Malware).
- **Log Collection and Analysis:** Centralizes system and application logs. Maps to A.8.15 (Logging).
- **Vulnerability Detection:** Identifies known CVEs on monitored hosts. Maps to A.8.8 (Technical Vulnerability Management).
- **Security Configuration Assessment (SCA):** Checks host configurations against CIS benchmarks. Maps to A.8.9.

### 6.2 Alert Forwarding

Wazuh alerts above a configurable severity threshold (default: level 7+) are forwarded to the Glue Layer via webhook. The Glue Layer maps them to the appropriate Annex A controls and creates evidence entries in CISO Assistant, following the same deduplication logic as Prowler findings.

### 6.3 Wazuh Agent Deployment

Wazuh agents must be installed on every host that needs monitoring. Choose the method that fits our infrastructure.

#### Method 1: AWS Systems Manager (SSM) — Recommended for EC2

Best if our EC2 instances already have the SSM agent installed (Amazon Linux 2/2023 and recent Ubuntu AMIs include it by default).

**Setup:**
1. Ensure target instances have an IAM instance profile with `AmazonSSMManagedInstanceCore` policy.
2. Store the Wazuh manager IP and enrollment key in SSM Parameter Store:
   ```
   aws ssm put-parameter --name "/wazuh/manager-ip" --value "<toolkit-instance-ip>" --type String
   aws ssm put-parameter --name "/wazuh/enrollment-key" --value "<key>" --type SecureString
   ```
3. Create an SSM Document (`wazuh-agent-install`) that:
   - Downloads the Wazuh agent package for the target OS
   - Configures `/var/ossec/etc/ossec.conf` with the manager IP
   - Registers the agent using `agent-auth` with the enrollment key
   - Starts the `wazuh-agent` service
4. Run the document against target instances using SSM Run Command or attach it to an SSM State Manager association for automatic deployment.

**For Auto Scaling Groups (ASG):**
- Add the SSM Document execution to the ASG Launch Template's user data script, so every new instance registers automatically on boot.
- Configure Wazuh manager with `auto_enrollment: yes` in `ossec.conf` so agents can self-register.
- Use the Wazuh API to clean up stale agents (disconnected > 24 hours) via a daily cron job in the Glue Layer.

#### Method 2: Manual Installation — Small Environments

For fewer than 10 hosts, use a simple shell script:

```bash
#!/bin/bash
# wazuh-agent-install.sh — run on target host
MANAGER_IP="<toolkit-instance-ip>"
curl -s https://packages.wazuh.com/4.x/apt/KEY.GPG | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install -y wazuh-agent
sed -i "s/MANAGER_IP/$MANAGER_IP/" /var/ossec/etc/ossec.conf
/var/ossec/bin/agent-auth -m $MANAGER_IP
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

#### Container Environments (ECS/EKS)

- **ECS:** Deploy the Wazuh agent as a sidecar container in each ECS task definition. The sidecar shares the task's network namespace and forwards logs from the application container.
- **EKS:** Deploy Wazuh as a DaemonSet so one agent pod runs on every node. The agent mounts the host filesystem for file integrity monitoring and reads container logs from `/var/log/containers/`.

---

## 7. Alerting and Notifications

### 7.1 Alert Channels

The toolkit sends alerts through multiple channels based on severity:

| Severity | Channel | Response Time |
|----------|---------|---------------|
| Critical (Prowler CRITICAL / Wazuh Level 12+) | Slack + Email | Immediate |
| High (Prowler HIGH / Wazuh Level 10-11) | Slack + Email | Within 4 hours |
| Medium (Prowler MEDIUM / Wazuh Level 7-9) | Email digest | Daily summary |
| Low/Informational | Dashboard only | Next review cycle |

### 7.2 Implementation

Alerting is handled by the Glue Layer using a pluggable notification system:

**SNS (Email):**
- The Terraform module creates an SNS topic: `iso27001-alerts`
- Subscribers are configured in `.env`: `ALERT_EMAILS=security@pyramidions.com`
- Critical findings trigger immediate SNS publish with: finding title, affected resource ARN, Annex A control, and remediation link.

**Slack:**
- Configure an incoming webhook URL in `.env`: `SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...`
- The Glue Layer posts formatted messages with severity color coding (red=critical, orange=high, yellow=medium).
- Messages include a direct link to the finding in CISO Assistant.

### 7.3 Alert Rules

The Glue Layer applies the following rules before sending alerts:

- **Deduplication:** Do not re-alert on findings that were already reported in the previous scan and remain unresolved.
- **New findings only:** Alert when a finding appears for the first time or when a previously remediated finding regresses.
- **Scan completion:** Send a summary notification after each scan completes (acts as a heartbeat to confirm the system is working).
- **Scan failure:** Alert immediately if Prowler or Wazuh fails to run on schedule.
- **Remediation celebration:** Send a positive notification when critical/high findings are remediated.

### 7.4 Configuration

All alerting is configured via environment variables:

```
ALERT_ENABLED=true
ALERT_EMAILS=security@pyramidions.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
ALERT_MIN_SEVERITY=medium
ALERT_DIGEST_HOUR=9
SCAN_FAILURE_ALERT_AFTER_MINUTES=120
```

---

## 8. Secrets Management

### 8.1 Overview

The toolkit handles several types of secrets that must never be hardcoded.

| Secret | Used By | Description |
|--------|---------|-------------|
| CISO Assistant admin password | CISO Assistant | Login for the GRC dashboard |
| CISO Assistant API token | Glue Layer | Authentication for pushing findings |
| Wazuh API credentials | Glue Layer | Authentication for Wazuh manager API |
| Wazuh agent enrollment key | Wazuh agents | Key for agents to register with manager |
| Slack webhook URL | Glue Layer | Alert delivery endpoint |
| Database credentials | CISO Assistant (PostgreSQL) | DB access for CISO Assistant backend |

### 8.2 AWS Deployment: Using AWS Secrets Manager

All secrets are stored in AWS Secrets Manager and injected at runtime.

**How it works:**

1. **Terraform creates the secrets** during initial deployment:
   ```hcl
   resource "aws_secretsmanager_secret" "toolkit_secrets" {
     name = "iso27001-toolkit/secrets"
   }

   resource "aws_secretsmanager_secret_version" "toolkit_secrets" {
     secret_id     = aws_secretsmanager_secret.toolkit_secrets.id
     secret_string = jsonencode({
       ciso_admin_password  = random_password.ciso_admin.result
       ciso_api_token       = ""  # populated after first boot
       wazuh_api_password   = random_password.wazuh_api.result
       wazuh_enrollment_key = random_password.wazuh_enrollment.result
       db_password          = random_password.db.result
       slack_webhook_url    = var.slack_webhook_url
     })
   }
   ```

2. **EC2 instance retrieves secrets on boot** using an IAM instance profile with `secretsmanager:GetSecretValue` permission. A startup script (`init-secrets.sh`) pulls the secret and writes the `.env` file to tmpfs (RAM disk — never touches persistent storage):
   ```bash
   #!/bin/bash
   SECRET=$(aws secretsmanager get-secret-value \
     --secret-id "iso27001-toolkit/secrets" \
     --query SecretString --output text)

   mkdir -p /run/toolkit
   echo "$SECRET" | python3 -c "
   import sys, json
   s = json.load(sys.stdin)
   for k, v in s.items():
       print(f'{k.upper()}={v}')
   " > /run/toolkit/.env

   cd /opt/toolkit && docker compose --env-file /run/toolkit/.env up -d
   ```

3. **Secret rotation:** Secrets Manager supports automatic rotation. API tokens are rotated manually on a quarterly cadence.

### 8.3 Local Development: Using .env

For local development:
- Copy `.env.example` to `.env` and fill in values.
- `.env` is in `.gitignore` — it must never be committed.

### 8.4 What Goes in `.env.example` (Committed to Git)

```
# Scan schedule
PROWLER_FULL_SCAN_CRON=0 2 * * 0
PROWLER_DELTA_SCAN_CRON=0 2 * * 1-6
AWS_REGION=ap-south-1

# Ports (local dev)
CISO_ASSISTANT_PORT=8443
WAZUH_DASHBOARD_PORT=5601

# Alerting
ALERT_ENABLED=true
ALERT_MIN_SEVERITY=medium
ALERT_DIGEST_HOUR=9

# Secrets — DO NOT fill these in .env.example
# In AWS: pulled from Secrets Manager automatically
# Locally: set in .env (gitignored)
CISO_ADMIN_PASSWORD=
CISO_API_TOKEN=
WAZUH_API_PASSWORD=
DB_PASSWORD=
SLACK_WEBHOOK_URL=
```

---

## 9. Deployment

### 9.1 Local Setup (Development)

1. Clone the repository: `git clone <repo-url> && cd iso27001-aws-toolkit`
2. Copy `.env.example` to `.env` and fill in your secrets.
3. Run `docker compose up -d`. All services start locally.
4. Ensure your AWS CLI is configured: `aws sts get-caller-identity` should show our account.
5. Trigger a manual scan: `docker compose run prowler`
6. Open CISO Assistant at `http://localhost:8443` and Wazuh dashboard at `https://localhost:5601`.

### 9.2 AWS Deployment (Persistent Monitoring)

1. Run `terraform apply` to provision the EC2 instance, EBS volume, security groups, IAM roles, Secrets Manager entries, and SNS topic.
2. Terraform outputs the instance IP. SSH in and verify Docker Compose services are running (the init script starts them automatically using secrets from Secrets Manager).
3. An initial Prowler scan runs automatically. Results populate CISO Assistant within 30 minutes.
4. Deploy Wazuh agents to our hosts using SSM or the manual script (see Section 6.3).
5. Add the Slack webhook URL to the Secrets Manager entry.
6. Access CISO Assistant dashboard via the instance IP (or configure a domain/VPN).

---

## 10. Repository Structure

```
iso27001-aws-toolkit/
├── docker-compose.yml          # All services: Prowler, CISO Assistant, Wazuh, Glue
├── .env.example                # Template for configuration
├── .gitignore                  # Excludes .env, secrets/, terraform state
├── terraform/
│   ├── main.tf                 # EC2, EBS, security groups, IAM, Secrets Manager, SNS
│   ├── variables.tf            # Configurable variables
│   └── outputs.tf              # Instance IP, dashboard URLs, SNS topic ARN
├── glue/
│   ├── prowler_mapper.py       # Transforms Prowler JSON to CISO Assistant format
│   ├── wazuh_mapper.py         # Transforms Wazuh alerts to CISO Assistant format
│   ├── ciso_client.py          # CISO Assistant API client
│   ├── alerter.py              # Notification dispatcher (SNS, Slack)
│   ├── run_scan.sh             # Cron script: triggers Prowler, then runs mapper
│   └── mappings/               # JSON mapping files (Prowler check → Annex A control)
├── wazuh/
│   └── wazuh-docker/           # Wazuh Docker config (ossec.conf overrides, rules)
├── scripts/
│   ├── init-secrets.sh         # Pulls secrets from Secrets Manager, generates .env
│   ├── backup.sh               # EBS snapshot + data export script
│   └── wazuh-agent-install.sh  # Manual agent installation script
├── docs/                       # Architecture diagrams
└── tests/                      # Unit tests for glue layer, integration tests
```

---

## 11. Implementation Milestones

| Phase | Timeline | Deliverables |
|-------|----------|-------------|
| Phase 1: Core Infrastructure | Week 1-2 | Terraform module, Docker Compose, Prowler scanning, secrets management |
| Phase 2: GRC Integration | Week 3-4 | CISO Assistant deployment, Glue Layer (Prowler mapper, CISO API client, dedup cache) |
| Phase 3: Monitoring | Week 5-6 | Wazuh deployment, agent installation on our hosts, alert forwarding to CISO Assistant |
| Phase 4: Alerting & Ops | Week 7-8 | SNS/Slack alerting, EBS backup automation, CloudWatch monitoring, health checks |

---

## 12. Technology Stack

- **Language:** Python 3.11+ (Glue Layer, mapper scripts, automation)
- **Compute:** Single EC2 t3.large instance (8 GB RAM)
- **Containerization:** Docker Compose orchestrating all services
- **Infrastructure as Code:** Terraform for provisioning EC2, EBS, security groups, and IAM roles
- **Storage:** Dedicated EBS volume for persistent data (Wazuh indexes, CISO Assistant DB, scan history)
- **Monitoring:** CloudWatch for instance-level alerts, SNS for scan completion notifications

## 13. Estimated Monthly Cost

| Item | Monthly Cost |
|------|-------------|
| EC2 t3.large (on-demand) | ~$60 |
| EBS volume (50GB gp3) | ~$4 |
| EBS snapshots (50GB, daily, 7 retained) | ~$5 |
| Secrets Manager (6 secrets) | ~$3 |
| SNS notifications | ~$1 |
| Data transfer (minimal) | ~$2-5 |
| **Total** | **~$75-80/month** |

All software components (Prowler, CISO Assistant, Wazuh) are open source with zero licensing costs. Costs can be reduced to ~$50/month with a 1-year Reserved Instance for t3.large. Local development mode has zero AWS cost.

---

## 14. Security Considerations

The toolkit itself must follow security best practices:

- Prowler runs with a read-only IAM role in the same account. No cross-account trust, no long-lived access keys.
- CISO Assistant is accessible only via VPN, SSH tunnel, or private subnet. Not exposed to the public internet.
- All data in transit uses TLS 1.2+. All data at rest is encrypted using AWS KMS.
- Scan results on the EBS volume are encrypted using EBS encryption with AWS KMS.
- Secrets are stored in AWS Secrets Manager and injected at runtime via `init-secrets.sh` into a tmpfs mount. No secrets are written to persistent disk or committed to Git. See Section 8 for full details.

---

## 15. Backup and Disaster Recovery

### 15.1 Automated EBS Snapshots

The Terraform module configures AWS Data Lifecycle Manager (DLM) to take daily snapshots of the data EBS volume:

- **Schedule:** Daily at 03:00 UTC (after the weekly full scan completes).
- **Retention:** 7 daily snapshots + 4 weekly snapshots (retained on Sundays).

### 15.2 CISO Assistant Database Export

In addition to EBS snapshots, the Glue Layer exports CISO Assistant data nightly:

- Calls the CISO Assistant API to export all frameworks, controls, findings, and evidence metadata as JSON.
- Uploads the export to an S3 bucket: `s3://pyramidions-iso27001-backups/ciso-assistant/YYYY-MM-DD.json.gz`
- S3 bucket has versioning enabled and a lifecycle rule to transition to Glacier after 90 days.

### 15.3 Recovery Procedure

**Scenario: Instance failure (EBS volume intact)**
1. Run `terraform apply` to launch a new instance.
2. Attach the existing EBS data volume.
3. Run `docker compose up -d`. Services resume with all data intact.
4. Recovery time: ~15 minutes.

**Scenario: EBS volume failure**
1. Create a new EBS volume from the most recent snapshot.
2. Run `terraform apply`, attach the restored volume.
3. Run `docker compose up -d`.
4. Recovery time: ~30 minutes. Data loss: up to 24 hours (last snapshot).

---

## 16. CISO Assistant API Assessment

### 16.1 API Capabilities

CISO Assistant (community edition) provides a Django REST Framework API with the following capabilities:

| Capability | Supported | Endpoint |
|-----------|-----------|----------|
| Authentication (token-based) | Yes | `POST /api/token/` (returns JWT) |
| List frameworks | Yes | `GET /api/frameworks/` |
| List/create compliance assessments | Yes | `GET/POST /api/compliance-assessments/` |
| List/update requirement assessments | Yes | `GET/PATCH /api/requirement-assessments/` |
| Create/list applied controls | Yes | `GET/POST /api/applied-controls/` |
| Upload evidence | Yes | `POST /api/evidences/` (multipart form) |
| List/filter findings | Yes | `GET /api/findings/?search=<query>` |
| Create findings | Yes | `POST /api/findings/` |
| Update finding status | Yes | `PATCH /api/findings/{id}/` |
| Risk assessments | Yes | `GET/POST /api/risk-assessments/` |
| Export (CSV/PDF) | Yes | Various export endpoints per model |
| Bulk import | Partial | CSV import via UI; API requires one-by-one creation |

### 16.2 API Limitations and Workarounds

1. **No native bulk import endpoint.** The API requires creating findings one at a time. The Glue Layer batches requests with concurrency control (5 parallel requests). A typical Prowler scan with ~200 findings imports in under 2 minutes.

2. **Deduplication must be handled client-side.** The Glue Layer maintains a local SQLite cache mapping `(resource_arn, check_id) → ciso_finding_id` to avoid querying the API for every finding on every scan.

3. **Evidence attachment is per-finding.** The Glue Layer attaches the raw Prowler JSON output as a single evidence file per scan, linked to a parent compliance assessment.

4. **Rate limiting.** The Glue Layer adds a 100ms delay between API calls to avoid degrading dashboard performance during imports.

### 16.3 Verdict: CISO Assistant Is the Right Choice

- **Best ISO 27001 support** among free tools — ships with the full ISO 27001:2022 framework including all 93 Annex A controls pre-mapped.
- **Active development** — 2,000+ GitHub stars, regular releases, responsive maintainers.
- **The API covers all critical operations** we need. The Glue Layer handles the gaps (bulk import, dedup) in application code.
- **Single Docker Compose deployment** — fits our architecture perfectly.
- **Dual use** — works for both automated findings (Prowler/Wazuh) and manual ISMS tracking (policies, vendor risk, HR controls).

**Alternatives considered and rejected:**

| Tool | Why Not |
|------|---------|
| **Eramba Community** | PHP-based, complex deployment, limited API, no native ISO 27001:2022 framework. |
| **OpenRMF** | Focused on STIG/NIST compliance, not ISO 27001. .NET-based, heavier deployment. |
| **Defect Dojo** | Vulnerability management tool, not GRC. No ISO 27001 framework, no compliance dashboards. |
| **Custom spreadsheet/Notion** | No API, no automation, no audit trail. |

---

## 17. Update and Maintenance Strategy

### 17.1 Component Updates

All components run as Docker containers with pinned image versions in `docker-compose.yml`:

```yaml
services:
  prowler:
    image: prowlercloud/prowler:4.x.x
  ciso-assistant:
    image: intuitem/ciso-assistant:x.x.x
  wazuh-manager:
    image: wazuh/wazuh-manager:4.x.x
```

**Update procedure:**
1. Check release notes for breaking changes.
2. Update the image tag in `docker-compose.yml`.
3. Test locally: `docker compose pull && docker compose up -d`.
4. Verify: run a Prowler scan, confirm findings import into CISO Assistant, check Wazuh dashboard.
5. Deploy to AWS: SSH in, pull new images, restart services.

**Update cadence:**
- **Prowler:** Monthly. Each update adds new checks.
- **CISO Assistant:** Quarterly. Test thoroughly — database migrations may be involved.
- **Wazuh:** Quarterly. Manager and agents should run the same minor version.

### 17.2 Monitoring the Toolkit Itself

- **CloudWatch Alarms:** CPU > 80% for 10 minutes, memory > 85%, disk > 80%. Alerts via SNS.
- **Scan heartbeat:** The Glue Layer sends a "scan completed" notification after each run. If no notification arrives within the expected window, a "scan failure" alert fires (see Section 7.3).
- **Docker health checks:** Each service in `docker-compose.yml` has a `healthcheck` configured. Docker restarts unhealthy containers automatically (`restart: unless-stopped`).
