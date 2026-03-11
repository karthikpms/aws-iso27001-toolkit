terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# ============================================================
# Random passwords for secrets
# ============================================================

resource "random_password" "ciso_admin" {
  length  = 24
  special = true
}

resource "random_password" "db" {
  length  = 24
  special = false
}

resource "random_password" "wazuh_api" {
  length  = 24
  special = false
}

resource "random_password" "wazuh_indexer" {
  length  = 24
  special = false
}

# ============================================================
# Security Group
# ============================================================

resource "aws_security_group" "toolkit" {
  name_prefix = "${var.project_name}-"
  description = "ISO 27001 toolkit instance security group"

  # SSH
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  # CISO Assistant dashboard
  ingress {
    description = "CISO Assistant UI"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = var.allowed_dashboard_cidrs
  }

  # Wazuh Dashboard
  ingress {
    description = "Wazuh Dashboard"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = var.allowed_dashboard_cidrs
  }

  # Wazuh Agent communication (private ranges only)
  ingress {
    description = "Wazuh agent communication"
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12"]
  }

  # Allow all outbound (Prowler needs AWS API access)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${var.project_name}-sg" })
}

# ============================================================
# IAM Role + Instance Profile
# ============================================================

data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "toolkit" {
  name               = "${var.project_name}-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
  tags               = local.common_tags
}

# AWS managed policies for Prowler scanning
resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.toolkit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.toolkit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.toolkit.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Custom policy: Secrets Manager + SNS + Prowler extras
data "aws_iam_policy_document" "toolkit_custom" {
  statement {
    sid    = "SecretsManagerRead"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = [aws_secretsmanager_secret.toolkit_secrets.arn]
  }

  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid    = "S3BackupAccess"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.backups.arn,
      "${aws_s3_bucket.backups.arn}/*"
    ]
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams"
    ]
    resources = ["arn:aws:logs:${var.aws_region}:*:log-group:iso27001-toolkit:*"]
  }

  statement {
    sid    = "CloudWatchMetrics"
    effect = "Allow"
    actions = [
      "cloudwatch:PutMetricData"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ISO27001Toolkit"]
    }
  }

  statement {
    sid    = "ProwlerAdditions"
    effect = "Allow"
    actions = [
      "account:Get*",
      "appstream:Describe*",
      "codeartifact:List*",
      "codebuild:BatchGet*",
      "ds:Describe*",
      "ds:Get*",
      "ds:List*",
      "elasticfilesystem:DescribeBackupPolicy",
      "glue:GetConnections",
      "glue:GetSecurityConfiguration*",
      "glue:SearchTables",
      "lambda:GetFunction",
      "macie2:GetMacieSession",
      "s3:GetAccountPublicAccessBlock",
      "shield:DescribeProtection",
      "shield:GetSubscriptionState",
      "ssm-incidents:List*",
      "support:Describe*",
      "tag:GetResources",
      "tag:GetTagKeys",
      "tag:GetTagValues",
      "wellarchitected:List*"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AssetInventoryConfig"
    effect = "Allow"
    actions = [
      "config:ListDiscoveredResources",
      "config:GetResourceConfigHistory"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "InspectorReadOnly"
    effect = "Allow"
    actions = [
      "inspector2:ListFindings",
      "inspector2:DescribeFindings",
      "inspector2:ListCoverage",
      "inspector2:BatchGetAccountStatus"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "IncidentDetection"
    effect = "Allow"
    actions = [
      "guardduty:ListFindings",
      "guardduty:GetFindings",
      "guardduty:ListDetectors",
      "guardduty:GetDetector",
      "cloudtrail:LookupEvents",
      "securityhub:GetFindings",
      "securityhub:BatchGetFindings"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "LogCompletenessAudit"
    effect = "Allow"
    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "ec2:DescribeVpcs",
      "ec2:DescribeFlowLogs",
      "s3:GetBucketLogging",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeLoadBalancerAttributes",
      "rds:DescribeDBInstances",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "lambda:ListFunctions",
      "config:DescribeConfigurationRecorderStatus"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "NetworkSecurityMonitoring"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkAcls",
      "ec2:DescribeVpcPeeringConnections",
      "ec2:DescribeRouteTables",
      "athena:StartQueryExecution",
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StopQueryExecution"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "NetworkSecurityAutoRemediation"
    effect = "Allow"
    actions = [
      "ec2:RevokeSecurityGroupIngress"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }

  statement {
    sid    = "AthenaFlowLogAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:PutObject"
    ]
    resources = [
      aws_s3_bucket.athena_results.arn,
      "${aws_s3_bucket.athena_results.arn}/*",
      "arn:aws:s3:::${var.project_name}-vpc-flow-logs",
      "arn:aws:s3:::${var.project_name}-vpc-flow-logs/*"
    ]
  }

  statement {
    sid    = "EncryptionComplianceAudit"
    effect = "Allow"
    actions = [
      "ec2:DescribeVolumes",
      "ec2:GetEbsEncryptionByDefault",
      "rds:DescribeDBInstances",
      "s3:ListAllMyBuckets",
      "s3:GetEncryptionConfiguration",
      "dynamodb:ListTables",
      "dynamodb:DescribeTable",
      "elasticfilesystem:DescribeFileSystems",
      "sqs:ListQueues",
      "sqs:GetQueueAttributes",
      "sns:ListTopics",
      "sns:GetTopicAttributes",
      "cloudfront:ListDistributions",
      "elasticloadbalancing:DescribeListeners",
      "apigateway:GET",
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
      "kms:GetKeyPolicy"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "BackupVerificationRead"
    effect = "Allow"
    actions = [
      "rds:DescribeDBSnapshots",
      "rds:ListTagsForResource",
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "s3:GetBucketVersioning"
    ]
    resources = ["*"]
  }

  statement {
    sid    = "BackupRestoreTestRDS"
    effect = "Allow"
    actions = [
      "rds:RestoreDBInstanceFromDBSnapshot",
      "rds:DeleteDBInstance",
      "rds:AddTagsToResource"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "rds:db-tag/Purpose"
      values   = ["iso27001-restore-test"]
    }
  }

  statement {
    sid    = "BackupRestoreTestRDSRestore"
    effect = "Allow"
    actions = [
      "rds:RestoreDBInstanceFromDBSnapshot"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/Purpose"
      values   = ["iso27001-restore-test"]
    }
  }

  statement {
    sid    = "BackupRestoreTestEBS"
    effect = "Allow"
    actions = [
      "ec2:CreateVolume",
      "ec2:DeleteVolume",
      "ec2:CreateTags"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/Purpose"
      values   = ["iso27001-restore-test"]
    }
  }

  statement {
    sid    = "BackupRestoreTestEBSCleanup"
    effect = "Allow"
    actions = [
      "ec2:DeleteVolume"
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "ec2:ResourceTag/Purpose"
      values   = ["iso27001-restore-test"]
    }
  }
}

resource "aws_iam_policy" "toolkit_custom" {
  name   = "${var.project_name}-custom-policy"
  policy = data.aws_iam_policy_document.toolkit_custom.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "toolkit_custom" {
  role       = aws_iam_role.toolkit.name
  policy_arn = aws_iam_policy.toolkit_custom.arn
}

resource "aws_iam_instance_profile" "toolkit" {
  name = "${var.project_name}-profile"
  role = aws_iam_role.toolkit.name
  tags = local.common_tags
}

# ============================================================
# IAM Role for Local Prowler Scanning (assume via STS)
# ============================================================

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "local_scan_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "AWS"
      identifiers = length(var.local_scan_user_arns) > 0 ? var.local_scan_user_arns : [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      ]
    }
    condition {
      test     = "NumericLessThan"
      variable = "aws:MaxSessionDuration"
      values   = ["3600"]
    }
  }
}

resource "aws_iam_role" "local_scan" {
  name                 = "${var.project_name}-local-scan-role"
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.local_scan_assume_role.json
  tags                 = merge(local.common_tags, { Purpose = "local-prowler-scanning" })
}

# Same read-only scanning permissions as the EC2 role
resource "aws_iam_role_policy_attachment" "local_scan_security_audit" {
  role       = aws_iam_role.local_scan.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "local_scan_view_only" {
  role       = aws_iam_role.local_scan.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Prowler additional permissions (read-only, no SNS/S3/Secrets access)
data "aws_iam_policy_document" "local_scan_prowler" {
  statement {
    sid    = "ProwlerAdditions"
    effect = "Allow"
    actions = [
      "account:Get*",
      "appstream:Describe*",
      "codeartifact:List*",
      "codebuild:BatchGet*",
      "ds:Describe*",
      "ds:Get*",
      "ds:List*",
      "elasticfilesystem:DescribeBackupPolicy",
      "glue:GetConnections",
      "glue:GetSecurityConfiguration*",
      "glue:SearchTables",
      "lambda:GetFunction",
      "macie2:GetMacieSession",
      "s3:GetAccountPublicAccessBlock",
      "shield:DescribeProtection",
      "shield:GetSubscriptionState",
      "ssm-incidents:List*",
      "support:Describe*",
      "tag:GetResources",
      "tag:GetTagKeys",
      "tag:GetTagValues",
      "wellarchitected:List*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "local_scan_prowler" {
  name   = "${var.project_name}-local-scan-prowler"
  policy = data.aws_iam_policy_document.local_scan_prowler.json
  tags   = local.common_tags
}

resource "aws_iam_role_policy_attachment" "local_scan_prowler" {
  role       = aws_iam_role.local_scan.name
  policy_arn = aws_iam_policy.local_scan_prowler.arn
}

# ============================================================
# Secrets Manager
# ============================================================

resource "aws_secretsmanager_secret" "toolkit_secrets" {
  name        = "${var.project_name}/secrets"
  description = "Secrets for ISO 27001 compliance toolkit"
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret_version" "toolkit_secrets" {
  secret_id = aws_secretsmanager_secret.toolkit_secrets.id
  secret_string = jsonencode({
    ciso_admin_email       = "admin@pyramidions.com"
    ciso_admin_password    = random_password.ciso_admin.result
    ciso_api_token         = ""
    wazuh_api_password     = random_password.wazuh_api.result
    wazuh_indexer_password = random_password.wazuh_indexer.result
    db_password            = random_password.db.result
    sns_topic_arn          = aws_sns_topic.alerts.arn
  })
}

# ============================================================
# EC2 Instance
# ============================================================

resource "aws_instance" "toolkit" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name
  iam_instance_profile   = aws_iam_instance_profile.toolkit.name
  vpc_security_group_ids = [aws_security_group.toolkit.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    aws_region  = var.aws_region
    secret_id   = aws_secretsmanager_secret.toolkit_secrets.id
    device_name = "/dev/xvdf"
  }))

  tags = merge(local.common_tags, { Name = var.project_name })

  lifecycle {
    ignore_changes = [ami]
  }
}

# ============================================================
# EBS Data Volume
# ============================================================

resource "aws_ebs_volume" "data" {
  availability_zone = aws_instance.toolkit.availability_zone
  size              = var.data_volume_size
  type              = "gp3"
  encrypted         = true
  tags              = merge(local.common_tags, { Name = "${var.project_name}-data" })
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.toolkit.id
}

# ============================================================
# SNS Topic for Alerting
# ============================================================

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
  tags = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_emails != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_emails
}

# ============================================================
# DLM Lifecycle Policy — Daily EBS Snapshots
# ============================================================

resource "aws_iam_role" "dlm" {
  name = "${var.project_name}-dlm-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "dlm.amazonaws.com" }
    }]
  })
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "dlm" {
  role       = aws_iam_role.dlm.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

resource "aws_dlm_lifecycle_policy" "daily_snapshots" {
  description        = "Daily snapshots of toolkit data volume"
  execution_role_arn = aws_iam_role.dlm.arn
  state              = "ENABLED"
  tags               = local.common_tags

  policy_details {
    resource_types = ["VOLUME"]

    target_tags = {
      Name = "${var.project_name}-data"
    }

    schedule {
      name = "Daily snapshot"
      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["03:00"]
      }
      retain_rule {
        count = 7
      }
      tags_to_add = {
        SnapshotCreator = "DLM"
      }
    }
  }
}

# ============================================================
# S3 Bucket for CISO Assistant Backups
# ============================================================

resource "aws_s3_bucket" "backups" {
  bucket = "${var.project_name}-backups"
  tags   = local.common_tags
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    id     = "glacier-transition"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }
  }
}

# ============================================================
# AWS Inspector v2 — Vulnerability Scanning
# ============================================================

resource "aws_inspector2_enabler" "this" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}

# ============================================================
# CloudWatch Alarms
# ============================================================

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.project_name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "CPU utilization > 80% for 10 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    InstanceId = aws_instance.toolkit.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "${var.project_name}-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "mem_used_percent"
  namespace           = "ISO27001Toolkit"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "Memory usage > 85% for 10 minutes"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "disk_high" {
  alarm_name          = "${var.project_name}-disk-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "used_percent"
  namespace           = "ISO27001Toolkit"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Disk usage > 80%"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    path = "/data"
  }

  tags = local.common_tags
}

# ============================================================
# CloudWatch Log Group
# ============================================================

resource "aws_cloudwatch_log_group" "toolkit" {
  name              = "iso27001-toolkit"
  retention_in_days = 90
  tags              = local.common_tags
}

# ============================================================
# EventBridge Rules — Network Security Monitoring (Automation 9)
# ============================================================

resource "aws_cloudwatch_event_rule" "network_security_changes" {
  name        = "${var.project_name}-network-security-changes"
  description = "Detect security group, NACL, VPC peering, and route table changes for ISO 27001 A.8.20"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateNetworkAclEntry",
        "ReplaceNetworkAclEntry",
        "DeleteNetworkAclEntry",
        "CreateVpcPeeringConnection",
        "CreateRoute",
        "ReplaceRoute",
        "DeleteRoute"
      ]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "network_security_sns" {
  rule      = aws_cloudwatch_event_rule.network_security_changes.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_sns_topic_policy" "allow_eventbridge" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_cloudwatch_event_rule.network_security_changes.arn
          }
        }
      }
    ]
  })
}

# ============================================================
# S3 Bucket for Athena Query Results
# ============================================================

resource "aws_s3_bucket" "athena_results" {
  bucket = "${var.project_name}-athena-results"
  tags   = local.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "cleanup-old-results"
    status = "Enabled"

    expiration {
      days = 30
    }
  }
}

# ============================================================
# Athena Workgroup for VPC Flow Log Analysis
# ============================================================

resource "aws_athena_workgroup" "toolkit" {
  name = "iso27001-toolkit"

  configuration {
    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
      }
    }

    enforce_workgroup_configuration = true
  }

  tags = local.common_tags
}

resource "aws_athena_database" "vpc_flow_logs" {
  name   = "iso27001_vpc_flow_logs"
  bucket = aws_s3_bucket.athena_results.id
}
