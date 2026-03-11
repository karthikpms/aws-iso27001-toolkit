output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.toolkit.id
}

output "instance_public_ip" {
  description = "Public IP of the toolkit instance"
  value       = aws_instance.toolkit.public_ip
}

output "ciso_assistant_url" {
  description = "URL for CISO Assistant dashboard"
  value       = "http://${aws_instance.toolkit.public_ip}:8443"
}

output "wazuh_dashboard_url" {
  description = "URL for Wazuh dashboard"
  value       = "https://${aws_instance.toolkit.public_ip}:5601"
}

output "sns_topic_arn" {
  description = "ARN of the SNS alerts topic"
  value       = aws_sns_topic.alerts.arn
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret"
  value       = aws_secretsmanager_secret.toolkit_secrets.arn
}

output "backup_s3_bucket" {
  description = "S3 bucket for CISO Assistant data exports"
  value       = aws_s3_bucket.backups.id
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for toolkit logs"
  value       = aws_cloudwatch_log_group.toolkit.name
}

output "local_scan_role_arn" {
  description = "IAM role ARN for local Prowler scanning (assume via STS)"
  value       = aws_iam_role.local_scan.arn
}

output "local_scan_command" {
  description = "Command to configure local AWS profile for scanning"
  value       = <<-EOT
    # Add to ~/.aws/config:
    [profile iso27001-scan]
    role_arn = ${aws_iam_role.local_scan.arn}
    source_profile = default
    region = ${var.aws_region}

    # Then run:
    export AWS_PROFILE=iso27001-scan
    ./glue/run_scan.sh delta
  EOT
}
