variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "ap-south-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.large"
}

variable "ami_id" {
  description = "AMI ID for the EC2 instance (Amazon Linux 2023 or Ubuntu 22.04)"
  type        = string
  # No default — must be set per-region
}

variable "key_pair_name" {
  description = "Name of existing EC2 key pair for SSH access"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed to SSH into the instance"
  type        = list(string)
  default     = []
}

variable "allowed_dashboard_cidrs" {
  description = "CIDR blocks allowed to access CISO Assistant and Wazuh dashboards"
  type        = list(string)
  default     = []
}

variable "data_volume_size" {
  description = "Size of the EBS data volume in GB"
  type        = number
  default     = 50
}

variable "alert_emails" {
  description = "Comma-separated email addresses for SNS alerts"
  type        = string
  default     = "security@pyramidions.com"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "iso27001-toolkit"
}

variable "environment" {
  description = "Environment tag (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "local_scan_user_arns" {
  description = "IAM user/role ARNs allowed to assume the local Prowler scan role (e.g. your IAM user)"
  type        = list(string)
  default     = []
}
