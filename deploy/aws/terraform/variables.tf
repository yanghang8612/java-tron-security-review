variable "aws_region" {
  description = "AWS region for the scheduled scanner."
  type        = string
  default     = "us-east-2"
}

variable "project_name" {
  description = "Lowercase name used for AWS resources."
  type        = string
  default     = "java-tron-security-review"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.project_name))
    error_message = "project_name must be 3-41 lowercase letters, digits, or hyphens."
  }
}

variable "target_repository_url" {
  description = "Authorized Git repository cloned for the scan."
  type        = string
  default     = "https://github.com/tronprotocol/java-tron.git"
}

variable "target_ref" {
  description = "Branch, tag, or commit fetched on every scheduled run."
  type        = string
  default     = "develop"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$", var.target_ref))
    error_message = "target_ref contains characters outside the supported Git ref/SHA set."
  }
}

variable "knowledge_base_repository_url" {
  description = "Optional java-tron knowledge-base repository; use an empty string to disable."
  type        = string
  default     = ""
}

variable "knowledge_base_ref" {
  description = "Knowledge-base branch, tag, or commit. Pin a reviewed commit in production."
  type        = string
  default     = "master"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$", var.knowledge_base_ref))
    error_message = "knowledge_base_ref contains characters outside the supported Git ref/SHA set."
  }
}

variable "schedule_expression" {
  description = "EventBridge Scheduler cron/rate expression."
  type        = string
  default     = "cron(17 2 * * ? *)"
}

variable "schedule_timezone" {
  description = "IANA timezone for the daily schedule."
  type        = string
  default     = "Asia/Shanghai"
}

variable "schedule_enabled" {
  description = "Enable only after an immutable scanner image and credentials are ready."
  type        = bool
  default     = false
}

variable "scanner_image_tag" {
  description = "ECR image tag. Use the reviewed security-system Git commit SHA."
  type        = string
  default     = "bootstrap"

  validation {
    condition     = can(regex("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$", var.scanner_image_tag))
    error_message = "scanner_image_tag must be a valid ECR image tag."
  }
}

variable "scan_provider" {
  description = "Inference provider used by the scheduled scanner."
  type        = string
  default     = "openai"

  validation {
    condition     = contains(["openai", "amazon-bedrock"], var.scan_provider)
    error_message = "scan_provider must be openai or amazon-bedrock."
  }
}

variable "scan_model_override" {
  description = "Explicit model for provider overrides; required for amazon-bedrock."
  type        = string
  default     = ""
}

variable "bedrock_model_arns" {
  description = "Foundation/inference-profile ARNs the CodeBuild role may invoke."
  type        = list(string)
  default     = []
}

variable "artifact_retention_days" {
  description = "Days before encrypted result archives expire."
  type        = number
  default     = 90

  validation {
    condition     = var.artifact_retention_days >= 7
    error_message = "artifact_retention_days must be at least 7."
  }
}

variable "log_retention_days" {
  description = "CloudWatch log retention."
  type        = number
  default     = 30
}

variable "codebuild_compute_type" {
  description = "CodeBuild EC2 compute size for TVM analysis."
  type        = string
  default     = "BUILD_GENERAL1_LARGE"
}

variable "codebuild_timeout_minutes" {
  description = "Hard timeout for a daily scan."
  type        = number
  default     = 180
}

variable "vpc_id" {
  description = "Optional VPC for CodeBuild. Requires subnet and security-group IDs plus HTTPS egress."
  type        = string
  default     = null
}

variable "subnet_ids" {
  description = "Private subnet IDs used when vpc_id is set."
  type        = list(string)
  default     = []
}

variable "security_group_ids" {
  description = "Security groups used when vpc_id is set."
  type        = list(string)
  default     = []
}

variable "alert_email" {
  description = "Optional email subscribed to failed/partial CodeBuild notifications."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to supported resources."
  type        = map(string)
  default = {
    Application = "java-tron-security-review"
    ManagedBy   = "Terraform"
    DataClass   = "confidential-security-findings"
  }
}
