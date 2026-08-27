data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  artifact_bucket_name = "${substr(var.project_name, 0, 30)}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  log_group_name       = "/aws/codebuild/${var.project_name}-daily-tvm"
  scanner_image        = "${aws_ecr_repository.scanner.repository_url}:${var.scanner_image_tag}"
  use_vpc              = var.vpc_id != null
  use_bedrock          = var.scan_provider == "amazon-bedrock"
}

check "bedrock_configuration" {
  assert {
    condition = !local.use_bedrock || (
      var.scan_model_override != "" && length(var.bedrock_model_arns) > 0
    )
    error_message = "amazon-bedrock requires scan_model_override and bedrock_model_arns."
  }
}

check "vpc_configuration" {
  assert {
    condition = !local.use_vpc || (
      length(var.subnet_ids) > 0 && length(var.security_group_ids) > 0
    )
    error_message = "vpc_id requires subnet_ids and security_group_ids."
  }
}

data "aws_iam_policy_document" "kms" {
  statement {
    sid    = "AccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogsEncryption"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.${data.aws_partition.current.dns_suffix}"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnEquals"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:${local.log_group_name}",
      ]
    }
  }

  # EventBridge-to-encrypted-SNS does not support SourceArn/SourceAccount conditions on this KMS
  # statement; AWS documents the service principal grant as the compatible pattern.
  statement {
    sid    = "EventBridgeEncryptedAlerts"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.${data.aws_partition.current.dns_suffix}"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchAlarmEncryptedAlerts"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.${data.aws_partition.current.dns_suffix}"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "findings" {
  description             = "Encrypt ${var.project_name} findings, logs, and secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "findings" {
  name          = "alias/${var.project_name}"
  target_key_id = aws_kms_key.findings.key_id
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = local.artifact_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.findings.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  depends_on = [aws_s3_bucket_versioning.artifacts]

  rule {
    id     = "expire-security-evidence"
    status = "Enabled"
    filter {}

    expiration {
      days = var.artifact_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

data "aws_iam_policy_document" "artifact_bucket" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.artifacts.arn,
      "${aws_s3_bucket.artifacts.arn}/*",
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyUnexpectedEncryption"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/*"]
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifact_bucket.json
}

resource "aws_ecr_repository" "scanner" {
  name                 = "${var.project_name}/scanner"
  image_tag_mutability = "IMMUTABLE"

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "scanner" {
  repository = aws_ecr_repository.scanner.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Retain the newest 30 scanner images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 30
      }
      action = { type = "expire" }
    }]
  })
}

resource "aws_secretsmanager_secret" "openai" {
  name                    = "/CodeBuild/${var.project_name}/openai"
  description             = "JSON object with OPENAI_API_KEY for the scheduled scanner"
  kms_key_id              = aws_kms_key.findings.arn
  recovery_window_in_days = 30
}

resource "aws_cloudwatch_log_group" "scanner" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.findings.arn
}

data "aws_iam_policy_document" "codebuild_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["codebuild.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role" "codebuild" {
  name               = "${var.project_name}-codebuild"
  assume_role_policy = data.aws_iam_policy_document.codebuild_assume.json
}

data "aws_iam_policy_document" "codebuild" {
  statement {
    sid = "WriteBuildLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }

  statement {
    sid = "InspectArtifactBucket"
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLocation",
    ]
    resources = [aws_s3_bucket.artifacts.arn]
  }

  statement {
    sid       = "WriteEncryptedArtifacts"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.artifacts.arn}/codex-security/*"]
  }

  statement {
    sid = "UseFindingsKey"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:ReEncrypt*",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.findings.arn]
  }

  statement {
    sid       = "AuthenticateToEcr"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  statement {
    sid = "PullScannerImage"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [aws_ecr_repository.scanner.arn]
  }

  dynamic "statement" {
    for_each = local.use_bedrock ? [] : [1]
    content {
      sid       = "ReadOpenAiSecret"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [aws_secretsmanager_secret.openai.arn]
    }
  }

  dynamic "statement" {
    for_each = local.use_bedrock ? [1] : []
    content {
      sid = "InvokeApprovedBedrockModels"
      actions = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
      ]
      resources = var.bedrock_model_arns
    }
  }

  dynamic "statement" {
    for_each = local.use_vpc ? [1] : []
    content {
      sid = "ManageVpcNetworkInterfaces"
      actions = [
        "ec2:CreateNetworkInterface",
        "ec2:CreateNetworkInterfacePermission",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeDhcpOptions",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "codebuild" {
  name   = "${var.project_name}-codebuild"
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.codebuild.json
}

resource "aws_codebuild_project" "daily_tvm" {
  name                   = "${var.project_name}-daily-tvm"
  description            = "Daily scoped Codex Security review of java-tron TVM"
  service_role           = aws_iam_role.codebuild.arn
  build_timeout          = var.codebuild_timeout_minutes
  queued_timeout         = 60
  concurrent_build_limit = 1
  encryption_key         = aws_kms_key.findings.arn

  source {
    type      = "NO_SOURCE"
    buildspec = file("${path.module}/../buildspec.yml")
  }

  artifacts {
    type                = "S3"
    location            = aws_s3_bucket.artifacts.bucket
    path                = "codex-security"
    name                = "daily-tvm"
    namespace_type      = "BUILD_ID"
    packaging           = "ZIP"
    encryption_disabled = false
  }

  environment {
    type                        = "LINUX_CONTAINER"
    compute_type                = var.codebuild_compute_type
    image                       = local.scanner_image
    image_pull_credentials_type = "SERVICE_ROLE"
    privileged_mode             = false

    environment_variable {
      name  = "TARGET_REPOSITORY_URL"
      value = var.target_repository_url
    }
    environment_variable {
      name  = "TARGET_REF"
      value = var.target_ref
    }
    environment_variable {
      name  = "KB_REPOSITORY_URL"
      value = var.knowledge_base_repository_url
    }
    environment_variable {
      name  = "KB_REF"
      value = var.knowledge_base_ref
    }
    environment_variable {
      name  = "JTSR_MODE"
      value = "daily-tvm"
    }
    environment_variable {
      name  = "SCAN_PROVIDER"
      value = var.scan_provider
    }
    environment_variable {
      name  = "SCAN_MODEL_OVERRIDE"
      value = var.scan_model_override
    }

    dynamic "environment_variable" {
      for_each = local.use_bedrock ? [] : [1]
      content {
        name  = "OPENAI_API_KEY"
        value = "${aws_secretsmanager_secret.openai.arn}:OPENAI_API_KEY"
        type  = "SECRETS_MANAGER"
      }
    }
  }

  dynamic "vpc_config" {
    for_each = local.use_vpc ? [1] : []
    content {
      vpc_id             = var.vpc_id
      subnets            = var.subnet_ids
      security_group_ids = var.security_group_ids
    }
  }

  logs_config {
    cloudwatch_logs {
      status      = "ENABLED"
      group_name  = aws_cloudwatch_log_group.scanner.name
      stream_name = "daily-tvm"
    }
    s3_logs {
      status = "DISABLED"
    }
  }

  depends_on = [
    aws_iam_role_policy.codebuild,
    aws_s3_bucket_policy.artifacts,
  ]
}

resource "aws_sqs_queue" "scheduler_dlq" {
  name                      = "${var.project_name}-scheduler-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.${data.aws_partition.current.dns_suffix}"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.project_name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    sid       = "StartDailyTvmBuild"
    actions   = ["codebuild:StartBuild"]
    resources = [aws_codebuild_project.daily_tvm.arn]
  }
  statement {
    sid       = "WriteSchedulerDlq"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.scheduler_dlq.arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "${var.project_name}-scheduler"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "daily_tvm" {
  name                         = "${var.project_name}-daily-tvm"
  description                  = "Start the daily java-tron TVM security scan"
  state                        = var.schedule_enabled ? "ENABLED" : "DISABLED"
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_codebuild_project.daily_tvm.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({})

    dead_letter_config {
      arn = aws_sqs_queue.scheduler_dlq.arn
    }

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 2
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-alerts"
  kms_master_key_id = aws_kms_key.findings.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "failed_build" {
  name        = "${var.project_name}-failed-build"
  description = "Notify on failed, partial, stopped, or timed-out TVM scans"
  event_pattern = jsonencode({
    source        = ["aws.codebuild"]
    "detail-type" = ["CodeBuild Build State Change"]
    detail = {
      "project-name" = [aws_codebuild_project.daily_tvm.name]
      "build-status" = ["FAILED", "FAULT", "STOPPED", "TIMED_OUT"]
    }
  })
}

resource "aws_cloudwatch_event_target" "failed_build" {
  rule = aws_cloudwatch_event_rule.failed_build.name
  arn  = aws_sns_topic.alerts.arn
}

data "aws_iam_policy_document" "alerts" {
  statement {
    sid     = "OwnerAdministration"
    effect  = "Allow"
    actions = ["sns:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid     = "AllowEventBridgePublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.${data.aws_partition.current.dns_suffix}"]
    }
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.failed_build.arn]
    }
  }

  statement {
    sid     = "AllowCloudWatchAlarmPublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.${data.aws_partition.current.dns_suffix}"]
    }
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts.json
}

resource "aws_cloudwatch_metric_alarm" "scheduler_dlq" {
  alarm_name          = "${var.project_name}-scheduler-dlq-not-empty"
  alarm_description   = "An EventBridge Scheduler delivery exhausted its retries"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    QueueName = aws_sqs_queue.scheduler_dlq.name
  }
}
