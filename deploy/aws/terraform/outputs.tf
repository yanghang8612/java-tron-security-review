output "codebuild_project_name" {
  value = aws_codebuild_project.daily_tvm.name
}

output "scanner_ecr_repository_uri" {
  value = aws_ecr_repository.scanner.repository_url
}

output "artifact_bucket_name" {
  value = aws_s3_bucket.artifacts.bucket
}

output "findings_kms_key_arn" {
  value = aws_kms_key.findings.arn
}

output "openai_secret_arn" {
  value       = aws_secretsmanager_secret.openai.arn
  description = "Populate with JSON containing OPENAI_API_KEY; Terraform never stores the value."
}

output "schedule_arn" {
  value = aws_scheduler_schedule.daily_tvm.arn
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "scheduler_dlq_url" {
  value = aws_sqs_queue.scheduler_dlq.url
}
