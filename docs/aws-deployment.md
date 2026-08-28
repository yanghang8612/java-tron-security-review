# Optional AWS-managed deployment: daily TVM review

This is not the default for a manually operated EC2 server. Use
[single-server deployment](server-deployment.md) when AWS is only the machine host. The resources
below are an optional, separate architecture for operators who explicitly want AWS-managed batch,
scheduling, storage and alerting.

The AWS deployment is an ephemeral batch pipeline, not a long-running service:

```text
EventBridge Scheduler (02:17 Asia/Shanghai)
             |
             v
CodeBuild, one non-privileged container, concurrency 1
             |
             +--> clone exact java-tron revision and optional KB
             +--> daily-tvm: terra investigation + sol falsification
             +--> one rotating TVM facet, read-only source, bounded model cost
             |
             v
KMS-encrypted S3 evidence + KMS-encrypted CloudWatch logs
             |
             +--> failed/partial build -> private SNS topic
             +--> failed schedule delivery -> encrypted SQS DLQ -> SNS alarm
```

This shape has no idle compute. It also keeps the model credential available only during a build.
The scanner does not run a node, Gradle tests, fuzzers, or transaction replays; it performs static,
source-based Codex Security path scans. Dynamic validation remains a separate confirmation step.

## Daily TVM scope

Every run selects one of eight TVM execution facets by day of year, even when there were no source
changes. Facets cover entry/context, opcode dispatch, call/create, state rollback,
precompiles/native work, resource limits, activation/replay and simulation parity. Each includes
cross-module callers and sinks so the review follows a complete execution flow instead of scanning
an isolated directory. Set `JTSR_SCOPE` only to force a specific facet for reproduction.

The default OpenAI configuration uses `gpt-5.6-sol` at `xhigh` for the first investigation and
separate `gpt-5.6-sol` at `high` invocations for per-candidate falsification. Triage has a 200 USD
estimated-cost threshold; primary verification has up to eight 30 USD attempts (240 USD total).
Availability-only GPT-5.5 fallbacks are additionally bounded by count and time, not cost. These
thresholds are not forecasts or hard whole-run billing caps. See [operations](operations.md).
A result is still a hypothesis until the repository's evidence and reachability policy is satisfied.

## Provisioning

Prerequisites are Terraform 1.6+, Docker Buildx, AWS CLI v2, and an AWS identity permitted to create
the resources in `deploy/aws/terraform`. The defaults use `us-east-2`, matching the existing AWS
deployment region, but the scanner is independent of the go-tron EC2 services and their ports.

1. Review `terraform.tfvars.example`, copy it to `terraform.tfvars`, and keep
   `schedule_enabled = false` for bootstrap.
2. Create the infrastructure:

   ```bash
   cd deploy/aws/terraform
   terraform init
   terraform plan -out bootstrap.tfplan
   terraform apply bootstrap.tfplan
   cd ../../..
   ```

3. For the default `openai` provider, populate the created Secrets Manager secret with a JSON
   value shaped as `{"OPENAI_API_KEY":"..."}`. Prefer the AWS console or an approved secret
   provisioning pipeline so the value does not enter shell history or Terraform state. Terraform
   deliberately creates no secret version.
4. Build and push a reviewed, immutable scanner image:

   ```bash
   export AWS_REGION=us-east-2
   export ECR_REPOSITORY_URI="$(terraform -chdir=deploy/aws/terraform output -raw scanner_ecr_repository_uri)"
   export IMAGE_TAG="$(git rev-parse HEAD)"
   deploy/aws/push-image.sh
   ```

5. Set `scanner_image_tag` to that reviewed commit SHA, set `schedule_enabled = true`, review the
   second plan, and apply it.
6. Confirm any email subscription sent by SNS, then start one manual acceptance build:

   ```bash
   aws codebuild start-build \
     --region us-east-2 \
     --project-name "$(terraform -chdir=deploy/aws/terraform output -raw codebuild_project_name)"
   ```

Do not use the mutable `bootstrap` tag in an enabled production schedule. The ECR repository rejects
tag replacement and scans images on push. The Docker base image, Codex Security version, and
Terraform provider are also locked in the repository.

## Authentication options

### OpenAI API key (default)

CodeBuild retrieves `OPENAI_API_KEY` from Secrets Manager. The Python wrapper passes that key to the
Codex Security child process but removes CodeBuild's AWS credential variables and disables EC2
metadata credential discovery. The target and KB clones never receive a Git credential helper.

### Amazon Bedrock

Set `scan_provider = "amazon-bedrock"`, an explicit `scan_model_override`, and the exact allowed
`bedrock_model_arns`. In this mode no OpenAI secret is injected; Codex Security uses the CodeBuild
role through the AWS default credential chain. The role can invoke only the listed model resources.
Because the single Bedrock override applies to both daily passes, this mode is a two-prompt
independent review, not a two-model review.

Model availability and inference-profile ARNs are region/account dependent. Confirm access in the
chosen AWS account before enabling the schedule.

## Network and VPC

The default is an AWS-managed, non-VPC CodeBuild environment with no inbound listener and outbound
HTTPS. To attach an existing VPC, set `vpc_id`, private `subnet_ids`, and `security_group_ids`.
Those subnets need:

- outbound HTTPS to GitHub and either OpenAI or the selected Bedrock endpoint;
- NAT or an approved egress proxy for public endpoints;
- preferably VPC endpoints for ECR API/DKR, S3, CloudWatch Logs, Secrets Manager, KMS, and Bedrock.

The security group should have no ingress rule and only the required egress. Do not reuse the
public Nginx or node API ports for this batch job.

## Storage, failure, and operations

- Findings are private S3 ZIP artifacts encrypted with a customer-managed KMS key, versioned, and
  expired after 90 days by default. Public access and plaintext transport are denied.
- CloudWatch logs use the same customer-managed key and expire after 30 days. Logs should contain
  orchestration status, while detailed findings stay in S3.
- Exit `2` (partial coverage) marks the CodeBuild run failed, just like operational exit `1`, while
  still uploading available evidence. Failed builds publish to the private SNS topic.
- Scheduler delivery is retried twice for up to one hour; exhausted deliveries enter the encrypted
  SQS dead-letter queue for 14 days and a CloudWatch alarm publishes to the private SNS topic.
- The schedule is limited to one concurrent build. A stuck run cannot create an unbounded fan-out.

Review `coverage.json`, `run-manifest.json`, and `aggregate.json` together. A successful scheduler
delivery or green build is not by itself evidence that TVM is vulnerability-free.
