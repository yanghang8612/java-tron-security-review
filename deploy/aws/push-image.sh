#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?set AWS_REGION to the ECR repository region}"
: "${ECR_REPOSITORY_URI:?set ECR_REPOSITORY_URI from the Terraform output}"
: "${IMAGE_TAG:?set IMAGE_TAG to an immutable tag, normally the reviewed Git commit SHA}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
REGISTRY="${ECR_REPOSITORY_URI%%/*}"
REPOSITORY_NAME="${ECR_REPOSITORY_URI#*/}"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

docker buildx build \
  --platform linux/amd64 \
  --file "$PROJECT_DIR/deploy/container/Dockerfile" \
  --tag "$ECR_REPOSITORY_URI:$IMAGE_TAG" \
  --push \
  "$PROJECT_DIR"

IMAGE_DIGEST="$(
  aws ecr describe-images \
    --region "$AWS_REGION" \
    --repository-name "$REPOSITORY_NAME" \
    --image-ids "imageTag=$IMAGE_TAG" \
    --query 'imageDetails[0].imageDigest' \
    --output text
)"

printf 'Pushed %s@%s\n' "$ECR_REPOSITORY_URI" "$IMAGE_DIGEST"
