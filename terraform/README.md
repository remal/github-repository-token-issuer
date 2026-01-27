# Terraform Infrastructure

This directory contains the Terraform configuration for deploying the GitHub Repository Token Issuer to Google Cloud Platform.

## Prerequisites

1. **GCP Project** with billing enabled
2. **Terraform** installed (see `.terraform-version` or `terraform/main.tf` for constraints)
3. **gcloud CLI** installed and authenticated
4. **GitHub App** created with repository permissions
5. **GitHub App private key** stored in GCP Secret Manager

## Required GCP APIs

Enable the following APIs in your GCP project:

```bash
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable iamcredentials.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

## Setup Steps

### 1. Store GitHub App Private Key

Before running Terraform, create the Secret Manager secret with your GitHub App private key:

```bash
gcloud secrets create github-app-private-key \
  --data-file=path/to/your-private-key.pem
```

### 2. Configure Terraform Backend

Update the GCS bucket name in `main.tf`:

```hcl
backend "gcs" {
  bucket = "your-terraform-state-bucket"  # Change this to your bucket
  prefix = "gh-repo-token-issuer"
}
```

Create the bucket if it doesn't exist:

```bash
gcloud storage buckets create gs://your-terraform-state-bucket \
  --location=us-east4 \
  --uniform-bucket-level-access
```

### 3. Configure Variables

Copy the example variables file and fill in your values:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
project_id    = "your-gcp-project-id"
region        = "us-east4"
github_app_id = "123456"  # Your GitHub App ID
oidc_audience = "gh-repo-token-issuer"  # Required: OIDC audience for Workload Identity

# Optional: Restrict which repositories can authenticate
# workload_identity_additional_condition = "attribute.repository.startsWith('myorg/')"
```

**Note**: The `oidc_audience` value must match the `audience` parameter used when requesting OIDC tokens in GitHub Actions workflows.

### 4. Initialize Terraform

```bash
terraform init
```

### 5. Review the Plan

```bash
terraform plan
```

### 6. Apply Configuration

```bash
terraform apply
```

After successful deployment, Terraform will output the Cloud Run service URL.

## Resources Created

This configuration creates the following GCP resources:

- **Cloud Run Service** (`gh-repo-token-issuer`) - The serverless function
- **Service Account** (`gh-repo-token-issuer-sa`) - Identity for Cloud Run
- **Artifact Registry Repository** - Docker container registry
- **Workload Identity Pool** (`users-github-actions`) - For GitHub OIDC authentication
- **Workload Identity Pool Provider** (`users-github-oidc`) - GitHub OIDC configuration
- **IAM Bindings** - Permissions for Cloud Run invocation and Secret Manager access

### Resource Dependency Diagram

```
                            GCP APIs (enabled first)
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        v                       v                       v
   run.googleapis.com    secretmanager.googleapis.com   iamcredentials.googleapis.com
        │                       │                       │
        │                       │                       v
        │                       │            ┌────────────────────────────┐
        │                       │            │ Workload Identity          │
        │                       │            │ Pool (users-github-actions)│
        │                       │            └──────────┬─────────────────┘
        │                       │                       │
        │                       │                       v
        │                       │            ┌───────────────────────┐
        │                       │            │ Workload Identity     │
        │                       │            │ (users-github-oidc)   │
        │                       │            └──────────┬────────────┘
        │                       │                       │
        v                       v                       │
   ┌─────────┐          ┌─────────────┐                 │
   │Artifact │          │ Service     │                 │
   │Registry │          │ Account     │                 │
   └────┬────┘          │ (cloud_run_sa)                │
        │               └──────┬──────┘                 │
        │                      │                        │
        │    ┌─────────────────┼────────────────────────┘
        │    │                 │
        │    │                 v
        │    │    ┌────────────────────────┐
        │    │    │ Secret Manager IAM     │
        │    │    │ (secretAccessor role)  │
        │    │    └────────────────────────┘
        │    │                 │
        v    v                 │
   ┌───────────────────────┐   │
   │ Cloud Run Service     │<──┘
   │ (gh-repo-token-issuer)│
   └──────────┬────────────┘
              │
              v
   ┌───────────────────────┐
   │ Cloud Run IAM         │<─── Workload Identity Pool (invoker permission)
   │ (github_oidc_invoker) │
   └───────────────────────┘

External (not managed by Terraform):
   ┌───────────────────────┐
   │ Secret Manager Secret │ (github-app-private-key)
   │ (created manually)    │
   └───────────────────────┘
```

## Deploying Code Changes

When you make changes to the Go code in `function/`, deploy using source-based deployment:

```bash
# From repository root
gcloud beta run deploy gh-repo-token-issuer \
  --source . \
  --region=us-east4 \
  --no-build \
  --base-image=osonly24 \
  --command=./function
```

For canary deployments (no traffic until verified):

```bash
gcloud beta run deploy gh-repo-token-issuer \
  --source . \
  --region=us-east4 \
  --no-build \
  --base-image=osonly24 \
  --command=./function \
  --no-traffic \
  --tag=commit-$(git rev-parse --short HEAD)
```

## Outputs

After deployment, Terraform provides:

- `cloud_run_url` - The HTTPS endpoint for your service
- `service_account_email` - The service account email
- `artifact_registry_repository` - The container registry URL
- `workload_identity_pool_provider` - The Workload Identity Federation provider name

## Updating Configuration

To update environment variables or scaling settings, modify `main.tf` and run:

```bash
terraform apply
```

## Destroying Resources

To remove all created resources:

```bash
terraform destroy
```

**Warning**: This will delete the Cloud Run service and all associated resources. The Secret Manager secret and GCS state bucket are not deleted automatically.

## Troubleshooting

### Secret Manager Access Error

If Cloud Run can't access the secret:

```bash
gcloud secrets add-iam-policy-binding github-app-private-key \
  --member="serviceAccount:gh-repo-token-issuer-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### Container Build Fails

Ensure you're in the correct directory and have the proper permissions:

```bash
gcloud auth configure-docker us-east4-docker.pkg.dev
```

### Workload Identity Federation Issues

Verify the Workload Identity Federation configuration:

```bash
gcloud iam workload-identity-pools describe users-github-actions \
  --location=global \
  --format=json
```

## Notes

- **No Logging**: This service intentionally has no logging enabled to reduce costs and complexity
- **Stateless**: No persistent storage; all state is managed per-request
- **Auto-scaling**: Configured for 0-10 instances with 80 concurrent requests per instance
- **Cost Optimization**: Minimum instances set to 0 to avoid idle charges
