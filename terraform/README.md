# Terraform Infrastructure

This directory contains the Terraform configuration for deploying the GitHub Repository Token Issuer to Google Cloud Platform.

## Prerequisites

1. **GCP Project** with billing enabled
2. **Terraform** installed (see `.terraform-version` or `terraform/main.tf` for constraints)
3. **gcloud CLI** installed and authenticated
4. **GitHub App** created with repository permissions
5. **GitHub App private key** downloaded (added manually to Secret Manager after Terraform creates the empty secret)

## Required GCP APIs

Enable the following APIs in your GCP project:

```bash
gcloud services enable run.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable iamcredentials.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

## Setup Steps

### 1. Configure Terraform Backend

Update the GCS bucket name in `main.tf`:

```hcl
backend "gcs" {
  bucket = "your-terraform-state-bucket"  # Change this to your bucket
  prefix = "default"
}
```

Create the bucket if it doesn't exist:

```bash
gcloud storage buckets create gs://your-terraform-state-bucket \
  --location=us-east4 \
  --uniform-bucket-level-access
```

### 2. Configure Variables

Copy the example variables file and fill in your values:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
project_id    = "your-gcp-project-id"
github_app_id = "123456"  # Your GitHub App ID

# Optional: Override default region (default: us-east4)
# region = "us-central1"

# Optional: Restrict which repository owners can request tokens
# github_allowed_owners = ["my-org", "my-username"]
```

### 3. Initialize Terraform

```bash
terraform init
```

### 4. Review the Plan

```bash
terraform plan
```

### 5. Apply Configuration

```bash
terraform apply
```

This creates all resources including an empty Secret Manager secret.

### 6. Add GitHub App Private Key

After Terraform creates the secret, add your private key:

```bash
gcloud secrets versions add github-app-private-key \
  --data-file=path/to/your-private-key.pem
```

After successful deployment, Terraform will output the Cloud Run service URL.

## Resources Created

This configuration creates the following GCP resources:

- **Cloud Run Service** (`gh-repo-token-issuer`) - The serverless function
- **Service Account** (`gh-repo-token-issuer-sa`) - Identity for Cloud Run
- **Artifact Registry Repository** - Docker container registry (with cleanup policies: deletes untagged images and images older than 1 hour)
- **Secret Manager Secret** (`github-app-private-key`) - Stores GitHub App private key
- **IAM Bindings** - Public access for Cloud Run invocation and Secret Manager access for service account

### Resource Dependency Diagram

```
                            GCP APIs (enabled first)
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        v                       v                       v
   run.googleapis.com    secretmanager.googleapis.com   artifactregistry.googleapis.com
        │                       │                       │
        v                       v                       v
   ┌─────────────┐       ┌─────────────┐          ┌─────────┐
   │ Service     │       │ Secret      │          │Artifact │
   │ Account     │       │ Manager     │          │Registry │
   │(cloud_run_sa)       │ Secret      │          └────┬────┘
   └──────┬──────┘       └──────┬──────┘               │
          │                     │                      │
          │                     v                      │
          │         ┌────────────────────────┐         │
          │         │ Secret Manager IAM     │         │
          │         │ (secretAccessor role)  │         │
          │         └────────────────────────┘         │
          │                     │                      │
          v                     v                      v
   ┌───────────────────────────────────────────────────────┐
   │ Cloud Run Service (gh-repo-token-issuer)              │
   └───────────────────────┬───────────────────────────────┘
                           │
                           v
   ┌───────────────────────────────────────────────────────┐
   │ Cloud Run IAM (public_invoker)                        │
   │ member = "allUsers" (public access)                   │
   │ Security enforced by function via OIDC token validation│
   └───────────────────────────────────────────────────────┘

Notes:
   - Secret has prevent_destroy lifecycle (won't be deleted on terraform destroy)
   - Secret version (private key value) is added manually via gcloud
   - Service is publicly accessible; security is enforced by GitHub OIDC token validation
```

## Deploying Code Changes

When you make changes to the Go code in `function/`, build and deploy via Artifact Registry:

```bash
# From repository root
cd function
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o function .
SHORT_SHA=$(git rev-parse --short HEAD)
docker build -t us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA} .
docker push us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA}
gcloud run deploy gh-repo-token-issuer \
  --image=us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA} \
  --region=us-east4
```

For canary deployments (no traffic until verified):

```bash
gcloud run deploy gh-repo-token-issuer \
  --image=us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA} \
  --region=us-east4 \
  --no-traffic \
  --tag=commit-$(git rev-parse --short HEAD)
```

## Outputs

After deployment, Terraform provides:

- `cloud_run_url` - The HTTPS endpoint for your service
- `service_account_email` - The service account email

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

**Warning**: This will delete the Cloud Run service and all associated resources. The Secret Manager secret is protected with `prevent_destroy` and will not be deleted. The GCS state bucket is also not deleted automatically.

To force-delete the secret, first remove it from state:

```bash
terraform state rm google_secret_manager_secret.github_app_private_key
```

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

## Notes

- **No Logging**: This service intentionally has no logging enabled to reduce costs and complexity
- **Stateless**: No persistent storage; all state is managed per-request
- **Auto-scaling**: Configured for 0-10 instances (uses Cloud Run default concurrency)
- **Cost Optimization**: Minimum instances set to 0 to avoid idle charges
