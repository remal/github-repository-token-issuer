variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "gh-repo-token-issuer"
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-east4"
}

variable "github_app_id" {
  description = "The GitHub App ID"
  type        = string
  default     = "2637135"
}

variable "cicd_service_account" {
  description = "Service account email for CI/CD pipeline (Artifact Registry push)"
  type        = string
  default     = "gh-remal-gh-repo-token-issuer@gh-repo-token-issuer.iam.gserviceaccount.com"
}
