variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "github-repository-token-issuer"
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
