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

variable "workload_identity_additional_condition" {
  description = "Optional additional CEL expression to append to attribute condition (e.g., \"attribute.repository.startsWith('myorg/')\")"
  type        = string
  default     = "attribute.repository.startsWith('remal/')"
}

variable "oidc_audience" {
  description = "Required OIDC audience value that must match in token claims"
  type        = string
  default     = "gh-repo-token-issuer"
}
