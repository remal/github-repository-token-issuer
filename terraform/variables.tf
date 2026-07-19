variable "project_id" {
  description = "The GCP project ID"
  type        = string
}

variable "region" {
  description = "The GCP region for resources"
  type        = string
  default     = "us-east4"
}

variable "github_app_id" {
  description = "The GitHub App ID"
  type        = string
}

variable "github_allowed_owner_ids" {
  description = "List of GitHub account IDs (organizations or users) allowed to request tokens. Account IDs are stable across renames, unlike owner names. If empty, all owners are allowed."
  type        = list(string)
  default     = []
}
