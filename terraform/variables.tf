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

variable "github_allowed_owners" {
  description = "List of GitHub repository owners (organizations or users) allowed to request tokens. If empty, all owners are allowed."
  type        = list(string)
  default     = []
}
