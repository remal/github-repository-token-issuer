terraform {
  required_version = ">= 1.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  backend "gcs" {
    bucket = "your-terraform-state-bucket" # Update this with your GCS bucket name
    prefix = "github-repository-token-issuer"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Service Account for Cloud Run
resource "google_service_account" "cloud_run_sa" {
  account_id   = "github-repository-token-issuer-sa"
  display_name = "GitHub Repository Token Issuer Service Account"
  description  = "Service account for github-repository-token-issuer Cloud Run service"
}

# Grant Secret Manager access to service account
resource "google_secret_manager_secret_iam_member" "secret_accessor" {
  secret_id = "github-app-private-key"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

# Cloud Run Service (2nd generation)
resource "google_cloud_run_v2_service" "github_token_issuer" {
  name     = "github-repository-token-issuer"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.cloud_run_sa.email

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/github-repository-token-issuer/app:latest"

      env {
        name  = "GITHUB_APP_ID"
        value = var.github_app_id
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle = true
      }

      ports {
        container_port = 8080
      }
    }

    max_instance_request_concurrency = 80
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
    ]
  }
}

# Artifact Registry repository for container images
resource "google_artifact_registry_repository" "container_repo" {
  location      = var.region
  repository_id = "github-repository-token-issuer"
  description   = "Container repository for GitHub Repository Token Issuer"
  format        = "DOCKER"
}

# IAM binding to allow GitHub OIDC tokens to invoke Cloud Run
# This allows any repository to invoke the Cloud Run service
# Authorization is handled by the function itself (checks if GitHub App is installed)
resource "google_cloud_run_v2_service_iam_member" "github_oidc_invoker" {
  name     = google_cloud_run_v2_service.github_token_issuer.name
  location = google_cloud_run_v2_service.github_token_issuer.location
  role     = "roles/run.invoker"
  member   = "principalSet://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github_actions.workload_identity_pool_id}/*"
}

# Workload Identity Pool for GitHub Actions
resource "google_iam_workload_identity_pool" "github_actions" {
  workload_identity_pool_id = "github-actions"
  display_name              = "GitHub Actions"
  description               = "Workload Identity Pool for GitHub Actions OIDC"
}

# Workload Identity Pool Provider for GitHub
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-oidc"
  display_name                       = "GitHub OIDC Provider"
  description                        = "OIDC provider for GitHub Actions"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.aud"        = "assertion.aud"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # No attribute condition - allow any GitHub repository to authenticate
  # Authorization is handled by the function itself
}

# Data source to get project number
data "google_project" "project" {
  project_id = var.project_id
}
