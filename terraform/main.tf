terraform {
  required_version = "~> 1.14"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.16.0"
    }
  }

  backend "gcs" {
    bucket = "gh-repo-token-issuer-terraform-state"
    prefix = "default"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# Enable required GCP services
resource "google_project_service" "run" {
  service            = "run.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "secretmanager" {
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iamcredentials" {
  service            = "iamcredentials.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "artifactregistry" {
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
}

# Artifact Registry repository for Docker images
resource "google_artifact_registry_repository" "docker" {
  repository_id = "gh-repo-token-issuer"
  location      = var.region
  format        = "DOCKER"
  description   = "Docker images for GitHub Repository Token Issuer"

  cleanup_policy_dry_run = false

  # Remove untagged images
  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      tag_state = "UNTAGGED"
    }
  }

  # Remove images older than 1 hour
  cleanup_policies {
    id     = "delete-old-images"
    action = "DELETE"
    condition {
      tag_state  = "ANY"
      older_than = "3600s"
    }
  }

  depends_on = [google_project_service.artifactregistry]
}

# Data source to get project number
data "google_project" "project" {
  project_id = var.project_id
}

# Service Account for Cloud Run
resource "google_service_account" "cloud_run_sa" {
  account_id   = "gh-repo-token-issuer-sa"
  display_name = "GitHub Repository Token Issuer Service Account"
  description  = "Service account for gh-repo-token-issuer Cloud Run service"
}

# Secret for GitHub App private key (value must be added manually after creation)
resource "google_secret_manager_secret" "github_app_private_key" {
  secret_id = "github-app-private-key"

  replication {
    auto {}
  }

  # Prevent accidental deletion - secret contains sensitive data added manually
  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.secretmanager]
}

# Grant Secret Manager access to service account
resource "google_secret_manager_secret_iam_member" "secret_accessor" {
  secret_id = google_secret_manager_secret.github_app_private_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run_sa.email}"
}

# Cloud Run service
resource "google_cloud_run_v2_service" "github_token_issuer" {
  name     = "gh-repo-token-issuer"
  location = var.region

  deletion_protection = false

  depends_on = [google_project_service.run, google_artifact_registry_repository.docker]

  template {
    service_account = google_service_account.cloud_run_sa.email

    #max_instance_request_concurrency = 50

    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }

    containers {
      # Placeholder image - actual deployment via CI/CD pipeline to Artifact Registry
      image = "us-docker.pkg.dev/cloudrun/container/hello"

      resources {
        limits = {
          memory = "128Mi"
          cpu    = "0.5"
        }
        cpu_idle = true # Throttle CPU when idle (allows <512Mi memory, reduces cost)
      }

      env {
        name  = "GITHUB_APP_ID"
        value = var.github_app_id
      }
    }

    timeout = "60s"
  }

  # Deployments are managed by gcloud, not Terraform
  lifecycle {
    ignore_changes = [
      template[0],
      template[0].containers[0].image,
      template[0].containers[0].base_image_uri,
      template[0].containers[0].command,
      template[0].revision,
      client,
      client_version,
    ]
  }
}

# IAM binding to allow GitHub OIDC tokens to invoke Cloud Run
# This allows any repository to invoke the service
# Authorization is handled by the service itself (checks if GitHub App is installed)
resource "google_cloud_run_v2_service_iam_member" "github_oidc_invoker" {
  project  = var.project_id
  location = google_cloud_run_v2_service.github_token_issuer.location
  name     = google_cloud_run_v2_service.github_token_issuer.name
  role     = "roles/run.invoker"
  member   = "principalSet://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.github_actions.workload_identity_pool_id}/*"
}

# Workload Identity Pool for GitHub Actions (users of this service)
resource "google_iam_workload_identity_pool" "github_actions" {
  workload_identity_pool_id = "users-github-actions"
  display_name              = "Users - GitHub Actions"
  description               = "Workload Identity Pool for GitHub Actions OIDC (service users)"

  depends_on = [google_project_service.iamcredentials]
}

# Workload Identity Pool Provider for GitHub
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_actions.workload_identity_pool_id
  workload_identity_pool_provider_id = "users-github-oidc"
  display_name                       = "Users - GitHub OIDC Provider"
  description                        = "OIDC provider for GitHub Actions (service users)"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.aud"        = "assertion.aud"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  # Require matching audience - authorization handled by the service
  attribute_condition = var.workload_identity_additional_condition != "" ? "attribute.aud == '${var.oidc_audience}' && (${var.workload_identity_additional_condition})" : "attribute.aud == '${var.oidc_audience}'"
}
