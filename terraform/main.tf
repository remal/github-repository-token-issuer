terraform {
  required_version = "~> 1.15"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "7.39.0"
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

  # Old images are deleted aggressively to keep storage cost down. Safe for the running
  # service: Cloud Run keeps its own copy of a serving revision's image, so deleting the
  # source here doesn't break serving or cold starts (https://docs.cloud.google.com/run/docs/deploying).
  # Tradeoff: rollback is limited to recently built images.
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

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      dynamic "env" {
        for_each = length(var.github_allowed_owner_ids) > 0 ? [1] : []
        content {
          name  = "GITHUB_ALLOWED_OWNER_IDS"
          value = join(",", var.github_allowed_owner_ids)
        }
      }
    }

    timeout = "300s"
  }

  # Deployments are managed by gcloud, not Terraform. template[0] ignores the whole
  # template subtree, so individual template fields (image, revision, etc.) are already
  # covered and don't need to be listed separately.
  lifecycle {
    ignore_changes = [
      template[0],
      client,
      client_version,
    ]
  }
}

# Cloud Run env vars aren't managed through the service resource above: its template is
# ignored (deployments go through gcloud), so this syncs the config env vars to the
# running service with gcloud whenever any of their values change.
resource "terraform_data" "env_vars" {
  triggers_replace = {
    app_id     = var.github_app_id
    project_id = var.project_id
    owner_ids  = join(",", var.github_allowed_owner_ids)
  }

  provisioner "local-exec" {
    command = <<-EOT
      if [ -n "${join(",", var.github_allowed_owner_ids)}" ]; then
        gcloud run services update ${google_cloud_run_v2_service.github_token_issuer.name} \
          --region=${var.region} \
          --update-env-vars=^@^GITHUB_APP_ID=${var.github_app_id}@GOOGLE_CLOUD_PROJECT=${var.project_id}@GITHUB_ALLOWED_OWNER_IDS=${join(",", var.github_allowed_owner_ids)}
      else
        gcloud run services update ${google_cloud_run_v2_service.github_token_issuer.name} \
          --region=${var.region} \
          --update-env-vars=^@^GITHUB_APP_ID=${var.github_app_id}@GOOGLE_CLOUD_PROJECT=${var.project_id} \
          --remove-env-vars=GITHUB_ALLOWED_OWNER_IDS
      fi
    EOT
  }
}

# IAM binding to allow public access to Cloud Run
# Security is enforced by the function via GitHub OIDC token validation
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = google_cloud_run_v2_service.github_token_issuer.location
  name     = google_cloud_run_v2_service.github_token_issuer.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
