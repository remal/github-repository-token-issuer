output "cloud_run_url" {
  description = "The URL of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.github_token_issuer.uri
}

output "service_account_email" {
  description = "The email of the Cloud Run service account"
  value       = google_service_account.cloud_run_sa.email
}

output "workload_identity_pool_provider" {
  description = "The Workload Identity Pool provider name for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}
