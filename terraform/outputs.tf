output "cloud_function_url" {
  description = "The URL of the deployed Cloud Function"
  value       = google_cloudfunctions2_function.github_token_issuer.service_config[0].uri
}

output "service_account_email" {
  description = "The email of the Cloud Function service account"
  value       = google_service_account.cloud_function_sa.email
}

output "workload_identity_pool_provider" {
  description = "The Workload Identity Pool provider name for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}
