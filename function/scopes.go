package main

// AllowedScopes defines repository permission scopes and their allowed permission levels.
// Only repository-level permissions are supported; organization and account permissions are not allowed.
var AllowedScopes = map[string][]string{
	// Read and write permissions
	"actions":            {"read", "write"},
	"attestations":       {"read", "write"},
	"checks":             {"read", "write"},
	"contents":           {"read", "write"},
	"dependabot_secrets": {"read", "write"},
	"deployments":        {"read", "write"},
	"discussions":        {"read", "write"},
	"environments":       {"read", "write"},
	"issues":             {"read", "write"},
	"merge_queues":       {"read", "write"},
	"packages":           {"read", "write"},
	"pages":              {"read", "write"},
	"projects":           {"read", "write"},
	"pull_requests":      {"read", "write"},
	"secrets":            {"read", "write"},
	"statuses":           {"read", "write"},
	"workflows":          {"read", "write"},

	// Read-only permissions (security and administrative)
	"administration":  {"read"}, // Repository administration settings
	"secret_scanning": {"read"}, // Secret scanning alerts
}

// BlacklistedScopes defines scopes that are explicitly forbidden.
// Currently empty but can be used to block specific scopes for security requirements.
var BlacklistedScopes = map[string]bool{}
