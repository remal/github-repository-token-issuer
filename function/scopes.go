package main

// AllowedScopes defines permission scopes and their allowed permission levels.
// Supports both repository-level and organization-level permissions.
var AllowedScopes = map[string][]string{
	// Repository permissions (read and write)
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

	// Repository permissions (read-only for security)
	"administration":  {"read"}, // Repository administration settings
	"secret_scanning": {"read"}, // Secret scanning alerts

	// Organization permissions (read-only)
	"members":                        {"read"}, // Organization members and teams
	"organization_secrets":           {"read"}, // Organization-level secrets
	"organization_actions_variables": {"read"}, // Organization-level Actions variables
}

// BlacklistedScopes defines scopes that are explicitly forbidden.
// Currently empty but can be used to block specific scopes for security requirements.
var BlacklistedScopes = map[string]bool{}
