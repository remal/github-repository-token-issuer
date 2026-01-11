package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractRepositoryFromOIDC extracts the repository claim from a GitHub OIDC token.
// Returns the repository in "owner/repo" format.
// Note: GCP IAM has already validated the token signature, issuer, audience, and expiration.
func ExtractRepositoryFromOIDC(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode the payload (middle part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Extract repository claim
	repository, ok := claims["repository"].(string)
	if !ok || repository == "" {
		return "", fmt.Errorf("repository claim not found in OIDC token")
	}

	// Validate format (should be "owner/repo")
	if !strings.Contains(repository, "/") {
		return "", fmt.Errorf("invalid repository format: %s", repository)
	}

	return repository, nil
}

// ValidateScopes validates requested scopes against allowlist and blacklist.
// Checks for:
// - Blacklisted scopes
// - Scopes not in allowlist
// - Invalid permission levels for each scope
func ValidateScopes(scopes map[string]string) error {
	for scopeID, permission := range scopes {
		// Check blacklist
		if BlacklistedScopes[scopeID] {
			return fmt.Errorf("scope '%s' is not allowed", scopeID)
		}

		// Check allowlist
		allowedLevels, exists := AllowedScopes[scopeID]
		if !exists {
			return fmt.Errorf("scope '%s' is not in allowlist", scopeID)
		}

		// Validate permission level
		validPermission := false
		for _, level := range allowedLevels {
			if permission == level {
				validPermission = true
				break
			}
		}

		if !validPermission {
			return fmt.Errorf("permission '%s' not allowed for scope '%s' (allowed: %v)",
				permission, scopeID, allowedLevels)
		}
	}

	return nil
}
