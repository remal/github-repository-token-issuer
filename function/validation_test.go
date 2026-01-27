package main

import (
	"strings"
	"testing"
)

// Note: OIDC token validation (ValidateAndExtractRepository) is tested via CI/CD integration
// as it requires valid GitHub-signed tokens and JWKS fetching.

// TestValidateScopes tests the scope validation logic against allowlist and blacklist.
// It verifies that valid scopes pass validation and invalid scopes are rejected with appropriate errors.
//
// Test steps:
//  1. Create a map of scopes with permission levels
//  2. Call ValidateScopes with the test scopes
//  3. Verify no error is returned for valid scopes
//  4. Verify appropriate error is returned for invalid scopes
func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name        string
		scopes      map[string]string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid scope with read",
			scopes:  map[string]string{"contents": "read"},
			wantErr: false,
		},
		{
			name:    "valid scope with write",
			scopes:  map[string]string{"contents": "write"},
			wantErr: false,
		},
		{
			name:    "multiple valid scopes",
			scopes:  map[string]string{"contents": "write", "issues": "read", "pull_requests": "write"},
			wantErr: false,
		},
		{
			name:    "all read-write scopes with read",
			scopes:  map[string]string{"actions": "read", "checks": "read", "deployments": "read"},
			wantErr: false,
		},
		{
			name:    "all read-write scopes with write",
			scopes:  map[string]string{"actions": "write", "checks": "write", "deployments": "write"},
			wantErr: false,
		},
		{
			name:    "read-only scope with read - administration",
			scopes:  map[string]string{"administration": "read"},
			wantErr: false,
		},
		{
			name:    "read-only scope with read - secret_scanning",
			scopes:  map[string]string{"secret_scanning": "read"},
			wantErr: false,
		},
		{
			name:        "read-only scope with write - administration",
			scopes:      map[string]string{"administration": "write"},
			wantErr:     true,
			errContains: "permission 'write' not allowed for scope 'administration'",
		},
		{
			name:        "read-only scope with write - secret_scanning",
			scopes:      map[string]string{"secret_scanning": "write"},
			wantErr:     true,
			errContains: "permission 'write' not allowed for scope 'secret_scanning'",
		},
		{
			name:        "unknown scope",
			scopes:      map[string]string{"unknown_scope": "read"},
			wantErr:     true,
			errContains: "not in allowlist",
		},
		{
			name:        "another unknown scope",
			scopes:      map[string]string{"made_up_permission": "write"},
			wantErr:     true,
			errContains: "not in allowlist",
		},
		{
			name:        "organization scope (not allowed)",
			scopes:      map[string]string{"organization_administration": "read"},
			wantErr:     true,
			errContains: "not in allowlist",
		},
		{
			name:    "empty scopes map",
			scopes:  map[string]string{},
			wantErr: false,
		},
		{
			name:    "nil scopes map",
			scopes:  nil,
			wantErr: false,
		},
		{
			name:        "mix of valid and invalid scopes",
			scopes:      map[string]string{"contents": "read", "invalid_scope": "write"},
			wantErr:     true,
			errContains: "not in allowlist",
		},
		{
			name:        "valid scope with invalid permission level",
			scopes:      map[string]string{"contents": "admin"},
			wantErr:     true,
			errContains: "permission 'admin' not allowed",
		},
		{
			name:        "valid scope with empty permission",
			scopes:      map[string]string{"contents": ""},
			wantErr:     true,
			errContains: "not allowed",
		},
		{
			name: "all allowed scopes with valid permissions",
			scopes: map[string]string{
				"actions":            "write",
				"attestations":       "read",
				"checks":             "write",
				"contents":           "read",
				"dependabot_secrets": "write",
				"deployments":        "read",
				"discussions":        "write",
				"environments":       "read",
				"issues":             "write",
				"merge_queues":       "read",
				"packages":           "write",
				"pages":              "read",
				"projects":           "write",
				"pull_requests":      "read",
				"secrets":            "write",
				"statuses":           "read",
				"workflows":          "write",
				"administration":     "read",
				"secret_scanning":    "read",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 2: Call the function under test
			err := ValidateScopes(tt.scopes)

			// Step 3 & 4: Verify results
			if tt.wantErr {
				// Verify error is returned
				if err == nil {
					t.Errorf("ValidateScopes() error = nil, wantErr = true")
					return
				}
				// Verify error message contains expected text
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateScopes() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify no error for valid scopes
			if err != nil {
				t.Errorf("ValidateScopes() unexpected error = %v", err)
			}
		})
	}
}
