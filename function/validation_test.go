package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// createTestJWT creates a structurally valid JWT with custom claims for testing.
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + signature
}

// TestExtractRepositoryFromOIDC tests the extraction of repository claims from GitHub OIDC tokens.
// It verifies that the function correctly parses valid tokens and rejects invalid ones.
//
// Test steps:
//  1. Create test JWT with specific claims (valid or invalid)
//  2. Call ExtractRepositoryFromOIDC with the test token
//  3. Verify the returned repository matches expected value (for valid tokens)
//  4. Verify the error message contains expected text (for invalid tokens)
func TestExtractRepositoryFromOIDC(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantRepo    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "valid JWT with repository claim",
			token:    createTestJWT(map[string]interface{}{"repository": "owner/repo"}),
			wantRepo: "owner/repo",
			wantErr:  false,
		},
		{
			name:     "valid JWT with repository claim containing org",
			token:    createTestJWT(map[string]interface{}{"repository": "my-org/my-repo"}),
			wantRepo: "my-org/my-repo",
			wantErr:  false,
		},
		{
			name:     "valid JWT with multiple claims",
			token:    createTestJWT(map[string]interface{}{"repository": "owner/repo", "sub": "repo:owner/repo:ref:refs/heads/main", "aud": "https://github.com/owner"}),
			wantRepo: "owner/repo",
			wantErr:  false,
		},
		{
			name:        "invalid JWT format - no dots",
			token:       "invalid",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "invalid JWT format - one dot",
			token:       "header.payload",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "invalid JWT format - four parts",
			token:       "a.b.c.d",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "invalid base64 in payload",
			token:       "header.!!!invalid-base64!!!.signature",
			wantErr:     true,
			errContains: "failed to decode JWT payload",
		},
		{
			name:        "invalid JSON in payload",
			token:       "header." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".signature",
			wantErr:     true,
			errContains: "failed to parse JWT claims",
		},
		{
			name:        "missing repository claim",
			token:       createTestJWT(map[string]interface{}{"sub": "test", "aud": "audience"}),
			wantErr:     true,
			errContains: "repository claim not found",
		},
		{
			name:        "empty repository claim",
			token:       createTestJWT(map[string]interface{}{"repository": ""}),
			wantErr:     true,
			errContains: "repository claim not found",
		},
		{
			name:        "repository claim is not a string",
			token:       createTestJWT(map[string]interface{}{"repository": 12345}),
			wantErr:     true,
			errContains: "repository claim not found",
		},
		{
			name:        "repository claim is null",
			token:       createTestJWT(map[string]interface{}{"repository": nil}),
			wantErr:     true,
			errContains: "repository claim not found",
		},
		{
			name:        "invalid repository format - no slash",
			token:       createTestJWT(map[string]interface{}{"repository": "noslash"}),
			wantErr:     true,
			errContains: "invalid repository format",
		},
		{
			name:        "invalid repository format - empty string with no slash",
			token:       createTestJWT(map[string]interface{}{"repository": "justarepo"}),
			wantErr:     true,
			errContains: "invalid repository format",
		},
		{
			name:     "repository with nested path (monorepo style)",
			token:    createTestJWT(map[string]interface{}{"repository": "org/repo/subpath"}),
			wantRepo: "org/repo/subpath",
			wantErr:  false,
		},
		{
			name:        "empty token",
			token:       "",
			wantErr:     true,
			errContains: "invalid JWT format",
		},
		{
			name:        "only dots",
			token:       "..",
			wantErr:     true,
			errContains: "failed to parse JWT claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 2: Call the function under test
			got, err := ExtractRepositoryFromOIDC(tt.token)

			// Step 3 & 4: Verify results
			if tt.wantErr {
				// Verify error is returned
				if err == nil {
					t.Errorf("ExtractRepositoryFromOIDC() error = nil, wantErr = true")
					return
				}
				// Verify error message contains expected text
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ExtractRepositoryFromOIDC() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify no error for valid tokens
			if err != nil {
				t.Errorf("ExtractRepositoryFromOIDC() unexpected error = %v", err)
				return
			}

			// Verify returned repository matches expected
			if got != tt.wantRepo {
				t.Errorf("ExtractRepositoryFromOIDC() = %v, want %v", got, tt.wantRepo)
			}
		})
	}
}

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
