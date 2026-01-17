package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Helper function to create a test JWT with custom claims
func createTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))

	return header + "." + payload + "." + signature
}

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
			got, err := ExtractRepositoryFromOIDC(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExtractRepositoryFromOIDC() error = nil, wantErr = true")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ExtractRepositoryFromOIDC() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ExtractRepositoryFromOIDC() unexpected error = %v", err)
				return
			}

			if got != tt.wantRepo {
				t.Errorf("ExtractRepositoryFromOIDC() = %v, want %v", got, tt.wantRepo)
			}
		})
	}
}

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
			err := ValidateScopes(tt.scopes)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateScopes() error = nil, wantErr = true")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateScopes() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateScopes() unexpected error = %v", err)
			}
		})
	}
}
