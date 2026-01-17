package main

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v81/github"
)

// generateTestRSAKey creates a 2048-bit RSA key pair for testing JWT signing.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

// TestCreateJWT tests JWT creation for GitHub App authentication.
// It verifies that valid keys produce valid JWTs and nil keys return errors.
//
// Test steps:
//  1. Generate a test RSA key (or use nil for error cases)
//  2. Call CreateJWT with the key and app ID
//  3. Verify JWT is returned for valid keys (non-empty, 3-part structure)
//  4. Verify error is returned for nil keys
func TestCreateJWT(t *testing.T) {
	tests := []struct {
		name        string
		appID       string
		useNilKey   bool
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid private key and app ID",
			appID:     "12345",
			useNilKey: false,
			wantErr:   false,
		},
		{
			name:      "valid private key with different app ID",
			appID:     "987654321",
			useNilKey: false,
			wantErr:   false,
		},
		{
			name:      "valid private key with string app ID",
			appID:     "my-app-id",
			useNilKey: false,
			wantErr:   false,
		},
		{
			name:        "nil private key returns error",
			appID:       "12345",
			useNilKey:   true,
			wantErr:     true,
			errContains: "private key is nil",
		},
	}

	// Step 1: Generate a shared test key for valid cases
	validKey := generateTestRSAKey(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Determine which key to use
			var key *rsa.PrivateKey
			if !tt.useNilKey {
				key = validKey
			}

			// Step 2: Call CreateJWT
			got, err := CreateJWT(key, tt.appID)

			// Step 3 & 4: Verify results
			if tt.wantErr {
				// Verify error is returned
				if err == nil {
					t.Errorf("CreateJWT() error = nil, wantErr = true")
					return
				}
				// Verify error message contains expected text
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("CreateJWT() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify no error for valid keys
			if err != nil {
				t.Errorf("CreateJWT() unexpected error = %v", err)
				return
			}

			// Verify JWT is not empty
			if got == "" {
				t.Error("CreateJWT() returned empty string")
				return
			}

			// Verify JWT structure (3 parts separated by dots)
			parts := strings.Split(got, ".")
			if len(parts) != 3 {
				t.Errorf("CreateJWT() returned invalid JWT format, got %d parts, want 3", len(parts))
			}
		})
	}
}

// TestCreateJWT_Claims tests that JWT claims are correctly set.
// It verifies iat (issued at), exp (expiration), and iss (issuer) claims.
//
// Test steps:
//  1. Generate a test RSA key
//  2. Record timestamp before/after JWT creation
//  3. Call CreateJWT to generate a token
//  4. Parse the JWT and extract claims
//  5. Verify iss claim matches app ID
//  6. Verify iat claim is within expected time range
//  7. Verify exp claim is exactly 10 minutes after iat
func TestCreateJWT_Claims(t *testing.T) {
	// Step 1: Generate test key
	key := generateTestRSAKey(t)
	appID := "12345"

	// Step 2: Record timestamps
	beforeCreate := time.Now().Unix()
	// Step 3: Create JWT
	tokenString, err := CreateJWT(key, appID)
	afterCreate := time.Now().Unix()

	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	// Step 4: Parse the token to verify claims
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("failed to get claims from token")
	}

	// Step 5: Verify issuer claim
	if iss, ok := claims["iss"].(string); !ok || iss != appID {
		t.Errorf("JWT iss claim = %v, want %v", claims["iss"], appID)
	}

	// Step 6: Verify iat claim (issued at)
	if iat, ok := claims["iat"].(float64); !ok {
		t.Error("JWT iat claim missing or invalid type")
	} else {
		iatInt := int64(iat)
		if iatInt < beforeCreate || iatInt > afterCreate {
			t.Errorf("JWT iat claim = %v, want between %v and %v", iatInt, beforeCreate, afterCreate)
		}
	}

	// Step 7: Verify exp claim (expiration - should be ~10 minutes from iat)
	if exp, ok := claims["exp"].(float64); !ok {
		t.Error("JWT exp claim missing or invalid type")
	} else {
		iat := int64(claims["iat"].(float64))
		expInt := int64(exp)
		expectedExp := iat + 600 // 10 minutes in seconds

		if expInt != expectedExp {
			t.Errorf("JWT exp claim = %v, want %v (iat + 600 seconds)", expInt, expectedExp)
		}
	}
}

// TestCreateJWT_Algorithm tests that the JWT uses RS256 signing algorithm.
// GitHub requires RS256 for App authentication.
//
// Test steps:
//  1. Generate a test RSA key
//  2. Call CreateJWT to generate a token
//  3. Parse the JWT header without verification
//  4. Verify the algorithm is RS256
func TestCreateJWT_Algorithm(t *testing.T) {
	// Step 1: Generate test key
	key := generateTestRSAKey(t)
	appID := "12345"

	// Step 2: Create JWT
	tokenString, err := CreateJWT(key, appID)
	if err != nil {
		t.Fatalf("CreateJWT() error = %v", err)
	}

	// Step 3: Parse without verification to check header
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	// Step 4: Verify RS256 algorithm
	if token.Method.Alg() != "RS256" {
		t.Errorf("JWT algorithm = %v, want RS256", token.Method.Alg())
	}
}

// TestVerifyRequestedScopes tests verification of requested vs granted scopes.
// It ensures the function correctly identifies missing or mismatched permissions.
//
// Test steps:
//  1. Create a map of requested scopes with permission levels
//  2. Create a mock InstallationPermissions struct with granted scopes
//  3. Call VerifyRequestedScopes with requested and granted
//  4. Verify no error when all scopes match
//  5. Verify error when scopes are missing or have wrong permission level
func TestVerifyRequestedScopes(t *testing.T) {
	tests := []struct {
		name        string
		requested   map[string]string
		granted     *github.InstallationPermissions
		wantErr     bool
		errContains string
	}{
		{
			name:      "single scope granted exactly",
			requested: map[string]string{"contents": "write"},
			granted:   &github.InstallationPermissions{Contents: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "single scope read granted",
			requested: map[string]string{"contents": "read"},
			granted:   &github.InstallationPermissions{Contents: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "multiple scopes all granted",
			requested: map[string]string{"contents": "write", "issues": "read", "pull_requests": "write"},
			granted: &github.InstallationPermissions{
				Contents:     github.Ptr("write"),
				Issues:       github.Ptr("read"),
				PullRequests: github.Ptr("write"),
			},
			wantErr: false,
		},
		{
			name:        "missing scope - contents requested but not granted",
			requested:   map[string]string{"contents": "write"},
			granted:     &github.InstallationPermissions{},
			wantErr:     true,
			errContains: "missing",
		},
		{
			name:        "wrong permission level - requested write, granted read",
			requested:   map[string]string{"contents": "write"},
			granted:     &github.InstallationPermissions{Contents: github.Ptr("read")},
			wantErr:     true,
			errContains: "missing",
		},
		{
			name:        "nil granted permissions",
			requested:   map[string]string{"contents": "read"},
			granted:     nil,
			wantErr:     true,
			errContains: "no permissions",
		},
		{
			name:      "extra granted scopes are ok",
			requested: map[string]string{"contents": "read"},
			granted: &github.InstallationPermissions{
				Contents: github.Ptr("read"),
				Issues:   github.Ptr("write"),
				Actions:  github.Ptr("read"),
			},
			wantErr: false,
		},
		{
			name:      "empty requested scopes",
			requested: map[string]string{},
			granted:   &github.InstallationPermissions{Contents: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "actions scope",
			requested: map[string]string{"actions": "write"},
			granted:   &github.InstallationPermissions{Actions: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "administration scope",
			requested: map[string]string{"administration": "read"},
			granted:   &github.InstallationPermissions{Administration: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "attestations scope",
			requested: map[string]string{"attestations": "write"},
			granted:   &github.InstallationPermissions{Attestations: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "checks scope",
			requested: map[string]string{"checks": "write"},
			granted:   &github.InstallationPermissions{Checks: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "dependabot_secrets scope",
			requested: map[string]string{"dependabot_secrets": "read"},
			granted:   &github.InstallationPermissions{DependabotSecrets: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "deployments scope",
			requested: map[string]string{"deployments": "write"},
			granted:   &github.InstallationPermissions{Deployments: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "discussions scope",
			requested: map[string]string{"discussions": "read"},
			granted:   &github.InstallationPermissions{Discussions: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "environments scope",
			requested: map[string]string{"environments": "write"},
			granted:   &github.InstallationPermissions{Environments: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "issues scope",
			requested: map[string]string{"issues": "write"},
			granted:   &github.InstallationPermissions{Issues: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "merge_queues scope",
			requested: map[string]string{"merge_queues": "read"},
			granted:   &github.InstallationPermissions{MergeQueues: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "packages scope",
			requested: map[string]string{"packages": "write"},
			granted:   &github.InstallationPermissions{Packages: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "pages scope",
			requested: map[string]string{"pages": "read"},
			granted:   &github.InstallationPermissions{Pages: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "projects scope maps to RepositoryProjects",
			requested: map[string]string{"projects": "write"},
			granted:   &github.InstallationPermissions{RepositoryProjects: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "pull_requests scope",
			requested: map[string]string{"pull_requests": "write"},
			granted:   &github.InstallationPermissions{PullRequests: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "secret_scanning scope maps to SecretScanningAlerts",
			requested: map[string]string{"secret_scanning": "read"},
			granted:   &github.InstallationPermissions{SecretScanningAlerts: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "secrets scope",
			requested: map[string]string{"secrets": "write"},
			granted:   &github.InstallationPermissions{Secrets: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:      "statuses scope",
			requested: map[string]string{"statuses": "read"},
			granted:   &github.InstallationPermissions{Statuses: github.Ptr("read")},
			wantErr:   false,
		},
		{
			name:      "workflows scope",
			requested: map[string]string{"workflows": "write"},
			granted:   &github.InstallationPermissions{Workflows: github.Ptr("write")},
			wantErr:   false,
		},
		{
			name:        "multiple missing scopes",
			requested:   map[string]string{"contents": "write", "issues": "write", "actions": "read"},
			granted:     &github.InstallationPermissions{Contents: github.Ptr("write")},
			wantErr:     true,
			errContains: "missing",
		},
		{
			name: "all scopes granted",
			requested: map[string]string{
				"actions":            "write",
				"administration":     "read",
				"attestations":       "write",
				"checks":             "write",
				"contents":           "write",
				"dependabot_secrets": "write",
				"deployments":        "write",
				"discussions":        "write",
				"environments":       "write",
				"issues":             "write",
				"merge_queues":       "write",
				"packages":           "write",
				"pages":              "write",
				"projects":           "write",
				"pull_requests":      "write",
				"secret_scanning":    "read",
				"secrets":            "write",
				"statuses":           "write",
				"workflows":          "write",
			},
			granted: &github.InstallationPermissions{
				Actions:              github.Ptr("write"),
				Administration:       github.Ptr("read"),
				Attestations:         github.Ptr("write"),
				Checks:               github.Ptr("write"),
				Contents:             github.Ptr("write"),
				DependabotSecrets:    github.Ptr("write"),
				Deployments:          github.Ptr("write"),
				Discussions:          github.Ptr("write"),
				Environments:         github.Ptr("write"),
				Issues:               github.Ptr("write"),
				MergeQueues:          github.Ptr("write"),
				Packages:             github.Ptr("write"),
				Pages:                github.Ptr("write"),
				RepositoryProjects:   github.Ptr("write"),
				PullRequests:         github.Ptr("write"),
				SecretScanningAlerts: github.Ptr("read"),
				Secrets:              github.Ptr("write"),
				Statuses:             github.Ptr("write"),
				Workflows:            github.Ptr("write"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 3: Call VerifyRequestedScopes
			err := VerifyRequestedScopes(tt.requested, tt.granted)

			// Step 4 & 5: Verify results
			if tt.wantErr {
				// Verify error is returned
				if err == nil {
					t.Errorf("VerifyRequestedScopes() error = nil, wantErr = true")
					return
				}
				// Verify error message contains expected text
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("VerifyRequestedScopes() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			// Verify no error when scopes match
			if err != nil {
				t.Errorf("VerifyRequestedScopes() unexpected error = %v", err)
			}
		})
	}
}

// TestNewGitHubClientWithJWT tests GitHub client creation with JWT authentication.
// It verifies the function returns a non-nil client.
//
// Test steps:
//  1. Call NewGitHubClientWithJWT with a test token
//  2. Verify the returned client is not nil
func TestNewGitHubClientWithJWT(t *testing.T) {
	// Step 1: Create client with test token
	token := "test-jwt-token"
	client := NewGitHubClientWithJWT(token)

	// Step 2: Verify client is not nil
	if client == nil {
		t.Error("NewGitHubClientWithJWT() returned nil")
	}
}
