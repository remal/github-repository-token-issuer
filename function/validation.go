package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	githubOIDCIssuer  = "https://token.actions.githubusercontent.com"
	githubJWKSURL     = "https://token.actions.githubusercontent.com/.well-known/jwks"
	expectedAudience  = "gh-repo-token-issuer"
	jwksCacheDuration = 1 * time.Hour
)

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

var (
	jwksCache     *JWKS
	jwksCacheTime time.Time
	jwksMutex     sync.RWMutex
)

// fetchJWKS fetches GitHub's JWKS with caching.
func fetchJWKS(ctx context.Context) (*JWKS, error) {
	jwksMutex.RLock()
	if jwksCache != nil && time.Since(jwksCacheTime) < jwksCacheDuration {
		defer jwksMutex.RUnlock()
		return jwksCache, nil
	}
	jwksMutex.RUnlock()

	jwksMutex.Lock()
	defer jwksMutex.Unlock()

	// Double-check after acquiring write lock
	if jwksCache != nil && time.Since(jwksCacheTime) < jwksCacheDuration {
		return jwksCache, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubJWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS request failed with status %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	jwksCache = &jwks
	jwksCacheTime = time.Now()
	return &jwks, nil
}

// getPublicKey extracts the RSA public key for the given key ID from JWKS.
func getPublicKey(jwks *JWKS, kid string) (*rsa.PublicKey, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			// Decode modulus
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, fmt.Errorf("failed to decode modulus: %w", err)
			}

			// Decode exponent
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, fmt.Errorf("failed to decode exponent: %w", err)
			}

			// Convert exponent bytes to int
			var e int
			for _, b := range eBytes {
				e = e<<8 + int(b)
			}

			return &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: e,
			}, nil
		}
	}
	return nil, fmt.Errorf("key %s not found in JWKS", kid)
}

// ValidateAndExtractRepository validates the GitHub OIDC token and extracts the repository claim.
// Validates: signature (against GitHub's JWKS), issuer, audience, and expiration.
func ValidateAndExtractRepository(ctx context.Context, tokenString string) (string, error) {
	// Fetch JWKS
	jwks, err := fetchJWKS(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Get public key from JWKS
		return getPublicKey(jwks, kid)
	}, jwt.WithIssuer(githubOIDCIssuer),
		jwt.WithAudience(expectedAudience),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		return "", fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to extract claims")
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
		if !slices.Contains(allowedLevels, permission) {
			return fmt.Errorf("permission '%s' not allowed for scope '%s' (allowed: %v)",
				permission, scopeID, allowedLevels)
		}
	}

	return nil
}

// ParseAllowedOwners parses the GITHUB_ALLOWED_OWNERS environment variable.
// Returns a slice of allowed owners (empty slice means all owners are allowed).
// Format: comma-separated list of owner names, whitespace is trimmed.
func ParseAllowedOwners() []string {
	owners := []string{}
	envValue := os.Getenv("GITHUB_ALLOWED_OWNERS")
	for _, part := range strings.Split(envValue, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			owners = append(owners, trimmed)
		}
	}
	return owners
}

// ValidateOwnerAllowed validates that the repository owner is in the allowed list.
// If allowedOwners is empty, all owners are allowed.
// Repository format is expected to be "owner/repo".
func ValidateOwnerAllowed(repository string, allowedOwners []string) error {
	if len(allowedOwners) == 0 {
		return nil
	}

	parts := strings.Split(repository, "/")
	if len(parts) < 2 {
		return fmt.Errorf("invalid repository format: %s", repository)
	}
	owner := parts[0]

	for _, allowed := range allowedOwners {
		if allowed == owner {
			return nil
		}
	}

	return fmt.Errorf("repository owner '%s' is not allowed", owner)
}
