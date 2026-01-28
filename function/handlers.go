package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// TokenResponse is the successful response format.
type TokenResponse struct {
	Token     string            `json:"token"`
	ExpiresAt string            `json:"expires_at"`
	Scopes    map[string]string `json:"scopes"`
}

// ErrorResponse is the error response format.
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// TokenHandler handles POST /token requests.
func TokenHandler(w http.ResponseWriter, r *http.Request) {
	// Enforce /token path
	if r.URL.Path != "/token" {
		writeError(w, http.StatusNotFound, "not found", nil)
		return
	}

	// Only allow POST method
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Extract GitHub OIDC token from Authorization header (Bearer token)
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeError(w, http.StatusUnauthorized, "missing Authorization header", nil)
		return
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		writeError(w, http.StatusUnauthorized, "invalid Authorization header format (expected 'Bearer <token>')", nil)
		return
	}
	oidcToken := strings.TrimPrefix(authHeader, bearerPrefix)
	if oidcToken == "" {
		writeError(w, http.StatusUnauthorized, "empty token in Authorization header", nil)
		return
	}

	// Validate OIDC token and extract repository
	repository, err := ValidateAndExtractRepository(ctx, oidcToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Sprintf("invalid OIDC token: %v", err), nil)
		return
	}

	// Parse scopes from query parameters
	scopes := make(map[string]string)
	for param, values := range r.URL.Query() {
		if len(values) > 1 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("duplicate scope '%s' in request", param), nil)
			return
		}
		permission := values[0]

		// Validate permission value
		if permission != "read" && permission != "write" {
			writeError(w,
				http.StatusBadRequest,
				fmt.Sprintf("invalid permission '%s' for scope '%s' (must be 'read' or 'write')", permission, param),
				nil)
			return
		}

		scopes[param] = permission
	}

	// Require at least one scope
	if len(scopes) == 0 {
		writeError(w, http.StatusBadRequest, "at least one scope is required", nil)
		return
	}

	// Validate scopes
	if err := ValidateScopes(scopes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Get GitHub App ID from environment (validated at startup in main.go)
	appID := os.Getenv("GITHUB_APP_ID")

	// Get GCP project ID from environment
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	if projectID == "" {
		// Try alternative environment variable
		projectID = os.Getenv("GCP_PROJECT")
	}
	if projectID == "" {
		writeError(w, http.StatusInternalServerError, "GCP project ID not configured", nil)
		return
	}

	// Fetch private key from Secret Manager
	privateKey, err := GetPrivateKey(ctx, projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error(), nil)
		return
	}

	// Create JWT for GitHub App authentication
	jwtToken, err := CreateJWT(privateKey, appID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create JWT: %v", err), nil)
		return
	}

	// Create GitHub client with JWT
	githubClient := NewGitHubClientWithJWT(jwtToken)

	// Get installation ID for repository
	installationID, err := GetInstallationID(ctx, githubClient.Apps, repository)
	if err != nil {
		if strings.Contains(err.Error(), "not installed") {
			writeError(w, http.StatusForbidden, err.Error(), nil)
		} else {
			writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("GitHub API error: %v", err), nil)
		}
		return
	}

	// Create installation token with requested scopes
	token, err := CreateInstallationToken(ctx, githubClient.Apps, installationID, scopes)
	if err != nil {
		if strings.Contains(err.Error(), "insufficient permissions") ||
			strings.Contains(err.Error(), "fewer scopes") ||
			strings.Contains(err.Error(), "suspended") {
			writeError(w, http.StatusForbidden, err.Error(), nil)
		} else {
			writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("GitHub API error: %v", err), nil)
		}
		return
	}

	// Build response
	response := TokenResponse{
		Token:     token.GetToken(),
		ExpiresAt: token.GetExpiresAt().Format(time.RFC3339),
		Scopes:    scopes,
	}

	writeJSON(w, http.StatusOK, response)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error: failed to encode response"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(jsonBytes)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, statusCode int, message string, details map[string]interface{}) {
	response := ErrorResponse{
		Error:   message,
		Details: details,
	}
	writeJSON(w, statusCode, response)
}
