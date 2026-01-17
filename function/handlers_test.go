package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/token", nil)
			w := httptest.NewRecorder()

			TokenHandler(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusMethodNotAllowed)
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if !strings.Contains(resp.Error, "method not allowed") {
				t.Errorf("TokenHandler() error = %v, want containing 'method not allowed'", resp.Error)
			}
		})
	}
}

func TestTokenHandler_MissingAuthorizationHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "missing Authorization header") {
		t.Errorf("TokenHandler() error = %v, want containing 'missing Authorization header'", resp.Error)
	}
}

func TestTokenHandler_InvalidAuthorizationFormat(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
	}{
		{"Basic auth", "Basic dXNlcjpwYXNz"},
		{"No scheme", "just-a-token"},
		{"Empty bearer", "Bearer"},
		{"Wrong scheme", "Token abc123"},
		{"Multiple spaces", "Bearer  token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
			req.Header.Set("Authorization", tt.authHeader)
			w := httptest.NewRecorder()

			TokenHandler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if !strings.Contains(resp.Error, "invalid") {
				t.Errorf("TokenHandler() error = %v, want containing 'invalid'", resp.Error)
			}
		})
	}
}

func TestTokenHandler_InvalidOIDCToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"invalid format", "not-a-jwt"},
		{"empty token", ""},
		{"malformed jwt", "a.b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			w := httptest.NewRecorder()

			TokenHandler(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if !strings.Contains(resp.Error, "invalid OIDC token") {
				t.Errorf("TokenHandler() error = %v, want containing 'invalid OIDC token'", resp.Error)
			}
		})
	}
}

func TestTokenHandler_DuplicateScope(t *testing.T) {
	// Create a valid-looking JWT for the test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Note: Go's url.Values doesn't allow true duplicates via query string parsing
	// in the same way, but we can test with the URL directly
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read&contents=write", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "duplicate scope") {
		t.Errorf("TokenHandler() error = %v, want containing 'duplicate scope'", resp.Error)
	}
}

func TestTokenHandler_InvalidPermissionValue(t *testing.T) {
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	tests := []struct {
		name  string
		query string
	}{
		{"admin permission", "?contents=admin"},
		{"execute permission", "?contents=execute"},
		{"empty permission", "?contents="},
		{"uppercase READ", "?contents=READ"},
		{"uppercase WRITE", "?contents=WRITE"},
		{"numeric permission", "?contents=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token"+tt.query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			TokenHandler(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if !strings.Contains(resp.Error, "invalid permission") {
				t.Errorf("TokenHandler() error = %v, want containing 'invalid permission'", resp.Error)
			}
		})
	}
}

func TestTokenHandler_NoScopes(t *testing.T) {
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "at least one scope is required") {
		t.Errorf("TokenHandler() error = %v, want containing 'at least one scope is required'", resp.Error)
	}
}

func TestTokenHandler_UnknownScope(t *testing.T) {
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	req := httptest.NewRequest(http.MethodPost, "/token?unknown_scope=read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "not in allowlist") {
		t.Errorf("TokenHandler() error = %v, want containing 'not in allowlist'", resp.Error)
	}
}

func TestTokenHandler_ReadOnlyScopeWithWrite(t *testing.T) {
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	req := httptest.NewRequest(http.MethodPost, "/token?administration=write", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "permission 'write' not allowed") {
		t.Errorf("TokenHandler() error = %v, want containing \"permission 'write' not allowed\"", resp.Error)
	}
}

func TestWriteJSON(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		data           interface{}
		wantStatusCode int
		wantBody       string
	}{
		{
			name:           "success response",
			statusCode:     http.StatusOK,
			data:           TokenResponse{Token: "ghs_xxx", ExpiresAt: "2024-01-01T00:00:00Z", Scopes: map[string]string{"contents": "read"}},
			wantStatusCode: http.StatusOK,
			wantBody:       `{"token":"ghs_xxx","expires_at":"2024-01-01T00:00:00Z","scopes":{"contents":"read"}}`,
		},
		{
			name:           "error response",
			statusCode:     http.StatusBadRequest,
			data:           ErrorResponse{Error: "bad request", Details: nil},
			wantStatusCode: http.StatusBadRequest,
			wantBody:       `{"error":"bad request"}`,
		},
		{
			name:           "error response with details",
			statusCode:     http.StatusForbidden,
			data:           ErrorResponse{Error: "forbidden", Details: map[string]interface{}{"scope": "contents"}},
			wantStatusCode: http.StatusForbidden,
			wantBody:       `{"error":"forbidden","details":{"scope":"contents"}}`,
		},
		{
			name:           "empty object",
			statusCode:     http.StatusOK,
			data:           struct{}{},
			wantStatusCode: http.StatusOK,
			wantBody:       `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			writeJSON(w, tt.statusCode, tt.data)

			if w.Code != tt.wantStatusCode {
				t.Errorf("writeJSON() status = %v, want %v", w.Code, tt.wantStatusCode)
			}

			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("writeJSON() Content-Type = %v, want application/json", contentType)
			}

			if strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("writeJSON() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestWriteJSON_UnmarshalableData(t *testing.T) {
	w := httptest.NewRecorder()

	// Channels cannot be marshaled to JSON
	data := make(chan int)
	writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("writeJSON() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	if !strings.Contains(w.Body.String(), "failed to encode response") {
		t.Errorf("writeJSON() body = %v, want containing 'failed to encode response'", w.Body.String())
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
		details    map[string]interface{}
		wantBody   string
	}{
		{
			name:       "simple error",
			statusCode: http.StatusBadRequest,
			message:    "bad request",
			details:    nil,
			wantBody:   `{"error":"bad request"}`,
		},
		{
			name:       "error with details",
			statusCode: http.StatusForbidden,
			message:    "insufficient permissions",
			details:    map[string]interface{}{"missing": []string{"contents", "issues"}},
			wantBody:   `{"error":"insufficient permissions","details":{"missing":["contents","issues"]}}`,
		},
		{
			name:       "internal server error",
			statusCode: http.StatusInternalServerError,
			message:    "internal error",
			details:    nil,
			wantBody:   `{"error":"internal error"}`,
		},
		{
			name:       "service unavailable",
			statusCode: http.StatusServiceUnavailable,
			message:    "GitHub API unavailable",
			details:    nil,
			wantBody:   `{"error":"GitHub API unavailable"}`,
		},
		{
			name:       "empty details map is omitted due to omitempty",
			statusCode: http.StatusBadRequest,
			message:    "error",
			details:    map[string]interface{}{},
			wantBody:   `{"error":"error"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			writeError(w, tt.statusCode, tt.message, tt.details)

			if w.Code != tt.statusCode {
				t.Errorf("writeError() status = %v, want %v", w.Code, tt.statusCode)
			}

			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("writeError() Content-Type = %v, want application/json", contentType)
			}

			if strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("writeError() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestTokenHandler_ContentTypeHeader(t *testing.T) {
	// Test that error responses have correct content type
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("TokenHandler() Content-Type = %v, want application/json", contentType)
	}
}

func TestTokenHandler_BearerCaseInsensitive(t *testing.T) {
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Test lowercase "bearer" - should work
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	req.Header.Set("Authorization", "bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	// Should get past auth parsing - will fail later due to missing GITHUB_APP_ID
	// but that's OK - we're testing the bearer parsing
	if w.Code == http.StatusUnauthorized {
		var resp ErrorResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		if strings.Contains(resp.Error, "invalid Authorization header format") {
			t.Error("TokenHandler() should accept lowercase 'bearer'")
		}
	}
}

func TestTokenHandler_MissingGitHubAppID(t *testing.T) {
	// Save and unset GITHUB_APP_ID
	originalAppID := os.Getenv("GITHUB_APP_ID")
	os.Unsetenv("GITHUB_APP_ID")
	defer os.Setenv("GITHUB_APP_ID", originalAppID)

	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "GITHUB_APP_ID not configured") {
		t.Errorf("TokenHandler() error = %v, want containing 'GITHUB_APP_ID not configured'", resp.Error)
	}
}
