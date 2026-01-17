package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestTokenHandler_MethodNotAllowed tests that non-POST methods are rejected.
// The token endpoint only accepts POST requests.
//
// Test steps:
//  1. Create HTTP request with non-POST method (GET, PUT, DELETE, etc.)
//  2. Call TokenHandler with the request
//  3. Verify response status is 405 Method Not Allowed
//  4. Verify response body contains "method not allowed" error message
func TestTokenHandler_MethodNotAllowed(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead, http.MethodOptions}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			// Step 1: Create request with non-POST method
			req := httptest.NewRequest(method, "/token", nil)
			w := httptest.NewRecorder()

			// Step 2: Call handler
			TokenHandler(w, req)

			// Step 3: Verify 405 status
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusMethodNotAllowed)
			}

			// Step 4: Verify error message
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

// TestTokenHandler_MissingAuthorizationHeader tests rejection of requests without auth header.
// Authorization header with OIDC token is required for all requests.
//
// Test steps:
//  1. Create POST request without Authorization header
//  2. Call TokenHandler with the request
//  3. Verify response status is 401 Unauthorized
//  4. Verify response body contains "missing Authorization header" error
func TestTokenHandler_MissingAuthorizationHeader(t *testing.T) {
	// Step 1: Create request without Authorization header
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	w := httptest.NewRecorder()

	// Step 2: Call handler
	TokenHandler(w, req)

	// Step 3: Verify 401 status
	if w.Code != http.StatusUnauthorized {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
	}

	// Step 4: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "missing Authorization header") {
		t.Errorf("TokenHandler() error = %v, want containing 'missing Authorization header'", resp.Error)
	}
}

// TestTokenHandler_InvalidAuthorizationFormat tests rejection of malformed auth headers.
// Authorization header must be in "Bearer <token>" format.
//
// Test steps:
//  1. Create POST request with invalid Authorization header format
//  2. Call TokenHandler with the request
//  3. Verify response status is 401 Unauthorized
//  4. Verify response body contains "invalid" error message
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
			// Step 1: Create request with invalid auth header
			req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
			req.Header.Set("Authorization", tt.authHeader)
			w := httptest.NewRecorder()

			// Step 2: Call handler
			TokenHandler(w, req)

			// Step 3: Verify 401 status
			if w.Code != http.StatusUnauthorized {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
			}

			// Step 4: Verify error message contains "invalid"
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

// TestTokenHandler_InvalidOIDCToken tests rejection of malformed OIDC tokens.
// OIDC tokens must be valid JWTs with repository claim.
//
// Test steps:
//  1. Create POST request with malformed Bearer token
//  2. Call TokenHandler with the request
//  3. Verify response status is 401 Unauthorized
//  4. Verify response body contains "invalid OIDC token" error
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
			// Step 1: Create request with malformed token
			req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			w := httptest.NewRecorder()

			// Step 2: Call handler
			TokenHandler(w, req)

			// Step 3: Verify 401 status
			if w.Code != http.StatusUnauthorized {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusUnauthorized)
			}

			// Step 4: Verify error message
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

// TestTokenHandler_DuplicateScope tests rejection of requests with duplicate scopes.
// Each scope must appear exactly once in the query parameters.
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request with duplicate scope in query params
//  3. Call TokenHandler with the request
//  4. Verify response status is 400 Bad Request
//  5. Verify response body contains "duplicate scope" error
func TestTokenHandler_DuplicateScope(t *testing.T) {
	// Step 1: Create valid JWT for test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Step 2: Create request with duplicate scope
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read&contents=write", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify 400 status
	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	// Step 5: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "duplicate scope") {
		t.Errorf("TokenHandler() error = %v, want containing 'duplicate scope'", resp.Error)
	}
}

// TestTokenHandler_InvalidPermissionValue tests rejection of invalid permission values.
// Permission values must be either "read" or "write" (lowercase).
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request with invalid permission value
//  3. Call TokenHandler with the request
//  4. Verify response status is 400 Bad Request
//  5. Verify response body contains "invalid permission" error
func TestTokenHandler_InvalidPermissionValue(t *testing.T) {
	// Step 1: Create valid JWT for test
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
			// Step 2: Create request with invalid permission
			req := httptest.NewRequest(http.MethodPost, "/token"+tt.query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			// Step 3: Call handler
			TokenHandler(w, req)

			// Step 4: Verify 400 status
			if w.Code != http.StatusBadRequest {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
			}

			// Step 5: Verify error message
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

// TestTokenHandler_NoScopes tests rejection of requests without any scopes.
// At least one scope must be specified in query parameters.
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request without any scope query params
//  3. Call TokenHandler with the request
//  4. Verify response status is 400 Bad Request
//  5. Verify response body contains "at least one scope is required" error
func TestTokenHandler_NoScopes(t *testing.T) {
	// Step 1: Create valid JWT for test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Step 2: Create request without scopes
	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify 400 status
	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	// Step 5: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "at least one scope is required") {
		t.Errorf("TokenHandler() error = %v, want containing 'at least one scope is required'", resp.Error)
	}
}

// TestTokenHandler_UnknownScope tests rejection of requests with unknown scopes.
// Scopes must be in the allowlist to be accepted.
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request with unknown scope in query params
//  3. Call TokenHandler with the request
//  4. Verify response status is 400 Bad Request
//  5. Verify response body contains "not in allowlist" error
func TestTokenHandler_UnknownScope(t *testing.T) {
	// Step 1: Create valid JWT for test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Step 2: Create request with unknown scope
	req := httptest.NewRequest(http.MethodPost, "/token?unknown_scope=read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify 400 status
	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	// Step 5: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "not in allowlist") {
		t.Errorf("TokenHandler() error = %v, want containing 'not in allowlist'", resp.Error)
	}
}

// TestTokenHandler_ReadOnlyScopeWithWrite tests rejection of write permission on read-only scopes.
// Some scopes (like administration, secret_scanning) only allow read access.
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request with write permission on read-only scope
//  3. Call TokenHandler with the request
//  4. Verify response status is 400 Bad Request
//  5. Verify response body contains "permission 'write' not allowed" error
func TestTokenHandler_ReadOnlyScopeWithWrite(t *testing.T) {
	// Step 1: Create valid JWT for test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Step 2: Create request with write on read-only scope
	req := httptest.NewRequest(http.MethodPost, "/token?administration=write", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify 400 status
	if w.Code != http.StatusBadRequest {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusBadRequest)
	}

	// Step 5: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "permission 'write' not allowed") {
		t.Errorf("TokenHandler() error = %v, want containing \"permission 'write' not allowed\"", resp.Error)
	}
}

// TestWriteJSON tests JSON response writing with various data types.
// It verifies correct status codes, content-type headers, and JSON body.
//
// Test steps:
//  1. Create response recorder
//  2. Call writeJSON with test data and status code
//  3. Verify response status matches expected
//  4. Verify Content-Type header is application/json
//  5. Verify response body matches expected JSON
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
			// Step 1: Create response recorder
			w := httptest.NewRecorder()

			// Step 2: Call writeJSON
			writeJSON(w, tt.statusCode, tt.data)

			// Step 3: Verify status code
			if w.Code != tt.wantStatusCode {
				t.Errorf("writeJSON() status = %v, want %v", w.Code, tt.wantStatusCode)
			}

			// Step 4: Verify Content-Type header
			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("writeJSON() Content-Type = %v, want application/json", contentType)
			}

			// Step 5: Verify response body
			if strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("writeJSON() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

// TestWriteJSON_UnmarshalableData tests error handling for unmarshalable data.
// When JSON marshaling fails, it should return 500 error.
//
// Test steps:
//  1. Create response recorder
//  2. Call writeJSON with unmarshalable data (channel)
//  3. Verify response status is 500 Internal Server Error
//  4. Verify response body contains error message
func TestWriteJSON_UnmarshalableData(t *testing.T) {
	// Step 1: Create response recorder
	w := httptest.NewRecorder()

	// Step 2: Call writeJSON with unmarshalable data (channels cannot be marshaled)
	data := make(chan int)
	writeJSON(w, http.StatusOK, data)

	// Step 3: Verify 500 status
	if w.Code != http.StatusInternalServerError {
		t.Errorf("writeJSON() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	// Step 4: Verify error message
	if !strings.Contains(w.Body.String(), "failed to encode response") {
		t.Errorf("writeJSON() body = %v, want containing 'failed to encode response'", w.Body.String())
	}
}

// TestWriteError tests error response writing with various status codes.
// It verifies correct JSON error format with optional details.
//
// Test steps:
//  1. Create response recorder
//  2. Call writeError with message, status code, and optional details
//  3. Verify response status matches expected
//  4. Verify Content-Type header is application/json
//  5. Verify response body matches expected JSON error format
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
			// Step 1: Create response recorder
			w := httptest.NewRecorder()

			// Step 2: Call writeError
			writeError(w, tt.statusCode, tt.message, tt.details)

			// Step 3: Verify status code
			if w.Code != tt.statusCode {
				t.Errorf("writeError() status = %v, want %v", w.Code, tt.statusCode)
			}

			// Step 4: Verify Content-Type header
			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("writeError() Content-Type = %v, want application/json", contentType)
			}

			// Step 5: Verify response body
			if strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("writeError() body = %v, want %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

// TestTokenHandler_ContentTypeHeader tests that all responses have JSON content type.
// All responses (success and error) must have Content-Type: application/json.
//
// Test steps:
//  1. Create request that will trigger an error response
//  2. Call TokenHandler with the request
//  3. Verify Content-Type header is application/json
func TestTokenHandler_ContentTypeHeader(t *testing.T) {
	// Step 1: Create request that triggers error (wrong method)
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	// Step 2: Call handler
	TokenHandler(w, req)

	// Step 3: Verify Content-Type header
	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("TokenHandler() Content-Type = %v, want application/json", contentType)
	}
}

// TestTokenHandler_BearerCaseInsensitive tests that "Bearer" scheme is case-insensitive.
// Both "Bearer" and "bearer" should be accepted in Authorization header.
//
// Test steps:
//  1. Create valid JWT token for test
//  2. Create POST request with lowercase "bearer" scheme
//  3. Call TokenHandler with the request
//  4. Verify request passes auth parsing (may fail later due to missing config)
func TestTokenHandler_BearerCaseInsensitive(t *testing.T) {
	// Step 1: Create valid JWT for test
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})

	// Step 2: Create request with lowercase "bearer"
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	req.Header.Set("Authorization", "bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify request passes auth parsing
	// (will fail later due to missing GITHUB_APP_ID, but that's OK)
	if w.Code == http.StatusUnauthorized {
		var resp ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}
		if strings.Contains(resp.Error, "invalid Authorization header format") {
			t.Error("TokenHandler() should accept lowercase 'bearer'")
		}
	}
}

// TestTokenHandler_MissingGitHubAppID tests error when GITHUB_APP_ID is not configured.
// The function should return 500 when required environment variable is missing.
//
// Test steps:
//  1. Save and unset GITHUB_APP_ID environment variable
//  2. Create valid JWT token and POST request
//  3. Call TokenHandler with the request
//  4. Verify response status is 500 Internal Server Error
//  5. Verify response contains "GITHUB_APP_ID not configured" error
//  6. Restore original GITHUB_APP_ID value
func TestTokenHandler_MissingGitHubAppID(t *testing.T) {
	// Step 1: Unset GITHUB_APP_ID (t.Setenv restores original value on cleanup)
	t.Setenv("GITHUB_APP_ID", "")
	if err := os.Unsetenv("GITHUB_APP_ID"); err != nil {
		t.Fatalf("failed to unset GITHUB_APP_ID: %v", err)
	}

	// Step 2: Create valid JWT and request
	token := createTestJWT(map[string]interface{}{"repository": "owner/repo"})
	req := httptest.NewRequest(http.MethodPost, "/token?contents=read", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// Step 3: Call handler
	TokenHandler(w, req)

	// Step 4: Verify 500 status
	if w.Code != http.StatusInternalServerError {
		t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusInternalServerError)
	}

	// Step 5: Verify error message
	var resp ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if !strings.Contains(resp.Error, "GITHUB_APP_ID not configured") {
		t.Errorf("TokenHandler() error = %v, want containing 'GITHUB_APP_ID not configured'", resp.Error)
	}
}
