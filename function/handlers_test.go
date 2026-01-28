package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Note: Tests requiring valid GitHub OIDC tokens (signature validation) are covered by CI/CD integration.
// Unit tests below cover request format validation that doesn't require valid tokens.

// TestTokenHandler_InvalidPath tests that requests to paths other than /token are rejected.
func TestTokenHandler_InvalidPath(t *testing.T) {
	paths := []string{"/", "/tokens", "/token/", "/api/token", "/foo"}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, nil)
			w := httptest.NewRecorder()

			TokenHandler(w, req)

			if w.Code != http.StatusNotFound {
				t.Errorf("TokenHandler() status = %v, want %v", w.Code, http.StatusNotFound)
			}

			var resp ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			if resp.Error != "not found" {
				t.Errorf("TokenHandler() error = %v, want 'not found'", resp.Error)
			}
		})
	}
}

// TestTokenHandler_MethodNotAllowed tests that non-POST methods are rejected.
// The token endpoint only accepts POST requests.
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

// TestTokenHandler_MissingAuthorizationHeader tests rejection of requests without Authorization header.
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

// TestTokenHandler_InvalidOIDCToken tests rejection of malformed OIDC tokens.
func TestTokenHandler_InvalidOIDCToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"invalid format", "not-a-jwt"},
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

// TestTokenHandler_ContentTypeHeader tests that all responses have JSON content type.
func TestTokenHandler_ContentTypeHeader(t *testing.T) {
	// Test that even error responses have JSON content type
	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()

	TokenHandler(w, req)

	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("TokenHandler() Content-Type = %v, want application/json", contentType)
	}
}

// TestWriteJSON tests JSON response writing with various data types.
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
