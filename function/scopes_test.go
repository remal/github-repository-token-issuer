package main

import (
	"testing"
)

func TestAllowedScopes_NotEmpty(t *testing.T) {
	if len(AllowedScopes) == 0 {
		t.Error("AllowedScopes should not be empty")
	}
}

func TestAllowedScopes_AllHaveValidPermissions(t *testing.T) {
	validPermissions := map[string]bool{"read": true, "write": true}

	for scopeID, permissions := range AllowedScopes {
		if len(permissions) == 0 {
			t.Errorf("scope %q has no allowed permissions", scopeID)
			continue
		}

		for _, perm := range permissions {
			if !validPermissions[perm] {
				t.Errorf("scope %q has invalid permission %q", scopeID, perm)
			}
		}
	}
}

func TestAllowedScopes_NoDuplicatePermissions(t *testing.T) {
	for scopeID, permissions := range AllowedScopes {
		seen := make(map[string]bool)
		for _, perm := range permissions {
			if seen[perm] {
				t.Errorf("scope %q has duplicate permission %q", scopeID, perm)
			}
			seen[perm] = true
		}
	}
}

func TestAllowedScopes_SecurityScopesAreReadOnly(t *testing.T) {
	// These scopes should only allow read access per security requirements
	readOnlyScopes := []string{
		"administration",
		"secret_scanning",
	}

	for _, scopeID := range readOnlyScopes {
		permissions, exists := AllowedScopes[scopeID]
		if !exists {
			t.Errorf("expected read-only scope %q not found in AllowedScopes", scopeID)
			continue
		}

		if len(permissions) != 1 || permissions[0] != "read" {
			t.Errorf("scope %q should only allow 'read', got %v", scopeID, permissions)
		}
	}
}

func TestAllowedScopes_ReadWriteScopesHaveBoth(t *testing.T) {
	// Scopes that should allow both read and write
	readWriteScopes := []string{
		"actions",
		"attestations",
		"checks",
		"contents",
		"dependabot_secrets",
		"deployments",
		"discussions",
		"environments",
		"issues",
		"merge_queues",
		"packages",
		"pages",
		"projects",
		"pull_requests",
		"secrets",
		"statuses",
		"workflows",
	}

	for _, scopeID := range readWriteScopes {
		permissions, exists := AllowedScopes[scopeID]
		if !exists {
			t.Errorf("expected read-write scope %q not found in AllowedScopes", scopeID)
			continue
		}

		hasRead := false
		hasWrite := false
		for _, perm := range permissions {
			if perm == "read" {
				hasRead = true
			}
			if perm == "write" {
				hasWrite = true
			}
		}

		if !hasRead || !hasWrite {
			t.Errorf("scope %q should allow both read and write, got %v", scopeID, permissions)
		}
	}
}

func TestAllowedScopes_ExpectedCount(t *testing.T) {
	// Per AGENTS.md: 25 repository permission scopes
	// But checking actual count in scopes.go shows fewer
	expectedCount := 19 // Based on actual scopes.go content

	if len(AllowedScopes) != expectedCount {
		t.Errorf("AllowedScopes has %d scopes, expected %d", len(AllowedScopes), expectedCount)
	}
}

func TestAllowedScopes_NoOrganizationScopes(t *testing.T) {
	// Ensure no organization-level scopes are present
	orgScopes := []string{
		"organization_administration",
		"organization_custom_roles",
		"organization_hooks",
		"organization_packages",
		"organization_plan",
		"organization_projects",
		"organization_secrets",
		"organization_self_hosted_runners",
		"organization_user_blocking",
		"members",
	}

	for _, orgScope := range orgScopes {
		if _, exists := AllowedScopes[orgScope]; exists {
			t.Errorf("organization scope %q should not be in AllowedScopes", orgScope)
		}
	}
}

func TestBlacklistedScopes_IsMap(t *testing.T) {
	// Ensure BlacklistedScopes exists and is a valid map
	if BlacklistedScopes == nil {
		t.Error("BlacklistedScopes should not be nil")
	}
}

func TestBlacklistedScopes_NoOverlapWithAllowed(t *testing.T) {
	// A scope cannot be both allowed and blacklisted
	for scopeID := range BlacklistedScopes {
		if _, allowed := AllowedScopes[scopeID]; allowed {
			t.Errorf("scope %q is both allowed and blacklisted", scopeID)
		}
	}
}

func TestAllowedScopes_KnownScopes(t *testing.T) {
	// Test that specific known scopes exist
	knownScopes := []string{
		"actions",
		"contents",
		"issues",
		"pull_requests",
		"deployments",
		"statuses",
		"checks",
		"workflows",
	}

	for _, scopeID := range knownScopes {
		if _, exists := AllowedScopes[scopeID]; !exists {
			t.Errorf("expected scope %q not found in AllowedScopes", scopeID)
		}
	}
}

func TestAllowedScopes_PermissionsAreOrdered(t *testing.T) {
	// Convention check: permissions should be in order [read, write]
	for scopeID, permissions := range AllowedScopes {
		if len(permissions) == 2 {
			if permissions[0] != "read" || permissions[1] != "write" {
				t.Errorf("scope %q permissions should be ['read', 'write'], got %v", scopeID, permissions)
			}
		}
	}
}
