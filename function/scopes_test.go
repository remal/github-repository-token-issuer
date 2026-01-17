package main

import (
	"testing"
)

// TestAllowedScopes_NotEmpty verifies that AllowedScopes map contains entries.
// The allowlist must have at least one scope defined.
//
// Test steps:
//  1. Check the length of AllowedScopes map
//  2. Verify it is not empty
func TestAllowedScopes_NotEmpty(t *testing.T) {
	// Step 1 & 2: Check map is not empty
	if len(AllowedScopes) == 0 {
		t.Error("AllowedScopes should not be empty")
	}
}

// TestAllowedScopes_AllHaveValidPermissions verifies all permissions are valid.
// Each scope must have at least one permission, and all must be "read" or "write".
//
// Test steps:
//  1. Define valid permission values (read, write)
//  2. Iterate through all scopes in AllowedScopes
//  3. Verify each scope has at least one permission
//  4. Verify each permission is either "read" or "write"
func TestAllowedScopes_AllHaveValidPermissions(t *testing.T) {
	// Step 1: Define valid permissions
	validPermissions := map[string]bool{"read": true, "write": true}

	// Step 2: Iterate through all scopes
	for scopeID, permissions := range AllowedScopes {
		// Step 3: Verify scope has permissions
		if len(permissions) == 0 {
			t.Errorf("scope %q has no allowed permissions", scopeID)
			continue
		}

		// Step 4: Verify each permission is valid
		for _, perm := range permissions {
			if !validPermissions[perm] {
				t.Errorf("scope %q has invalid permission %q", scopeID, perm)
			}
		}
	}
}

// TestAllowedScopes_NoDuplicatePermissions verifies no scope has duplicate permissions.
// Each permission should appear at most once per scope.
//
// Test steps:
//  1. Iterate through all scopes in AllowedScopes
//  2. Track seen permissions for each scope
//  3. Verify no permission appears more than once
func TestAllowedScopes_NoDuplicatePermissions(t *testing.T) {
	// Step 1: Iterate through all scopes
	for scopeID, permissions := range AllowedScopes {
		// Step 2: Track seen permissions
		seen := make(map[string]bool)
		for _, perm := range permissions {
			// Step 3: Check for duplicates
			if seen[perm] {
				t.Errorf("scope %q has duplicate permission %q", scopeID, perm)
			}
			seen[perm] = true
		}
	}
}

// TestAllowedScopes_SecurityScopesAreReadOnly verifies security-sensitive scopes are read-only.
// Scopes like administration and secret_scanning must only allow read access.
//
// Test steps:
//  1. Define list of scopes that should be read-only
//  2. Iterate through each read-only scope
//  3. Verify scope exists in AllowedScopes
//  4. Verify scope only allows "read" permission
func TestAllowedScopes_SecurityScopesAreReadOnly(t *testing.T) {
	// Step 1: Define read-only scopes
	readOnlyScopes := []string{
		"administration",
		"secret_scanning",
	}

	// Step 2: Check each read-only scope
	for _, scopeID := range readOnlyScopes {
		// Step 3: Verify scope exists
		permissions, exists := AllowedScopes[scopeID]
		if !exists {
			t.Errorf("expected read-only scope %q not found in AllowedScopes", scopeID)
			continue
		}

		// Step 4: Verify only read is allowed
		if len(permissions) != 1 || permissions[0] != "read" {
			t.Errorf("scope %q should only allow 'read', got %v", scopeID, permissions)
		}
	}
}

// TestAllowedScopes_ReadWriteScopesHaveBoth verifies non-security scopes allow both read and write.
// Most repository scopes should support both permission levels.
//
// Test steps:
//  1. Define list of scopes that should allow both read and write
//  2. Iterate through each scope
//  3. Verify scope exists in AllowedScopes
//  4. Verify scope has both "read" and "write" permissions
func TestAllowedScopes_ReadWriteScopesHaveBoth(t *testing.T) {
	// Step 1: Define read-write scopes
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

	// Step 2: Check each scope
	for _, scopeID := range readWriteScopes {
		// Step 3: Verify scope exists
		permissions, exists := AllowedScopes[scopeID]
		if !exists {
			t.Errorf("expected read-write scope %q not found in AllowedScopes", scopeID)
			continue
		}

		// Step 4: Verify both permissions exist
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

// TestAllowedScopes_ExpectedCount verifies the total number of allowed scopes.
// This helps catch accidental additions or removals of scopes.
//
// Test steps:
//  1. Define expected scope count
//  2. Count actual scopes in AllowedScopes
//  3. Verify counts match
func TestAllowedScopes_ExpectedCount(t *testing.T) {
	// Step 1: Define expected count (based on scopes.go content)
	expectedCount := 19

	// Step 2 & 3: Verify count matches
	if len(AllowedScopes) != expectedCount {
		t.Errorf("AllowedScopes has %d scopes, expected %d", len(AllowedScopes), expectedCount)
	}
}

// TestAllowedScopes_NoOrganizationScopes verifies no organization-level scopes are present.
// Only repository-level permissions are allowed per security requirements.
//
// Test steps:
//  1. Define list of organization-level scopes that should NOT be present
//  2. Iterate through each org scope
//  3. Verify scope does NOT exist in AllowedScopes
func TestAllowedScopes_NoOrganizationScopes(t *testing.T) {
	// Step 1: Define organization scopes that should be blocked
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

	// Step 2 & 3: Verify none of these exist
	for _, orgScope := range orgScopes {
		if _, exists := AllowedScopes[orgScope]; exists {
			t.Errorf("organization scope %q should not be in AllowedScopes", orgScope)
		}
	}
}

// TestBlacklistedScopes_IsMap verifies BlacklistedScopes is a valid map.
// The blacklist must be initialized even if empty.
//
// Test steps:
//  1. Check if BlacklistedScopes is nil
//  2. Verify it is not nil (empty map is OK)
func TestBlacklistedScopes_IsMap(t *testing.T) {
	// Step 1 & 2: Verify map is initialized
	if BlacklistedScopes == nil {
		t.Error("BlacklistedScopes should not be nil")
	}
}

// TestBlacklistedScopes_NoOverlapWithAllowed verifies no scope is both allowed and blacklisted.
// A scope cannot be in both lists simultaneously.
//
// Test steps:
//  1. Iterate through all blacklisted scopes
//  2. Check if each scope exists in AllowedScopes
//  3. Fail if any scope is in both lists
func TestBlacklistedScopes_NoOverlapWithAllowed(t *testing.T) {
	// Step 1: Check each blacklisted scope
	for scopeID := range BlacklistedScopes {
		// Step 2 & 3: Verify not in allowlist
		if _, allowed := AllowedScopes[scopeID]; allowed {
			t.Errorf("scope %q is both allowed and blacklisted", scopeID)
		}
	}
}

// TestAllowedScopes_KnownScopes verifies commonly used scopes are present.
// This ensures essential scopes are not accidentally removed.
//
// Test steps:
//  1. Define list of essential scopes that must exist
//  2. Iterate through each essential scope
//  3. Verify scope exists in AllowedScopes
func TestAllowedScopes_KnownScopes(t *testing.T) {
	// Step 1: Define essential scopes
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

	// Step 2 & 3: Verify each scope exists
	for _, scopeID := range knownScopes {
		if _, exists := AllowedScopes[scopeID]; !exists {
			t.Errorf("expected scope %q not found in AllowedScopes", scopeID)
		}
	}
}

// TestAllowedScopes_PermissionsAreOrdered verifies permission order convention.
// Permissions should be listed as [read, write] for consistency.
//
// Test steps:
//  1. Iterate through all scopes with 2 permissions
//  2. Verify first permission is "read"
//  3. Verify second permission is "write"
func TestAllowedScopes_PermissionsAreOrdered(t *testing.T) {
	// Step 1: Check scopes with 2 permissions
	for scopeID, permissions := range AllowedScopes {
		if len(permissions) == 2 {
			// Step 2 & 3: Verify order
			if permissions[0] != "read" || permissions[1] != "write" {
				t.Errorf("scope %q permissions should be ['read', 'write'], got %v", scopeID, permissions)
			}
		}
	}
}
