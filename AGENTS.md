# Agent Development Guidelines

Project-specific guidelines for AI-assisted development of the GitHub Repository Token Issuer App.

## Operational Constraints

- **Budget Watchdog:** You are running on a restricted token budget.
- **Trigger:** If our conversation history exceeds 20 messages or the context feels bloated, you MUST end your response with: "⚠️ [Budget Alert] Context is heavy. Run /compact."
- **Files:** Do not read lockfiles (package-lock.json, etc) or huge logs unless explicitly told.
- **Documentation:** NEVER mark a task complete without updating documentation. See "Documentation Maintenance" checklist below.

## Project Philosophy

**Core Principle**: Secure, cost-effective, and simple. This is a single-purpose utility that issues GitHub tokens. Resist feature creep and over-engineering at all costs.

### Priorities (in order)

1. **Security** (but not too restrictive - enable necessary workflows)
2. **Costs**
3. **Simplicity**

### Architectural Decisions

1. **Stateless** - No database or persistent storage, all validation happens per-request
2. **Fail Fast** - No retries, no fallbacks, immediate error responses
3. **No Caching** - Fetch fresh data from Secret Manager and GitHub API on every request
4. **No Observability** - No logging, no metrics, no monitoring (intentional cost/complexity reduction)

## Technology Stack

- **Language**: Go
- **Platform**: Google Cloud Run
- **IaC**: Terraform (single main.tf file, GCS backend with locking)
- **CI/CD**: GitHub Actions (lint → terraform plan → gcloud deploy)
- **Libraries**:
  - `google/go-github` for GitHub API
  - `golang-jwt/jwt` or go-github's JWT methods
  - GCP Go SDK for Secret Manager
  - `GoogleCloudPlatform/functions-framework-go` for HTTP server

## Code Organization

```
function/     # All Go code
terraform/    # All infrastructure code
action.yml    # Composite action in root
.github/workflows/build.yml  # CI/CD
```

**Never** create files in repository root except:

- `action.yml` (already exists)
- Documentation (README.md, DEVELOPMENT.md, AGENTS.md)
- Standard files (.gitignore, LICENSE, etc.)

## Documentation Standards

- **README.md**: User-facing only (overview, usage, error codes, repo structure)
- **DEVELOPMENT.md**: Technical details (architecture, implementation, local dev, deployment)
- **CLAUDE.md**: AI agent development guidelines (this file)
- Keep Table of Contents updated in README.md and DEVELOPMENT.md
- No emojis unless explicitly requested
- Use GitHub-flavored markdown
- **Do not document `service_tag` action input in README.md** - this is an internal input for testing; it can be documented in DEVELOPMENT.md only

### Documentation Maintenance

**MANDATORY**: You MUST update documentation when code changes affect documented behavior. Add documentation updates to your todo list BEFORE starting implementation. Before completing any code change, verify:

- [ ] **README.md** updated (if usage, examples, variable defaults, or feature descriptions changed)
- [ ] **DEVELOPMENT.md** updated (if architecture, implementation, local dev, deployment changed)
- [ ] **AGENTS.md** updated (if variable design, coding patterns, or workflows changed)
- [ ] **terraform.tfvars.example** updated

Check for these files both at the repository root and in affected subdirectories. Do not consider a task complete until documentation matches the current code.

## Security Rules (NEVER violate)

1. **Repository permissions only** - Never add organization or account-level permissions
2. **Read-only security scopes** - These must stay read-only:

- `administration`
- `secret_scanning`

3. **No logging** of:

- OIDC tokens
- GitHub App private keys
- Installation access tokens
- JWT tokens

4. **Duplicate scope rejection** - Always return 400 if same scope appears multiple times

## What NOT to Add (Unless Explicitly Requested)

- ❌ Logging or monitoring
- ❌ Caching (tokens, Secret Manager responses, etc.)
- ❌ Retries or fallback logic
- ❌ Request deduplication
- ❌ Health check endpoints
- ❌ Metrics or observability
- ❌ Token revocation
- ❌ Custom token expiration
- ❌ Organization permissions
- ❌ Testing infrastructure (mentioned as "will think about later")
- ❌ Documentation beyond README.md, DEVELOPMENT.md, AGENTS.md

## Code Style

- **Error handling**: Fail fast, return errors immediately
- **Comments**: Only where logic isn't self-evident
- **Validation**: At system boundaries only (user input, external APIs)
- **Abstractions**: Avoid creating them for one-time operations
- **Configuration**: Environment variables for runtime, hardcoded Go constants for scopes
- **Formatting**: Run `gofmt -w .` after making changes to Go code
- **Terraform Formatting**: Run `terraform fmt -recursive` after making changes to Terraform files
- **Linting**: Run both `go vet ./...` and `golangci-lint run ./...` after code is changed

## Common Tasks

### Adding a New Repository Permission Scope

1. Update `function/scopes.go` with scope ID and allowed levels
2. Update README.md Allowed Scopes table
3. Update DEVELOPMENT.md if needed
4. Test and deploy via CI/CD

### Modifying API Behavior

- API is intentionally simple: single POST /token endpoint with query params
- Don't add new endpoints or change request/response format without explicit user request

### Updating Documentation

- README changes: Update Table of Contents if adding/removing sections
- Technical details go in DEVELOPMENT.md, not README
- Keep examples accurate and tested

## Deployment Approach

- **Image Registry**: Artifact Registry at `us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer`
- **Changes to function/**: Build Go binary, create Docker image, push to Artifact Registry, deploy to Cloud Run:
  ```bash
  cd function
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o function .
  SHORT_SHA=$(git rev-parse --short HEAD)
  docker build -t us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA} .
  docker push us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA}
  gcloud run deploy gh-repo-token-issuer --image=us-east4-docker.pkg.dev/gh-repo-token-issuer/gh-repo-token-issuer/function:${SHORT_SHA} --region=us-east4
  ```
- **Changes to terraform/**: Run `terraform validate`, then plan, then apply
- **CI/CD**: Triggered on push to main, runs lint → terraform apply → go build → docker build/push → gcloud deploy
- **Canary deployments**: Use `--no-traffic --tag=commit-$(git rev-parse --short HEAD)` for safe rollouts

## Scope Management

**Allowlist** (in `function/scopes.go`):

- 19 repository permission scopes
- Map of scope_id → []string{"read", "write"} or []string{"read"}
- Security scopes are read-only

**Blacklist**: Currently empty, can be used to block specific scopes

**Validation order**:

1. Check for duplicates → 400
2. Check blacklist → 400
3. Check allowlist → 400
4. Verify permission levels → 400
5. Query GitHub for granted permissions → 403 if insufficient
6. Request token → 403 if GitHub returns fewer scopes than requested

## GitHub Actions Integration

- Composite action at `./action.yml`
- Inputs:
  - `scopes` (required): multiline format, one scope:permission per line
- Output: `token`
- Requires `permissions: id-token: write` in workflow

## When Modifying This Project

1. **Read first** - Never propose changes to code you haven't read
2. **Stay minimal** - Only make changes directly requested or clearly necessary
3. **No "improvements"** - Don't refactor, don't add error handling for impossible scenarios
4. **Test assumptions** - If unclear, use AskUserQuestion
5. **Update both docs** - README.md and DEVELOPMENT.md must stay in sync

## Error Response Format

Always return JSON errors with this structure:

```json
{
  "error": "Human-readable message",
  "details": {
    /* optional context */
  }
}
```

Standard status codes: 400, 401, 403, 500, 503 (see DEVELOPMENT.md for mappings)

## API Design Principles

### Single Endpoint Philosophy

- **One endpoint**: POST /token
- **Query parameters for scopes**: `?scope_id=permission&scope_id=permission`
- **No path parameters**: No `/repos/{owner}/{repo}` style paths
- **No path validation**: Don't validate repository in URL against OIDC claims
- **Single-token authentication**: GitHub OIDC token for authentication and repository identification

### Request Format

**Query Parameters**:

```
?contents=write&deployments=write&statuses=write
```

**Headers**:

```
Authorization: Bearer <GITHUB_OIDC_TOKEN>
```

**No request body** - all parameters in query string

### Response Format

**Success (200)**:

```json
{
  "token": "ghs_...",
  "expires_at": "2026-01-11T13:00:00Z",
  "scopes": {
    "contents": "write",
    "deployments": "write"
  }
}
```

**Error (4xx/5xx)**:

```json
{
  "error": "Human-readable message",
  "details": {
    /* optional */
  }
}
```

## Implementation Details

### OIDC Token Handling

- **Function validates** the GitHub OIDC token from Authorization header (Bearer token):
  - Signature against GitHub's JWKS
  - Issuer (`https://token.actions.githubusercontent.com`)
  - Audience (`gh-repo-token-issuer`)
  - Expiration
- **Function extracts** repository claim from validated OIDC token
- **Service is publicly accessible** - security is enforced by OIDC token validation

### Scope Parsing

```go
// Parse query parameters
scopes := make(map[string]string)
for param, values := range r.URL.Query() {
if len(values) > 1 {
return fmt.Errorf("duplicate scope '%s' in request", param)
}
permission := values[0]
if permission != "read" && permission != "write" {
return fmt.Errorf("invalid permission '%s' for scope '%s'", permission, param)
}
scopes[param] = permission
}
```

### JWT Creation

- **Algorithm**: RS256
- **Expiration**: 10 minutes (GitHub's maximum)
- **Claims**: iat, exp, iss (GitHub App ID)
- **Signing**: Use private key from Secret Manager

### Installation Token Request

- Request token with exact scopes
- Fixed 1-hour expiration
- Verify granted scopes match requested scopes exactly
- Return 403 if GitHub returns fewer scopes than requested

## File Structure

### function/

```
function/
├── Dockerfile     # Multi-stage build for Cloud Run
├── main.go        # Functions Framework entry point, startup validation
├── handlers.go    # TokenHandler, query param parsing, response formatting
├── validation.go  # ValidateScopes, ExtractRepositoryFromOIDC, duplicate detection
├── scopes.go      # AllowedScopes map, BlacklistedScopes set
├── github.go      # GitHub API client, JWT creation, token issuance
├── go.mod         # Dependencies
└── go.sum         # Checksums
```

### terraform/

```
terraform/
├── main.tf      # All GCP resources (Cloud Run, Secret Manager IAM, Workload Identity)
├── variables.tf # Input variables (project_id, region, github_app_id)
└── outputs.tf   # Output values (Cloud Run URL)
```

## Future Work

**Testing**: User mentioned "will think about testing later" - don't add test infrastructure proactively

**Monitoring**: Intentionally omitted for simplicity - don't add unless explicitly requested

**Performance**: Current design (no caching, fetch every request) is intentional for simplicity
