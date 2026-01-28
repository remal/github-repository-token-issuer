# GitHub Repository Token Issuer App

A secure, serverless GitHub App hosted on Google Cloud Platform that issues short-lived, scoped GitHub installation tokens to GitHub Actions workflows.

## Table of Contents

- [Overview](#overview)
- [Usage](#usage)
- [Repository Structure](#repository-structure)
- [Contributing](#contributing)
- [Support](#support)

## Overview

This GitHub App provides a secure mechanism for GitHub Actions workflows to obtain short-lived GitHub installation tokens with specific scopes and permissions. The app runs as a Cloud Run service on GCP and authenticates callers by validating GitHub OIDC tokens directly.

### Why Use This?

GitHub Actions workflows typically use the built-in `GITHUB_TOKEN`, but it has significant limitations:

- **Cannot trigger other workflows**: Actions performed with `GITHUB_TOKEN` (especially with `contents: write`) do not trigger subsequent GitHub Actions workflows, breaking automation chains
- **Limited scope control**: You cannot request tokens with only the specific scopes you need
- **Repository-bound**: The default token is tied to the repository running the workflow
- **Requires manual secret management**: Personal Access Tokens (PATs) must be created, stored in GitHub Secrets, rotated manually, and managed across all repositories

This app solves these problems by issuing short-lived GitHub App installation tokens that:

- **Trigger workflows**: Operations performed with these tokens trigger GitHub Actions normally
- **Fine-grained repository permissions**: Request only the specific repository-level scopes you need (e.g., `issues:write`, `pull_requests:read`, `deployments:write`)
- **Enhanced security**: Short-lived tokens (1 hour expiration) minimize exposure risk
- **No secret management required**: Just install the GitHub App on your repositories and use the action - no need to create, store, or rotate tokens in GitHub Secrets
- **Centralized access control**: Install the app once, use it across all repositories without duplicating secrets
- **Easier onboarding**: New repositories can start using tokens immediately after app installation, no manual secret configuration needed

**Note**: This app only issues tokens with **repository-level permissions**. Organization-level or account-level permissions are not supported.

### Key Features

- Serverless Cloud Run service for automatic scaling
- Direct GitHub OIDC token validation (no GCP IAM required for callers)
- Scope allowlisting and blacklisting for security
- Simple API with query parameter-based scope specification
- Automated CI/CD pipeline using GitHub Actions and Terraform
- Minimal operational overhead with no logging or observability

> **For Developers**: See [DEVELOPMENT.md](DEVELOPMENT.md) for technical architecture, implementation details, and local development setup.

## Usage

### Composite GitHub Action

The repository includes a composite action (`action.yml`) that simplifies calling the function from workflows.

**Location**: `./action.yml` in repository root

**Inputs**:

- `scopes`: (required) Repository permission scopes in format `scope_id:permission`, one per line
  - Use scope IDs from the [Allowed Repository Permission Scopes](#allowed-repository-permission-scopes) table
  - Example:
    ```yaml
    scopes: |
      issues:write
      pull_requests:read
      deployments:write
    ```
- `service_tag`: (optional) Cloud Run service tag for canary deployments
  - When set, uses the tag-specific URL (e.g., `https://<tag>---gh-repo-token-issuer-...`)
  - Used for testing new deployments before migrating traffic

**Outputs**:

- `token`: The issued GitHub installation token

**Example Usage**:

```yaml
name: Deploy

on:
  push:
    branches: [ main ]

permissions:
  id-token: write  # Required for OIDC token

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - name: Get GitHub Token
      id: get-token
      uses: remal/github-repository-token-issuer@main
      with:
        scopes: |
          contents:write
          deployments:write
          statuses:write

    - name: Use Token
      env:
        GITHUB_TOKEN: ${{ steps.get-token.outputs.token }}
      run: |
        # Use the token for authenticated GitHub API calls that trigger workflows
        # Unlike the default GITHUB_TOKEN, this will trigger subsequent workflow runs
        git config user.name "github-actions[bot]"
        git config user.email "github-actions[bot]@users.noreply.github.com"
        echo "deployed" > deployment.txt
        git add deployment.txt
        git commit -m "Deploy to production"
        git push
```

### Manual API Call (for testing)

The service authenticates callers using GitHub OIDC tokens. The token is validated by the function itself (signature verification against GitHub's JWKS, issuer, audience, and expiration).

```bash
# 1. Obtain GitHub OIDC token (audience must be 'gh-repo-token-issuer')
GITHUB_OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=gh-repo-token-issuer" | jq -r .value)

# 2. Call the function with the OIDC token
curl -X POST \
  -H "Authorization: Bearer ${GITHUB_OIDC_TOKEN}" \
  "https://gh-repo-token-issuer-xyz.run.app/token?contents=write&deployments=write&statuses=write"
```

**Note**: This endpoint is only accessible from GitHub Actions workflows. The OIDC token proves the request originated from a specific repository's workflow.

### Allowed Repository Permission Scopes

**Important**: This app only works with **repository-level permissions**. Organization-level and account-level permissions are not supported.

The following repository permission scopes are allowed (use the Scope ID in your action):

| Permission Name        | Scope ID             | Available Levels |
|------------------------|----------------------|------------------|
| Actions                | `actions`            | read, write      |
| Administration         | `administration`     | read             |
| Attestations           | `attestations`       | read, write      |
| Checks                 | `checks`             | read, write      |
| Commit statuses        | `statuses`           | read, write      |
| Contents               | `contents`           | read, write      |
| Dependabot secrets     | `dependabot_secrets` | read, write      |
| Deployments            | `deployments`        | read, write      |
| Discussions            | `discussions`        | read, write      |
| Environments           | `environments`       | read, write      |
| Issues                 | `issues`             | read, write      |
| Merge queues           | `merge_queues`       | read, write      |
| Packages               | `packages`           | read, write      |
| Pages                  | `pages`              | read, write      |
| Projects               | `projects`           | read, write      |
| Pull requests          | `pull_requests`      | read, write      |
| Secret scanning alerts | `secret_scanning`    | read             |
| Secrets                | `secrets`            | read, write      |
| Workflows              | `workflows`          | read, write      |

**Note**: `secret_scanning` is restricted to read-only access for security reasons.

### Error Code Catalog

| Error Message                                        | Cause                                                         | Resolution                                                                                                                              |
|------------------------------------------------------|---------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `duplicate scope 'X' in request`                     | Same scope appears multiple times in query params             | Remove duplicate scopes - each scope should appear only once                                                                            |
| `scope 'X' is not allowed`                           | Requested scope is blacklisted or not a repository permission | Check the [Allowed Repository Permission Scopes](#allowed-repository-permission-scopes) table for valid repository permission scope IDs |
| `scope 'X' is not in allowlist`                      | Requested scope ID is not recognized                          | Use a valid scope ID from the [Allowed Repository Permission Scopes](#allowed-repository-permission-scopes) table                       |
| `repository owner 'X' is not allowed`                | Repository owner not in configured allowlist                  | Contact administrator to add owner to GITHUB_ALLOWED_OWNERS                                                                             |
| `GitHub App is not installed on repository`          | App not installed on the target repository                    | Install the GitHub App on the repository in GitHub settings                                                                             |
| `insufficient permissions for scope 'X'`             | App doesn't have repository permission for requested scope    | Update GitHub App's repository permissions or request fewer scopes                                                                      |
| `GitHub API returned fewer scopes than requested`    | Repository-level restrictions limit available scopes          | Check repository settings and branch protection rules                                                                                   |
| `GitHub App installation is suspended`               | App has been suspended                                        | Check GitHub App status and resolve suspension                                                                                          |
| `failed to retrieve private key from Secret Manager` | Secret Manager unavailable or misconfigured                   | Verify Secret Manager permissions and secret exists                                                                                     |

## Repository Structure

```
.
├── function/                  # Cloud Run service source code
├── terraform/                 # Infrastructure as Code
├── action.yml                 # Composite GitHub Action
├── .github/
│   └── workflows/
│       └── build.yml          # CI/CD deployment workflow
├── AGENTS.md                  # AI agent development guidelines
├── CLAUDE.md                  # Claude development entry point
├── DEVELOPMENT.md             # Technical implementation details
└── README.md                  # This file

```

## Contributing

This is a single-purpose utility. Contributions should maintain simplicity and avoid feature creep.

For technical implementation details, architecture decisions, and development setup, see [DEVELOPMENT.md](DEVELOPMENT.md).

For AI-assisted development guidelines, see [AGENTS.md](AGENTS.md).

## Support

For issues or questions, open a GitHub issue in this repository.
