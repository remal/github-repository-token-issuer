project_id = "gh-repo-token-issuer"

# Your GitHub App ID (found in GitHub App settings)
github_app_id = "2637135"

github_allowed_owner_ids = [
  "231188",   # remal (User)
  "77341723", # remal-gradle-plugins (Organization)
  "77626445", # remal-github-actions (Organization)
]

# Optional: List of GitHub account IDs allowed to request tokens
# If empty or not set, all owners are allowed
# Look up an ID via https://api.github.com/users/<login>
# github_allowed_owner_ids = ["12345678", "87654321"]
