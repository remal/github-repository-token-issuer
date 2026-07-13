#!/usr/bin/env bash
# Perform a curl request, retrying on transient failures. Connection errors and
# HTTP 5xx are retried; HTTP 4xx (and any other non-2xx that is not a connection
# failure or 5xx) are treated as fatal and returned without retrying. This mirrors
# the retry policy of the Cloud Run service (3 attempts, backoff 30s then 60s).
#
# Usage: curl-with-retry.sh <output-file> <curl-arg>...
#   <output-file>   file the response body is written to (passed to curl --output)
#   <curl-arg>...   arguments passed through to curl (method, headers, url, ...)
#
# Prints the final HTTP status code to stdout ("000" when the connection failed).
# Retry progress goes to stderr. Exits non-zero only on a usage error.
#
# Overridable via env (used by tests): CURL_RETRY_MAX_ATTEMPTS, CURL_RETRY_BACKOFF_SECONDS.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <output-file> <curl-arg>..." >&2
  exit 2
fi

output_file="$1"
shift

max_attempts="${CURL_RETRY_MAX_ATTEMPTS:-3}"
backoff="${CURL_RETRY_BACKOFF_SECONDS:-30}"

http_code=000
for (( attempt=1; attempt<=max_attempts; attempt++ )); do
  http_code=$(curl --silent --show-error --write-out '%{http_code}' \
    --output "$output_file" "$@") || http_code=000
  http_code="${http_code:-000}"

  # Success.
  if [[ "$http_code" =~ ^2 ]]; then
    break
  fi

  # Non-transient failure (not a connection error and not 5xx): do not retry.
  if [[ "$http_code" != 000 && "$http_code" -lt 500 ]]; then
    break
  fi

  # Transient failure (connection error or 5xx): retry with exponential backoff.
  if (( attempt < max_attempts )); then
    echo "Request failed (HTTP $http_code), retrying in ${backoff}s (attempt $attempt/$max_attempts)" >&2
    sleep "$backoff"
    backoff=$(( backoff * 2 ))
  fi
done

echo "$http_code"
