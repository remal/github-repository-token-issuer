#!/usr/bin/env bash
# Tests for curl-with-retry.sh using a fake curl on PATH.
# Run: bash curl-with-retry.test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/curl-with-retry.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fake curl. Reads MOCK_CODES (space-separated, one outcome per attempt) and a
# MOCK_COUNTER file. Each outcome is either an HTTP code (writes a body, prints
# the code, exit 0) or "conn" (simulates a connection reset: prints 000, exit 35,
# just like real curl with --write-out '%{http_code}').
mkdir -p "$WORK/bin"
cat > "$WORK/bin/curl" <<'FAKE'
#!/usr/bin/env bash
set -u
out=""
prev=""
for a in "$@"; do
  [[ "$prev" == "--output" ]] && out="$a"
  prev="$a"
done
n=$(( $(cat "$MOCK_COUNTER" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$MOCK_COUNTER"
read -r -a codes <<< "$MOCK_CODES"
idx=$(( n - 1 ))
(( idx >= ${#codes[@]} )) && idx=$(( ${#codes[@]} - 1 ))
code="${codes[$idx]}"
if [[ "$code" == "conn" ]]; then
  [[ -n "$out" ]] && : > "$out"
  printf '000'
  exit 35
fi
[[ -n "$out" ]] && printf '{"value":"tok","token":"tok"}' > "$out"
printf '%s' "$code"
exit 0
FAKE
chmod +x "$WORK/bin/curl"

MOCK_COUNTER="$WORK/counter"
export MOCK_COUNTER

fail=0
run_case() {
  local name="$1" expect_code="$2" expect_attempts="$3" codes="$4" max="${5:-3}"
  : > "$MOCK_COUNTER"
  local out
  out="$(
    PATH="$WORK/bin:$PATH" \
    MOCK_CODES="$codes" \
    CURL_RETRY_MAX_ATTEMPTS="$max" \
    CURL_RETRY_BACKOFF_SECONDS=0 \
    bash "$HELPER" "$WORK/resp" --request GET "https://example/test"
  )"
  local attempts
  attempts="$(cat "$MOCK_COUNTER")"
  if [[ "$out" == "$expect_code" && "$attempts" == "$expect_attempts" ]]; then
    echo "PASS: $name (code=$out attempts=$attempts)"
  else
    echo "FAIL: $name -> got code=$out attempts=$attempts, want code=$expect_code attempts=$expect_attempts"
    fail=1
  fi
}

run_case "success on first try"            200 1 "200"
run_case "connection reset then success"   200 2 "conn 200"
run_case "5xx then success"                200 2 "503 200"
run_case "4xx is fatal, no retry"          403 1 "403 200"
run_case "persistent connection failure"   000 3 "conn conn conn conn"
run_case "persistent 5xx exhausts retries" 503 3 "503 503 503 503"

if [[ "$fail" -ne 0 ]]; then
  echo "SOME TESTS FAILED"
  exit 1
fi
echo "ALL TESTS PASSED"
