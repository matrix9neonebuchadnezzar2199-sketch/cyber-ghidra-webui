#!/usr/bin/env bash
# smoke_test.sh — cyber-ghidra-webui E2E smoke (WSL2 / Linux)
# Usage: bash scripts/smoke_test.sh [path-to-binary]
#   Default: copy /bin/ls to /tmp/ghidra_smoke_test_ls

set -euo pipefail

API="${API:-http://localhost:8000}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
MAX_WAIT="${MAX_WAIT:-300}"

info()  { printf "\033[36m[INFO]\033[0m  %s\n" "$*"; }
ok()    { printf "\033[32m[OK]\033[0m    %s\n" "$*"; }
fail()  { printf "\033[31m[FAIL]\033[0m  %s\n" "$*"; exit 1; }

if [[ ${1:-} ]]; then
    SAMPLE="$1"
else
    SAMPLE="/tmp/ghidra_smoke_test_ls"
    cp /bin/ls "$SAMPLE"
    info "Using /bin/ls copy: $SAMPLE"
fi
[[ -f "$SAMPLE" ]] || fail "$SAMPLE not found"

info "Health check..."
HEALTH=$(curl -sf "$API/health") || fail "backend not reachable (docker compose up -d?)"
echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if d.get('ghidra_cli') is True else 1)" \
    || fail "ghidra_cli is not true — is this the backend image with Ghidra?"
ok "backend up, ghidra_cli=true"

info "Upload: $(basename "$SAMPLE")"
UPLOAD=$(curl -sf -X POST "$API/api/upload" -F "file=@${SAMPLE}") || fail "POST /api/upload failed"

JOB_ID=$(echo "$UPLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin)['job_id'])")
SHA256=$(echo "$UPLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin)['hashes']['sha256'])")
ok "job_id=$JOB_ID sha256=${SHA256:0:16}..."

info "Waiting for ghidra-worker (max ${MAX_WAIT}s)..."
ELAPSED=0
while true; do
    JOB=$(curl -sf "$API/api/jobs/$JOB_ID") || fail "GET /api/jobs/$JOB_ID failed"
    STATUS=$(echo "$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")

    if [[ "$STATUS" == "completed" ]]; then
        ok "job completed (${ELAPSED}s)"
        break
    elif [[ "$STATUS" == "failed" ]]; then
        ERROR=$(echo "$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error','unknown'))")
        fail "job failed: $ERROR"
    fi

    if (( ELAPSED >= MAX_WAIT )); then
        fail "timeout (${MAX_WAIT}s) status=$STATUS"
    fi
    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
    printf "  ...%ds status=%s\n" "$ELAPSED" "$STATUS"
done

info "Fetch analysis JSON..."
ANALYSIS_FILE=$(echo "$JOB" | python3 -c "import sys,json; print(json.load(sys.stdin).get('analysis_json') or '')")
if [[ -n "$ANALYSIS_FILE" ]]; then
    info "Using job.analysis_json=$ANALYSIS_FILE"
    ANALYSIS=$(curl -sf "$API/api/results/$ANALYSIS_FILE") || fail "GET /api/results/$ANALYSIS_FILE failed"
else
    info "No analysis_json on job; using first entry from /api/results"
    RESULTS=$(curl -sf "$API/api/results") || fail "GET /api/results failed"
    FIRST=$(echo "$RESULTS" | python3 -c "import sys,json; r=json.load(sys.stdin).get('results',[]); print(r[0]['filename'] if r else '')")
    [[ -n "$FIRST" ]] || fail "no *_analysis.json in output"
    ANALYSIS=$(curl -sf "$API/api/results/$FIRST") || fail "GET /api/results/$FIRST failed"
fi

echo "$ANALYSIS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
checks = {
    'file_name': bool(data.get('file_name')),
    'architecture': bool(data.get('architecture')),
    'functions_count': len(data.get('functions', [])) > 0,
    'has_decompiled': any(f.get('decompiled_c') for f in data.get('functions', [])),
}
for name, passed in checks.items():
    mark = 'OK' if passed else 'FAIL'
    print(f'  [{mark}] {name}')
    if not passed and name in ('file_name', 'architecture', 'functions_count', 'has_decompiled'):
        sys.exit(1)
" || fail "JSON structure check failed"

ok "All checks passed"

echo ""
echo "=========================================="
echo "  SMOKE TEST PASSED"
echo "=========================================="
echo "$ANALYSIS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  file:       {d.get('file_name')}\")
print(f\"  arch:       {d.get('architecture')}\")
print(f\"  functions:  {len(d.get('functions', []))}\")
print(f\"  strings:    {len(d.get('strings', []))}\")
print(f\"  imports:    {len(d.get('imports', []))}\")
print(f\"  suspicious: {len(d.get('suspicious_apis', []))}\")
print(f\"  truncated:  {d.get('truncated', False)}\")
"
echo "=========================================="
