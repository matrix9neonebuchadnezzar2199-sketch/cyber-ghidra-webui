# smoke_test.ps1 — cyber-ghidra-webui E2E smoke (Windows)
# Usage: .\scripts\smoke_test.ps1 [-Sample "C:\path\to\file.exe"]
# Requires: curl.exe (Windows 10+), PowerShell 5.1+
# Upload uses curl.exe for simple multipart; other steps use Invoke-RestMethod.
# If corporate proxy behaves differently between the two, switch upload to the same stack or configure both.

param(
    [string]$Sample = "",
    [string]$Api = "http://localhost:8000",
    [int]$MaxWait = 300,
    [int]$Poll = 5
)

$ErrorActionPreference = "Stop"

function Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "[OK]    $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "[FAIL]  $msg" -ForegroundColor Red; exit 1 }

if (-not $Sample) {
    $Sample = Join-Path $env:TEMP "ghidra_smoke_notepad.exe"
    Copy-Item "C:\Windows\notepad.exe" $Sample -Force
    Info "Using notepad.exe copy: $Sample"
}
if (-not (Test-Path $Sample)) { Fail "$Sample not found" }

Info "Health check..."
try {
    $health = Invoke-RestMethod -Uri "$Api/health" -Method Get
} catch { Fail "backend not reachable (docker compose up -d?)" }

if ($health.ghidra_cli -ne $true) { Fail "ghidra_cli is not true" }
Ok "backend up, ghidra_cli=true"

Info "Unipacker proxy health (GET /api/unpack/health)..."
try {
    $uh = Invoke-RestMethod -Uri "$Api/api/unpack/health" -Method Get
} catch { Fail "GET /api/unpack/health failed" }
if ($uh.status -ne "ok" -or $uh.service -ne "unipacker-worker") {
    Fail "unipacker-worker not healthy: $($uh | ConvertTo-Json -Compress)"
}
Ok "unipacker-worker reachable"

Info "detect-packer (non-PE)..."
$notPe = Join-Path $env:TEMP "smoke_test_notpe.bin"
[IO.File]::WriteAllBytes($notPe, [Text.Encoding]::ASCII.GetBytes("not a PE"))
try {
    $detJson = & curl.exe -sS -F "file=@$notPe" "$Api/api/detect-packer"
} finally {
    Remove-Item $notPe -Force -ErrorAction SilentlyContinue
}
if (-not $detJson) { Fail "POST /api/detect-packer failed" }
$det = $detJson | ConvertFrom-Json
if ($det.is_pe -ne $false) { Fail "detect-packer expected is_pe=false" }
Ok "detect-packer non-PE"

Info "Upload: $(Split-Path $Sample -Leaf)"
$upJson = & curl.exe -sS -X POST "$Api/api/upload" -F "file=@$Sample"
if (-not $upJson) { Fail "POST /api/upload failed" }
$upload = $upJson | ConvertFrom-Json
if (-not $upload.job_id) { Fail "no job_id in response" }
Ok "job_id=$($upload.job_id)"

Info "Waiting for ghidra-worker (max ${MaxWait}s)..."
$elapsed = 0
while ($true) {
    $job = Invoke-RestMethod -Uri "$Api/api/jobs/$($upload.job_id)" -Method Get
    if ($job.status -eq "completed") { Ok "job completed (${elapsed}s)"; break }
    if ($job.status -eq "failed") { Fail "job failed: $($job.error)" }
    if ($elapsed -ge $MaxWait) { Fail "timeout (${MaxWait}s) status=$($job.status)" }
    Start-Sleep -Seconds $Poll
    $elapsed += $Poll
    Write-Host "  ...${elapsed}s status=$($job.status)"
}

Info "Fetch analysis JSON..."
$analysisFile = $job.analysis_json
if ($analysisFile) {
    Info "Using job.analysis_json=$analysisFile"
    $analysis = Invoke-RestMethod -Uri "$Api/api/results/$analysisFile" -Method Get
} else {
    $results = Invoke-RestMethod -Uri "$Api/api/results" -Method Get
    if ($results.results.Count -eq 0) { Fail "no *_analysis.json in output" }
    $first = $results.results[0].filename
    $analysis = Invoke-RestMethod -Uri "$Api/api/results/$first" -Method Get
}

$checks = @{
    file_name       = [bool]$analysis.file_name
    architecture    = [bool]$analysis.architecture
    functions       = $analysis.functions.Count -gt 0
    has_decompiled  = ($analysis.functions | Where-Object { $_.decompiled_c }).Count -gt 0
}
$allOk = $true
foreach ($kv in $checks.GetEnumerator()) {
    $mark = if ($kv.Value) { "OK" } else { "FAIL" }
    Write-Host "  [$mark] $($kv.Key)"
    if (-not $kv.Value -and $kv.Key -in @("file_name","architecture","functions","has_decompiled")) {
        $allOk = $false
    }
}
if (-not $allOk) { Fail "JSON structure check failed" }
Ok "All checks passed"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Yellow
Write-Host "  SMOKE TEST PASSED" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Yellow
Write-Host "  file:       $($analysis.file_name)"
Write-Host "  arch:       $($analysis.architecture)"
Write-Host "  functions:  $($analysis.functions.Count)"
Write-Host "  strings:    $($analysis.strings.Count)"
Write-Host "  imports:    $($analysis.imports.Count)"
Write-Host "  suspicious: $($analysis.suspicious_apis.Count)"
Write-Host "  truncated:  $($analysis.truncated)"
Write-Host "==========================================" -ForegroundColor Yellow
