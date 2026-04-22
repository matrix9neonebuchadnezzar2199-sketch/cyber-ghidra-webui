# バックエンド品質: ruff + pytest
# Usage: プロジェクトルートで .\scripts\quality_check.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $Root "app\backend")

$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) { $pyCmd = Get-Command py -ErrorAction Stop }
$pyExe = $pyCmd.Source
& $pyExe -m pip show ruff *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Error "Install: pip install -r requirements.txt -r requirements-dev.txt (ruff)"
  exit 1
}

Write-Host "==> ruff check" -ForegroundColor Cyan
& ruff check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "==> ruff format (check)" -ForegroundColor Cyan
& ruff format --check .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "==> pytest (scanners)" -ForegroundColor Cyan
& $pyExe -m pytest
exit $LASTEXITCODE
