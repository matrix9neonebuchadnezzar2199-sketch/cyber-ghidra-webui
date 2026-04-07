$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$sourceDir = "H:\TOOL\cyber-ghidra-webui"
$backupDir = Join-Path $sourceDir "backup\$timestamp"

# 除外フォルダのリスト
$exclude = @("node_modules", ".git", "ghidra_data", "models", "backup", "__pycache__")

Write-Host "--- Backup Starting: $timestamp ---" -ForegroundColor Yellow
if (!(Test-Path (Join-Path $sourceDir "backup"))) { New-Item -ItemType Directory -Path (Join-Path $sourceDir "backup") -Force }
New-Item -ItemType Directory -Path $backupDir -Force

Get-ChildItem -Path $sourceDir -Exclude $exclude | Copy-Item -Destination $backupDir -Recurse -Force
Write-Host "Backup completed to: $backupDir" -ForegroundColor Green