$ErrorActionPreference = "Stop"

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "backups\ids_$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

$dbPath = $env:IDS_DB_PATH
if ([string]::IsNullOrWhiteSpace($dbPath)) { $dbPath = "data/ids.db" }
$modelPath = $env:IDS_MODEL_PATH
if ([string]::IsNullOrWhiteSpace($modelPath)) { $modelPath = "data/isolation_forest.joblib" }

if (Test-Path $dbPath) { Copy-Item $dbPath "$backupDir\ids.db" -Force }
if (Test-Path $modelPath) { Copy-Item $modelPath "$backupDir\isolation_forest.joblib" -Force }
if (Test-Path ".env") { Copy-Item ".env" "$backupDir\.env" -Force }

Write-Host "Backup complete: $backupDir"
