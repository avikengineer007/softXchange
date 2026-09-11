# =============================================================================
# softXchange Production PostgreSQL Automated Backup Script (PowerShell)
# Performs pg_dump of all 4 logical databases with timestamping.
# =============================================================================

param (
    [string]$BackupDir = ".\backups",
    [string]$HostName = "localhost",
    [int]$Port = 5432,
    [string]$UserName = "softxchange",
    [int]$RetentionDays = 30
)

$ErrorActionPreference = "Stop"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

$Databases = @("softxchange_auth", "softxchange_listings", "softxchange_payments", "softxchange_scan")

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting softXchange Database Backup at $Timestamp" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

foreach ($db in $Databases) {
    $outFile = Join-Path $BackupDir "${db}_${Timestamp}.sql"
    Write-Host "Backing up $db -> $outFile..."
    & pg_dump -h $HostName -p $Port -U $UserName -f $outFile $db
    Write-Host "[OK] $db backed up successfully." -ForegroundColor Green
}

# Cleanup older files
$Cutoff = (Get-Date).AddDays(-$RetentionDays)
Get-ChildItem -Path $BackupDir -Filter "*.sql" | Where-Object { $_.LastWriteTime -lt $Cutoff } | Remove-Item -Force

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Backup complete." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
