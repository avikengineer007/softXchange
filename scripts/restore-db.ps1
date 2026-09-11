# =============================================================================
# softXchange Database Restore & Staging Verification Script (PowerShell)
# =============================================================================

param (
    [Parameter(Mandatory=$true)][string]$DatabaseName,
    [Parameter(Mandatory=$true)][string]$BackupFile,
    [string]$HostName = "localhost",
    [int]$Port = 5432,
    [string]$UserName = "softxchange"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BackupFile)) {
    Write-Error "Backup file '$BackupFile' does not exist."
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Restoring $BackupFile into $DatabaseName..." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

& psql -h $HostName -p $Port -U $UserName -d $DatabaseName -f $BackupFile

$tableCount = & psql -h $HostName -p $Port -U $UserName -d $DatabaseName -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';"

Write-Host "[OK] Restore complete. Table count in $DatabaseName: $tableCount" -ForegroundColor Green
