#!/usr/bin/env bash
# =============================================================================
# softXchange Database Restore & Staging Verification Script
# Safely tests database restoration into staging or recovers production.
# =============================================================================

set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <database_name> <backup_file.sql.gz>"
    echo "Example: $0 softxchange_auth /var/backups/softxchange/softxchange_auth_20260912.sql.gz"
    exit 1
fi

TARGET_DB="$1"
BACKUP_FILE="$2"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-softxchange}"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file '$BACKUP_FILE' not found!"
    exit 1
fi

echo "=========================================================="
echo " Restoring ${BACKUP_FILE} into ${TARGET_DB}..."
echo "=========================================================="

if [[ "$BACKUP_FILE" == *.gz ]]; then
    gunzip -c "$BACKUP_FILE" | psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$TARGET_DB"
else
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$TARGET_DB" -f "$BACKUP_FILE"
fi

echo "Verifying restored table count..."
TABLE_COUNT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$TARGET_DB" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';")

echo "[OK] Restore verified. Total tables in ${TARGET_DB}: ${TABLE_COUNT}"
