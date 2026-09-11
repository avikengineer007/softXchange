#!/usr/bin/env bash
# =============================================================================
# softXchange Production PostgreSQL Automated Backup Script
# Performs pg_dump of all 4 logical databases with gzip compression & timestamp.
# Retains backups for 30 days.
# =============================================================================

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/var/backups/softxchange}"
POSTGRES_HOST="${POSTGRES_HOST:-localhost}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-softxchange}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

DATABASES=("softxchange_auth" "softxchange_listings" "softxchange_payments" "softxchange_scan")

echo "=========================================================="
echo " Starting softXchange Database Backup at $TIMESTAMP"
echo "=========================================================="

for DB in "${DATABASES[@]}"; do
    BACKUP_FILE="${BACKUP_DIR}/${DB}_${TIMESTAMP}.sql.gz"
    echo "Backing up ${DB} -> ${BACKUP_FILE}..."
    pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" "$DB" | gzip -9 > "$BACKUP_FILE"
    echo "[OK] ${DB} backed up successfully ($(du -h "$BACKUP_FILE" | cut -f1))"
done

# Prune backups older than retention window
echo "Pruning backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -type f -name "*.sql.gz" -mtime +"$RETENTION_DAYS" -delete

echo "=========================================================="
echo " Backup completed successfully."
echo "=========================================================="
