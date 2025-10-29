#!/bin/bash
set -euo pipefail

# Configuration
BACKUP_NAME="nacf-backup-$(date +%Y%m%d%H%M%S)
NAMESPACE="nacf"
BACKUP_RETENTION_DAYS=30
LOG_FILE="/var/log/nacf-backup.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
handle_error() {
    log "ERROR: Backup failed - $1"
    # Send alert (example: Slack, PagerDuty, etc.)
    # curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"NACF Backup Failed: $1\"}" $SLACK_WEBHOOK
    exit 1
}

# Check if Velero CLI is installed
if ! command -v velero &> /dev/null; then
    handle_error "Velero CLI is not installed. Please install it first."
fi

# Create backup
log "Starting NACF backup: $BACKUP_NAME"
if ! velero backup create "$BACKUP_NAME" \
    --include-namespaces "$NAMESPACE" \
    --include-resources "*" \
    --snapshot-volumes \
    --ttl "${BACKUP_RETENTION_DAYS * 24}h" \
    --wait; then
    handle_error "Failed to create Velero backup"
fi

# Verify backup was created successfully
if ! velero backup describe "$BACKUP_NAME" --details &>/dev/null; then
    handle_error "Backup verification failed for $BACKUP_NAME"
fi

# Clean up old backups
log "Cleaning up backups older than $BACKUP_RETENTION_DAYS days"
velero backup delete --confirm \
    --selector "velero.io/created<$(date -d "$BACKUP_RETENTION_DAYS days ago" --utc +%s)" \
    || log "Warning: Failed to clean up old backups"

log "Backup completed successfully: $BACKUP_NAME"

# Example restore command (commented out for safety)
# velero restore create --from-backup "$BACKUP_NAME" --wait

exit 0
