#!/bin/bash
set -euo pipefail

# =============================================================================
# run_scan.sh
# Triggers a Prowler scan via Docker Compose, imports findings, sends alerts.
#
# Usage:
#   ./run_scan.sh              # Delta scan (IAM, S3, CloudTrail, EC2)
#   ./run_scan.sh full         # Full scan (all services, all regions)
#   ./run_scan.sh delta        # Delta scan (explicit)
# =============================================================================

SCAN_TYPE="${1:-delta}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
COMPOSE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ENV_FILE:-}"

echo "[$TIMESTAMP] Starting Prowler $SCAN_TYPE scan..."

cd "$COMPOSE_DIR"

# Determine env-file flag (AWS deployment uses /run/toolkit/.env)
ENV_FLAG=""
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
  ENV_FLAG="--env-file $ENV_FILE"
fi

# --- Run Prowler scan ---
# Prowler exit codes: 0 = all pass, 3 = some findings failed (expected), others = error
if [ "$SCAN_TYPE" = "full" ]; then
  docker compose $ENV_FLAG --profile scan run --rm prowler \
    aws --compliance iso27001_2013_aws -M json-ocsf \
    --output-directory /home/prowler/output || PROWLER_EXIT=$?
elif [ "$SCAN_TYPE" = "delta" ]; then
  # Note: Prowler does not allow --compliance with --services, so delta scans
  # run without --compliance. The glue mapper handles ISO 27001 control mapping.
  docker compose $ENV_FLAG --profile scan run --rm prowler \
    aws -M json-ocsf \
    --output-directory /home/prowler/output \
    --services iam s3 cloudtrail ec2 || PROWLER_EXIT=$?
else
  echo "Unknown scan type: $SCAN_TYPE (use 'full' or 'delta')"
  exit 1
fi

PROWLER_EXIT=${PROWLER_EXIT:-0}
if [ "$PROWLER_EXIT" -ne 0 ] && [ "$PROWLER_EXIT" -ne 3 ]; then
  echo "Prowler failed with exit code $PROWLER_EXIT"
  exit "$PROWLER_EXIT"
fi

echo "[$(date +%Y%m%d-%H%M%S)] Scan complete. Output in prowler-output volume."

# --- Import findings to CISO Assistant ---
echo "[$(date +%Y%m%d-%H%M%S)] Starting Prowler mapper — importing findings to CISO Assistant..."

docker compose $ENV_FLAG run --rm -e SCAN_TYPE="$SCAN_TYPE" glue-mapper

echo "[$(date +%Y%m%d-%H%M%S)] Mapper complete. Findings imported to CISO Assistant."

# --- Run asset inventory sync ---
echo "[$(date +%Y%m%d-%H%M%S)] Starting asset inventory sync..."

docker compose $ENV_FLAG run --rm --entrypoint python glue-mapper asset_inventory.py || {
  echo "[$(date +%Y%m%d-%H%M%S)] Asset inventory sync failed (non-fatal)."
}

echo "[$(date +%Y%m%d-%H%M%S)] Asset inventory sync complete."

# --- Run compliance sync (framework + requirement assessment updates + evidence) ---
echo "[$(date +%Y%m%d-%H%M%S)] Starting compliance sync..."

docker compose $ENV_FLAG run --rm --entrypoint python glue-mapper compliance_sync.py || {
  echo "[$(date +%Y%m%d-%H%M%S)] Compliance sync failed (non-fatal)."
}

echo "[$(date +%Y%m%d-%H%M%S)] Compliance sync complete."

# --- Run daily digest (for medium/low findings summary) ---
echo "[$(date +%Y%m%d-%H%M%S)] Sending daily digest..."

docker compose $ENV_FLAG run --rm glue-mapper python -c "
from alerter import send_daily_digest
import os
send_daily_digest(os.getenv('SCAN_SUMMARY_PATH', '/data/glue/last_scan_summary.json'))
" 2>/dev/null || echo "[$(date +%Y%m%d-%H%M%S)] Digest skipped (no summary available)."

echo "[$(date +%Y%m%d-%H%M%S)] Scan pipeline complete."
