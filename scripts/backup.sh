#!/bin/bash
set -euo pipefail

# =============================================================================
# backup.sh — CISO Assistant Data Export
#
# Exports CISO Assistant data via API (frameworks, controls, findings) as JSON,
# compresses it, and uploads to S3 for long-term retention.
#
# Usage:
#   ./backup.sh                    # Uses defaults from environment
#   ./backup.sh --upload           # Export + upload to S3
#   ./backup.sh --export-only      # Export only, no S3 upload
# =============================================================================

TIMESTAMP=$(date +%Y-%m-%d)
EXPORT_DIR="${BACKUP_EXPORT_DIR:-/data/glue/backups}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
S3_PREFIX="${BACKUP_S3_PREFIX:-ciso-assistant}"
CISO_URL="${CISO_ASSISTANT_URL:-http://ciso-backend:8000}"
CISO_EMAIL="${CISO_ADMIN_EMAIL:-admin@pyramidions.com}"
CISO_PASSWORD="${CISO_ADMIN_PASSWORD:-changeme}"
UPLOAD="${1:---upload}"

mkdir -p "$EXPORT_DIR"

echo "[$TIMESTAMP] Starting CISO Assistant data export..."

# --- Authenticate ---
echo "[backup] Authenticating with CISO Assistant..."
TOKEN=$(curl -sf -X POST "$CISO_URL/api/iam/login/" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$CISO_EMAIL\", \"password\": \"$CISO_PASSWORD\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

if [ -z "$TOKEN" ]; then
  echo "[backup] ERROR: Authentication failed"
  exit 1
fi

AUTH_HEADER="Authorization: Token $TOKEN"

# --- Export each endpoint ---
EXPORT_FILE="$EXPORT_DIR/ciso-export-$TIMESTAMP.json"

echo "[backup] Exporting data..."

python3 -c "
import json, sys, urllib.request

base_url = '$CISO_URL/api'
token = '$TOKEN'
headers = {'Authorization': f'Token {token}', 'Content-Type': 'application/json'}

endpoints = [
    'frameworks',
    'folders',
    'compliance-assessments',
    'requirement-assessments',
    'applied-controls',
    'evidences',
    'risk-assessments',
    'risk-scenarios',
]

export = {'export_date': '$TIMESTAMP', 'source': base_url}

for ep in endpoints:
    results = []
    url = f'{base_url}/{ep}/'
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                results.extend(data.get('results', []))
                url = data.get('next')
        except Exception as e:
            print(f'  Warning: failed to export {ep}: {e}', file=sys.stderr)
            url = None
    export[ep] = results
    print(f'  Exported {len(results)} {ep}')

with open('$EXPORT_FILE', 'w') as f:
    json.dump(export, f, indent=2, default=str)

print(f'Export written to $EXPORT_FILE')
"

# --- Compress ---
echo "[backup] Compressing export..."
gzip -f "$EXPORT_FILE"
COMPRESSED="${EXPORT_FILE}.gz"
SIZE=$(du -h "$COMPRESSED" | cut -f1)
echo "[backup] Compressed export: $COMPRESSED ($SIZE)"

# --- Upload to S3 ---
if [ "$UPLOAD" = "--upload" ] && [ -n "$S3_BUCKET" ]; then
  S3_KEY="$S3_PREFIX/$TIMESTAMP.json.gz"
  echo "[backup] Uploading to s3://$S3_BUCKET/$S3_KEY ..."
  aws s3 cp "$COMPRESSED" "s3://$S3_BUCKET/$S3_KEY" --quiet
  echo "[backup] Upload complete."
elif [ "$UPLOAD" = "--upload" ] && [ -z "$S3_BUCKET" ]; then
  echo "[backup] WARNING: BACKUP_S3_BUCKET not set, skipping S3 upload."
  echo "[backup] Local export saved at: $COMPRESSED"
else
  echo "[backup] Export-only mode. File saved at: $COMPRESSED"
fi

# --- Cleanup old local exports (keep 7 days) ---
find "$EXPORT_DIR" -name "ciso-export-*.json.gz" -mtime +7 -delete 2>/dev/null || true

echo "[$TIMESTAMP] Backup complete."
