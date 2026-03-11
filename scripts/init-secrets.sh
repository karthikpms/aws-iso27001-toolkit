#!/bin/bash
set -euo pipefail

# =============================================================================
# init-secrets.sh
# Pulls secrets from AWS Secrets Manager and writes them to a tmpfs-backed .env
# file. Used on the EC2 instance — NOT for local development.
#
# Usage: ./init-secrets.sh <secret-id>
# =============================================================================

SECRET_ID="${1:?Usage: init-secrets.sh <secret-id>}"

echo "[init-secrets] Fetching secrets from AWS Secrets Manager..."
SECRET=$(aws secretsmanager get-secret-value \
  --secret-id "$SECRET_ID" \
  --query SecretString \
  --output text)

# Write .env to tmpfs (RAM disk) — secrets never touch persistent storage
mkdir -p /run/toolkit
chmod 700 /run/toolkit

python3 -c "
import sys, json
s = json.load(sys.stdin)
for k, v in s.items():
    print(f'{k.upper()}={v}')
" <<< "$SECRET" > /run/toolkit/.env

# Append non-secret configuration
cat >> /run/toolkit/.env <<EOF
AWS_REGION=${AWS_DEFAULT_REGION:-ap-south-1}
CISO_ASSISTANT_PORT=8443
WAZUH_DASHBOARD_PORT=5601
ALERT_ENABLED=true
ALERT_MIN_SEVERITY=medium
WAZUH_INDEXER_USERNAME=admin
EOF

chmod 600 /run/toolkit/.env
echo "[init-secrets] Secrets written to /run/toolkit/.env"
