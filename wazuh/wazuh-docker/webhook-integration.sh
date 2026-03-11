#!/bin/bash
# =============================================================================
# webhook-integration.sh
# Called by Wazuh integratord to forward alerts to the Glue Layer webhook.
#
# Wazuh passes alert JSON via a temp file as $1 (alert file) and $3 (API key).
# See: https://documentation.wazuh.com/current/user-manual/manager/integration.html
# =============================================================================

ALERT_FILE="$1"
API_KEY="$3"
WEBHOOK_URL="${WEBHOOK_URL:-http://glue-webhook:9000/webhook}"

if [ -z "$ALERT_FILE" ] || [ ! -f "$ALERT_FILE" ]; then
  echo "Error: No alert file provided" >&2
  exit 1
fi

# Forward alert JSON to the webhook receiver
curl -s -X POST \
  -H "Content-Type: application/json" \
  -d @"$ALERT_FILE" \
  "$WEBHOOK_URL" \
  --max-time 10 \
  --retry 2 \
  --retry-delay 1 \
  -o /dev/null -w "%{http_code}" | {
    read -r status
    if [ "$status" -ge 200 ] && [ "$status" -lt 300 ]; then
      exit 0
    else
      echo "Webhook returned HTTP $status" >&2
      exit 1
    fi
  }
