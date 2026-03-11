#!/usr/bin/env python3
"""
Webhook Receiver — Glue Layer

Lightweight HTTP server that receives:
  - Wazuh alert webhooks (POST /webhook)
  - Network security events from EventBridge → SNS (POST /network-event)

Wazuh's integratord sends alerts as JSON POST requests.
EventBridge → SNS sends CloudTrail events for network changes.
"""

import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from ciso_client import CISOClient
from prowler_mapper import DedupCache, ensure_project, ensure_findings_assessment
from alerter import alert_wazuh_finding
from wazuh_mapper import parse_wazuh_alert, push_wazuh_finding
from network_monitor import (
    process_network_event,
    load_config as load_network_config,
    ensure_findings_assessment as ensure_network_assessment,
    CONFIG_FILE as NETWORK_CONFIG_FILE,
)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("webhook_server")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LISTEN_PORT = int(os.getenv("WEBHOOK_PORT", "9000"))
CISO_URL = os.getenv("CISO_ASSISTANT_URL", "http://ciso-backend:8000")
CISO_EMAIL = os.getenv("CISO_ADMIN_EMAIL", "admin@pyramidions.com")
CISO_PASSWORD = os.getenv("CISO_ADMIN_PASSWORD", "changeme")
DB_PATH = os.getenv("DEDUP_DB_PATH", "/data/glue/dedup_cache.db")
PROJECT_NAME = os.getenv("CISO_PROJECT_NAME", "AWS ISO 27001 Toolkit")

# Lazily initialized globals
_client: CISOClient | None = None
_cache: DedupCache | None = None
_folder_id: str | None = None
_findings_assessment_id: str | None = None
_network_assessment_id: str | None = None
_network_config: dict | None = None


def get_client() -> CISOClient:
    global _client
    if _client is None:
        _client = CISOClient(CISO_URL, CISO_EMAIL, CISO_PASSWORD)
    return _client


def get_cache() -> DedupCache:
    global _cache
    if _cache is None:
        _cache = DedupCache(DB_PATH)
    return _cache


def get_folder_id() -> str:
    global _folder_id
    if _folder_id is None:
        _folder_id = ensure_project(get_client(), PROJECT_NAME)
    return _folder_id


def get_findings_assessment_id() -> str:
    global _findings_assessment_id
    if _findings_assessment_id is None:
        _findings_assessment_id = ensure_findings_assessment(
            get_client(), get_folder_id(), name="Wazuh SIEM Alerts"
        )
    return _findings_assessment_id


def get_network_assessment_id() -> str:
    global _network_assessment_id
    if _network_assessment_id is None:
        _network_assessment_id = ensure_network_assessment(
            get_client(), get_folder_id()
        )
    return _network_assessment_id


def get_network_config() -> dict:
    global _network_config
    if _network_config is None:
        _network_config = load_network_config(NETWORK_CONFIG_FILE)
    return _network_config


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------
class WebhookHandler(BaseHTTPRequestHandler):
    """Handles POST /webhook (Wazuh) and POST /network-event (EventBridge)."""

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self._respond(400, {"error": "Empty body"})
            return

        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "Invalid JSON"})
            return

        path = self.path.rstrip("/")

        if path == "/network-event":
            self._handle_network_event(payload)
        elif path == "/webhook":
            self._handle_wazuh_webhook(payload)
        else:
            self._respond(404, {"error": f"Unknown path: {path}"})

    def _handle_wazuh_webhook(self, payload: dict) -> None:
        """Process Wazuh alert webhook."""
        # Wazuh integratord sends the alert in the root or under "alert"
        alert = payload.get("alert", payload)

        finding = parse_wazuh_alert(alert)
        if finding is None:
            self._respond(200, {"status": "skipped", "reason": "below threshold"})
            return

        try:
            result = push_wazuh_finding(
                get_client(), finding, get_cache(), get_findings_assessment_id()
            )
            # Send email alert for critical/high Wazuh findings
            if result == "new":
                alert_wazuh_finding(finding)
            self._respond(200, {"status": result, "check_id": finding["check_id"]})
        except Exception:
            logger.exception("Error processing Wazuh webhook")
            global _client
            _client = None
            self._respond(500, {"error": "Internal server error"})

    def _handle_network_event(self, payload: dict) -> None:
        """Process EventBridge → SNS network change event."""
        # SNS wraps the event in a Message field
        if "Message" in payload:
            try:
                event = json.loads(payload["Message"])
            except (json.JSONDecodeError, TypeError):
                self._respond(400, {"error": "Invalid SNS Message JSON"})
                return
        else:
            event = payload

        # Handle SNS subscription confirmation
        if payload.get("Type") == "SubscriptionConfirmation":
            logger.info("SNS subscription confirmation received — confirm via AWS Console")
            self._respond(200, {"status": "subscription_confirmation"})
            return

        try:
            result = process_network_event(
                event,
                get_client(),
                get_cache(),
                get_network_assessment_id(),
                get_network_config(),
            )
            self._respond(200, result)
        except Exception:
            logger.exception("Error processing network event")
            global _client
            _client = None
            self._respond(500, {"error": "Internal server error"})

    def do_GET(self) -> None:
        """Health check endpoint."""
        self._respond(200, {"status": "ok", "service": "webhook-receiver"})

    def _respond(self, status: int, body: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, format: str, *args: object) -> None:
        """Route access logs through the logger."""
        logger.debug(format, *args)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), WebhookHandler)
    logger.info("Webhook receiver listening on port %d (Wazuh: /webhook, Network: /network-event)", LISTEN_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down webhook server")
        server.server_close()


if __name__ == "__main__":
    main()
