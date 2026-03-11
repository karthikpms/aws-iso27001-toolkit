#!/bin/bash
set -euo pipefail

# =============================================================================
# wazuh-agent-install.sh
# Installs and registers the Wazuh agent on a target host.
#
# Usage:
#   sudo ./wazuh-agent-install.sh <MANAGER_IP> [ENROLLMENT_KEY]
#
# Supports: Ubuntu/Debian, Amazon Linux/RHEL/CentOS
# Wazuh version: 4.10.x (matches docker-compose.yml)
# =============================================================================

WAZUH_VERSION="4.10.2-1"
MANAGER_IP="${1:-}"
ENROLLMENT_KEY="${2:-}"

if [ -z "$MANAGER_IP" ]; then
  echo "Usage: sudo $0 <MANAGER_IP> [ENROLLMENT_KEY]"
  echo "  MANAGER_IP:     IP or hostname of the Wazuh manager"
  echo "  ENROLLMENT_KEY:  (optional) agent enrollment key"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: This script must be run as root (use sudo)"
  exit 1
fi

echo "Installing Wazuh agent ${WAZUH_VERSION} — manager: ${MANAGER_IP}"

# ---------------------------------------------------------------------------
# Detect OS and install
# ---------------------------------------------------------------------------
install_debian() {
  echo "Detected Debian/Ubuntu — using apt"
  apt-get update -qq
  apt-get install -y -qq curl apt-transport-https

  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

  apt-get update -qq
  WAZUH_MANAGER="$MANAGER_IP" apt-get install -y -qq "wazuh-agent=${WAZUH_VERSION}"
}

install_rhel() {
  echo "Detected RHEL/Amazon Linux/CentOS — using yum"
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

  cat > /etc/yum.repos.d/wazuh.repo << 'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO

  WAZUH_MANAGER="$MANAGER_IP" yum install -y "wazuh-agent-${WAZUH_VERSION}"
}

if [ -f /etc/debian_version ]; then
  install_debian
elif [ -f /etc/redhat-release ] || [ -f /etc/amazon-linux-release ]; then
  install_rhel
else
  echo "Error: Unsupported OS. Manually install the Wazuh agent."
  echo "See: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/"
  exit 1
fi

# ---------------------------------------------------------------------------
# Configure manager address
# ---------------------------------------------------------------------------
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|" "$OSSEC_CONF"
  echo "Configured manager address: ${MANAGER_IP}"
else
  echo "Warning: ${OSSEC_CONF} not found — agent may not be installed correctly"
fi

# ---------------------------------------------------------------------------
# Register agent
# ---------------------------------------------------------------------------
if [ -n "$ENROLLMENT_KEY" ]; then
  echo "Registering agent with enrollment key..."
  /var/ossec/bin/agent-auth -m "$MANAGER_IP" -P "$ENROLLMENT_KEY"
else
  echo "Registering agent (auto-enrollment)..."
  /var/ossec/bin/agent-auth -m "$MANAGER_IP"
fi

# ---------------------------------------------------------------------------
# Enable and start
# ---------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo ""
echo "Wazuh agent installed and running."
echo "  Manager:  ${MANAGER_IP}"
echo "  Agent ID: $(cat /var/ossec/etc/client.keys 2>/dev/null | awk '{print $1}' | head -1 || echo 'pending')"
echo "  Status:   $(systemctl is-active wazuh-agent)"
