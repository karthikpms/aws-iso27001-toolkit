#!/bin/bash
set -euo pipefail

# =============================================================================
# install-wazuh-agent.sh
# Installs and configures the Wazuh agent on Ubuntu servers.
# Must match the Wazuh Manager version (4.10.2).
#
# Usage: curl -s <raw-url> | sudo bash
#    or: sudo bash install-wazuh-agent.sh
# =============================================================================

WAZUH_MANAGER_IP="13.203.156.174"
WAZUH_VERSION="4.10.2-1"

echo "=== Installing Wazuh Agent v${WAZUH_VERSION} ==="
echo "    Manager: ${WAZUH_MANAGER_IP}"

# Add Wazuh GPG key and repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import - 2>/dev/null
chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' \
  > /etc/apt/sources.list.d/wazuh.list

# Install
apt-get update -qq
DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER="$WAZUH_MANAGER_IP" \
  apt-get install -y wazuh-agent="$WAZUH_VERSION"

# Ensure manager address is set (in case env var didn't take)
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER_IP}</address>|" /var/ossec/etc/ossec.conf

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

echo ""
echo "=== Wazuh Agent installed and running ==="
echo "    Verify: systemctl status wazuh-agent"
echo "    Logs:   tail -f /var/ossec/logs/ossec.log"
