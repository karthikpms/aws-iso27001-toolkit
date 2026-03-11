#!/bin/bash
set -euo pipefail
exec > /var/log/toolkit-init.log 2>&1

echo "=== [$(date)] Installing Docker ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg jq python3 git

# Add Docker's official GPG key and repo
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin unzip wget

echo "=== [$(date)] Installing AWS CLI v2 ==="
curl -s "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
cd /tmp && unzip -qo awscliv2.zip && ./aws/install

echo "=== [$(date)] Formatting and mounting data volume ==="
# On NVMe instances, /dev/xvdf maps to /dev/nvme1n1
DEVICE="${device_name}"
if [ ! -b "$DEVICE" ]; then
  # Try NVMe device naming
  for dev in /dev/nvme1n1 /dev/nvme2n1; do
    if [ -b "$dev" ]; then
      DEVICE="$dev"
      break
    fi
  done
fi

# Wait up to 60s for the volume to appear
WAIT=0
while [ ! -b "$DEVICE" ] && [ $WAIT -lt 60 ]; do
  echo "Waiting for $DEVICE..."
  sleep 5
  WAIT=$((WAIT + 5))
done

# Only format if the volume has no filesystem
if ! blkid "$DEVICE" > /dev/null 2>&1; then
  mkfs.ext4 "$DEVICE"
fi
mkdir -p /data
mount "$DEVICE" /data
echo "$DEVICE /data ext4 defaults,nofail 0 2" >> /etc/fstab

# Configure Docker to use /data for volume storage
mkdir -p /data/docker-volumes
cat > /etc/docker/daemon.json <<DOCKER_EOF
{
  "data-root": "/data/docker-data"
}
DOCKER_EOF
systemctl restart docker

echo "=== [$(date)] Cloning toolkit repo ==="
mkdir -p /opt/toolkit
git clone https://github.com/karthikpms/aws-iso27001-toolkit.git /opt/toolkit

echo "=== [$(date)] Running init-secrets.sh ==="
export AWS_DEFAULT_REGION="${aws_region}"
chmod +x /opt/toolkit/scripts/init-secrets.sh
chmod +x /opt/toolkit/scripts/backup.sh
chmod +x /opt/toolkit/glue/run_scan.sh
/opt/toolkit/scripts/init-secrets.sh "${secret_id}"

echo "=== [$(date)] Starting services ==="
cd /opt/toolkit
docker compose --env-file /run/toolkit/.env up -d

echo "=== [$(date)] Installing CloudWatch agent ==="
wget -q https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb -O /tmp/amazon-cloudwatch-agent.deb
dpkg -i /tmp/amazon-cloudwatch-agent.deb
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'CW_EOF'
{
  "agent": { "metrics_collection_interval": 60 },
  "metrics": {
    "namespace": "ISO27001Toolkit",
    "metrics_collected": {
      "cpu": { "measurement": ["cpu_usage_idle"], "totalcpu": true },
      "mem": { "measurement": ["mem_used_percent"] },
      "disk": { "measurement": ["used_percent"], "resources": ["/", "/data"] }
    }
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          { "file_path": "/var/log/toolkit-init.log", "log_group_name": "iso27001-toolkit", "log_stream_name": "init" },
          { "file_path": "/var/log/toolkit-scan.log", "log_group_name": "iso27001-toolkit", "log_stream_name": "scans" }
        ]
      }
    }
  }
}
CW_EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
  -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

echo "=== [$(date)] Setting up cron schedules ==="

cat > /etc/cron.d/iso27001-toolkit <<'CRON_EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Weekly full scan — Sunday 02:00 UTC
0 2 * * 0 root cd /opt/toolkit && ENV_FILE=/run/toolkit/.env ./glue/run_scan.sh full >> /var/log/toolkit-scan.log 2>&1

# Daily delta scan — Mon-Sat 02:00 UTC
0 2 * * 1-6 root cd /opt/toolkit && ENV_FILE=/run/toolkit/.env ./glue/run_scan.sh delta >> /var/log/toolkit-scan.log 2>&1

# Daily Inspector vulnerability scan — 02:30 UTC (before asset inventory at 03:00)
30 2 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python inspector_mapper.py >> /var/log/toolkit-scan.log 2>&1

# Daily asset inventory sync — 03:00 UTC (after delta scans)
0 3 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python asset_inventory.py >> /var/log/toolkit-scan.log 2>&1

# Nightly CISO Assistant data export — 04:00 UTC
0 4 * * * root cd /opt/toolkit && ./scripts/backup.sh --upload >> /var/log/toolkit-scan.log 2>&1

# Incident auto-detection — every 15 minutes
*/15 * * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python incident_detector.py >> /var/log/toolkit-scan.log 2>&1

# Daily log completeness verification — 06:00 UTC
0 6 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python log_auditor.py >> /var/log/toolkit-scan.log 2>&1

# Daily backup verification — 05:00 UTC
0 5 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python backup_verifier.py >> /var/log/toolkit-scan.log 2>&1

# Monthly backup restore tests — 1st of month at 07:00 UTC
0 7 1 * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python backup_verifier.py --restore-test >> /var/log/toolkit-scan.log 2>&1

# Safety-net cleanup of stale restore-test resources — every 3 hours
0 */3 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python backup_verifier.py --cleanup >> /var/log/toolkit-scan.log 2>&1

# Monthly IAM access review — 1st of month at 06:30 UTC
30 6 1 * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python access_reviewer.py >> /var/log/toolkit-scan.log 2>&1

# Weekly network security: full SG scan — Sunday 05:30 UTC
30 5 * * 0 root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python network_monitor.py --scan-all >> /var/log/toolkit-scan.log 2>&1

# Weekly network security: VPC Flow Log analysis — Sunday 06:00 UTC
0 6 * * 0 root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python network_monitor.py --flow-analysis >> /var/log/toolkit-scan.log 2>&1

# Weekly encryption compliance audit — Sunday 05:00 UTC (after full Prowler scan)
0 5 * * 0 root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python encryption_auditor.py >> /var/log/toolkit-scan.log 2>&1

# Daily digest email — 09:00 UTC
0 9 * * * root cd /opt/toolkit && docker compose --env-file /run/toolkit/.env run --rm glue-mapper python -c "from alerter import send_daily_digest; import os; send_daily_digest(os.getenv('SCAN_SUMMARY_PATH', '/data/glue/last_scan_summary.json'))" >> /var/log/toolkit-scan.log 2>&1
CRON_EOF

chmod 644 /etc/cron.d/iso27001-toolkit

# Log rotation for scan logs
cat > /etc/logrotate.d/toolkit-scan <<'LOGROTATE_EOF'
/var/log/toolkit-scan.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
LOGROTATE_EOF

echo "=== [$(date)] Running initial delta scan in background ==="
cd /opt/toolkit
ENV_FILE=/run/toolkit/.env ./glue/run_scan.sh delta >> /var/log/toolkit-scan.log 2>&1 &

echo "=== [$(date)] Toolkit initialization complete ==="
