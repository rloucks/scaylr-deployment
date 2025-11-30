# SentinelOne Collector Setup - Quick Start

## Prerequisites

- Root/sudo access
- Linux server (Arch, RHEL, Fedora, Ubuntu, or Debian)
- SentinelOne Data Lake API key (Log Write Access)
- Your SentinelOne server URL (e.g., https://xdr.us1.sentinelone.net)

## Installation

### Single Server

```bash
# Download the script
wget https://your-server/setup_sentinelone_collector.sh

# Make it executable
chmod +x setup_sentinelone_collector.sh

# Run it
sudo ./setup_sentinelone_collector.sh
```

The script will prompt you for:
1. Your OS confirmation
2. Username (default: `scalyr`)
3. SentinelOne API key
4. SentinelOne server URL

### Multiple Servers

```bash
# Deploy to multiple servers via SSH
for host in server1 server2 server3; do
    echo "=== Setting up $host ==="
    scp setup_sentinelone_collector.sh root@$host:/tmp/
    ssh root@$host "bash /tmp/setup_sentinelone_collector.sh"
done
```

## What It Does

1. ✅ Detects your Linux distribution
2. ✅ Creates read-only user for log collection
3. ✅ Installs SentinelOne Collector (official method)
4. ✅ Configures log file access
5. ✅ Applies security hardening
6. ✅ Starts the collector service
7. ✅ Verifies installation

## Verification

```bash
# Check agent status
scalyr-agent-2 status

# View logs
tail -f /var/log/scalyr-agent-2/agent.log

# Check in SentinelOne UI
# Go to: Policy & Settings > Products > Singularity Data Lake > Custom Log Sources
```

## Configuration

- **Config file**: `/etc/scalyr-agent-2/agent.json`
- **Modular configs**: `/etc/scalyr-agent-2/agent.d/`
- **Agent logs**: `/var/log/scalyr-agent-2/`

Changes to config files are auto-detected within 30 seconds (no restart needed).

## Common SentinelOne Server URLs

- US1: `https://xdr.us1.sentinelone.net`
- US2: `https://xdr.us2.sentinelone.net`
- EU1: `https://xdr.eu1.sentinelone.net`

## Troubleshooting

**Logs not appearing?**
```bash
scalyr-agent-2 status
tail -f /var/log/scalyr-agent-2/agent.log
```

**Permission issues?**
```bash
# Check user groups
id scalyr

# Test log access
sudo -u scalyr cat /var/log/messages
```

**Need to reconfigure?**
```bash
# Edit config
sudo vim /etc/scalyr-agent-2/agent.json

# Restart (if needed)
scalyr-agent-2 restart
```
