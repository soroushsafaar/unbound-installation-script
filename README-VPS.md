# Unbound DNS Server - VPS Installation Script

A simple, non-interactive bash script for installing Unbound DNS server on VPS/servers. No prompts, sensible defaults, just works.

## Features

- **Zero Interaction**: No prompts or user input required
- **VPS Optimized**: Configured for server environments
- **Secure Defaults**: Recursive DNS with DNSSEC validation
- **Auto-Updates**: Monthly root hints refresh
- **Localhost Only**: Secure by default (no external access)
- **systemd Integration**: Works with systemd-resolved

## Quick Install

```bash
# Download and run
curl -fsSL https://raw.githubusercontent.com/your-repo/setup-unbound-vps.sh | sudo bash

# Or download first
wget https://raw.githubusercontent.com/your-repo/setup-unbound-vps.sh
chmod +x setup-unbound-vps.sh
sudo ./setup-unbound-vps.sh
```

## What It Does

1. **Installs Unbound** with required packages
2. **Configures recursive DNS** (queries root servers directly)
3. **Enables DNSSEC** validation for security
4. **Sets up systemd-resolved** integration
5. **Creates auto-update timer** for root hints
6. **Runs validation tests** to ensure everything works

## Default Configuration

- **Mode**: Recursive DNS (no upstream forwarders)
- **Listening**: 127.0.0.1 and ::1 only (localhost)
- **Access**: Local system only
- **DNSSEC**: Enabled with automatic trust anchor
- **Updates**: Monthly root hints refresh
- **Integration**: systemd-resolved forwards to Unbound

## Testing Your Installation

```bash
# Test basic DNS resolution
dig @127.0.0.1 google.com

# Test DNSSEC validation
dig @127.0.0.1 cloudflare.com +dnssec

# Check service status
systemctl status unbound

# View logs
journalctl -u unbound -f
```

## Configuration Files

- **Main config**: `/etc/unbound/unbound.conf.d/local.conf`
- **Root hints**: `/var/lib/unbound/root.hints`
- **Trust anchor**: `/var/lib/unbound/root.key`
- **systemd-resolved**: `/etc/systemd/resolved.conf`

## Customization

To allow external access (use with caution):

```bash
# Edit config to listen on all interfaces
sudo nano /etc/unbound/unbound.conf.d/local.conf

# Add your server's IP and allow your network
interface: 0.0.0.0
access-control: 10.0.0.0/8 allow
access-control: 172.16.0.0/12 allow  
access-control: 192.168.0.0/16 allow

# Restart Unbound
sudo systemctl restart unbound

# Open firewall (if using UFW)
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
```

## Monitoring

```bash
# Service status
systemctl status unbound

# Real-time logs
journalctl -u unbound -f

# Check DNS resolution
resolvectl status

# Test DNSSEC
dig @127.0.0.1 dnssec-failed.org (should fail)
dig @127.0.0.1 cloudflare.com +dnssec (should show AD flag)
```

## Troubleshooting

### Unbound won't start
```bash
# Check configuration
sudo unbound-checkconf

# View detailed logs
sudo journalctl -u unbound --no-pager

# Check port conflicts
sudo netstat -tulpn | grep :53
```

### DNS not resolving
```bash
# Check resolv.conf
cat /etc/resolv.conf

# Test direct query
dig @127.0.0.1 google.com

# Check systemd-resolved
systemctl status systemd-resolved
```

### DNSSEC issues
```bash
# Check trust anchor
ls -la /var/lib/unbound/root.key

# Re-bootstrap if needed
sudo unbound-anchor -a /var/lib/unbound/root.key
sudo systemctl restart unbound
```

## Uninstallation

```bash
# Stop services
sudo systemctl stop unbound
sudo systemctl disable unbound

# Remove packages
sudo apt remove --purge unbound unbound-anchor

# Remove configuration
sudo rm -rf /etc/unbound/unbound.conf.d/local.conf
sudo rm -f /etc/systemd/system/unbound-root-hints.*

# Restore systemd-resolved
sudo systemctl restart systemd-resolved
```

## Requirements

- Ubuntu/Debian-based system
- Root/sudo access
- Internet connection
- systemd

## Security Notes

- **Localhost only**: Default config only accepts local queries
- **DNSSEC enabled**: Validates DNS responses
- **No recursion for external**: Prevents DNS amplification attacks
- **Regular updates**: Monthly root hints refresh keeps it current

This script is designed for VPS environments where you want a simple, secure DNS resolver without complexity.