# Unbound DNS Server Installation Script

An interactive bash script for installing and configuring Unbound DNS server on Ubuntu 22.04 with enhanced security, validation, and error handling.

## Features

- **Interactive Setup**: Choose between GUI (whiptail) or fallback text interface
- **Multiple DNS Modes**: Recursive DNS or forwarding to upstream providers
- **DNS-over-TLS Support**: Secure DNS queries with DoT encryption
- **System Integration**: Works with systemd-resolved or replaces it entirely
- **LAN Support**: Optional network-wide DNS service with firewall configuration
- **DNSSEC Validation**: Built-in DNSSEC support with trust anchor management
- **Automated Maintenance**: Optional monthly root hints refresh
- **Comprehensive Testing**: Built-in health checks and validation

## Recent Security Improvements

This script has been enhanced to address several security and reliability issues:

### Fixed Medium Severity Issues:

1. **OS Compatibility Validation**: Now requires explicit confirmation to proceed on non-Ubuntu 22.04 systems
2. **User Consent for Dependencies**: Asks permission before installing whiptail package
3. **Input Validation**: Validates IP addresses and CIDR notation for custom DNS servers and LAN configuration
4. **Connectivity Checks**: Verifies internet connection before downloading files
5. **Race Condition Prevention**: Ensures Unbound is running before reconfiguring systemd-resolved
6. **Enhanced Error Handling**: Better error messages and recovery for package installation failures

## Requirements

- Ubuntu 22.04 LTS (other versions supported with confirmation)
- Root/sudo privileges
- Internet connection
- Basic understanding of DNS concepts

## Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/your-repo/setup-unbound-pretty.sh
# or
curl -O https://raw.githubusercontent.com/your-repo/setup-unbound-pretty.sh
```

2. Make it executable:
```bash
chmod +x setup-unbound-pretty.sh
```

3. Run with root privileges:
```bash
sudo ./setup-unbound-pretty.sh
```

## Configuration Options

### DNS Resolution Modes

1. **Recommended**: systemd-resolved forwards to Unbound on 127.0.0.1
   - Maintains system compatibility
   - Preserves existing network manager integration
   - Safest option for most users

2. **Static**: Disable systemd-resolved, use static /etc/resolv.conf
   - Direct DNS resolution through Unbound
   - More control but may conflict with network managers

### Unbound Operating Modes

1. **Recursive** (Default): Full recursive DNS resolution
   - Queries root servers directly
   - Maximum privacy and independence
   - Slower initial queries, faster subsequent ones

2. **Forwarding**: Use upstream DNS providers
   - Faster initial responses
   - Choose from Cloudflare, Quad9, Google, or custom servers
   - Optional DNS-over-TLS encryption

### Network Configuration

- **Localhost Only**: DNS service available only to local system
- **LAN Access**: Allow other devices on your network to use the DNS server
  - Automatically configures UFW firewall rules
  - Validates CIDR notation for network ranges

## DNS Providers (Forwarding Mode)

| Provider | IPv4 Servers | IPv6 Servers | DoT Support |
|----------|--------------|--------------|-------------|
| Cloudflare | 1.1.1.1, 1.0.0.1 | 2606:4700:4700::1111, 2606:4700:4700::1001 | ✅ |
| Quad9 | 9.9.9.9, 149.112.112.112 | 2620:fe::fe, 2620:fe::9 | ✅ |
| Google | 8.8.8.8, 8.8.4.4 | 2001:4860:4860::8888, 2001:4860:4860::8844 | ✅ |
| Custom | User-defined | User-defined | ✅ |

## Security Features

- **DNSSEC Validation**: Automatic trust anchor management and validation
- **Query Privacy**: Hide DNS server identity and version information
- **Cache Hardening**: Protection against cache poisoning attacks
- **Access Control**: Strict IP-based access controls
- **TLS Certificate Validation**: Proper certificate bundle configuration for DoT

## Post-Installation

### Health Checks

The script automatically runs several tests:
- Root server connectivity
- DNSSEC positive validation (cloudflare.com)
- DNSSEC negative validation (dnssec-failed.org)
- System resolver configuration

### Manual Testing

Test your installation anytime:
```bash
# Basic DNS resolution
dig @127.0.0.1 . NS +dnssec

# DNSSEC positive test
dig @127.0.0.1 cloudflare.com A +dnssec

# DNSSEC negative test (should SERVFAIL)
dig @127.0.0.1 dnssec-failed.org A +dnssec
```

### Monitoring

Check Unbound status:
```bash
sudo systemctl status unbound
sudo journalctl -u unbound -f
```

View resolver configuration:
```bash
resolvectl status
cat /etc/resolv.conf
```

## Maintenance

### Root Hints Updates

If you enabled the monthly timer, root hints are automatically updated. Manual update:
```bash
sudo curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints
sudo chown unbound:unbound /var/lib/unbound/root.hints
sudo systemctl reload unbound
```

### Configuration Changes

Main configuration file: `/etc/unbound/unbound.conf.d/local.conf`

After making changes:
```bash
sudo unbound-checkconf
sudo systemctl restart unbound
```

## Troubleshooting

### Common Issues

1. **DNS Resolution Fails**:
   - Check Unbound status: `sudo systemctl status unbound`
   - Verify configuration: `sudo unbound-checkconf`
   - Check logs: `sudo journalctl -u unbound`

2. **DNSSEC Validation Issues**:
   - Verify trust anchor: `ls -la /var/lib/unbound/root.key`
   - Re-bootstrap: `sudo unbound-anchor -a /var/lib/unbound/root.key`

3. **Network Connectivity Problems**:
   - Check firewall: `sudo ufw status`
   - Verify interfaces: `sudo netstat -tulpn | grep :53`

4. **systemd-resolved Conflicts**:
   - Check resolver status: `resolvectl status`
   - Verify configuration: `cat /etc/systemd/resolved.conf`

### Log Analysis

View detailed logs:
```bash
# Unbound logs
sudo journalctl -u unbound --since "1 hour ago"

# systemd-resolved logs (if using recommended mode)
sudo journalctl -u systemd-resolved --since "1 hour ago"
```

## Uninstallation

To remove Unbound and restore original DNS configuration:

```bash
# Stop and disable Unbound
sudo systemctl stop unbound
sudo systemctl disable unbound

# Remove packages
sudo apt remove --purge unbound unbound-anchor

# Restore systemd-resolved (if it was disabled)
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved

# Remove custom configuration
sudo rm -rf /etc/unbound/unbound.conf.d/local.conf
sudo rm -f /etc/systemd/system/unbound-root-hints.*

# Reset resolv.conf (if using static mode)
sudo rm -f /etc/resolv.conf
sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```

## Contributing

Contributions are welcome! Please:
1. Test changes on Ubuntu 22.04
2. Maintain backward compatibility
3. Add appropriate error handling
4. Update documentation

## License

This script is provided as-is under the MIT License. Use at your own risk.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review system logs
3. Consult Unbound documentation: https://unbound.docs.nlnetlabs.nl/
4. Open an issue with detailed logs and system information