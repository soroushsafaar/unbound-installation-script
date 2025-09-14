#!/usr/bin/env bash
# setup-unbound-vps.sh
# Simple Unbound DNS installer for VPS/servers - no interactive prompts

set -euo pipefail

# Colors
RED="\033[31m"; GRN="\033[32m"; YEL="\033[33m"; BLU="\033[34m"; RST="\033[0m"

ok() { echo -e "${GRN}✔${RST} $*"; }
warn() { echo -e "${YEL}➜${RST} $*"; }
err() { echo -e "${RED}✖${RST} $*" >&2; }
info() { echo -e "${BLU}•${RST} $*"; }
die() { err "$*"; exit 1; }

need_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this script with sudo/root."
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

check_connectivity() {
  if ! curl -s --connect-timeout 5 --max-time 10 https://www.internic.net >/dev/null 2>&1; then
    die "No internet connectivity. Check your connection."
  fi
}

main() {
  need_root
  
  echo -e "${BLU}Installing Unbound DNS Server for VPS${RST}"
  echo "Using defaults: Recursive mode, localhost only, systemd-resolved integration"
  
  # Check OS (warn but continue)
  . /etc/os-release 2>/dev/null || true
  if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "Not Ubuntu - may have issues (detected: ${PRETTY_NAME:-unknown})"
  fi
  
  check_connectivity
  
  info "Installing packages..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || die "Failed to update package lists"
  apt-get install -y --no-install-recommends unbound unbound-anchor dnsutils curl ca-certificates || die "Failed to install packages"
  
  info "Creating directories..."
  install -d -o root -g root -m 755 /etc/unbound/unbound.conf.d
  install -d -o unbound -g unbound -m 750 /var/lib/unbound
  
  info "Downloading root hints..."
  curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints || die "Failed to download root hints"
  chown unbound:unbound /var/lib/unbound/root.hints
  chmod 644 /var/lib/unbound/root.hints
  
  info "Setting up DNSSEC trust anchor..."
  unbound-anchor -a /var/lib/unbound/root.key || warn "Trust anchor setup had issues"
  chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
  chmod 644 /var/lib/unbound/root.key 2>/dev/null || true
  
  info "Writing Unbound configuration..."
  cat > /etc/unbound/unbound.conf.d/local.conf <<'EOF'
server:
  # Basic settings
  interface: 127.0.0.1
  interface: ::1
  access-control: 127.0.0.0/8 allow
  access-control: ::1 allow
  
  # Privacy & Security
  hide-identity: yes
  hide-version: yes
  use-caps-for-id: yes
  qname-minimisation: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-below-nxdomain: yes
  harden-referral-path: yes
  aggressive-nsec: yes
  unwanted-reply-threshold: 10000000
  
  # Performance
  prefetch: yes
  prefetch-key: yes
  cache-min-ttl: 60
  cache-max-ttl: 86400
  rrset-roundrobin: yes
  infra-cache-numhosts: 10000
  
  # DNSSEC
  root-hints: "/var/lib/unbound/root.hints"
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  val-clean-additional: yes
  tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"
EOF
  
  info "Validating configuration..."
  unbound-checkconf || die "Invalid Unbound configuration"
  
  info "Configuring systemd-resolved..."
  # Configure systemd-resolved to use Unbound
  {
    echo "DNS=127.0.0.1"
    echo "DNSStubListener=no"
    echo "Domains=~."
    echo "FallbackDNS="
  } > /etc/systemd/resolved.conf
  
  # Fix resolv.conf symlink
  rm -f /etc/resolv.conf
  ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
  
  info "Starting services..."
  systemctl enable unbound
  systemctl restart unbound
  sleep 2
  
  if ! systemctl is-active --quiet unbound; then
    die "Unbound failed to start. Check: journalctl -u unbound"
  fi
  
  systemctl restart systemd-resolved
  
  info "Setting up monthly root hints refresh..."
  cat > /etc/systemd/system/unbound-root-hints.service <<'EOF'
[Unit]
Description=Refresh Unbound root hints

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints
ExecStartPost=/bin/chown unbound:unbound /var/lib/unbound/root.hints
ExecStartPost=/bin/chmod 644 /var/lib/unbound/root.hints
ExecStartPost=/bin/systemctl reload unbound
EOF
  
  cat > /etc/systemd/system/unbound-root-hints.timer <<'EOF'
[Unit]
Description=Monthly Unbound root hints refresh

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
EOF
  
  systemctl daemon-reload
  systemctl enable --now unbound-root-hints.timer
  
  info "Running tests..."
  sleep 2
  
  # Test DNS resolution
  if dig @127.0.0.1 . NS +time=3 +retry=1 >/dev/null 2>&1; then
    ok "DNS resolution working"
  else
    warn "DNS test failed - check logs"
  fi
  
  # Test DNSSEC
  if dig @127.0.0.1 cloudflare.com A +dnssec +time=3 +retry=1 2>/dev/null | grep -q "flags:.*ad"; then
    ok "DNSSEC validation active"
  else
    warn "DNSSEC may not be working properly"
  fi
  
  # Verify system DNS
  if grep -q "127.0.0.1" /etc/resolv.conf; then
    ok "System DNS configured correctly"
  else
    warn "System DNS configuration issue"
  fi
  
  echo
  ok "Unbound installation complete!"
  echo "• Mode: Recursive DNS (no forwarders)"
  echo "• Listening: localhost only (127.0.0.1)"
  echo "• DNSSEC: enabled"
  echo "• Auto-updates: monthly root hints refresh"
  echo
  echo "Test commands:"
  echo "  dig @127.0.0.1 google.com"
  echo "  systemctl status unbound"
  echo "  journalctl -u unbound -f"
}

main "$@"