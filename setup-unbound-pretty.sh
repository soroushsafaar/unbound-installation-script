#!/usr/bin/env bash
# setup-unbound-pretty.sh
# Interactive installer for Unbound on Ubuntu 22.04, with forwarding/DoT options,
# ensuring the WHOLE system resolves via Unbound.

set -euo pipefail

# =========[ Styling ]=========
BLD="\033[1m"; DIM="\033[2m"; RED="\033[31m"; GRN="\033[32m"; YEL="\033[33m"; BLU="\033[34m"; RST="\033[0m"

banner() {
  echo -e "${BLD}${BLU}
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                Unbound DNS Installer (22.04)           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛${RST}"
}

ok()   { echo -e "${GRN}✔${RST} $*"; }
warn() { echo -e "${YEL}➜${RST} $*"; }
err()  { echo -e "${RED}✖${RST} $*" >&2; }
info() { echo -e "${BLD}•${RST} $*"; }
die()  { err "$*"; exit 1; }

need_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run this script with sudo/root."
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# Validate IP address format
validate_ip() {
  local ip="$1"
  if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $ip =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$ ]]; then
    return 0
  fi
  return 1
}

# Validate CIDR format
validate_cidr() {
  local cidr="$1"
  [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || [[ $cidr =~ ^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}/[0-9]{1,3}$ ]]
}

# Check internet connectivity
check_connectivity() {
  if ! curl -s --connect-timeout 5 --max-time 10 https://www.internic.net >/dev/null 2>&1; then
    err "No internet connectivity detected. Please check your connection."
    return 1
  fi
  return 0
}

# =========[ Whiptail helpers ]=========
WT=0
wt_yesno() { whiptail --title "$1" --yesno "$2" 12 70; }
wt_menu()  { whiptail --title "$1" --nocancel --menu "$2" 17 72 7 "${@:3}"; }
wt_input() { whiptail --title "$1" --inputbox "$2" 10 70 "$3"; }

fallback_yesno() {
  local prompt="$1 [y/N]: "; read -r -p "$prompt" a; [[ "${a,,}" == "y" || "${a,,}" == "yes" ]]
}

fallback_menu() {
  local title="$1" msg="$2"; shift 2
  echo -e "${BLD}$title${RST}\n$msg"
  local i=1; local opts=("$@")
  while (( i<=${#opts[@]} )); do
    echo "  ${i}) ${opts[$((i-1))]}"
    ((i++))
  done
  read -r -p "Choose 1-${#opts[@]}: " choice
  echo "${opts[$((choice-1))]}"
}

fallback_input() {
  local title="$1" msg="$2" def="$3"
  echo -e "${BLD}$title${RST}\n$msg"
  read -r -p "> " val || true
  echo "${val:-$def}"
}

# =========[ Detection ]=========
detect_lan_cidr() {
  ip -o -f inet addr show | awk '!/ lo / {print $4; exit}' 2>/dev/null || true
}

primary_ipv4() {
  ip -o -4 addr show | awk '!/ lo / {print $4}' | head -n1 | cut -d/ -f1 2>/dev/null || true
}

# =========[ Forwarding Builder ]=========
# Build forward-zone config lines based on provider/DoT/custom entry
build_forward_zone() {
  local provider="$1" use_dot="$2" custom_list="$3"
  local zone="forward-zone:\n  name: \".\""

  if [[ "$use_dot" == "yes" ]]; then
    zone+="\n  forward-tls-upstream: yes"
  fi

  # Helper to append forward-addr (with optional @853 and auth name)
  append_addr() {
    local ip="$1" auth="$2"
    if [[ "$use_dot" == "yes" ]]; then
      if [[ -n "$auth" ]]; then
        zone+="\n  forward-addr: ${ip}@853#${auth}"
      else
        zone+="\n  forward-addr: ${ip}@853"
      fi
    else
      zone+="\n  forward-addr: ${ip}"
    fi
  }

  case "$provider" in
    "Cloudflare")
      append_addr "1.1.1.1"   "cloudflare-dns.com"
      append_addr "1.0.0.1"   "cloudflare-dns.com"
      append_addr "2606:4700:4700::1111" "cloudflare-dns.com"
      append_addr "2606:4700:4700::1001" "cloudflare-dns.com"
      ;;
    "Quad9")
      append_addr "9.9.9.9"           "dns.quad9.net"
      append_addr "149.112.112.112"   "dns.quad9.net"
      append_addr "2620:fe::fe"       "dns.quad9.net"
      append_addr "2620:fe::9"        "dns.quad9.net"
      ;;
    "Google")
      append_addr "8.8.8.8"     "dns.google"
      append_addr "8.8.4.4"     "dns.google"
      append_addr "2001:4860:4860::8888" "dns.google"
      append_addr "2001:4860:4860::8844" "dns.google"
      ;;
    "Custom")
      # Expect inputs like: "1.2.3.4, 2.3.4.5" or with optional auth via ip#name when DoT
      # Example DoT custom: "1.2.3.4#example.tld, 2.3.4.5#other.tld"
      IFS=',' read -r -a arr <<< "$custom_list"
      for raw in "${arr[@]}"; do
        raw="$(echo "$raw" | xargs)"  # trim
        [[ -z "$raw" ]] && continue
        local ip="${raw%%#*}"
        local auth=""
        if [[ "$raw" == *"#"* ]]; then auth="${raw#*#}"; fi
        append_addr "$ip" "$auth"
      done
      ;;
  esac

  # shellcheck disable=SC2059
  printf "%b\n" "$zone"
}

# =========[ Main ]=========
main() {
  need_root
  banner

  . /etc/os-release 2>/dev/null || true
  if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
    warn "This script is tailored for Ubuntu 22.04 (you have ${PRETTY_NAME:-unknown})."
    if ! fallback_yesno "Continue anyway? (may cause issues)"; then
      die "Installation cancelled."
    fi
  fi

  if have_cmd whiptail; then 
    WT=1
  else 
    warn "whiptail not found. Install it for better UI?"
    if fallback_yesno "Install whiptail package?"; then
      info "Installing whiptail…"
      apt-get update -y && apt-get install -y whiptail
      WT=1
    else
      WT=0
    fi
  fi

  # =====[ Choices ]=====
  local RESOLVE_MODE CHOICE ALLOW_LAN="no" LAN_CIDR="" SET_TIMER="no"
  local RECURSE_OR_FORWARD="" PROVIDER="" USE_DOT="yes" CUSTOM_FWDS=""

  # Mode: how the OS uses Unbound
  if (( WT )); then
    CHOICE=$(wt_menu "Resolver Mode" \
      "How should we force the WHOLE system to use Unbound?" \
      "Recommended (systemd-resolved forwards to 127.0.0.1)" "strict-static (/etc/resolv.conf static; disable resolved)")
    RESOLVE_MODE="$CHOICE"

    # Recursion vs Forwarding
    RECURSE_OR_FORWARD=$(wt_menu "Unbound Operating Mode" \
      "Pick Unbound mode:" \
      "Recursive (default; no forwarders)" "Forwarding (use upstream DNS servers)")

    if [[ "$RECURSE_OR_FORWARD" == "Forwarding (use upstream DNS servers)" ]]; then
      PROVIDER=$(wt_menu "Forwarders" \
        "Choose upstream DNS provider(s) for '.' zone:" \
        "Cloudflare" "Quad9" "Google" "Custom")
      if wt_yesno "DNS-over-TLS" "Use DNS-over-TLS to your upstreams? (Recommended)"; then
        USE_DOT="yes"
      else
        USE_DOT="no"
      fi
      if [[ "$PROVIDER" == "Custom" ]]; then
        while true; do
          CUSTOM_FWDS=$(wt_input "Custom forwarders" "Enter IPs separated by commas.\nFor DoT, you may append #auth.name to each IP (e.g., 1.2.3.4#auth.example).\nExamples:\n  1.1.1.1, 9.9.9.9\n  1.1.1.1#cloudflare-dns.com, 8.8.8.8#dns.google" "")
          # Validate custom forwarders
          local valid=true
          IFS=',' read -r -a test_arr <<< "$CUSTOM_FWDS"
          for raw in "${test_arr[@]}"; do
            raw="$(echo "$raw" | xargs)"
            [[ -z "$raw" ]] && continue
            local test_ip="${raw%%#*}"
            if ! validate_ip "$test_ip"; then
              valid=false
              break
            fi
          done
          if [[ "$valid" == "true" ]]; then
            break
          else
            wt_yesno "Invalid IP" "Invalid IP address format detected. Try again?" || die "Installation cancelled."
          fi
        done
      fi
    fi

    if wt_yesno "LAN Access" "Let other LAN devices use this Unbound server? (opens UFW for your LAN CIDR)"; then
      ALLOW_LAN="yes"
      LAN_CIDR="$(detect_lan_cidr)"
      while true; do
        LAN_CIDR=$(wt_input "LAN CIDR" "Detected: ${LAN_CIDR:-<none>}\nEnter the CIDR allowed to query (e.g., 192.168.1.0/24):" "${LAN_CIDR:-192.168.1.0/24}") || true
        if validate_cidr "$LAN_CIDR"; then
          break
        else
          wt_yesno "Invalid CIDR" "Invalid CIDR format. Try again?" || { ALLOW_LAN="no"; break; }
        fi
      done
    fi

    if wt_yesno "Monthly root.hints refresh" "Install a systemd timer to refresh root hints monthly?"; then
      SET_TIMER="yes"
    fi
  else
    RESOLVE_MODE=$(fallback_menu "Resolver Mode" "Choose mode for whole system:" \
      "Recommended (systemd-resolved forwards to 127.0.0.1)" "strict-static (/etc/resolv.conf static; disable resolved)")
    RECURSE_OR_FORWARD=$(fallback_menu "Unbound Operating Mode" "Pick Unbound mode:" \
      "Recursive (default; no forwarders)" "Forwarding (use upstream DNS servers)")
    if [[ "$RECURSE_OR_FORWARD" == "Forwarding (use upstream DNS servers)" ]]; then
      PROVIDER=$(fallback_menu "Forwarders" "Choose upstream DNS:" \
        "Cloudflare" "Quad9" "Google" "Custom")
      if fallback_yesno "Use DNS-over-TLS to upstreams? (recommended)"; then USE_DOT="yes"; else USE_DOT="no"; fi
      if [[ "$PROVIDER" == "Custom" ]]; then
        while true; do
          CUSTOM_FWDS=$(fallback_input "Custom forwarders" "Enter IPs comma-separated. For DoT, you can add #auth.name (e.g., 1.2.3.4#auth.example):" "")
          # Validate custom forwarders
          local valid=true
          IFS=',' read -r -a test_arr <<< "$CUSTOM_FWDS"
          for raw in "${test_arr[@]}"; do
            raw="$(echo "$raw" | xargs)"
            [[ -z "$raw" ]] && continue
            local test_ip="${raw%%#*}"
            if ! validate_ip "$test_ip"; then
              err "Invalid IP address: $test_ip"
              valid=false
              break
            fi
          done
          if [[ "$valid" == "true" ]]; then
            break
          else
            if ! fallback_yesno "Try again?"; then
              die "Installation cancelled."
            fi
          fi
        done
      fi
    fi
    if fallback_yesno "Allow LAN clients?"; then
      ALLOW_LAN="yes"
      LAN_CIDR="$(detect_lan_cidr)"
      while true; do
        LAN_CIDR=$(fallback_input "LAN CIDR" "CIDR allowed to query (e.g., 192.168.1.0/24). Detected: ${LAN_CIDR:-<none>}" "${LAN_CIDR:-192.168.1.0/24}")
        if validate_cidr "$LAN_CIDR"; then
          break
        else
          err "Invalid CIDR format: $LAN_CIDR"
          if ! fallback_yesno "Try again?"; then
            ALLOW_LAN="no"
            break
          fi
        fi
      done
    fi
    if fallback_yesno "Install monthly root.hints refresh timer?"; then SET_TIMER="yes"; fi
  fi

  info "Installing packages…"
  export DEBIAN_FRONTEND=noninteractive
  if ! apt-get update -y; then
    err "Failed to update package lists. Check your internet connection and repositories."
    exit 1
  fi
  if ! apt-get install -y --no-install-recommends unbound unbound-anchor dnsutils curl ca-certificates; then
    err "Failed to install required packages. Check available disk space and repositories."
    exit 1
  fi

  install -d -o root -g root -m 755 /etc/unbound/unbound.conf.d
  install -d -o unbound -g unbound -m 750 /var/lib/unbound

  info "Fetching latest root hints…"
  if ! check_connectivity; then
    exit 1
  fi
  if ! curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints; then
    err "Failed to download root hints. Check internet connectivity."
    exit 1
  fi
  chown unbound:unbound /var/lib/unbound/root.hints; chmod 644 /var/lib/unbound/root.hints

  info "Bootstrapping DNSSEC trust anchor…"
  unbound-anchor -a /var/lib/unbound/root.key || true
  chown unbound:unbound /var/lib/unbound/root.key; chmod 644 /var/lib/unbound/root.key

  # ---- Unbound config ----
  local UNBOUND_CONF="/etc/unbound/unbound.conf.d/local.conf"
  info "Writing Unbound configuration…"
  cat > "$UNBOUND_CONF" <<'EOF'
server:
  # Privacy + Security
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

  # Caching
  prefetch: yes
  prefetch-key: yes
  cache-min-ttl: 60
  cache-max-ttl: 86400
  rrset-roundrobin: yes
  infra-cache-numhosts: 20000

  # Root & DNSSEC
  root-hints: "/var/lib/unbound/root.hints"
  auto-trust-anchor-file: "/var/lib/unbound/root.key"
  val-clean-additional: yes

  # Ensure system CA bundle is available for DoT validation (safe in both modes)
  tls-cert-bundle: "/etc/ssl/certs/ca-certificates.crt"

  # Interfaces & ACL appended by installer
EOF

  # Bind to localhost always; optionally bind to primary LAN IP.
  local PRIMARY_IP; PRIMARY_IP="$(primary_ipv4 || true)"
  {
    echo "  interface: 127.0.0.1"
    echo "  interface: ::1"
    echo "  access-control: 127.0.0.0/8 allow"
    echo "  access-control: ::1 allow"
  } >> "$UNBOUND_CONF"

  if [[ "$ALLOW_LAN" == "yes" && -n "${PRIMARY_IP:-}" && -n "${LAN_CIDR:-}" ]]; then
    {
      echo "  interface: ${PRIMARY_IP}"
      echo "  access-control: ${LAN_CIDR} allow"
    } >> "$UNBOUND_CONF"
  fi

  # Forwarding mode vs recursive
  if [[ "$RECURSE_OR_FORWARD" == "Forwarding (use upstream DNS servers)" ]]; then
    info "Adding forwarders (${PROVIDER}, DoT: ${USE_DOT})…"
    build_forward_zone "$PROVIDER" "$USE_DOT" "$CUSTOM_FWDS" >> "$UNBOUND_CONF"
  else
    info "Using full recursive mode (no forwarders)."
  fi

  info "Validating Unbound config…"
  unbound-checkconf

  # ---- systemd-resolved integration or disable ----
  if [[ "$RESOLVE_MODE" == "Recommended (systemd-resolved forwards to 127.0.0.1)" ]]; then
    info "Configuring systemd-resolved to forward to Unbound & free port 53…"
    touch /etc/systemd/resolved.conf

    if grep -Eq '^\s*DNSStubListener=' /etc/systemd/resolved.conf; then
      sed -i 's/^\s*DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
    else
      echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
    fi
    if grep -Eq '^\s*DNS=' /etc/systemd/resolved.conf; then
      sed -i 's/^\s*DNS=.*/DNS=127.0.0.1/' /etc/systemd/resolved.conf
    else
      echo "DNS=127.0.0.1" >> /etc/systemd/resolved.conf
    fi
    # Resolve everything via Unbound
    if grep -Eq '^\s*Domains=' /etc/systemd/resolved.conf; then
      sed -i 's/^\s*Domains=.*/Domains=~./' /etc/systemd/resolved.conf
    else
      echo "Domains=~." >> /etc/systemd/resolved.conf
    fi
    # No fallback
    if grep -Eq '^\s*FallbackDNS=' /etc/systemd/resolved.conf; then
      sed -i 's/^\s*FallbackDNS=.*/FallbackDNS=/' /etc/systemd/resolved.conf
    else
      echo "FallbackDNS=" >> /etc/systemd/resolved.conf
    fi

    # Ensure resolv.conf points to resolved's generated file
    if [[ ! -L /etc/resolv.conf ]] || [[ "$(readlink -f /etc/resolv.conf)" != "/run/systemd/resolve/resolv.conf" ]]; then
      rm -f /etc/resolv.conf
      ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
    fi

    # Ensure Unbound is running before restarting systemd-resolved
    info "Starting Unbound first…"
    systemctl enable unbound
    systemctl restart unbound
    sleep 3
    if ! systemctl is-active --quiet unbound; then
      err "Unbound failed to start. Check 'journalctl -u unbound'."
      exit 1
    fi
    systemctl restart systemd-resolved
  else
    info "Disabling systemd-resolved and writing static /etc/resolv.conf…"
    systemctl stop systemd-resolved || true
    systemctl disable systemd-resolved || true
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf <<'EOF'
# Managed by setup-unbound-pretty.sh
# Force all processes to use Unbound on localhost.
nameserver 127.0.0.1
options edns0 trust-ad
EOF
    # Optional: lock resolv.conf to prevent overwrites
    # chattr +i /etc/resolv.conf || true
  fi

  # ---- Enable & start Unbound (if not already done) ----
  if [[ "$RESOLVE_MODE" != "Recommended (systemd-resolved forwards to 127.0.0.1)" ]]; then
    info "Enabling & (re)starting Unbound…"
    systemctl enable unbound
    systemctl restart unbound
  fi

  # ---- UFW Rules ----
  if have_cmd ufw && ufw status | grep -qi "Status: active"; then
    if [[ "$ALLOW_LAN" == "yes" && -n "$LAN_CIDR" ]]; then
      info "Opening UFW for DNS from ${LAN_CIDR}…"
      ufw allow from "$LAN_CIDR" to any port 53 proto udp || true
      ufw allow from "$LAN_CIDR" to any port 53 proto tcp || true
    else
      warn "UFW is active; keeping DNS closed to LAN (localhost-only listening)."
    fi
  fi

  # ---- Optional monthly root.hints refresh ----
  if [[ "$SET_TIMER" == "yes" ]]; then
    info "Creating systemd timer to refresh root.hints monthly…"
    cat > /etc/systemd/system/unbound-root-hints.service <<'EOF'
[Unit]
Description=Refresh Unbound root.hints

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -fsSL https://www.internic.net/domain/named.cache -o /var/lib/unbound/root.hints
ExecStartPost=/bin/chown unbound:unbound /var/lib/unbound/root.hints
ExecStartPost=/bin/chmod 644 /var/lib/unbound/root.hints
ExecStartPost=/bin/systemctl reload unbound
EOF
    cat > /etc/systemd/system/unbound-root-hints.timer <<'EOF'
[Unit]
Description=Monthly refresh of Unbound root.hints

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now unbound-root-hints.timer
  fi

  # ---- Health checks ----
  info "Running health checks…"
  sleep 2

  echo -e "${DIM}systemctl status unbound (first 12 lines):${RST}"
  systemctl --no-pager --full status unbound | sed -n '1,12p' || true

  echo
  ok "dig @127.0.0.1 . NS"
  if ! dig @127.0.0.1 . NS +time=3 +retry=1 >/tmp/dig_root.txt 2>&1; then
    err "Unbound did not answer root NS query. See 'journalctl -u unbound'."
    exit 1
  fi
  grep -q "status: NOERROR" /tmp/dig_root.txt && ok "Root query OK." || warn "Root query did not return NOERROR."

  echo
  ok "DNSSEC positive test (AD flag expected): cloudflare.com"
  dig @127.0.0.1 cloudflare.com A +dnssec +time=3 +retry=1 >/tmp/dig_dnssec_ok.txt 2>&1 || true
  if grep -Eqi "flags:.* ad[ ;]" /tmp/dig_dnssec_ok.txt; then
    ok "DNSSEC validation appears ACTIVE (AD flag present)."
  else
    warn "AD flag not seen — check /var/lib/unbound/root.key and logs."
  fi

  echo
  ok "DNSSEC negative test (SERVFAIL expected): dnssec-failed.org"
  dig @127.0.0.1 dnssec-failed.org A +dnssec +time=3 +retry=1 >/tmp/dig_dnssec_bad.txt 2>&1 || true
  grep -q "status: SERVFAIL" /tmp/dig_dnssec_bad.txt && ok "dnssec-failed.org correctly SERVFAILed." || warn "Unexpected response for dnssec-failed.org."

  echo
  ok "Verifying the WHOLE SYSTEM uses Unbound (resolv.conf → 127.0.0.1)…"
  if grep -qE '^\s*nameserver\s+127\.0\.0\.1\b' /etc/resolv.conf; then
    ok "/etc/resolv.conf points to 127.0.0.1 ✅"
  else
    err "/etc/resolv.conf does not point to 127.0.0.1. Investigate your resolver config."
    exit 1
  fi

  if have_cmd resolvectl && systemctl is-active --quiet systemd-resolved; then
    echo
    info "resolvectl status (for reference):"
    resolvectl status | sed -n '1,80p' || true
  fi

  echo
  banner
  ok "Installation complete."
  echo -e "${BLD}Summary:${RST}"
  echo "  • OS DNS mode: $RESOLVE_MODE"
  echo "  • Unbound mode: $RECURSE_OR_FORWARD"
  if [[ "$RECURSE_OR_FORWARD" == "Forwarding (use upstream DNS servers)" ]]; then
    echo "  • Provider: $PROVIDER  |  DoT: $USE_DOT"
    [[ "$PROVIDER" == "Custom" ]] && echo "  • Custom list: ${CUSTOM_FWDS}"
  fi
  if [[ "$ALLOW_LAN" == "yes" ]]; then
    echo "  • Listening: 127.0.0.1 and ${PRIMARY_IP:-<auto>}; ACL: ${LAN_CIDR}"
  else
    echo "  • Listening: 127.0.0.1 only (localhost)"
  fi
  echo "  • DNSSEC: enabled (trust anchor + tests run)"
  [[ "$SET_TIMER" == "yes" ]] && echo "  • Root hints timer: monthly refresh enabled"
  echo
  echo "Re-run tests anytime:"
  echo "  dig @127.0.0.1 . NS +dnssec"
  echo "  dig @127.0.0.1 cloudflare.com A +dnssec"
  echo "  dig @127.0.0.1 dnssec-failed.org A +dnssec"
}

main "$@"
