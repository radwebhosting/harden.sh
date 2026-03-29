#!/usr/bin/env bash
set -Eeuo pipefail

# VPS one-click hardening script
# Supports: Ubuntu, Debian, AlmaLinux, Rocky Linux, RHEL-compatible systems
#
# What it does:
# - Creates a sudo admin user
# - Installs SSH public key for that user
# - Disables root SSH login
# - Disables SSH password authentication
# - Optionally changes SSH port
# - Configures firewall for SSH/HTTP/HTTPS
# - Installs and enables Fail2Ban
# - Enables automatic security updates
# - Applies basic sysctl hardening
# - Sets sane file permissions
# - Disables unnecessary services if present
#
# Usage examples:
#   curl -fsSL https://example.com/harden.sh -o harden.sh && bash harden.sh
#   ADMIN_USER=deploy SSH_PUBKEY_FILE=/root/.ssh/id_ed25519.pub SSH_PORT=2222 bash harden.sh
#   ADMIN_USER=deploy SSH_PUBKEY="ssh-ed25519 AAAA..." bash harden.sh
#
# Recommended environment variables:
#   ADMIN_USER=secureadmin
#   SSH_PORT=2222
#   SSH_PUBKEY="ssh-ed25519 AAAA..."
#   SSH_PUBKEY_FILE=/path/to/public.key
#   ALLOW_HTTP=yes
#   ALLOW_HTTPS=yes
#   DISABLE_IPV6=no
#   REBOOT_IF_NEEDED=no

readonly SCRIPT_NAME="$(basename "$0")"
readonly BACKUP_DIR="/root/hardening-backups-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

ADMIN_USER="${ADMIN_USER:-secureadmin}"
SSH_PORT="${SSH_PORT:-2222}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
SSH_PUBKEY_FILE="${SSH_PUBKEY_FILE:-}"
ALLOW_HTTP="${ALLOW_HTTP:-yes}"
ALLOW_HTTPS="${ALLOW_HTTPS:-yes}"
DISABLE_IPV6="${DISABLE_IPV6:-no}"
REBOOT_IF_NEEDED="${REBOOT_IF_NEEDED:-no}"

OS_FAMILY=""
PKG_INSTALL=""
PKG_UPDATE=""
SSH_SERVICE="sshd"
FIREWALL_BACKEND=""
NEED_RESTART=0

log() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "Run this script as root."
  fi
}

backup_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    cp -a "$file" "$BACKUP_DIR/"
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_os() {
  [[ -r /etc/os-release ]] || fail "/etc/os-release not found."
  # shellcheck disable=SC1091
  source /etc/os-release

  case "${ID:-}${ID_LIKE:+ ${ID_LIKE}}" in
    *debian*|*ubuntu*)
      OS_FAMILY="debian"
      PKG_INSTALL="apt-get install -y"
      PKG_UPDATE="apt-get update"
      ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
      OS_FAMILY="rhel"
      if command_exists dnf; then
        PKG_INSTALL="dnf install -y"
        PKG_UPDATE="dnf makecache"
      else
        PKG_INSTALL="yum install -y"
        PKG_UPDATE="yum makecache"
      fi
      ;;
    *)
      fail "Unsupported OS: ${PRETTY_NAME:-unknown}"
      ;;
  esac

  log "Detected OS family: $OS_FAMILY"
}

validate_inputs() {
  [[ "$ADMIN_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || fail "Invalid ADMIN_USER: $ADMIN_USER"
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || fail "SSH_PORT must be numeric."
  (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) || fail "SSH_PORT must be between 1 and 65535."

  if [[ -n "$SSH_PUBKEY_FILE" ]]; then
    [[ -r "$SSH_PUBKEY_FILE" ]] || fail "SSH_PUBKEY_FILE is not readable: $SSH_PUBKEY_FILE"
    SSH_PUBKEY="$(tr -d '\r' < "$SSH_PUBKEY_FILE")"
  fi

  [[ -n "$SSH_PUBKEY" ]] || fail "Provide SSH_PUBKEY or SSH_PUBKEY_FILE."

  case "$ALLOW_HTTP" in yes|no) ;; *) fail "ALLOW_HTTP must be yes or no." ;; esac
  case "$ALLOW_HTTPS" in yes|no) ;; *) fail "ALLOW_HTTPS must be yes or no." ;; esac
  case "$DISABLE_IPV6" in yes|no) ;; *) fail "DISABLE_IPV6 must be yes or no." ;; esac
  case "$REBOOT_IF_NEEDED" in yes|no) ;; *) fail "REBOOT_IF_NEEDED must be yes or no." ;; esac
}

install_base_packages() {
  log "Updating package metadata..."
  eval "$PKG_UPDATE"

  if [[ "$OS_FAMILY" == "debian" ]]; then
    DEBIAN_FRONTEND=noninteractive eval "$PKG_INSTALL" sudo curl ca-certificates gnupg lsb-release fail2ban ufw unattended-upgrades apt-listchanges
  else
    eval "$PKG_INSTALL" sudo curl ca-certificates fail2ban firewalld policycoreutils-python-utils || \
    eval "$PKG_INSTALL" sudo curl ca-certificates fail2ban firewalld
  fi
}

create_admin_user() {
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    log "User $ADMIN_USER already exists."
  else
    log "Creating admin user: $ADMIN_USER"
    useradd -m -s /bin/bash "$ADMIN_USER"
  fi

  if [[ "$OS_FAMILY" == "debian" ]]; then
    usermod -aG sudo "$ADMIN_USER"
  else
    usermod -aG wheel "$ADMIN_USER"
  fi

  install -d -m 700 -o "$ADMIN_USER" -g "$ADMIN_USER" "/home/$ADMIN_USER/.ssh"
  printf '%s\n' "$SSH_PUBKEY" > "/home/$ADMIN_USER/.ssh/authorized_keys"
  chown "$ADMIN_USER:$ADMIN_USER" "/home/$ADMIN_USER/.ssh/authorized_keys"
  chmod 600 "/home/$ADMIN_USER/.ssh/authorized_keys"

  log "Installed SSH key for $ADMIN_USER"
}

configure_sshd() {
  local sshd_config="/etc/ssh/sshd_config"
  backup_file "$sshd_config"

  mkdir -p /etc/ssh/sshd_config.d
  local hardening_conf="/etc/ssh/sshd_config.d/99-hardening.conf"

  cat > "$hardening_conf" <<EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
AllowUsers $ADMIN_USER
EOF

  if sshd -t; then
    systemctl enable "$SSH_SERVICE"
    systemctl restart "$SSH_SERVICE"
    log "SSH daemon reloaded successfully."
  else
    fail "sshd configuration test failed. Review: $hardening_conf"
  fi
}

configure_firewall_debian() {
  FIREWALL_BACKEND="ufw"
  log "Configuring UFW firewall..."

  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp" comment 'SSH'

  [[ "$ALLOW_HTTP" == "yes" ]] && ufw allow 80/tcp comment 'HTTP'
  [[ "$ALLOW_HTTPS" == "yes" ]] && ufw allow 443/tcp comment 'HTTPS'

  ufw --force enable
  ufw status verbose
}

configure_firewall_rhel() {
  FIREWALL_BACKEND="firewalld"
  log "Configuring firewalld..."

  systemctl enable --now firewalld

  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
  [[ "$ALLOW_HTTP" == "yes" ]] && firewall-cmd --permanent --add-service=http
  [[ "$ALLOW_HTTPS" == "yes" ]] && firewall-cmd --permanent --add-service=https

  if [[ "$SSH_PORT" != "22" ]]; then
    firewall-cmd --permanent --remove-service=ssh || true
  fi

  firewall-cmd --reload
  firewall-cmd --list-all
}

configure_firewall() {
  if [[ "$OS_FAMILY" == "debian" ]]; then
    configure_firewall_debian
  else
    configure_firewall_rhel
  fi
}

configure_fail2ban() {
  log "Configuring Fail2Ban..."
  mkdir -p /etc/fail2ban
  local jail_local="/etc/fail2ban/jail.local"
  backup_file "$jail_local"

  cat > "$jail_local" <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
destemail = root@localhost
sender = fail2ban@$(hostname -f 2>/dev/null || hostname)
mta = sendmail

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
  fail2ban-client ping >/dev/null 2>&1 || fail "Fail2Ban failed to start."
}

configure_auto_updates_debian() {
  log "Enabling unattended upgrades..."
  mkdir -p /etc/apt/apt.conf.d

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

  cat > /etc/apt/apt.conf.d/52unattended-upgrades-local <<'EOF'
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
}

configure_auto_updates_rhel() {
  log "Enabling dnf-automatic..."
  eval "$PKG_INSTALL dnf-automatic" || true

  if [[ -f /etc/dnf/automatic.conf ]]; then
    backup_file /etc/dnf/automatic.conf
    sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
    sed -i 's/^download_updates = .*/download_updates = yes/' /etc/dnf/automatic.conf
  fi

  systemctl enable --now dnf-automatic.timer || true
}

configure_auto_updates() {
  if [[ "$OS_FAMILY" == "debian" ]]; then
    configure_auto_updates_debian
  else
    configure_auto_updates_rhel
  fi
}

apply_sysctl_hardening() {
  log "Applying sysctl hardening..."
  local sysctl_file="/etc/sysctl.d/99-vps-hardening.conf"

  cat > "$sysctl_file" <<EOF
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

  if [[ "$DISABLE_IPV6" == "yes" ]]; then
    cat >> "$sysctl_file" <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
  fi

  sysctl --system >/dev/null
}

set_permissions() {
  log "Setting baseline permissions..."
  chmod 700 /root
  [[ -d /root/.ssh ]] && chmod 700 /root/.ssh
  [[ -f /root/.ssh/authorized_keys ]] && chmod 600 /root/.ssh/authorized_keys
}

disable_unused_services() {
  log "Disabling unnecessary services when present..."
  local services=(
    avahi-daemon
    cups
    isc-dhcp-server
    slapd
    telnet.socket
    tftp.socket
    rpcbind
    nfs-server
  )

  for svc in "${services[@]}"; do
    if systemctl list-unit-files | awk '{print $1}' | grep -qx "${svc}"; then
      systemctl disable --now "${svc}" || true
    fi
  done
}

maybe_install_aide() {
  log "Installing AIDE if available..."
  if [[ "$OS_FAMILY" == "debian" ]]; then
    DEBIAN_FRONTEND=noninteractive eval "$PKG_INSTALL aide"
  else
    eval "$PKG_INSTALL aide" || true
  fi

  if command_exists aide; then
    if [[ ! -f /var/lib/aide/aide.db.gz && ! -f /var/lib/aide/aide.db ]]; then
      aideinit || true
    fi
  fi
}

print_summary() {
  cat <<EOF

Hardening complete.

Summary:
- Admin user: $ADMIN_USER
- SSH port: $SSH_PORT
- Root SSH login: disabled
- SSH password auth: disabled
- Firewall: $FIREWALL_BACKEND
- Fail2Ban: enabled
- Automatic updates: enabled
- Sysctl hardening: applied
- Backups of original files: $BACKUP_DIR

Important:
1. Open a new terminal and verify SSH access before closing your current root session:
   ssh -p $SSH_PORT $ADMIN_USER@YOUR_SERVER_IP

2. If login works, keep using the new admin account with sudo.

3. If this server uses provider-level firewalls or security groups, make sure port $SSH_PORT is allowed there too.

EOF
}

maybe_reboot() {
  if [[ "$REBOOT_IF_NEEDED" == "yes" ]]; then
    log "Reboot requested. Rebooting now..."
    reboot
  else
    warn "A reboot was not performed. Reboot manually during a maintenance window if desired."
  fi
}

main() {
  require_root
  detect_os
  validate_inputs
  install_base_packages
  create_admin_user
  configure_firewall
  configure_sshd
  configure_fail2ban
  configure_auto_updates
  apply_sysctl_hardening
  set_permissions
  disable_unused_services
  maybe_install_aide
  print_summary
  maybe_reboot
}
main "$@"
