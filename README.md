harden.sh
What it does:
- Creates a sudo admin user
- Installs SSH public key for that user
- Disables root SSH login
- Disables SSH password authentication
- Optionally changes SSH port
- Configures firewall for SSH/HTTP/HTTPS
- Installs and enables Fail2Ban
- Enables automatic security updates
- Applies basic sysctl hardening
- Sets sane file permissions
- Disables unnecessary services if present

Usage examples:
  curl -fsSL https://example.com/harden.sh -o harden.sh && bash harden.sh
  ADMIN_USER=deploy SSH_PUBKEY_FILE=/root/.ssh/id_ed25519.pub SSH_PORT=2222 bash harden.sh
  ADMIN_USER=deploy SSH_PUBKEY="ssh-ed25519 AAAA..." bash harden.sh

Recommended environment variables:
  ADMIN_USER=secureadmin
  SSH_PORT=2222
  SSH_PUBKEY="ssh-ed25519 AAAA..."
  SSH_PUBKEY_FILE=/path/to/public.key
  ALLOW_HTTP=yes
  ALLOW_HTTPS=yes
  DISABLE_IPV6=no
  REBOOT_IF_NEEDED=no
