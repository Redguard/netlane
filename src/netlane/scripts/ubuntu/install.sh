#!/bin/bash
# Persistent base hardening of a dedicated server.
# Interfaces in the trusted set are the only way past its drop policies.
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (or via sudo)"
  exit 1
fi

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <app_name> <base_table> <trusted_set> <wg_port>"
    exit 1
fi

APP_NAME=$1
BASE_TABLE=$2
TRUSTED_SET=$3
WG_PORT=$4

echo "[*] Updating apt and installing wireguard, nftables, conntrack..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard nftables conntrack

echo "[*] Writing persistent base firewall ruleset..."
cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet ${BASE_TABLE} {
    set ${TRUSTED_SET} {
        type ifname
    }

    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop
        iifname lo accept
        meta l4proto { icmp, icmpv6 } accept
        tcp dport 22 accept
        udp dport ${WG_PORT} accept
        iifname @${TRUSTED_SET} accept
    }

    # A drop in any base chain is final, so passthrough traffic must also be accepted here.
    chain forward {
        type filter hook forward priority filter; policy drop;

        ct state established,related accept
        # Invalid packets skip NAT and would leave unmasqueraded.
        ct state invalid drop
        iifname @${TRUSTED_SET} accept
    }
}
EOF

echo "[*] Applying ruleset and enabling nftables persistence..."
nft -f /etc/nftables.conf
systemctl enable --now nftables

echo "[*] Allowing the SSH reverse tunnel to bind the WireGuard tunnel address..."
cat > /etc/ssh/sshd_config.d/99-${APP_NAME}-gatewayports.conf <<EOF
# Lets an explicit "ssh -R <wg_server_addr>:port:..." bind that address
# instead of being silently forced to loopback-only.
GatewayPorts clientspecified
EOF
systemctl reload ssh

echo "[*] Ubuntu install complete!"
