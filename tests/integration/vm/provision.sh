#!/bin/sh
# Prepares an Ubuntu VM as the Docker host of the integration test stack.
# Runs as root and can be repeated.
set -eu
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends docker.io docker-compose-v2
usermod -aG docker vagrant

# The containers share the VM's kernel.
# Redroid needs binder and the legacy iptables tables, the VPS WireGuard and nftables.
modules="binder_linux
iptable_filter iptable_nat ip6table_filter ip6table_nat
xt_owner xt_comment ipt_REJECT ip6t_REJECT
wireguard nf_tables nft_ct nft_chain_nat nft_nat nft_masq nft_reject_inet"

if ! modinfo binder_linux >/dev/null 2>&1; then
    apt-get install -y --no-install-recommends "linux-modules-extra-$(uname -r)"
fi
echo "options binder_linux devices=binder,hwbinder,vndbinder" > /etc/modprobe.d/integration-test.conf
printf '%s\n' $modules > /etc/modules-load.d/integration-test.conf
modprobe -a $modules
