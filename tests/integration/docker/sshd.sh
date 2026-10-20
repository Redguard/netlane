#!/bin/sh
# Authorizes the stack's client key for root, starts dropbear with the stack's host key and runs the command.
set -eu

mkdir -p /root/.ssh /etc/dropbear
cp /keys/id_ed25519.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

dropbearconvert openssh dropbear /keys/host_ed25519 /etc/dropbear/dropbear_ed25519_host_key

# -s and -g: no password logins.
dropbear -E -s -g

exec "$@"
