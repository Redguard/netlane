#!/bin/sh
# Creates the stack's client key, host key and known_hosts once.
set -eu

cd /keys

test -f id_ed25519 || ssh-keygen -q -t ed25519 -N '' -C integration-test -f id_ed25519
test -f host_ed25519 || ssh-keygen -q -t ed25519 -N '' -C integration-test -f host_ed25519

printf 'vps,client,remote %s\n' "$(cat host_ed25519.pub)" > known_hosts
