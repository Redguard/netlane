#!/bin/sh
# Stands in for a host on the internet. Answers on a few ports and records in
# /received what reached them, so tests can tell which traffic was let through.
: > /received
for port in $TCP_PORTS; do
    socat "TCP-LISTEN:$port,fork,reuseaddr" "EXEC:/record.sh tcp/$port" &
done
for port in $UDP_PORTS; do
    socat "UDP-RECVFROM:$port,fork,reuseaddr" "EXEC:/record.sh udp/$port" &
done
wait
