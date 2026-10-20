#!/bin/sh
# Records one line as "<protocol>/<port> <peer address> <line>" and answers it.
read -r line
echo "$1 $SOCAT_PEERADDR $line" >> /received
echo pong
