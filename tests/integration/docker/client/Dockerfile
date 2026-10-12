FROM alpine:3.22

# bash and coreutils: the tests send with bash's /dev/tcp under GNU timeout.
RUN apk add --no-cache bash coreutils iproute2 wireguard-tools-wg

# Stays idle, the `wg_client` fixture brings the tunnel up and sends from it.
CMD ["sleep", "infinity"]
