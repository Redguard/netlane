FROM alpine:3.24

# bash and coreutils: the tests send with bash's /dev/tcp under GNU timeout.
RUN apk add --no-cache bash coreutils iproute2 wireguard-tools-wg dropbear dropbear-convert

COPY --chmod=755 sshd.sh /

# Stays idle, the `wg_client` fixture brings the tunnel up and sends from it.
ENTRYPOINT ["/sshd.sh"]
CMD ["sleep", "infinity"]
