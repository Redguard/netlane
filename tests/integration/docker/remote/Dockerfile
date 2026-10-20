FROM alpine:3.24

RUN apk add --no-cache socat dropbear dropbear-convert

COPY --chmod=755 sshd.sh remote/serve.sh remote/record.sh /

# Ports the test profiles pass through, redirect, reject or drop.
ENV TCP_PORTS="80 443 8443 8444"
ENV UDP_PORTS="53 443"

ENTRYPOINT ["/sshd.sh"]
CMD ["/serve.sh"]
