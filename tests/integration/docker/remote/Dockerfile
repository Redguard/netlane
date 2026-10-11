FROM alpine:3.22

RUN apk add --no-cache socat

COPY --chmod=755 serve.sh record.sh /

# Ports the test profiles pass through, redirect, reject or drop.
ENV TCP_PORTS="80 443 8443 8444"
ENV UDP_PORTS="53 443"

CMD ["/serve.sh"]
