FROM alpine:3.24

RUN apk add --no-cache openssh-keygen

COPY --chmod=755 generate.sh /

CMD ["/generate.sh"]
