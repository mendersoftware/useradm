FROM alpine:3.4

COPY ./useradm /usr/bin/

RUN mkdir /etc/useradm
COPY ./config.yaml /etc/useradm/

RUN mkdir /etc/useradm/rsa
COPY ./crypto/private.pem /etc/useradm/rsa/private.pem

ENTRYPOINT ["/usr/bin/useradm", "-config", "/etc/useradm/config.yaml"]
