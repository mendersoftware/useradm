FROM alpine:3.4

COPY ./useradm /usr/bin/

RUN mkdir /etc/useradm
COPY ./config.yaml /etc/useradm/

RUN mkdir /etc/useradm/rsa

ENTRYPOINT ["/usr/bin/useradm", "-config", "/etc/useradm/config.yaml"]
