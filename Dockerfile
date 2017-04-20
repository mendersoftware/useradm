FROM alpine:3.4

EXPOSE 8080

RUN mkdir /etc/useradm
COPY ./config.yaml /etc/useradm/

RUN mkdir /etc/useradm/rsa

ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]

COPY ./useradm /usr/bin/

