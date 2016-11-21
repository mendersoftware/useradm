FROM iron/base

COPY ./useradm /usr/bin/

RUN mkdir /etc/useradm
COPY ./config.yaml /etc/useradm/

ENTRYPOINT ["/usr/bin/useradm", "-config", "/etc/useradm/config.yaml"]
