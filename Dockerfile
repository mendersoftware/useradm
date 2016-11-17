FROM iron/base

COPY ./useradm /usr/bin/

ENTRYPOINT ["/usr/bin/useradm"]
