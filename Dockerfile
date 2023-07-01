FROM golang:1.20.5-alpine3.17 as builder
WORKDIR /go/src/github.com/mendersoftware/useradm
RUN mkdir -p /etc_extra
RUN echo "nobody:x:65534:" > /etc_extra/group
RUN echo "nobody:!::0:::::" > /etc_extra/shadow
RUN echo "nobody:x:65534:65534:Nobody:/:" > /etc_extra/passwd
RUN chown -R nobody:nobody /etc_extra
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o useradm .


FROM scratch
EXPOSE 8080
COPY --from=builder /etc_extra/ /etc/
USER 65534
WORKDIR /etc/useradm/rsa
COPY --from=builder --chown=nobody /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chown=nobody ./config.yaml /etc/useradm/
COPY --from=builder --chown=nobody /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/

ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
