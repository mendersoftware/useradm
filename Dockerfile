FROM golang:1.11-alpine3.9 as builder
RUN mkdir -p /go/src/github.com/mendersoftware/useradm
WORKDIR /go/src/github.com/mendersoftware/useradm
ADD ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o useradm .


FROM alpine:3.9
EXPOSE 8080
RUN mkdir -p /etc/useradm/rsa
ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
COPY ./config.yaml /etc/useradm/
COPY --from=builder /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/
RUN apk add --update ca-certificates curl && update-ca-certificates
HEALTHCHECK --interval=8s --timeout=15s --start-period=120s --retries=128 CMD curl -f -s -o /dev/null 127.0.0.1:8080/api/management/v1/useradm/settings
