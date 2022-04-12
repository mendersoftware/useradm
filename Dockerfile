FROM golang:1.16.5-alpine3.12 as builder
WORKDIR /go/src/github.com/mendersoftware/useradm
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o useradm .


FROM scratch
EXPOSE 8080
WORKDIR /etc/useradm/rsa
COPY ./config.yaml /etc/useradm/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/

ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
