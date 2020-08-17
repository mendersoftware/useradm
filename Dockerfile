FROM golang:1.15.0-alpine3.12 as builder
WORKDIR /go/src/github.com/mendersoftware/useradm
ADD ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o useradm .


FROM alpine:3.12
EXPOSE 8080
RUN mkdir -p /etc/useradm/rsa
ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
COPY ./config.yaml /etc/useradm/
COPY --from=builder /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/
RUN apk add --update ca-certificates && update-ca-certificates
