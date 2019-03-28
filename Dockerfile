FROM golang:1.11 as builder
RUN mkdir -p /go/src/github.com/mendersoftware/useradm
WORKDIR /go/src/github.com/mendersoftware/useradm
ADD ./ .
RUN CGO_ENABLED=0 GOARCH=amd64 go build -o useradm .


FROM alpine:3.4
EXPOSE 8080
RUN mkdir -p /etc/useradm/rsa
ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
COPY ./config.yaml /etc/useradm/
COPY --from=builder /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/
RUN apk add --update ca-certificates && update-ca-certificates
