FROM --platform=$BUILDPLATFORM golang:1.23.9-alpine3.20 as builder
ARG TARGETARCH
WORKDIR /go/src/github.com/mendersoftware/useradm
RUN apk add --no-cache ca-certificates
COPY ./ .
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o useradm .


FROM scratch
EXPOSE 8080
USER 65534:65534
WORKDIR /etc/useradm/rsa
COPY --from=builder --chown=65534:65534 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chown=65534:65534 ./config.yaml /etc/useradm/
COPY --chown=65534:65534 ./config/plans.yaml /etc/useradm/
COPY --from=builder --chown=65534:65534 /go/src/github.com/mendersoftware/useradm/useradm /usr/bin/

ENTRYPOINT ["/usr/bin/useradm", "--config", "/etc/useradm/config.yaml"]
