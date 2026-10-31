FROM golang:1.25.0-alpine3.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/ ./internal/
COPY cmd/raven/ ./cmd/raven/
COPY web/embed.go ./web/embed.go
COPY web/dist/ ./web/dist/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/raven ./cmd/raven \
    && mkdir -p /image-data/inbox /image-data/output /image-packs

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /bin/raven /bin/raven
COPY --from=builder --chown=10001:10001 /image-packs/ /raven/packs/
COPY schemas/ /raven/schemas/
COPY --chown=10001:10001 sources/ /raven/sources/
COPY --chown=10001:10001 sinks/ /raven/sinks/
COPY --from=builder --chown=10001:10001 /image-data/ /data/
USER 10001:10001
WORKDIR /raven
EXPOSE 1514/udp 1514/tcp 7514/tcp 8080/tcp 9090/tcp
VOLUME ["/data"]
ENTRYPOINT ["/bin/raven"]
CMD ["-syslog-udp", ":1514", "-syslog-tcp", ":1514", "-syslog-tls", "none", "-http", ":8080", "-ui", ":9090", "-inbox", "/data/inbox", "-output-file", "/data/output/normalized.ndjson", "-packs-dir", "/raven/packs", "-sources-dir", "/raven/sources", "-sinks-dir", "/raven/sinks", "-db", "/data/raven.db"]
