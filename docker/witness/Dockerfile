FROM golang:1.25.0-alpine3.22 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/integrity/ ./internal/integrity/
COPY internal/witness/ ./internal/witness/
COPY cmd/raven-witness/ ./cmd/raven-witness/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /raven-witness ./cmd/raven-witness

FROM scratch
COPY --from=builder /raven-witness /bin/raven-witness
USER 10001:10001
ENTRYPOINT ["/bin/raven-witness"]
