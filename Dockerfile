# Minimal OpenID Provider with Federation endpoints for integration testing
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY proxy.go .
RUN go mod init federation-op && \
    go mod tidy && \
    go build -o proxy proxy.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/proxy /app/proxy
EXPOSE 8080
CMD ["/app/proxy"]
