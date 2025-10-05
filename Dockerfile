# Minimal OpenID Provider with Federation endpoints for integration testing
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY main.go .
RUN go mod init federation-op && \
    go mod tidy && \
    go build -o proxy main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/proxy /app/proxy
COPY index.html /app/index.html
EXPOSE 8080
CMD ["/app/proxy"]
