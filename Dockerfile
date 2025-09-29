# Minimal OpenID Provider with Federation endpoints for integration testing
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY op.go .
RUN go mod init test-op && go mod tidy && go build -o op op.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/op /app/op
EXPOSE 8081
CMD ["/app/op"]
