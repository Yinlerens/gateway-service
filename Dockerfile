FROM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/gateway-service ./cmd/gateway-service

FROM alpine:3.20

RUN addgroup -S app && adduser -S -G app app \
  && apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /out/gateway-service /app/gateway-service

USER app:app
EXPOSE 8080

ENTRYPOINT ["/app/gateway-service"]
