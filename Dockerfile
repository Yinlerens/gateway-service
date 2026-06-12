FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/gateway-service ./cmd/gateway-service

FROM alpine:3.20

RUN addgroup -S -g 10001 app && adduser -S -D -H -u 10001 -G app app \
  && apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /out/gateway-service /app/gateway-service

USER 10001:10001
EXPOSE 8080

ENTRYPOINT ["/app/gateway-service"]
