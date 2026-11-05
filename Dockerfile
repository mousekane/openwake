# OpenWake: x86_64 / arm64 / armv7 多架构
# 构建：docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t ghcr.io/mousekane/openwake:latest .
FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 纯静态，TARGETARCH/TARGETVARIANT 由 buildx 传入
ARG TARGETARCH
ARG TARGETVARIANT
RUN if [ "$TARGETARCH" = "arm" ]; then export GOARM=${TARGETVARIANT#v}; fi; \
  CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /openwake .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates iputils tzdata
COPY --from=builder /openwake /openwake
VOLUME ["/data"]
EXPOSE 5155 5055
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD wget -qO- http://127.0.0.1:5155/api/health || exit 1
ENTRYPOINT ["/openwake"]
