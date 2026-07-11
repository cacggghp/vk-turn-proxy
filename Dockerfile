FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o vk-turn-proxy ./server

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY docker-entrypoint.sh .
COPY --from=builder /build/vk-turn-proxy .
RUN chmod +x docker-entrypoint.sh

EXPOSE 56000/udp

ENTRYPOINT ["./docker-entrypoint.sh"]
