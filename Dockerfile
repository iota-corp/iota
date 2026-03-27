# go-duckdb ships a glibc-linked libduckdb.a; musl (Alpine) cannot link it. Use Debian (glibc).
FROM golang:1.24-bookworm AS builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libc6-dev libsqlite3-dev python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o iota ./cmd/iota

FROM debian:bookworm-slim

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates libsqlite3-0 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/iota /app/iota
COPY --from=builder /build/engines/iota /app/engines/iota

RUN mkdir -p /data/events /data/rules /data/state && \
    chmod +x /app/iota

VOLUME ["/data/events", "/data/rules", "/data/state"]

EXPOSE 8080

ENTRYPOINT ["/app/iota"]
CMD ["--mode=watch", "--events-dir=/data/events", "--rules=/data/rules", "--state=/data/state/iota.db"]
