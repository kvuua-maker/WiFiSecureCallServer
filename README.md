# WiFi Secure Call Server

Single-process Go MVP providing authenticated HTTPS signaling, production APNs alert delivery, and a WSS binary media relay. Active calls and media stay in memory; audio is never persisted.

## Runtime

The service binds only to `127.0.0.1:8790`. Nginx exposes `/wifi-secure-call/v1/` and `/wifi-secure-call/media` using the host's existing TLS certificate. Runtime data is confined to `/opt/wifi-secure-call`.

The server starts safely with `APNS_ENABLED=false`. Install the topic-scoped production key later with `deploy/install-apns-key.sh`; never commit or print the key.

## Build and test

```sh
go test ./...
go build -trimpath -ldflags='-s -w' -o wifi-secure-call-server ./cmd/server
```

