# WiFi Secure Call Server

Single-process Go MVP providing authenticated HTTPS signaling, production APNs alert delivery, and a WSS binary media relay. Active calls and media stay in memory; audio is never persisted.

## Runtime

The service binds only to `127.0.0.1:8790`. Nginx exposes `/wifi-secure-call/v1/` and `/wifi-secure-call/media` using the host's existing TLS certificate. Runtime data is confined to `/opt/wifi-secure-call`.

The server starts safely with `APNS_ENABLED=false`. Install the topic-scoped production key later with `deploy/install-apns-key.sh`; never commit or print the key.

## Phone accounts (v2 foundation)

Phone numbers are canonical E.164 account identities. The server generates and verifies a six-digit, ten-minute OTP; SMSClub only transports the message. One verified phone maps to one AccountID, while one installation may hold multiple accounts. Apple ID is not required. Apple Watch account linking uses the Internet and a short-lived server link code, not Bluetooth or WatchConnectivity.

The feature is fail-closed and disabled by default. To enable it, configure `SMS_PROVIDER=smsclub`, `SMSCLUB_TOKEN`, an owner-selected `SMSCLUB_ORIGINATOR`, a strong `WSC_OTP_PEPPER`, positive `SMS_MAX_SENDS_PER_DAY`, and optionally `WSC_ACCOUNT_STATE_PATH` (default `/opt/wifi-secure-call/state/accounts.json`). No secret has a built-in default.

Calls remain on the legacy role A/B `/v1` API in this phase. Media remains TLS/WSS and is not end-to-end encrypted; account-to-account call routing and E2EE are later phases.

## Build and test

```sh
go test ./...
go build -trimpath -ldflags='-s -w' -o wifi-secure-call-server ./cmd/server
```
