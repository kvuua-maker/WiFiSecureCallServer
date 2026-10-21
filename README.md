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

## SIP gateway for standalone watches

The HTTP API above routes a call between two devices that both run the app. A
watch that has to dial a phone number needs SIP instead, so `cmd/sipgateway`
provides the front door: a registrar, a signalling proxy and an RTP relay. It is
a separate process because it owns ports 5060/udp and 5061/tcp and must not share
a failure domain with the account and notification API.

It is fail-closed. There is no built-in realm, password, trunk or media address;
`SIPGW_DOMAIN`, `SIPGW_USERS` and `SIPGW_NONCE_SECRET` are required and the
process exits without them.

What it does:

| Step | Behaviour |
| --- | --- |
| `REGISTER` | Digest challenge (`MD5`/`SHA-256`, `qop=auth`) with HMAC-signed nonces, then a binding with the requested expiry |
| Contact behind NAT | A private or unspecified contact host is rewritten to the source address of the REGISTER, because that is the only address the VPS can reach |
| Outbound `INVITE` | The caller must hold a live registration; the request is authenticated, routed to the trunk (or to another registered user) and every response is relayed back |
| Inbound `INVITE` | A number in `SIPGW_DIDS` is resolved to a registered user and forwarded to that device |
| In-dialog | `ACK`, `BYE`, `CANCEL` and `INFO` are routed to the stored next hop; a hangup before answer sends `CANCEL` upstream |
| Media | SDP addresses and the audio port are rewritten to the relay, one socket per leg, so a watch behind a home router still exchanges audio. SRTP parameters are passed through untouched |
| Status | `/healthz`, `/status` (registrations and counters) and `/metrics` (Prometheus) on `SIPGW_HTTP_ADDR`, bound to loopback |

Registering a watch against the gateway from outside the host:

```sh
# OPTIONS answers 200 and lists the allowed methods
printf 'OPTIONS sip:sip.example.com SIP/2.0\r\nVia: SIP/2.0/UDP 0.0.0.0:5062;branch=z9hG4bK1;rport\r\nMax-Forwards: 70\r\nFrom: <sip:probe@sip.example.com>;tag=1\r\nTo: <sip:sip.example.com>\r\nCall-ID: probe-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n' | nc -u -w1 sip.example.com 5060
```

A `REGISTER` without credentials answers `401` with a `WWW-Authenticate`
challenge; the same request with the matching digest answers `200` and the
binding appears in `/status`.

### Deploy

```sh
sudo install -d -m 0750 /opt/wifi-secure-call/config
sudo install -m 0600 deploy/sipgw.env.example /opt/wifi-secure-call/config/sipgw.env
sudo editor /opt/wifi-secure-call/config/sipgw.env          # fill every REPLACE_WITH value
go build -trimpath -ldflags='-s -w' -o /tmp/wifi-secure-call-sipgw ./cmd/sipgateway
sudo WSC_EXPECTED_BUILD=$(git rev-parse HEAD) ./deploy/install-sipgateway.sh /tmp/wifi-secure-call-sipgw
```

The installer refuses a configuration that still contains a placeholder, a
nonce secret shorter than 16 bytes, or a missing media address, and it verifies
`/healthz` before reporting success.

Open `5060/udp` (and `5061/tcp` plus the relay's UDP range if you enable TLS) in
the host firewall. The relay allocates one port pair per call on
`SIPGW_MEDIA_BIND`, so the range has to cover the peak number of concurrent calls.
