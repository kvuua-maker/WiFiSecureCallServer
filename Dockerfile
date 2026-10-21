# Build both binaries in one stage and ship them in a distroless-like image.
#
# The SIP gateway and the HTTP signalling server are separate processes with
# separate ports, so the image carries both and the command selects one.
FROM golang:1.23-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/wifi-secure-call-server ./cmd/server \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/wifi-secure-call-sipgw ./cmd/sipgateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wifi-secure-call-server /usr/local/bin/wifi-secure-call-server
COPY --from=build /out/wifi-secure-call-sipgw /usr/local/bin/wifi-secure-call-sipgw
USER nonroot:nonroot

# The SIP gateway needs 5060/udp, 5061/tcp and a UDP range for the relay; the
# HTTP server listens on 8790. Publish the ones you use.
EXPOSE 8790 5060/udp 5061/tcp 8791

ENTRYPOINT ["/usr/local/bin/wifi-secure-call-sipgw"]
