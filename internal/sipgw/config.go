// Package sipgw implements the SIP side of WiFi Secure Call: a registrar plus a
// stateful signalling proxy that lets a standalone Apple Watch talk to a SIP
// trunk without any paired iPhone.
//
// The gateway is deliberately off the media path. RTP flows directly between the
// watch and the trunk, so the server only has to be reachable on the signalling
// ports and never has to relay audio.
package sipgw

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Trunk describes the upstream SIP provider that terminates calls into the
// PSTN, or an IP PBX. It is optional: without it the gateway only routes calls
// between registered devices on the same domain.
type Trunk struct {
	Host      string
	Port      int
	Transport string
	Username  string
	Password  string
}

// Enabled reports whether an upstream trunk has been configured.
func (t Trunk) Enabled() bool { return t.Host != "" }

// Address returns host:port for the trunk, applying the transport default port.
func (t Trunk) Address() string {
	port := t.Port
	if port == 0 {
		if t.Transport == "tls" {
			port = 5061
		} else {
			port = 5060
		}
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

// Config is the complete runtime configuration of the gateway.
type Config struct {
	Domain string
	Realm  string

	ListenUDP string
	ListenTLS string
	ListenWSS string

	TLSCert string
	TLSKey  string

	// Users maps a SIP username to its password. Registration and outbound
	// calls are only accepted for these users.
	Users map[string]string

	// DIDs maps an inbound PSTN number to a local SIP username. When a trunk
	// delivers an INVITE for one of these numbers the gateway forwards it to
	// the device registered for that user.
	DIDs map[string]string

	Trunk Trunk

	RegistrationTTL time.Duration
	NonceLifetime   time.Duration
	NonceSecret     []byte

	RegistrationHost string
	UserAgent        string

	// MediaRelay enables the RTP relay. "off" disables it and leaves the SDP
	// untouched, which only works when the device is directly reachable.
	MediaRelay string
	// MediaBind is the local address the relay sockets bind to.
	MediaBind string
	// MediaPublicIP is the address written into SDP so both legs send media to
	// the relay. It must be reachable from the internet.
	MediaPublicIP string
}

// MediaRelayEnabled reports whether the RTP relay should be used.
func (c Config) MediaRelayEnabled() bool {
	return c.MediaRelay != "off" && c.MediaPublicIP != ""
}

// MediaBindAddress is the local address the relay binds to.
func (c Config) MediaBindAddress() string {
	if c.MediaBind == "" {
		return "0.0.0.0"
	}
	return c.MediaBind
}

// LoadConfig reads the gateway configuration from the environment.
//
// Every value is explicit: there is no built-in password, realm or trunk, and a
// missing mandatory value is an error rather than a silent default.
func LoadConfig(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := Config{
		Domain:          strings.TrimSpace(getenv("SIPGW_DOMAIN")),
		Realm:           strings.TrimSpace(getenv("SIPGW_REALM")),
		ListenUDP:       strings.TrimSpace(getenv("SIPGW_LISTEN_UDP")),
		ListenTLS:       strings.TrimSpace(getenv("SIPGW_LISTEN_TLS")),
		ListenWSS:       strings.TrimSpace(getenv("SIPGW_LISTEN_WSS")),
		TLSCert:         strings.TrimSpace(getenv("SIPGW_TLS_CERT")),
		TLSKey:          strings.TrimSpace(getenv("SIPGW_TLS_KEY")),
		RegistrationTTL: 300 * time.Second,
		NonceLifetime:   10 * time.Minute,
		UserAgent:       "WiFiSecureCall-SIPGW/1.0",
	}
	if cfg.Domain == "" {
		return Config{}, errors.New("sipgw: SIPGW_DOMAIN is required")
	}
	if strings.ContainsAny(cfg.Domain, " \t/@") {
		return Config{}, fmt.Errorf("sipgw: SIPGW_DOMAIN %q is not a host name", cfg.Domain)
	}
	if cfg.Realm == "" {
		cfg.Realm = cfg.Domain
	}
	cfg.RegistrationHost = strings.TrimSpace(getenv("SIPGW_REGISTRATION_HOST"))
	if cfg.RegistrationHost == "" {
		cfg.RegistrationHost = cfg.Domain
	}
	if cfg.ListenUDP == "" && cfg.ListenTLS == "" && cfg.ListenWSS == "" {
		cfg.ListenUDP = "0.0.0.0:5060"
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return Config{}, errors.New("sipgw: SIPGW_TLS_CERT and SIPGW_TLS_KEY must be set together")
	}
	if cfg.ListenTLS != "" || cfg.ListenWSS != "" {
		if cfg.TLSCert == "" {
			return Config{}, errors.New("sipgw: a TLS or WSS listener needs SIPGW_TLS_CERT and SIPGW_TLS_KEY")
		}
	}

	users, err := ParseSecretPairs(getenv("SIPGW_USERS"))
	if err != nil {
		return Config{}, fmt.Errorf("sipgw: SIPGW_USERS: %w", err)
	}
	if len(users) == 0 {
		return Config{}, errors.New("sipgw: SIPGW_USERS must list at least one user:password pair")
	}
	cfg.Users = users

	dids, err := ParseDIDs(getenv("SIPGW_DIDS"))
	if err != nil {
		return Config{}, fmt.Errorf("sipgw: SIPGW_DIDS: %w", err)
	}
	cfg.DIDs = dids

	if ttl := strings.TrimSpace(getenv("SIPGW_REGISTRATION_TTL")); ttl != "" {
		parsed, err := time.ParseDuration(ttl)
		if err != nil || parsed < 30*time.Second || parsed > 24*time.Hour {
			return Config{}, fmt.Errorf("sipgw: SIPGW_REGISTRATION_TTL %q must be a duration between 30s and 24h", ttl)
		}
		cfg.RegistrationTTL = parsed
	}

	secret := getenv("SIPGW_NONCE_SECRET")
	if secret == "" {
		return Config{}, errors.New("sipgw: SIPGW_NONCE_SECRET is required and must be at least 16 bytes")
	}
	if len(secret) < 16 {
		return Config{}, errors.New("sipgw: SIPGW_NONCE_SECRET must be at least 16 bytes")
	}
	cfg.NonceSecret = []byte(secret)

	if host := strings.TrimSpace(getenv("SIPGW_TRUNK_HOST")); host != "" {
		cfg.Trunk.Host = host
		cfg.Trunk.Username = strings.TrimSpace(getenv("SIPGW_TRUNK_USER"))
		cfg.Trunk.Password = getenv("SIPGW_TRUNK_PASS")
		cfg.Trunk.Transport = strings.ToLower(strings.TrimSpace(getenv("SIPGW_TRUNK_TRANSPORT")))
		if cfg.Trunk.Transport == "" {
			cfg.Trunk.Transport = "udp"
		}
		switch cfg.Trunk.Transport {
		case "udp", "tcp", "tls":
		default:
			return Config{}, fmt.Errorf("sipgw: SIPGW_TRUNK_TRANSPORT %q must be udp, tcp or tls", cfg.Trunk.Transport)
		}
		if port := strings.TrimSpace(getenv("SIPGW_TRUNK_PORT")); port != "" {
			parsed, err := strconv.Atoi(port)
			if err != nil || parsed < 1 || parsed > 65535 {
				return Config{}, fmt.Errorf("sipgw: SIPGW_TRUNK_PORT %q is not a port", port)
			}
			cfg.Trunk.Port = parsed
		}
		if (cfg.Trunk.Username == "") != (cfg.Trunk.Password == "") {
			return Config{}, errors.New("sipgw: SIPGW_TRUNK_USER and SIPGW_TRUNK_PASS must be set together")
		}
	}

	cfg.MediaRelay = strings.ToLower(strings.TrimSpace(getenv("SIPGW_MEDIA_RELAY")))
	switch cfg.MediaRelay {
	case "", "auto":
		cfg.MediaRelay = "auto"
	case "off":
	default:
		return Config{}, fmt.Errorf("sipgw: SIPGW_MEDIA_RELAY %q must be auto or off", cfg.MediaRelay)
	}
	cfg.MediaBind = strings.TrimSpace(getenv("SIPGW_MEDIA_BIND"))
	cfg.MediaPublicIP = strings.TrimSpace(getenv("SIPGW_MEDIA_PUBLIC_IP"))
	if cfg.MediaRelayEnabled() && net.ParseIP(cfg.MediaPublicIP) == nil {
		return Config{}, fmt.Errorf("sipgw: SIPGW_MEDIA_PUBLIC_IP %q is not an IP address", cfg.MediaPublicIP)
	}
	if cfg.MediaBind != "" && net.ParseIP(cfg.MediaBind) == nil {
		return Config{}, fmt.Errorf("sipgw: SIPGW_MEDIA_BIND %q is not an IP address", cfg.MediaBind)
	}
	return cfg, nil
}

// ParseSecretPairs parses "user:password,user:password" into a map. A colon is
// only a separator once, so a password may itself contain colons.
func ParseSecretPairs(value string) (map[string]string, error) {
	out := map[string]string{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		user, password, ok := strings.Cut(entry, ":")
		user = strings.TrimSpace(user)
		if !ok || user == "" || password == "" {
			return nil, fmt.Errorf("entry %q is not user:password", entry)
		}
		if len(password) < 8 {
			return nil, fmt.Errorf("user %q has a password shorter than 8 characters", user)
		}
		if _, exists := out[user]; exists {
			return nil, fmt.Errorf("user %q is listed twice", user)
		}
		out[user] = password
	}
	return out, nil
}

// ParseDIDs parses "number:user,number:user" into a map of inbound numbers.
// Punctuation in the number is ignored so +380 (44) 123-45-67 and 380441234567
// address the same device.
func ParseDIDs(value string) (map[string]string, error) {
	out := map[string]string{}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		number, user, ok := strings.Cut(entry, ":")
		if !ok {
			return nil, fmt.Errorf("entry %q is not number:user", entry)
		}
		digits := NormalizeNumber(number)
		user = strings.TrimSpace(user)
		if digits == "" || user == "" {
			return nil, fmt.Errorf("entry %q is not number:user", entry)
		}
		out[digits] = user
	}
	return out, nil
}

// NormalizeNumber strips everything that is not a digit from a dialled number.
func NormalizeNumber(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}
