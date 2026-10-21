package sipgw

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigRejectsIncompleteInput(t *testing.T) {
	base := map[string]string{
		"SIPGW_DOMAIN":       "sip.example.com",
		"SIPGW_USERS":        "alice:correct horse battery",
		"SIPGW_NONCE_SECRET": "0123456789abcdef0123456789abcdef",
	}
	cases := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"missing domain", func(m map[string]string) { delete(m, "SIPGW_DOMAIN") }, "SIPGW_DOMAIN"},
		{"missing users", func(m map[string]string) { delete(m, "SIPGW_USERS") }, "SIPGW_USERS"},
		{"short password", func(m map[string]string) { m["SIPGW_USERS"] = "alice:short" }, "shorter than 8"},
		{"missing secret", func(m map[string]string) { delete(m, "SIPGW_NONCE_SECRET") }, "SIPGW_NONCE_SECRET"},
		{"short secret", func(m map[string]string) { m["SIPGW_NONCE_SECRET"] = "abc" }, "at least 16 bytes"},
		{"half a tls pair", func(m map[string]string) { m["SIPGW_TLS_CERT"] = "/tmp/cert.pem" }, "must be set together"},
		{"bad media ip", func(m map[string]string) {
			m["SIPGW_MEDIA_PUBLIC_IP"] = "not-an-ip"
		}, "not an IP address"},
		{"bad trunk password pairing", func(m map[string]string) {
			m["SIPGW_TRUNK_HOST"] = "trunk.example.com"
			m["SIPGW_TRUNK_USER"] = "user"
		}, "must be set together"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{}
			for key, value := range base {
				env[key] = value
			}
			tc.mutate(env)
			_, err := LoadConfig(func(key string) string { return env[key] })
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	env := map[string]string{
		"SIPGW_DOMAIN":       "sip.example.com",
		"SIPGW_USERS":        "alice:correct horse battery,bob:another long one",
		"SIPGW_NONCE_SECRET": "0123456789abcdef0123456789abcdef",
		"SIPGW_DIDS":         "+380 (44) 123-45-67:alice",
	}
	cfg, err := LoadConfig(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Realm != "sip.example.com" {
		t.Fatalf("realm = %q, want the domain", cfg.Realm)
	}
	if cfg.ListenUDP != "0.0.0.0:5060" {
		t.Fatalf("default listener = %q", cfg.ListenUDP)
	}
	if cfg.RegistrationTTL != 5*time.Minute {
		t.Fatalf("default TTL = %s", cfg.RegistrationTTL)
	}
	if cfg.Users["bob"] != "another long one" {
		t.Fatalf("did not parse the second user")
	}
	if cfg.DIDs["380441234567"] != "alice" {
		t.Fatalf("DID was not normalised: %v", cfg.DIDs)
	}
	if cfg.MediaRelayEnabled() {
		t.Fatal("the media relay must stay off when no public IP is configured")
	}
}

func TestParseSecretPairsKeepsColonsInPassword(t *testing.T) {
	users, err := ParseSecretPairs("alice:pa:ss:word")
	if err != nil {
		t.Fatalf("ParseSecretPairs: %v", err)
	}
	if users["alice"] != "pa:ss:word" {
		t.Fatalf("password = %q", users["alice"])
	}
}

func TestParseDIDsRejectsMalformed(t *testing.T) {
	if _, err := ParseDIDs("380441234567"); err == nil {
		t.Fatal("expected an error for an entry without a user")
	}
}

func TestTrunkAddressDefaultsByTransport(t *testing.T) {
	udp := Trunk{Host: "trunk.example.com", Transport: "udp"}
	if got := udp.Address(); got != "trunk.example.com:5060" {
		t.Fatalf("udp address = %q", got)
	}
	tls := Trunk{Host: "trunk.example.com", Transport: "tls"}
	if got := tls.Address(); got != "trunk.example.com:5061" {
		t.Fatalf("tls address = %q", got)
	}
}

func TestNormalizeNumber(t *testing.T) {
	if got := NormalizeNumber("+380 (44) 123-45-67"); got != "380441234567" {
		t.Fatalf("normalise = %q", got)
	}
	if got := NormalizeNumber(""); got != "" {
		t.Fatalf("empty normalise = %q", got)
	}
}

func TestMediaBindAddressDefaults(t *testing.T) {
	cfg := Config{}
	if got := cfg.MediaBindAddress(); got != "0.0.0.0" {
		t.Fatalf("bind = %q", got)
	}
	cfg.MediaBind = "10.0.0.2"
	if got := cfg.MediaBindAddress(); got != "10.0.0.2" {
		t.Fatalf("bind = %q", got)
	}
}

func ExampleConfig() {
	fmt.Println(Config{MediaRelay: "auto", MediaPublicIP: "203.0.113.10"}.MediaRelayEnabled())
	// Output: true
}
