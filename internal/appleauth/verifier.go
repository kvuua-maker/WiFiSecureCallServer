package appleauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

const issuer = "https://appleid.apple.com"

type Claims struct {
	Subject, Email string
	EmailVerified  bool
}
type Verifier interface {
	Verify(context.Context, string, string) (Claims, error)
}

type RemoteVerifier struct {
	Audience string
	Client   *http.Client
	KeysURL  string
	now      func() time.Time
	mu       sync.Mutex
	keys     map[string]*rsa.PublicKey
	keysAt   time.Time
}

func New(audience string) *RemoteVerifier {
	return &RemoteVerifier{Audience: audience, Client: &http.Client{Timeout: 8 * time.Second}, KeysURL: issuer + "/auth/keys", now: time.Now}
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}
type tokenClaims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      any    `json:"aud"`
	Expires       int64  `json:"exp"`
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
}
type jwkSet struct {
	Keys []struct {
		KeyID     string `json:"kid"`
		KeyType   string `json:"kty"`
		Algorithm string `json:"alg"`
		Use       string `json:"use"`
		N         string `json:"n"`
		E         string `json:"e"`
	} `json:"keys"`
}

func (v *RemoteVerifier) Verify(ctx context.Context, raw, nonce string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	var header tokenHeader
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	key, err := v.key(ctx, header.KeyID)
	if err != nil {
		return Claims{}, errors.New("Apple identity verification unavailable")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	var c tokenClaims
	if json.Unmarshal(pb, &c) != nil || c.Issuer != issuer || c.Subject == "" || c.Expires <= v.now().Unix() || !audienceIncludes(c.Audience, v.Audience) {
		return Claims{}, errors.New("invalid Apple identity token")
	}
	if nonce != "" {
		h := sha256.Sum256([]byte(nonce))
		if !strings.EqualFold(c.Nonce, base64.RawURLEncoding.EncodeToString(h[:])) && !strings.EqualFold(c.Nonce, hexDigest(h[:])) {
			return Claims{}, errors.New("invalid Apple identity token nonce")
		}
	}
	verified := c.EmailVerified == true || c.EmailVerified == "true"
	return Claims{Subject: c.Subject, Email: c.Email, EmailVerified: verified}, nil
}

func audienceIncludes(value any, expected string) bool {
	if s, ok := value.(string); ok {
		return s == expected
	}
	if list, ok := value.([]any); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}
func hexDigest(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = h[v>>4]
		out[i*2+1] = h[v&15]
	}
	return string(out)
}

func (v *RemoteVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.keysAt) < 12*time.Hour {
		if k := v.keys[kid]; k != nil {
			return k, nil
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.KeysURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Apple keys unavailable")
	}
	var set jwkSet
	if json.NewDecoder(resp.Body).Decode(&set) != nil {
		return nil, errors.New("invalid Apple keys")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.KeyType != "RSA" || j.Algorithm != "RS256" {
			continue
		}
		n, ne := base64.RawURLEncoding.DecodeString(j.N)
		e, ee := base64.RawURLEncoding.DecodeString(j.E)
		if ne != nil || ee != nil || len(e) == 0 {
			continue
		}
		exponent := 0
		for _, x := range e {
			exponent = exponent<<8 + int(x)
		}
		keys[j.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}
	v.keys, v.keysAt = keys, v.now()
	if k := keys[kid]; k != nil {
		return k, nil
	}
	return nil, errors.New("Apple signing key unavailable")
}
