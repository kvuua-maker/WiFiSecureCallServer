package appleauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifierSecurityContract(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(2000000000, 0)
	kid := "test"
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e}}})
	}))
	defer server.Close()
	sign := func(claim map[string]any, k *rsa.PrivateKey) string {
		h := enc(map[string]any{"alg": "RS256", "kid": kid})
		p := enc(claim)
		sum := sha256.Sum256([]byte(h + "." + p))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	nonce := "secret"
	nh := sha256.Sum256([]byte(nonce))
	base := map[string]any{"iss": issuer, "sub": "stable-subject", "aud": "com.vkapps.wifisecurecall", "exp": now.Add(time.Hour).Unix(), "nonce": hexDigest(nh[:])}
	v := New("com.vkapps.wifisecurecall")
	v.KeysURL = server.URL
	v.now = func() time.Time { return now }
	if c, err := v.Verify(context.Background(), sign(base, key), nonce); err != nil || c.Subject != "stable-subject" {
		t.Fatalf("valid token rejected: %v", err)
	}
	cases := []map[string]any{}
	for _, change := range []func(map[string]any){func(c map[string]any) { c["iss"] = "wrong" }, func(c map[string]any) { c["aud"] = "wrong" }, func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, func(c map[string]any) { c["nonce"] = "wrong" }} {
		c := map[string]any{}
		for k, v := range base {
			c[k] = v
		}
		change(c)
		cases = append(cases, c)
	}
	for i, c := range cases {
		if _, err := v.Verify(context.Background(), sign(c, key), nonce); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := v.Verify(context.Background(), sign(base, other), nonce); err == nil {
		t.Fatal("invalid signature accepted")
	}
}
