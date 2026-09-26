package appleauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifierSecurityContract(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(2000000000, 0)
	kid := "test"
	encode := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": n, "e": e,
		}}})
	}))
	defer server.Close()

	sign := func(claim map[string]any, signingKey *rsa.PrivateKey, header map[string]any) string {
		h := encode(header)
		p := encode(claim)
		sum := sha256.Sum256([]byte(h + "." + p))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, sum[:])
		return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	signValid := func(claim map[string]any, signingKey *rsa.PrivateKey) string {
		return sign(claim, signingKey, map[string]any{"alg": "RS256", "kid": kid})
	}

	rawNonce := "native-client-raw-nonce"
	nonceHash := sha256.Sum256([]byte(rawNonce))
	baseClaims := map[string]any{
		"iss": issuer, "sub": "stable-subject", "aud": "com.vkapps.wifisecurecall",
		"exp": now.Add(time.Hour).Unix(), "nonce": hexDigest(nonceHash[:]),
		"email": "relay@example.com", "email_verified": true,
	}
	verifier := New("com.vkapps.wifisecurecall")
	verifier.KeysURL = server.URL
	verifier.now = func() time.Time { return now }

	claims, err := verifier.Verify(context.Background(), signValid(baseClaims, key), rawNonce)
	if err != nil || claims.Subject != "stable-subject" || !claims.EmailVerified {
		t.Fatalf("valid native token rejected: claims=%+v error=%v", claims, err)
	}

	for name, test := range map[string]struct {
		mutate func(map[string]any)
		code   FailureCode
	}{
		"issuer":   {func(c map[string]any) { c["iss"] = "wrong" }, FailureIssuer},
		"audience": {func(c map[string]any) { c["aud"] = "wrong" }, FailureAudience},
		"expired":  {func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, FailureExpired},
		"nonce":    {func(c map[string]any) { c["nonce"] = "wrong" }, FailureNonce},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneClaims(baseClaims)
			test.mutate(candidate)
			assertVerifyFailure(t, verifier, signValid(candidate, key), rawNonce, test.code)
		})
	}

	doubleHashed := hexDigest(nonceHash[:])
	assertVerifyFailure(t, verifier, signValid(baseClaims, key), doubleHashed, FailureNonce)
	assertVerifyFailure(t, verifier, signValid(baseClaims, key), "another-raw-nonce", FailureNonce)

	base64NonceClaim := cloneClaims(baseClaims)
	base64NonceClaim["nonce"] = base64.RawURLEncoding.EncodeToString(nonceHash[:])
	assertVerifyFailure(t, verifier, signValid(base64NonceClaim, key), rawNonce, FailureNonce)

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	assertVerifyFailure(t, verifier, signValid(baseClaims, otherKey), rawNonce, FailureSignature)
	assertVerifyFailure(t, verifier, sign(baseClaims, key, map[string]any{"alg": "HS256", "kid": kid}), rawNonce, FailureHeader)
	assertVerifyFailure(t, verifier, "not-a-jwt", rawNonce, FailureJWTFormat)
	assertVerifyFailure(t, verifier, sign(baseClaims, key, map[string]any{"alg": "RS256", "kid": "unknown"}), rawNonce, FailureKeyFetch)
}

func TestVerifierEmailVerifiedBoolAndStringForms(t *testing.T) {
	for _, value := range []any{true, "true", "TRUE"} {
		if !emailVerified(value) {
			t.Fatalf("email_verified form was not accepted: %#v", value)
		}
	}
	for _, value := range []any{false, "false", nil, 1} {
		if emailVerified(value) {
			t.Fatalf("email_verified form was incorrectly accepted: %#v", value)
		}
	}
}

func emailVerified(value any) bool { return parseEmailVerified(value) }

func cloneClaims(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func assertVerifyFailure(t *testing.T, verifier *RemoteVerifier, token, nonce string, expected FailureCode) {
	t.Helper()
	_, err := verifier.Verify(context.Background(), token, nonce)
	var verificationError *VerificationError
	if !errors.As(err, &verificationError) || verificationError.Code != expected {
		t.Fatalf("expected %s, got %T %v", expected, err, err)
	}
}
