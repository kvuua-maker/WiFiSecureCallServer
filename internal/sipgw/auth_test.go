package sipgw

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
	"time"
)

const (
	testRealm    = "sip.example.com"
	testPassword = "correct horse battery"
	testSecret   = "0123456789abcdef0123456789abcdef"
)

func newTestAuthenticator() *Authenticator {
	return NewAuthenticator(testRealm, map[string]string{"alice": testPassword}, []byte(testSecret), 10*time.Minute)
}

// clientDigest reproduces what a SIP client sends, independently of the server
// implementation, so the test does not just check the code against itself.
func clientDigest(t *testing.T, challenge, username, password, method, uri, cnonce, nc string) string {
	t.Helper()
	params, err := parseChallengeForTest(challenge)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	nonce := params["nonce"]
	qop := params["qop"]
	hash := func(parts ...string) string {
		sum := md5.Sum([]byte(joinColon(parts)))
		return hex.EncodeToString(sum[:])
	}
	ha1 := hash(username, params["realm"], password)
	ha2 := hash(method, uri)
	if qop == "auth" {
		return hash(ha1, nonce, nc, cnonce, qop, ha2)
	}
	return hash(ha1, nonce, ha2)
}

func joinColon(parts []string) string {
	out := ""
	for i, part := range parts {
		if i > 0 {
			out += ":"
		}
		out += part
	}
	return out
}

func parseChallengeForTest(value string) (map[string]string, error) {
	return parseDigestParams(value)
}

func TestVerifyAcceptsValidCredentials(t *testing.T) {
	auth := newTestAuthenticator()
	challenge := auth.ChallengeHeader(false)
	response := clientDigest(t, challenge, "alice", testPassword, "REGISTER", "sip:sip.example.com", "abc123", "00000001")
	header := `Digest username="alice", realm="` + testRealm + `", nonce="` + nonceOf(t, challenge) + `", uri="sip:sip.example.com", ` +
		`response="` + response + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="abc123"`

	result := auth.Verify([]string{header}, "REGISTER", "sip:sip.example.com")
	if !result.OK {
		t.Fatalf("verification failed: %s", result.Reason)
	}
	if result.Username != "alice" {
		t.Fatalf("username = %q", result.Username)
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	auth := newTestAuthenticator()
	challenge := auth.ChallengeHeader(false)
	response := clientDigest(t, challenge, "alice", "wrong password", "REGISTER", "sip:sip.example.com", "abc123", "00000001")
	header := `Digest username="alice", realm="` + testRealm + `", nonce="` + nonceOf(t, challenge) + `", uri="sip:sip.example.com", ` +
		`response="` + response + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="abc123"`
	if result := auth.Verify([]string{header}, "REGISTER", "sip:sip.example.com"); result.OK {
		t.Fatal("wrong password was accepted")
	}
}

func TestVerifyRejectsTamperedNonce(t *testing.T) {
	auth := newTestAuthenticator()
	challenge := auth.ChallengeHeader(false)
	nonce := nonceOf(t, challenge)
	tampered := nonce[:len(nonce)-2] + "AA"
	response := clientDigest(t, challenge, "alice", testPassword, "REGISTER", "sip:sip.example.com", "abc123", "00000001")
	header := `Digest username="alice", realm="` + testRealm + `", nonce="` + tampered + `", uri="sip:sip.example.com", ` +
		`response="` + response + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="abc123"`
	if result := auth.Verify([]string{header}, "REGISTER", "sip:sip.example.com"); result.OK {
		t.Fatal("a tampered nonce was accepted")
	}
}

func TestVerifyMarksStaleNonce(t *testing.T) {
	auth := newTestAuthenticator()
	challenge := auth.ChallengeHeader(false)
	response := clientDigest(t, challenge, "alice", testPassword, "REGISTER", "sip:sip.example.com", "abc123", "00000001")
	header := `Digest username="alice", realm="` + testRealm + `", nonce="` + nonceOf(t, challenge) + `", uri="sip:sip.example.com", ` +
		`response="` + response + `", algorithm=MD5, qop=auth, nc=00000001, cnonce="abc123"`

	// Move the clock past the nonce lifetime but keep the signature valid.
	auth.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	result := auth.Verify([]string{header}, "REGISTER", "sip:sip.example.com")
	if result.OK {
		t.Fatal("an expired nonce was accepted")
	}
	if !result.Stale {
		t.Fatal("an expired, correctly signed nonce must be reported as stale")
	}
}

func TestVerifyWithoutHeaderChallenges(t *testing.T) {
	auth := newTestAuthenticator()
	result := auth.Verify(nil, "REGISTER", "sip:sip.example.com")
	if result.OK || result.Challenge == "" {
		t.Fatalf("expected a challenge, got %+v", result)
	}
}

func TestVerifyNonceOnlyAuth(t *testing.T) {
	auth := newTestAuthenticator()
	challenge := auth.ChallengeHeader(false)
	// RFC 2069 style: no qop at all.
	sum1 := md5.Sum([]byte("alice:" + testRealm + ":" + testPassword))
	ha1 := hex.EncodeToString(sum1[:])
	sum2 := md5.Sum([]byte("INVITE:sip:sip.example.com"))
	ha2 := hex.EncodeToString(sum2[:])
	sum3 := md5.Sum([]byte(ha1 + ":" + nonceOf(t, challenge) + ":" + ha2))
	header := `Digest username="alice", realm="` + testRealm + `", nonce="` + nonceOf(t, challenge) + `", ` +
		`uri="sip:sip.example.com", response="` + hex.EncodeToString(sum3[:]) + `"`
	if result := auth.Verify([]string{header}, "INVITE", "sip:sip.example.com"); !result.OK {
		t.Fatalf("nonce-only digest rejected: %s", result.Reason)
	}
}

func nonceOf(t *testing.T, challenge string) string {
	t.Helper()
	params, err := parseDigestParams(challenge)
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	return params["nonce"]
}
