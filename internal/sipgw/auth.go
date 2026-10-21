package sipgw

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthResult is the outcome of checking one Authorization header.
type AuthResult struct {
	Username string
	OK       bool
	// Stale means the credentials were well formed and correctly signed but the
	// nonce has aged out, so the client should retry with a fresh challenge
	// instead of prompting for a password.
	Stale bool
	// Challenge is a ready WWW-Authenticate / Proxy-Authenticate value.
	Challenge string
	// Reason explains a rejection in logs.
	Reason string
}

// Authenticator performs HTTP Digest authentication (RFC 7616) for SIP.
//
// SIP uses the same digest scheme as HTTP, so this is deliberately the same
// computation: the only addition is a signed nonce so that the gateway can
// reject replayed registrations without keeping server-side state.
type Authenticator struct {
	realm         string
	users         map[string]string
	secret        []byte
	nonceLifetime time.Duration
	now           func() time.Time
}

// NewAuthenticator builds an authenticator over a fixed user table.
func NewAuthenticator(realm string, users map[string]string, secret []byte, nonceLifetime time.Duration) *Authenticator {
	if nonceLifetime <= 0 {
		nonceLifetime = 10 * time.Minute
	}
	return &Authenticator{
		realm:         realm,
		users:         users,
		secret:        secret,
		nonceLifetime: nonceLifetime,
		now:           time.Now,
	}
}

// ChallengeHeader renders a challenge. stale is included only when relevant.
func (a *Authenticator) ChallengeHeader(stale bool) string {
	var builder strings.Builder
	builder.WriteString(`Digest realm="`)
	builder.WriteString(a.realm)
	builder.WriteString(`", qop="auth", algorithm=MD5, nonce="`)
	builder.WriteString(a.nonce())
	builder.WriteString(`"`)
	if stale {
		builder.WriteString(`, stale=true`)
	}
	return builder.String()
}

// nonce returns "timestamp:random:signature" in base64url.
func (a *Authenticator) nonce() string {
	stamp := strconv.FormatInt(a.now().Unix(), 10)
	random := make([]byte, 9)
	if _, err := rand.Read(random); err != nil {
		// A nonce without randomness is still unguessable because it is signed,
		// so this degrades to a deterministic nonce rather than failing a call.
		random = []byte(stamp)
	}
	payload := stamp + ":" + base64.RawURLEncoding.EncodeToString(random)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + ":" + hex.EncodeToString(mac.Sum(nil))))
}

// checkNonce validates the signature and age of a nonce.
func (a *Authenticator) checkNonce(nonce string) (stale bool, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return false, false
	}
	parts := strings.SplitN(string(raw), ":", 3)
	if len(parts) != 3 {
		return false, false
	}
	payload := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return false, false
	}
	issued, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false, false
	}
	age := a.now().Sub(time.Unix(issued, 0))
	if age < -time.Minute {
		return false, false
	}
	if age > a.nonceLifetime {
		return true, false
	}
	return false, true
}

// Verify checks the credentials carried by a request.
//
// values are the raw header values of Authorization or Proxy-Authorization,
// method is the SIP method and requestURI is the URI the client signed.
func (a *Authenticator) Verify(values []string, method, requestURI string) AuthResult {
	if len(values) == 0 {
		return AuthResult{Challenge: a.ChallengeHeader(false)}
	}
	stale := false
	reason := "credentials are missing or malformed"
	for _, value := range values {
		params, err := parseDigestParams(value)
		if err != nil {
			reason = err.Error()
			continue
		}
		username := params["username"]
		password, known := a.users[username]
		if !known {
			reason = "unknown user"
			continue
		}
		if realm := params["realm"]; realm != "" && realm != a.realm {
			reason = "realm does not match"
			continue
		}
		nonceStale, nonceOK := a.checkNonce(params["nonce"])
		if !nonceOK {
			if nonceStale {
				stale = true
			}
			reason = "nonce is not valid"
			continue
		}
		algorithm := strings.ToUpper(strings.TrimSpace(params["algorithm"]))
		if algorithm == "" {
			algorithm = "MD5"
		}
		hashFn, session, ok := digestAlgorithm(algorithm)
		if !ok {
			reason = "unsupported algorithm " + algorithm
			continue
		}
		qop := strings.ToLower(params["qop"])
		if qop == "auth-int" {
			reason = "qop auth-int is not supported"
			continue
		}
		uri := params["uri"]
		if uri == "" {
			uri = requestURI
		}
		expected := digestResponse(hashFn, digestInput{
			username: username,
			realm:    a.realm,
			password: password,
			method:   method,
			uri:      uri,
			nonce:    params["nonce"],
			nc:       params["nc"],
			cnonce:   params["cnonce"],
			qop:      qop,
			session:  session,
		})
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(expected)), []byte(strings.ToLower(params["response"]))) != 1 {
			reason = "response does not match"
			continue
		}
		return AuthResult{Username: username, OK: true}
	}
	return AuthResult{Stale: stale, Challenge: a.ChallengeHeader(stale), Reason: reason}
}

type digestInput struct {
	username, realm, password, method, uri, nonce, nc, cnonce, qop string
	session                                                        bool
}

func digestResponse(newHash func() hash.Hash, in digestInput) string {
	h := func(parts ...string) string {
		digest := newHash()
		digest.Write([]byte(strings.Join(parts, ":")))
		return hex.EncodeToString(digest.Sum(nil))
	}
	ha1 := h(in.username, in.realm, in.password)
	if in.session {
		ha1 = h(ha1, in.nonce, in.cnonce)
	}
	ha2 := h(in.method, in.uri)
	if in.qop == "auth" {
		return h(ha1, in.nonce, in.nc, in.cnonce, in.qop, ha2)
	}
	return h(ha1, in.nonce, ha2)
}

func digestAlgorithm(name string) (func() hash.Hash, bool, bool) {
	switch name {
	case "MD5", "MD5-SESS":
		return md5.New, name == "MD5-SESS", true
	case "SHA-256", "SHA-256-SESS":
		return sha256.New, name == "SHA-256-SESS", true
	default:
		return nil, false, false
	}
}

// parseDigestParams parses `Digest k=v, k="v"` into a map.
func parseDigestParams(value string) (map[string]string, error) {
	value = strings.TrimSpace(value)
	const prefix = "digest "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return nil, fmt.Errorf("authorization scheme is not Digest")
	}
	params := map[string]string{}
	rest := value[len(prefix):]
	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " ,\t")
		if rest == "" {
			break
		}
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("malformed digest parameter")
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = rest[eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			var builder strings.Builder
			escaped := false
			closed := false
			for i := 0; i < len(rest); i++ {
				c := rest[i]
				switch {
				case escaped:
					builder.WriteByte(c)
					escaped = false
				case c == '\\':
					escaped = true
				case c == '"':
					closed = true
					rest = rest[i+1:]
				default:
					builder.WriteByte(c)
				}
				if closed {
					break
				}
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted digest parameter %q", key)
			}
			val = builder.String()
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				val = strings.TrimSpace(rest)
				rest = ""
			} else {
				val = strings.TrimSpace(rest[:end])
				rest = rest[end:]
			}
		}
		params[key] = val
	}
	if len(params) == 0 {
		return nil, fmt.Errorf("digest header carries no parameters")
	}
	return params, nil
}

// sortedKeys is used by tests and diagnostics to render parameters stably.
func sortedKeys(params map[string]string) []string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
