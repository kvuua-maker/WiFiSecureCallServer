package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Sender interface {
	IncomingCall(context.Context, string, string, string, string) error
	Configured() bool
}
type Disabled struct{}

func (Disabled) IncomingCall(context.Context, string, string, string, string) error { return nil }
func (Disabled) Configured() bool                                                   { return false }

type Client struct {
	teamID, keyID                  string
	topicIOSAlert, topicWatchAlert string
	topicIOSVoIP, topicWatchVoIP   string
	key                            *ecdsa.PrivateKey
	http                           *http.Client
	mu                             sync.Mutex
	jwt                            string
	jwtAt                          time.Time
}

func New(teamID, keyID, keyPath, topicIOSAlert, topicWatchAlert, topicIOSVoIP, topicWatchVoIP string) (*Client, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid APNs key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("APNs key is not EC")
	}
	return &Client{
		teamID: teamID, keyID: keyID,
		topicIOSAlert: topicIOSAlert, topicWatchAlert: topicWatchAlert,
		topicIOSVoIP: topicIOSVoIP, topicWatchVoIP: topicWatchVoIP,
		key:  key,
		http: &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true}},
	}, nil
}
func (c *Client) Configured() bool { return true }
func (c *Client) IncomingCall(ctx context.Context, role, deviceToken, callID, pushType string) error {
	topic := c.topicIOSAlert
	platform := "iOS"
	if role == "A" {
		topic = c.topicWatchAlert
		platform = "watchOS"
	}
	expiration := time.Now().Add(30 * time.Second).Unix()
	priority := "10"
	bodyValue := map[string]any{
		"aps": map[string]any{
			"alert": map[string]string{"title": "WiFi Secure Call", "body": "Incoming Wi-Fi call"},
			"sound": "default", "category": "INCOMING_CALL", "interruption-level": "time-sensitive",
		},
		"callID": callID, "serverCallID": callID, "event": "incoming_call",
	}
	if pushType == "voip" {
		expiration = 0
		bodyValue = map[string]any{
			"aps":          map[string]any{"content-available": 1},
			"serverCallID": callID,
			"event":        "incoming_call",
		}
		if role == "A" {
			topic = c.topicWatchVoIP
		} else {
			topic = c.topicIOSVoIP
		}
	}
	body, _ := json.Marshal(bodyValue)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.push.apple.com/3/device/"+deviceToken, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	token, err := c.bearer()
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", topic)
	req.Header.Set("apns-push-type", pushType)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", fmt.Sprint(expiration))
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	reason := "Success"
	if resp.StatusCode/100 != 2 {
		var payload struct {
			Reason string `json:"reason"`
		}
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(limited, &payload) == nil && payload.Reason != "" {
			reason = payload.Reason
		} else {
			reason = "Unknown"
		}
	}
	prefix := deviceToken
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	slog.Info("APNs incoming-call response",
		"callID", callID,
		"destinationPlatform", platform,
		"tokenPrefix", prefix,
		"tokenLength", len(deviceToken),
		"topic", topic,
		"pushType", pushType,
		"priority", priority,
		"expiration", expiration,
		"status", resp.StatusCode,
		"reason", reason,
		"apnsID", resp.Header.Get("apns-id"),
	)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("APNs status %d reason %s", resp.StatusCode, reason)
	}
	return nil
}
func (c *Client) bearer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwt != "" && time.Since(c.jwtAt) < 50*time.Minute {
		return c.jwt, nil
	}
	now := time.Now()
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID})
	claims, _ := json.Marshal(map[string]any{"iss": c.teamID, "iat": now.Unix()})
	unsigned := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	hash := sha256Sum([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, hash)
	if err != nil {
		return "", err
	}
	sig := append(padded(r, 32), padded(s, 32)...)
	c.jwt = unsigned + "." + enc.EncodeToString(sig)
	c.jwtAt = now
	return c.jwt, nil
}
func padded(value *big.Int, size int) []byte {
	raw := value.Bytes()
	out := make([]byte, size)
	copy(out[size-len(raw):], raw)
	return out
}
