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
	IncomingCall(context.Context, string, string, string, string, time.Time) (Result, error)
	Configured() bool
}
type AccountSender interface {
	IncomingAccountCall(context.Context, string, string, string, string, time.Time, string) (Result, error)
}
type UserCallSender interface {
	IncomingUserCall(context.Context, string, string, string, string, time.Time, string, string, string) (Result, error)
}
type Result struct {
	Status                            int
	Reason, APNSID                    string
	Timestamp                         time.Time
	Retryable, DeadToken, AuthFailure bool
}
type Disabled struct{}

func (Disabled) IncomingCall(context.Context, string, string, string, string, time.Time) (Result, error) {
	return Result{}, errors.New("APNs disabled")
}
func (Disabled) IncomingAccountCall(context.Context, string, string, string, string, time.Time, string) (Result, error) {
	return Result{}, errors.New("APNs disabled")
}
func (Disabled) IncomingUserCall(context.Context, string, string, string, string, time.Time, string, string, string) (Result, error) {
	return Result{}, errors.New("APNs disabled")
}
func (Disabled) Configured() bool { return false }

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
func (c *Client) IncomingCall(ctx context.Context, role, deviceToken, callID, pushType string, ringExpiresAt time.Time) (Result, error) {
	result, err := c.incomingCall(ctx, role, deviceToken, callID, pushType, ringExpiresAt)
	if result.Reason == "ExpiredProviderToken" {
		c.mu.Lock()
		c.jwt = ""
		c.jwtAt = time.Time{}
		c.mu.Unlock()
		return c.incomingCall(ctx, role, deviceToken, callID, pushType, ringExpiresAt)
	}
	return result, err
}

func (c *Client) IncomingAccountCall(ctx context.Context, platform, deviceToken, callID, pushType string, ringExpiresAt time.Time, accountID string) (Result, error) {
	result, err := c.incomingAccountCall(ctx, platform, deviceToken, callID, pushType, ringExpiresAt, accountID, "incoming_call_v2", "", "")
	if result.Reason == "ExpiredProviderToken" {
		c.mu.Lock()
		c.jwt = ""
		c.jwtAt = time.Time{}
		c.mu.Unlock()
		return c.incomingAccountCall(ctx, platform, deviceToken, callID, pushType, ringExpiresAt, accountID, "incoming_call_v2", "", "")
	}
	return result, err
}

func (c *Client) IncomingUserCall(ctx context.Context, platform, deviceToken, callID, pushType string, ringExpiresAt time.Time, accountID, callerUsername, callerDisplayName string) (Result, error) {
	result, err := c.incomingAccountCall(ctx, platform, deviceToken, callID, pushType, ringExpiresAt, accountID, "incoming_call_v3", callerUsername, callerDisplayName)
	if result.Reason == "ExpiredProviderToken" {
		c.mu.Lock()
		c.jwt = ""
		c.jwtAt = time.Time{}
		c.mu.Unlock()
		return c.incomingAccountCall(ctx, platform, deviceToken, callID, pushType, ringExpiresAt, accountID, "incoming_call_v3", callerUsername, callerDisplayName)
	}
	return result, err
}

func (c *Client) incomingAccountCall(ctx context.Context, platform, deviceToken, callID, pushType string, ringExpiresAt time.Time, accountID, event, callerUsername, callerDisplayName string) (Result, error) {
	topic := c.topicIOSAlert
	if platform == "watchOS" {
		topic = c.topicWatchAlert
	}
	expiration, priority := ringExpiresAt.Unix(), "10"
	bodyValue := map[string]any{
		"aps": map[string]any{
			"alert": map[string]string{"title": "WiFi Secure Call", "body": "Incoming Wi-Fi call"},
			"sound": "default", "category": "INCOMING_CALL", "interruption-level": "time-sensitive",
		},
		"event": event, "serverCallID": callID, "accountID": accountID,
	}
	if event == "incoming_call_v3" {
		bodyValue["callerUsername"] = callerUsername
		bodyValue["callerPublicIdentity"] = "wsc:user:" + callerUsername
		if callerDisplayName != "" {
			bodyValue["callerDisplayName"] = callerDisplayName
		}
		bodyValue["aps"].(map[string]any)["alert"] = map[string]string{"title": "WiFi Secure Call", "body": "Incoming call from @" + callerUsername}
	}
	if platform == "watchOS" && pushType == "alert" {
		bodyValue["aps"].(map[string]any)["content-available"] = 1
	}
	if pushType == "voip" {
		expiration = 0
		bodyValue = map[string]any{"aps": map[string]any{"content-available": 1}, "event": event, "serverCallID": callID, "accountID": accountID}
		if event == "incoming_call_v3" {
			bodyValue["callerUsername"] = callerUsername
			bodyValue["callerPublicIdentity"] = "wsc:user:" + callerUsername
			if callerDisplayName != "" {
				bodyValue["callerDisplayName"] = callerDisplayName
			}
		}
		if platform == "watchOS" {
			topic = c.topicWatchVoIP
		} else {
			topic = c.topicIOSVoIP
		}
	}
	body, _ := json.Marshal(bodyValue)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.push.apple.com/3/device/"+deviceToken, strings.NewReader(string(body)))
	if err != nil {
		return Result{}, err
	}
	token, err := c.bearer()
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", topic)
	req.Header.Set("apns-push-type", pushType)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", fmt.Sprint(expiration))
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	reason := "Success"
	var apnsTimestamp time.Time
	if resp.StatusCode/100 != 2 {
		var payload struct {
			Reason    string `json:"reason"`
			Timestamp int64  `json:"timestamp"`
		}
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(limited, &payload) == nil && payload.Reason != "" {
			reason = payload.Reason
		} else {
			reason = "Unknown"
		}
		if payload.Timestamp > 0 {
			apnsTimestamp = time.UnixMilli(payload.Timestamp).UTC()
		}
	}
	slog.Info("APNs account incoming-call response", "callID", callID, "destinationPlatform", platform, "tokenLength", len(deviceToken), "topic", topic, "pushType", pushType, "priority", priority, "expiration", expiration, "status", resp.StatusCode, "reason", reason, "apnsID", resp.Header.Get("apns-id"))
	result := Result{Status: resp.StatusCode, Reason: reason, APNSID: resp.Header.Get("apns-id"), Timestamp: apnsTimestamp, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, DeadToken: resp.StatusCode == 410 || reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic" || reason == "Unregistered", AuthFailure: reason == "ExpiredProviderToken" || reason == "InvalidProviderToken"}
	if resp.StatusCode/100 != 2 {
		return result, fmt.Errorf("APNs status %d reason %s", resp.StatusCode, reason)
	}
	return result, nil
}

func (c *Client) incomingCall(ctx context.Context, role, deviceToken, callID, pushType string, ringExpiresAt time.Time) (Result, error) {
	topic := c.topicIOSAlert
	platform := "iOS"
	if role == "A" {
		topic = c.topicWatchAlert
		platform = "watchOS"
	}
	expiration := ringExpiresAt.Unix()
	priority := "10"
	bodyValue := map[string]any{
		"aps": map[string]any{
			"alert": map[string]string{"title": "WiFi Secure Call", "body": "Incoming Wi-Fi call"},
			"sound": "default", "category": "INCOMING_CALL", "interruption-level": "time-sensitive",
		},
		"callID": callID, "serverCallID": callID, "event": "incoming_call",
	}
	if role == "A" && pushType == "alert" {
		bodyValue["aps"].(map[string]any)["content-available"] = 1
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
		return Result{}, err
	}
	token, err := c.bearer()
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", topic)
	req.Header.Set("apns-push-type", pushType)
	req.Header.Set("apns-priority", priority)
	req.Header.Set("apns-expiration", fmt.Sprint(expiration))
	req.Header.Set("content-type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	reason := "Success"
	var apnsTimestamp time.Time
	if resp.StatusCode/100 != 2 {
		var payload struct {
			Reason    string `json:"reason"`
			Timestamp int64  `json:"timestamp"`
		}
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if json.Unmarshal(limited, &payload) == nil && payload.Reason != "" {
			reason = payload.Reason
		} else {
			reason = "Unknown"
		}
		if payload.Timestamp > 0 {
			apnsTimestamp = time.UnixMilli(payload.Timestamp).UTC()
		}
	}
	slog.Info("APNs incoming-call response",
		"callID", callID,
		"destinationPlatform", platform,
		"tokenLength", len(deviceToken),
		"topic", topic,
		"pushType", pushType,
		"priority", priority,
		"expiration", expiration,
		"status", resp.StatusCode,
		"reason", reason,
		"apnsID", resp.Header.Get("apns-id"),
	)
	result := Result{Status: resp.StatusCode, Reason: reason, APNSID: resp.Header.Get("apns-id"), Timestamp: apnsTimestamp, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, DeadToken: resp.StatusCode == 410 || reason == "BadDeviceToken" || reason == "DeviceTokenNotForTopic" || reason == "Unregistered", AuthFailure: reason == "ExpiredProviderToken" || reason == "InvalidProviderToken"}
	if resp.StatusCode/100 != 2 {
		return result, fmt.Errorf("APNs status %d reason %s", resp.StatusCode, reason)
	}
	return result, nil
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
