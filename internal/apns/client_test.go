package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type capturedAPNSRequest struct {
	header  http.Header
	payload map[string]any
}

func testClient(t *testing.T, captured *capturedAPNSRequest) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		captured.header = request.Header.Clone()
		if err := json.Unmarshal(body, &captured.payload); err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
		}, nil
	})
	return &Client{
		teamID:          "TEAMID",
		keyID:           "KEYID",
		topicIOSAlert:   "com.vkapps.wifisecurecall",
		topicWatchAlert: "com.vkapps.wifisecurecall.watchkitapp",
		topicIOSVoIP:    "com.vkapps.wifisecurecall.voip",
		topicWatchVoIP:  "com.vkapps.wifisecurecall.watchkitapp.voip",
		key:             key,
		http:            &http.Client{Transport: transport},
	}
}

func TestWatchAlertIncludesBackgroundDeliveryAndVisibleAlert(t *testing.T) {
	var captured capturedAPNSRequest
	client := testClient(t, &captured)
	callID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	expiresAt := time.Now().Add(30 * time.Second).UTC()
	if _, err := client.IncomingCall(context.Background(), "A", "0123456789abcdef", callID, "alert", expiresAt); err != nil {
		t.Fatal(err)
	}

	if got := captured.header.Get("apns-push-type"); got != "alert" {
		t.Fatalf("push type = %q", got)
	}
	if got := captured.header.Get("apns-priority"); got != "10" {
		t.Fatalf("priority = %q", got)
	}
	if got := captured.header.Get("apns-topic"); got != "com.vkapps.wifisecurecall.watchkitapp" {
		t.Fatalf("topic = %q", got)
	}
	aps, ok := captured.payload["aps"].(map[string]any)
	if !ok {
		t.Fatal("missing aps dictionary")
	}
	if got := aps["content-available"]; got != float64(1) {
		t.Fatalf("content-available = %#v", got)
	}
	if aps["sound"] != "default" || aps["category"] != "INCOMING_CALL" || aps["interruption-level"] != "time-sensitive" {
		t.Fatalf("visible alert fields changed: %#v", aps)
	}
	alert, ok := aps["alert"].(map[string]any)
	if !ok || alert["title"] != "WiFi Secure Call" || alert["body"] != "Incoming Wi-Fi call" {
		t.Fatalf("alert = %#v", aps["alert"])
	}
	if captured.payload["event"] != "incoming_call" || captured.payload["callID"] != callID || captured.payload["serverCallID"] != callID {
		t.Fatalf("root payload = %#v", captured.payload)
	}
}

func TestIPhoneAlertFallbackDoesNotGainWatchBackgroundAugmentation(t *testing.T) {
	var captured capturedAPNSRequest
	client := testClient(t, &captured)
	if _, err := client.IncomingCall(context.Background(), "B", "0123456789abcdef", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "alert", time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	aps := captured.payload["aps"].(map[string]any)
	if _, exists := aps["content-available"]; exists {
		t.Fatal("iPhone alert fallback unexpectedly contains content-available")
	}
	if captured.header.Get("apns-topic") != "com.vkapps.wifisecurecall" || captured.header.Get("apns-push-type") != "alert" || captured.header.Get("apns-priority") != "10" {
		t.Fatalf("iPhone alert headers changed: %#v", captured.header)
	}
}

func TestAccountIncomingCallTopicsAndPayload(t *testing.T) {
	tests := []struct {
		name, platform, pushType, topic string
		background                      bool
	}{
		{"iOS VoIP", "iOS", "voip", "com.vkapps.wifisecurecall.voip", true},
		{"iOS alert", "iOS", "alert", "com.vkapps.wifisecurecall", false},
		{"Watch alert", "watchOS", "alert", "com.vkapps.wifisecurecall.watchkitapp", true},
		{"Watch VoIP", "watchOS", "voip", "com.vkapps.wifisecurecall.watchkitapp.voip", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var captured capturedAPNSRequest
			client := testClient(t, &captured)
			callID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
			accountID := "11111111-2222-4333-8444-555555555555"
			if _, err := client.IncomingAccountCall(context.Background(), test.platform, "0123456789abcdef", callID, test.pushType, time.Now().Add(30*time.Second), accountID); err != nil {
				t.Fatal(err)
			}
			if captured.header.Get("apns-topic") != test.topic || captured.header.Get("apns-push-type") != test.pushType || captured.header.Get("apns-priority") != "10" {
				t.Fatalf("headers=%v", captured.header)
			}
			aps, ok := captured.payload["aps"].(map[string]any)
			if !ok {
				t.Fatal("missing aps")
			}
			_, hasBackground := aps["content-available"]
			if hasBackground != test.background {
				t.Fatalf("content-available present=%v", hasBackground)
			}
			if test.pushType == "alert" && (aps["sound"] != "default" || aps["category"] != "INCOMING_CALL") {
				t.Fatalf("visible alert changed: %#v", aps)
			}
			if captured.payload["event"] != "incoming_call_v2" || captured.payload["serverCallID"] != callID || captured.payload["accountID"] != accountID {
				t.Fatalf("payload=%#v", captured.payload)
			}
			for _, forbidden := range []string{"phoneNumber", "mediaToken", "accessToken", "refreshToken"} {
				if _, exists := captured.payload[forbidden]; exists {
					t.Fatalf("payload exposed %s", forbidden)
				}
			}
		})
	}
}

func TestUserIncomingCallCarriesSafeCallerIdentityAndOneLogicalCallID(t *testing.T) {
	tests := []struct {
		platform, pushType, topic string
	}{
		{"iOS", "voip", "com.vkapps.wifisecurecall.voip"},
		{"watchOS", "alert", "com.vkapps.wifisecurecall.watchkitapp"},
	}
	for _, test := range tests {
		var captured capturedAPNSRequest
		client := testClient(t, &captured)
		callID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		accountID := "11111111-2222-4333-8444-555555555555"
		if _, err := client.IncomingUserCall(context.Background(), test.platform, "0123456789abcdef", callID, test.pushType, time.Now().Add(30*time.Second), accountID, "alice", "Alice"); err != nil {
			t.Fatal(err)
		}
		if captured.header.Get("apns-topic") != test.topic || captured.payload["event"] != "incoming_call_v3" {
			t.Fatalf("headers=%v payload=%#v", captured.header, captured.payload)
		}
		if captured.payload["serverCallID"] != callID || captured.payload["accountID"] != accountID || captured.payload["callerUsername"] != "alice" || captured.payload["callerPublicIdentity"] != "wsc:user:alice" || captured.payload["callerDisplayName"] != "Alice" {
			t.Fatalf("payload=%#v", captured.payload)
		}
		for _, forbidden := range []string{"email", "appleSubject", "mediaToken", "accessToken", "refreshToken"} {
			if _, exists := captured.payload[forbidden]; exists {
				t.Fatalf("payload exposed %s", forbidden)
			}
		}
	}
}

func TestRemoteCellularControlUsesOpaqueIdentifierOnly(t *testing.T) {
	var captured capturedAPNSRequest
	client := testClient(t, &captured)
	requestID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	accountID := "11111111-2222-4333-8444-555555555555"
	if _, err := client.RemoteCellularControl(context.Background(), "0123456789abcdef", requestID, time.Now().Add(2*time.Minute), accountID); err != nil {
		t.Fatal(err)
	}
	if captured.header.Get("apns-topic") != "com.vkapps.wifisecurecall" || captured.header.Get("apns-push-type") != "alert" || captured.header.Get("apns-priority") != "10" {
		t.Fatalf("headers=%v", captured.header)
	}
	if captured.payload["event"] != "remote_cellular_control" || captured.payload["requestID"] != requestID || captured.payload["accountID"] != accountID {
		t.Fatalf("payload=%#v", captured.payload)
	}
	aps, ok := captured.payload["aps"].(map[string]any)
	if !ok || aps["category"] != "REMOTE_CELLULAR_CONTROL" || aps["content-available"] != float64(1) {
		t.Fatalf("aps=%#v", captured.payload["aps"])
	}
	encoded, err := json.Marshal(captured.payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"+380501234567", "phoneNumber", "tel:", "telephony:", "accessToken", "refreshToken"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("payload exposed %q: %s", forbidden, encoded)
		}
	}
}
