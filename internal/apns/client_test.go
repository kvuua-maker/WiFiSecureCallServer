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
