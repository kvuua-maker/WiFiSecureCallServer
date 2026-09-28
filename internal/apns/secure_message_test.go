package apns

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSecureMessageAlertContainsOnlyOpaqueIdentifiers(t *testing.T) {
	var captured capturedAPNSRequest
	client := testClient(t, &captured)
	conversationID := "11111111-1111-4111-8111-111111111111"
	messageID := "22222222-2222-4222-8222-222222222222"
	accountID := "33333333-3333-4333-8333-333333333333"
	expiresAt := time.Now().Add(time.Hour).UTC()
	if _, err := client.SecureMessage(context.Background(), "iOS", "0123456789abcdef", conversationID, messageID, accountID, expiresAt); err != nil {
		t.Fatal(err)
	}
	if captured.header.Get("apns-topic") != "com.vkapps.wifisecurecall" || captured.header.Get("apns-push-type") != "alert" || captured.header.Get("apns-priority") != "10" {
		t.Fatalf("headers=%v", captured.header)
	}
	if captured.payload["event"] != "secure_message" || captured.payload["conversationID"] != conversationID || captured.payload["messageID"] != messageID || captured.payload["accountID"] != accountID {
		t.Fatalf("payload=%#v", captured.payload)
	}
	aps, ok := captured.payload["aps"].(map[string]any)
	if !ok {
		t.Fatalf("aps=%#v", captured.payload["aps"])
	}
	alert, ok := aps["alert"].(map[string]any)
	if !ok || alert["body"] != "New secure message" {
		t.Fatalf("alert=%#v", aps["alert"])
	}
	encoded, err := json.Marshal(captured.payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"plaintext", "phoneNumber", "privateKey", "symmetricKey", "sharedSecret", "mediaToken"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("payload exposed %q: %s", forbidden, encoded)
		}
	}
}
