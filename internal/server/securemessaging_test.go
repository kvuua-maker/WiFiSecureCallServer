package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/devicekeys"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/messages"
)

func fixtureEncryptedMessage(t *testing.T, fixture userCallFixture, conversationID, messageID, clientMessageID string) messages.MessageInput {
	t.Helper()
	encoded := func(size int, fill byte) string { return base64.StdEncoding.EncodeToString(bytesOf(size, fill)) }
	input := messages.MessageInput{
		MessageID: messageID, ClientMessageID: clientMessageID, ProtocolVersion: 1, KeyVersion: 1,
		Nonce: encoded(12, 1), Ciphertext: encoded(32, 2), Tag: encoded(16, 3),
		Envelopes: []messages.Envelope{
			{DeviceID: fixture.caller.DeviceID, EphemeralPublicKey: encoded(32, 12), Nonce: encoded(12, 13), Ciphertext: encoded(32, 14), Tag: encoded(16, 15), KeyVersion: 1},
			{DeviceID: fixture.targetIOS.DeviceID, EphemeralPublicKey: encoded(32, 4), Nonce: encoded(12, 5), Ciphertext: encoded(32, 6), Tag: encoded(16, 7), KeyVersion: 1},
			{DeviceID: fixture.targetWatch.DeviceID, EphemeralPublicKey: encoded(32, 8), Nonce: encoded(12, 9), Ciphertext: encoded(32, 10), Tag: encoded(16, 11), KeyVersion: 1},
		},
	}
	input.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.signingKeys[fixture.caller.DeviceID], messages.SignatureMessage(conversationID, fixture.caller.User.UserID, fixture.caller.DeviceID, input)))
	return input
}
func bytesOf(size int, fill byte) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = fill
	}
	return value
}

func TestSecureMessagingAPIEnforcesParticipantsKeysAndReceipts(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations", fixture.caller.AccessToken, map[string]string{"requestID": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "targetUserID": fixture.targetUserID})
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	var conversation messages.Conversation
	if err := json.Unmarshal(created.Body.Bytes(), &conversation); err != nil {
		t.Fatal(err)
	}
	messageID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	input := fixtureEncryptedMessage(t, fixture, conversation.ConversationID, messageID, "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	sent := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, input)
	if sent.Code != http.StatusOK || strings.Contains(sent.Body.String(), "private message sentinel") {
		t.Fatalf("send=%d %s", sent.Code, sent.Body.String())
	}
	duplicate := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, input)
	if duplicate.Code != http.StatusOK {
		t.Fatalf("idempotent=%d %s", duplicate.Code, duplicate.Body.String())
	}
	denied := performUserRequest(t, fixture.server, http.MethodGet, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.unrelated.AccessToken, nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("nonparticipant=%d %s", denied.Code, denied.Body.String())
	}
	page := performUserRequest(t, fixture.server, http.MethodGet, "/v3/conversations/"+conversation.ConversationID+"/messages?limit=1", fixture.targetIOS.AccessToken, nil)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), messageID) {
		t.Fatalf("page=%d %s", page.Code, page.Body.String())
	}
	read := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages/"+messageID+"/read", fixture.targetIOS.AccessToken, map[string]string{"requestID": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"})
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), "readAt") {
		t.Fatalf("read=%d %s", read.Code, read.Body.String())
	}
}

func TestDeviceKeyAPIRejectsAnotherAuthenticatedDevice(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	registration := devicekeys.Registration{RequestID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", DeviceID: fixture.targetIOS.DeviceID, SigningPublicKey: base64.StdEncoding.EncodeToString(bytesOf(32, 1)), AgreementPublicKey: base64.StdEncoding.EncodeToString(bytesOf(32, 2)), KeyVersion: 1, ProtocolVersion: 2, ProofSignature: base64.StdEncoding.EncodeToString(bytesOf(64, 3))}
	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/device-keys", fixture.caller.AccessToken, registration)
	if response.Code != http.StatusBadRequest && response.Code != http.StatusForbidden {
		t.Fatalf("cross-device=%d %s", response.Code, response.Body.String())
	}
	keys := performUserRequest(t, fixture.server, http.MethodGet, "/v3/users/"+fixture.targetUserID+"/device-keys", fixture.caller.AccessToken, nil)
	if keys.Code != http.StatusOK || strings.Contains(keys.Body.String(), "private") {
		t.Fatalf("keys=%d %s", keys.Code, keys.Body.String())
	}
}

func TestCrossUserCallsRequireAuthenticatedE2EEPackages(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	callID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	missing := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, map[string]string{"requestID": "12121212-1212-4212-8212-121212121212", "callID": callID, "targetUserID": fixture.targetUserID})
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), "invalid_key_package") { t.Fatalf("missing=%d %s", missing.Code, missing.Body.String()) }
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "13131313-1313-4313-8313-131313131313", callID, fixture.targetUserID))
	if created.Code != http.StatusOK { t.Fatalf("create=%d %s", created.Code, created.Body.String()) }
	withoutCallee := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, map[string]string{"requestID": "14141414-1414-4414-8414-141414141414"})
	if withoutCallee.Code != http.StatusUpgradeRequired || !strings.Contains(withoutCallee.Body.String(), "e2ee_protocol_required") { t.Fatalf("accept=%d %s", withoutCallee.Code, withoutCallee.Body.String()) }
}
