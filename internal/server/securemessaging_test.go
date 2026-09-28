package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/devicekeys"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/messages"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/usercalls"
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

func TestSecureMessagingAPIRejectsInvalidSignatureAndIncompleteEnvelopesWithoutPersistence(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations", fixture.caller.AccessToken, map[string]string{
		"requestID":    "41414141-4141-4141-8141-414141414141",
		"targetUserID": fixture.targetUserID,
	})
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	var conversation messages.Conversation
	if err := json.Unmarshal(created.Body.Bytes(), &conversation); err != nil {
		t.Fatal(err)
	}

	resign := func(input *messages.MessageInput) {
		input.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(
			fixture.signingKeys[fixture.caller.DeviceID],
			messages.SignatureMessage(conversation.ConversationID, fixture.caller.User.UserID, fixture.caller.DeviceID, *input),
		))
	}
	assertNoMessages := func(stage string) {
		response := performUserRequest(t, fixture.server, http.MethodGet, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.targetIOS.AccessToken, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s page=%d %s", stage, response.Code, response.Body.String())
		}
		var page messages.Page
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatalf("%s decode page: %v", stage, err)
		}
		if len(page.Messages) != 0 {
			t.Fatalf("%s persisted %d rejected messages", stage, len(page.Messages))
		}
	}

	tampered := fixtureEncryptedMessage(t, fixture, conversation.ConversationID, "42424242-4242-4242-8242-424242424242", "43434343-4343-4343-8343-434343434343")
	tampered.Signature = base64.StdEncoding.EncodeToString(bytesOf(ed25519.SignatureSize, 0xff))
	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, tampered)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_message_signature") {
		t.Fatalf("tampered signature=%d %s", response.Code, response.Body.String())
	}
	assertNoMessages("tampered signature")

	missing := fixtureEncryptedMessage(t, fixture, conversation.ConversationID, "44444444-4444-4444-8444-444444444444", "45454545-4545-4545-8545-454545454545")
	missing.Envelopes = missing.Envelopes[:len(missing.Envelopes)-1]
	resign(&missing)
	response = performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, missing)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "recipient_key_unavailable") {
		t.Fatalf("missing envelope=%d %s", response.Code, response.Body.String())
	}
	assertNoMessages("missing envelope")

	extra := fixtureEncryptedMessage(t, fixture, conversation.ConversationID, "46464646-4646-4646-8646-464646464646", "47474747-4747-4747-8747-474747474747")
	extra.Envelopes = append(extra.Envelopes, messages.Envelope{
		DeviceID: fixture.unrelated.DeviceID, EphemeralPublicKey: base64.StdEncoding.EncodeToString(bytesOf(32, 21)),
		Nonce: base64.StdEncoding.EncodeToString(bytesOf(12, 22)), Ciphertext: base64.StdEncoding.EncodeToString(bytesOf(32, 23)),
		Tag: base64.StdEncoding.EncodeToString(bytesOf(16, 24)), KeyVersion: 1,
	})
	resign(&extra)
	response = performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, extra)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "recipient_key_unavailable") {
		t.Fatalf("extra envelope=%d %s", response.Code, response.Body.String())
	}
	assertNoMessages("extra envelope")

	duplicate := fixtureEncryptedMessage(t, fixture, conversation.ConversationID, "48484848-4848-4848-8848-484848484848", "49494949-4949-4949-8949-494949494949")
	duplicate.Envelopes[len(duplicate.Envelopes)-1] = duplicate.Envelopes[0]
	resign(&duplicate)
	response = performUserRequest(t, fixture.server, http.MethodPost, "/v3/conversations/"+conversation.ConversationID+"/messages", fixture.caller.AccessToken, duplicate)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "recipient_key_unavailable") {
		t.Fatalf("duplicate envelope=%d %s", response.Code, response.Body.String())
	}
	assertNoMessages("duplicate envelope")
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
	if missing.Code != http.StatusBadRequest || !strings.Contains(missing.Body.String(), "invalid_key_package") {
		t.Fatalf("missing=%d %s", missing.Code, missing.Body.String())
	}
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "13131313-1313-4313-8313-131313131313", callID, fixture.targetUserID))
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	withoutCallee := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, map[string]string{"requestID": "14141414-1414-4414-8414-141414141414"})
	if withoutCallee.Code != http.StatusUpgradeRequired || !strings.Contains(withoutCallee.Body.String(), "e2ee_protocol_required") {
		t.Fatalf("accept=%d %s", withoutCallee.Code, withoutCallee.Body.String())
	}
}

func TestCrossUserCallPackagesAreBoundToCallIdentityWinnerAndEpoch(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	callID := "21212121-2121-4121-8121-212121212121"
	otherCallID := "22222222-2222-4222-8222-222222222222"

	crossCallBody := fixtureCreateBody(t, fixture, "23232323-2323-4323-8323-232323232323", callID, fixture.targetUserID)
	crossCallBody["callerKeyPackage"] = fixtureKeyPackage(t, fixture, fixture.caller, otherCallID, usercalls.SideCaller)
	crossCall := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, crossCallBody)
	if crossCall.Code != http.StatusBadRequest || !strings.Contains(crossCall.Body.String(), "invalid_key_package") {
		t.Fatalf("cross-call package=%d %s", crossCall.Code, crossCall.Body.String())
	}

	wrongCallerBody := fixtureCreateBody(t, fixture, "24242424-2424-4424-8424-242424242424", callID, fixture.targetUserID)
	wrongCallerBody["callerKeyPackage"] = fixtureKeyPackage(t, fixture, fixture.unrelated, callID, usercalls.SideCaller)
	wrongCaller := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, wrongCallerBody)
	if wrongCaller.Code != http.StatusBadRequest || !strings.Contains(wrongCaller.Body.String(), "invalid_key_package") {
		t.Fatalf("wrong caller package=%d %s", wrongCaller.Code, wrongCaller.Body.String())
	}

	overflowBody := fixtureCreateBody(t, fixture, "25252525-2525-4525-8525-252525252525", callID, fixture.targetUserID)
	overflowPackage := fixtureKeyPackage(t, fixture, fixture.caller, callID, usercalls.SideCaller)
	overflowPackage.KeyEpoch = uint64(math.MaxUint32) + 1
	overflowPackage.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.signingKeys[fixture.caller.DeviceID], usercalls.KeyPackageMessage(overflowPackage)))
	overflowBody["callerKeyPackage"] = overflowPackage
	overflow := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, overflowBody)
	if overflow.Code != http.StatusBadRequest || !strings.Contains(overflow.Body.String(), "invalid_key_package") {
		t.Fatalf("overflow epoch=%d %s", overflow.Code, overflow.Body.String())
	}

	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "26262626-2626-4626-8626-262626262626", callID, fixture.targetUserID))
	if created.Code != http.StatusOK {
		t.Fatalf("create=%d %s", created.Code, created.Body.String())
	}
	createdView := decodeUserCallView(t, created)
	if createdView.CallerUserID != fixture.caller.User.UserID || createdView.CallerDeviceID != fixture.caller.DeviceID || createdView.CalleeUserID != fixture.targetUserID || createdView.CalleeDeviceID != "" {
		t.Fatalf("created authoritative identities=%+v", createdView)
	}

	crossCallAccept := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, fixtureAcceptBody(t, fixture, "27272727-2727-4727-8727-272727272727", otherCallID, fixture.targetIOS))
	if crossCallAccept.Code != http.StatusBadRequest || !strings.Contains(crossCallAccept.Body.String(), "invalid_key_package") {
		t.Fatalf("cross-call accept=%d %s", crossCallAccept.Code, crossCallAccept.Body.String())
	}

	wrongDeviceAccept := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, fixtureAcceptBody(t, fixture, "28282828-2828-4828-8828-282828282828", callID, fixture.targetWatch))
	if wrongDeviceAccept.Code != http.StatusBadRequest || !strings.Contains(wrongDeviceAccept.Body.String(), "invalid_key_package") {
		t.Fatalf("wrong-device accept=%d %s", wrongDeviceAccept.Code, wrongDeviceAccept.Body.String())
	}

	mismatchedEpoch := fixtureKeyPackage(t, fixture, fixture.targetIOS, callID, usercalls.SideCallee)
	mismatchedEpoch.KeyEpoch = 2
	mismatchedEpoch.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.signingKeys[fixture.targetIOS.DeviceID], usercalls.KeyPackageMessage(mismatchedEpoch)))
	epochAccept := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, map[string]any{"requestID": "29292929-2929-4929-8929-292929292929", "calleeKeyPackage": mismatchedEpoch})
	if epochAccept.Code != http.StatusConflict || !strings.Contains(epochAccept.Body.String(), "invalid_key_package") {
		t.Fatalf("mismatched epoch=%d %s", epochAccept.Code, epochAccept.Body.String())
	}

	winner := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetWatch.AccessToken, fixtureAcceptBody(t, fixture, "30303030-3030-4030-8030-303030303030", callID, fixture.targetWatch))
	if winner.Code != http.StatusOK {
		t.Fatalf("winner=%d %s", winner.Code, winner.Body.String())
	}
	winnerView := decodeUserCallView(t, winner)
	if winnerView.CalleeDeviceID != fixture.targetWatch.DeviceID || winnerView.CalleeKeyPackage == nil || winnerView.CalleeKeyPackage.DeviceID != fixture.targetWatch.DeviceID {
		t.Fatalf("winner identity/package=%+v", winnerView)
	}

	loser := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetIOS.AccessToken, fixtureAcceptBody(t, fixture, "31313131-3131-4131-8131-313131313131", callID, fixture.targetIOS))
	if loser.Code != http.StatusOK {
		t.Fatalf("loser=%d %s", loser.Code, loser.Body.String())
	}
	loserView := decodeUserCallView(t, loser)
	if loserView.LegState != usercalls.LegAnsweredElsewhere || loserView.MediaToken != "" || loserView.CalleeDeviceID != fixture.targetWatch.DeviceID || loserView.CalleeKeyPackage == nil || loserView.CalleeKeyPackage.DeviceID != fixture.targetWatch.DeviceID {
		t.Fatalf("loser derived non-winner package=%+v", loserView)
	}
}
