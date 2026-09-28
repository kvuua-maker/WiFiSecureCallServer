package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/appleauth"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devicekeys"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/usercalls"
)

type serverAppleVerifier struct {
	mu      sync.Mutex
	subject string
}

func (v *serverAppleVerifier) setSubject(value string) {
	v.mu.Lock()
	v.subject = value
	v.mu.Unlock()
}
func (v *serverAppleVerifier) Verify(context.Context, string, string) (appleauth.Claims, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return appleauth.Claims{Subject: v.subject, EmailVerified: false}, nil
}

type capturedUserPush struct {
	platform, callID, pushType, accountID, callerUsername, callerDisplayName string
}

type userCallPushFake struct {
	mu       sync.Mutex
	requests []capturedUserPush
	failFor  map[string]apns.Result
}

func (f *userCallPushFake) Configured() bool { return true }
func (f *userCallPushFake) IncomingCall(context.Context, string, string, string, string, time.Time) (apns.Result, error) {
	return apns.Result{Status: 200}, nil
}
func (f *userCallPushFake) IncomingAccountCall(context.Context, string, string, string, string, time.Time, string) (apns.Result, error) {
	return apns.Result{Status: 200}, nil
}
func (f *userCallPushFake) IncomingUserCall(_ context.Context, platform, token, callID, pushType string, _ time.Time, accountID, callerUsername, callerDisplayName string) (apns.Result, error) {
	f.mu.Lock()
	f.requests = append(f.requests, capturedUserPush{platform: platform, callID: callID, pushType: pushType, accountID: accountID, callerUsername: callerUsername, callerDisplayName: callerDisplayName})
	result, failed := f.failFor[token]
	f.mu.Unlock()
	if failed {
		return result, errors.New("synthetic APNs failure")
	}
	return apns.Result{Status: 200, APNSID: "safe-test-id"}, nil
}
func (f *userCallPushFake) snapshot() []capturedUserPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]capturedUserPush(nil), f.requests...)
}

type userCallFixture struct {
	server                 *Server
	auth                   *phoneauth.Service
	accountStore           *accounts.Store
	accountCalls           *accountcalls.Store
	push                   *userCallPushFake
	caller, targetIOS      phoneauth.SessionResult
	targetWatch, unrelated phoneauth.SessionResult
	targetUserID           string
	targetIOSToken         string
	targetWatchToken       string
	signingKeys            map[string]ed25519.PrivateKey
}

func newUserCallFixture(t *testing.T, failures map[string]apns.Result) userCallFixture {
	t.Helper()
	accountStore, err := accounts.Open(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := phoneauth.New(accountStore, nil, strings.Repeat("p", 32), 5)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &serverAppleVerifier{}
	auth.ConfigureAppleIdentity(verifier)
	signIn := func(subject, requestID, deviceID, platform string) phoneauth.SessionResult {
		verifier.setSubject(subject)
		result, signInErr := auth.AppleSignIn(context.Background(), phoneauth.AppleSignInRequest{
			RequestID: requestID, DeviceID: deviceID, Platform: platform, IdentityToken: "synthetic", Nonce: "synthetic",
		})
		if signInErr != nil {
			t.Fatal(signInErr)
		}
		return result
	}
	caller := signIn("caller-subject", "11111111-1111-4111-8111-111111111111", "21111111-1111-4111-8111-111111111111", "iOS")
	targetIOS := signIn("target-subject", "31111111-1111-4111-8111-111111111111", "41111111-1111-4111-8111-111111111111", "iOS")
	targetWatch := signIn("target-subject", "51111111-1111-4111-8111-111111111111", "61111111-1111-4111-8111-111111111111", "watchOS")
	unrelated := signIn("unrelated-subject", "71111111-1111-4111-8111-111111111111", "81111111-1111-4111-8111-111111111111", "iOS")
	iosToken, watchToken := strings.Repeat("a", 64), strings.Repeat("b", 64)
	register := func(session phoneauth.SessionResult, platform, pushType, token string) {
		identity, authErr := auth.Authenticate(session.AccessToken)
		if authErr != nil {
			t.Fatal(authErr)
		}
		err := auth.RegisterDevice(identity, phoneauth.DeviceRegistration{
			RequestID: "91111111-1111-4111-8111-111111111111", DeviceID: session.DeviceID, Platform: platform,
			PushType: pushType, Token: token, InstallationGeneration: 1, Environment: "production",
			Capabilities: accounts.DeviceCapabilities{VoIPPush: platform == "iOS", AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	register(targetIOS, "iOS", "voip", iosToken)
	register(targetWatch, "watchOS", "alert", watchToken)
	deviceStore, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	push := &userCallPushFake{failFor: failures}
	accountCallStore := accountcalls.New(30 * time.Second)
	server := NewWithCallStores("a", "b", calls.New(30*time.Second, 0), deviceStore, push, auth, accountCallStore, usercalls.New(30*time.Second))
	keys := map[string]ed25519.PrivateKey{}
	for _, session := range []phoneauth.SessionResult{caller, targetIOS, targetWatch, unrelated} {
		keys[session.DeviceID] = registerFixtureDeviceKey(t, server.deviceKeys, session)
	}
	return userCallFixture{server: server, auth: auth, accountStore: accountStore, accountCalls: accountCallStore, push: push, caller: caller, targetIOS: targetIOS, targetWatch: targetWatch, unrelated: unrelated, targetUserID: targetIOS.User.UserID, targetIOSToken: iosToken, targetWatchToken: watchToken, signingKeys: keys}
}

func registerFixtureDeviceKey(t *testing.T, store *devicekeys.Store, session phoneauth.SessionResult) ed25519.PrivateKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreement := make([]byte, 32)
	if _, err = rand.Read(agreement); err != nil {
		t.Fatal(err)
	}
	request := devicekeys.Registration{
		RequestID: strings.ToLower(session.DeviceID), DeviceID: strings.ToLower(session.DeviceID),
		SigningPublicKey: base64.StdEncoding.EncodeToString(publicKey), AgreementPublicKey: base64.StdEncoding.EncodeToString(agreement),
		KeyVersion: 1, ProtocolVersion: 2,
	}
	request.ProofSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, devicekeys.ProofMessage(request)))
	if _, _, err = store.Register(session.User.UserID, session.DeviceID, request); err != nil {
		t.Fatal(err)
	}
	return privateKey
}

func fixtureKeyPackage(t *testing.T, fixture userCallFixture, session phoneauth.SessionResult, callID string, side usercalls.Side) usercalls.KeyPackage {
	t.Helper()
	ephemeral := make([]byte, 32)
	if _, err := rand.Read(ephemeral); err != nil {
		t.Fatal(err)
	}
	value := usercalls.KeyPackage{ProtocolVersion: 2, KeyEpoch: 1, CallID: callID, UserID: session.User.UserID, DeviceID: session.DeviceID, Side: side, EphemeralPublicKey: base64.StdEncoding.EncodeToString(ephemeral)}
	value.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.signingKeys[session.DeviceID], usercalls.KeyPackageMessage(value)))
	return value
}

func fixtureCreateBody(t *testing.T, fixture userCallFixture, requestID, callID, targetUserID string) map[string]any {
	return map[string]any{"requestID": requestID, "callID": callID, "targetUserID": targetUserID, "callerKeyPackage": fixtureKeyPackage(t, fixture, fixture.caller, callID, usercalls.SideCaller)}
}

func fixtureAcceptBody(t *testing.T, fixture userCallFixture, requestID, callID string, session phoneauth.SessionResult) map[string]any {
	return map[string]any{"requestID": requestID, "calleeKeyPackage": fixtureKeyPackage(t, fixture, session, callID, usercalls.SideCallee)}
}

func performUserRequest(t *testing.T, server *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func decodeUserCallView(t *testing.T, response *httptest.ResponseRecorder) usercalls.View {
	t.Helper()
	var view usercalls.View
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode status=%d body=%q err=%v", response.Code, response.Body.String(), err)
	}
	return view
}

func waitForPushes(t *testing.T, fake *userCallPushFake, count int) []capturedUserPush {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if values := fake.snapshot(); len(values) >= count {
			return values
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("push count=%d want=%d", len(fake.snapshot()), count)
	return nil
}

func waitForUserCallView(t *testing.T, server *Server, token, callID string, ready func(usercalls.View) bool) usercalls.View {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last usercalls.View
	for time.Now().Before(deadline) {
		response := performUserRequest(t, server, http.MethodGet, "/v3/calls/"+callID, token, nil)
		last = decodeUserCallView(t, response)
		if ready(last) {
			return last
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("call %s did not reach expected state: %+v", callID, last)
	return usercalls.View{}
}

func waitForAccountPushTokenCleared(t *testing.T, auth *phoneauth.Service, accountID, deviceID, pushType string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		device, found := auth.DeviceForAccount(accountID, deviceID)
		if found && ((pushType == "voip" && device.VoIPToken == "") || (pushType == "alert" && device.AlertToken == "")) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s token for device %s was not cleared", pushType, deviceID)
}

func TestV3ResolverAndCrossUserFanoutFirstAnswer(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	resolve := performUserRequest(t, fixture.server, http.MethodPost, "/v3/recipients/resolve", fixture.caller.AccessToken, map[string]string{"recipient": "@" + fixture.targetIOS.User.Username})
	if resolve.Code != http.StatusOK {
		t.Fatalf("resolver status=%d body=%q", resolve.Code, resolve.Body.String())
	}
	var recipient phoneauth.RecipientView
	if err := json.Unmarshal(resolve.Body.Bytes(), &recipient); err != nil || recipient.UserID != fixture.targetUserID || recipient.PublicIdentity == "" {
		t.Fatalf("recipient=%+v err=%v", recipient, err)
	}
	for _, forbidden := range []string{"email", "accountID", "deviceID", "apple", "token"} {
		if strings.Contains(strings.ToLower(resolve.Body.String()), strings.ToLower(forbidden)) {
			t.Fatalf("resolver leaked %q: %s", forbidden, resolve.Body.String())
		}
	}
	callID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	create := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", callID, fixture.targetUserID))
	if create.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", create.Code, create.Body.String())
	}
	created := decodeUserCallView(t, create)
	if created.State != usercalls.Ringing || created.LocalSide != usercalls.SideCaller || created.MediaToken != "" {
		t.Fatalf("created=%+v", created)
	}
	if fixture.server.userCalls.RequiredMediaProtocol(callID) != 2 {
		t.Fatal("secure cross-user call did not require media protocol v2")
	}
	pushes := waitForPushes(t, fixture.push, 2)
	if len(pushes) != 2 {
		t.Fatalf("pushes=%+v", pushes)
	}
	seenPlatforms := map[string]string{}
	for _, push := range pushes {
		if push.callID != callID || push.callerUsername != fixture.caller.User.Username || push.accountID != fixture.targetIOS.Account.AccountID {
			t.Fatalf("unsafe/wrong push=%+v", push)
		}
		seenPlatforms[push.platform] = push.pushType
	}
	if seenPlatforms["iOS"] != "voip" || seenPlatforms["watchOS"] != "alert" {
		t.Fatalf("push preferences=%+v", seenPlatforms)
	}
	accept := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls/"+callID+"/accept", fixture.targetWatch.AccessToken, fixtureAcceptBody(t, fixture, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", callID, fixture.targetWatch))
	winner := decodeUserCallView(t, accept)
	if accept.Code != http.StatusOK || winner.State != usercalls.Accepted || winner.LegState != usercalls.LegAccepted || winner.MediaToken == "" {
		t.Fatalf("winner status=%d view=%+v", accept.Code, winner)
	}
	loserResponse := performUserRequest(t, fixture.server, http.MethodGet, "/v3/calls/"+callID, fixture.targetIOS.AccessToken, nil)
	loser := decodeUserCallView(t, loserResponse)
	if loser.LegState != usercalls.LegAnsweredElsewhere || loser.MediaToken != "" {
		t.Fatalf("loser=%+v", loser)
	}
	callerResponse := performUserRequest(t, fixture.server, http.MethodGet, "/v3/calls/"+callID, fixture.caller.AccessToken, nil)
	caller := decodeUserCallView(t, callerResponse)
	if caller.MediaToken == "" || caller.MediaToken == winner.MediaToken {
		t.Fatalf("caller/winner tokens caller=%q winner=%q", caller.MediaToken, winner.MediaToken)
	}
	unrelated := performUserRequest(t, fixture.server, http.MethodGet, "/v3/calls/"+callID, fixture.unrelated.AccessToken, nil)
	if unrelated.Code != http.StatusNotFound || !strings.Contains(unrelated.Body.String(), "call_not_participant") {
		t.Fatalf("unrelated status=%d body=%q", unrelated.Code, unrelated.Body.String())
	}
}

func TestV3SelfCallAndPrivateResolverInputsRejected(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	self := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", fixture.caller.User.UserID))
	if self.Code != http.StatusConflict || !strings.Contains(self.Body.String(), "self_call_not_allowed") {
		t.Fatalf("self status=%d body=%q", self.Code, self.Body.String())
	}
	for _, input := range []string{"private@example.invalid", strings.Repeat("a", 64)} {
		response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/recipients/resolve", fixture.caller.AccessToken, map[string]string{"recipient": input})
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_recipient") {
			t.Fatalf("private resolver input=%q status=%d body=%q", input, response.Code, response.Body.String())
		}
	}
}

func TestV3PartialAPNSFailurePreservesOtherTargetAndAllFailureTerminates(t *testing.T) {
	fixture := newUserCallFixture(t, map[string]apns.Result{strings.Repeat("a", 64): {Status: 410, Reason: "Unregistered", DeadToken: true}})
	callID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	create := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "12121212-1212-4212-8212-121212121212", callID, fixture.targetUserID))
	if create.Code != http.StatusOK {
		t.Fatalf("create=%d %q", create.Code, create.Body.String())
	}
	waitForPushes(t, fixture.push, 2)
	view := waitForUserCallView(t, fixture.server, fixture.caller.AccessToken, callID, func(value usercalls.View) bool {
		return value.State == usercalls.Ringing && value.DeliveryStatus == "submission_accepted"
	})
	waitForAccountPushTokenCleared(t, fixture.auth, fixture.targetIOS.Account.AccountID, fixture.targetIOS.DeviceID, "voip")
	if view.State != usercalls.Ringing || view.DeliveryStatus != "submission_accepted" {
		t.Fatalf("partial failure killed call: %+v", view)
	}

	all := newUserCallFixture(t, map[string]apns.Result{
		strings.Repeat("a", 64): {Status: 400, Reason: "BadDeviceToken", DeadToken: true},
		strings.Repeat("b", 64): {Status: 400, Reason: "DeviceTokenNotForTopic", DeadToken: true},
	})
	allCallID := "13131313-1313-4313-8313-131313131313"
	created := performUserRequest(t, all.server, http.MethodPost, "/v3/calls", all.caller.AccessToken, fixtureCreateBody(t, all, "14141414-1414-4414-8414-141414141414", allCallID, all.targetUserID))
	if created.Code != http.StatusOK {
		t.Fatalf("all create=%d %q", created.Code, created.Body.String())
	}
	waitForPushes(t, all.push, 2)
	terminalView := waitForUserCallView(t, all.server, all.caller.AccessToken, allCallID, func(value usercalls.View) bool {
		return value.State == usercalls.Expired && value.TerminalReason == "delivery_failed"
	})
	waitForAccountPushTokenCleared(t, all.auth, all.targetIOS.Account.AccountID, all.targetIOS.DeviceID, "voip")
	waitForAccountPushTokenCleared(t, all.auth, all.targetWatch.Account.AccountID, all.targetWatch.DeviceID, "alert")
	if terminalView.State != usercalls.Expired || terminalView.TerminalReason != "delivery_failed" {
		t.Fatalf("all failure=%+v", terminalView)
	}
}

func TestUserCallRouteSelectionDeduplicatesPhysicalDeviceAndPreservesPreferences(t *testing.T) {
	now := time.Now().UTC()
	ready := accounts.Device{DeviceID: "15151515-1515-4515-8515-151515151515", Environment: "production", InstallationGeneration: 1, LastSeenAt: now, Capabilities: accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}, AlertToken: strings.Repeat("a", 64), VoIPToken: strings.Repeat("b", 64)}
	ready.AccountID, ready.Platform = "16161616-1616-4616-8616-161616161616", "iOS"
	older := ready
	older.AccountID, older.LastSeenAt = "17171717-1717-4717-8717-171717171717", now.Add(-time.Minute)
	watch := ready
	watch.DeviceID, watch.AccountID, watch.Platform = "18181818-1818-4818-8818-181818181818", "19191919-1919-4919-8919-191919191919", "watchOS"
	routes := eligibleUserCallRoutes([]accounts.Device{older, watch, ready})
	if len(routes) != 2 {
		t.Fatalf("routes=%+v", routes)
	}
	if routes[0].target.AccountID != ready.AccountID || routes[0].pushType != "voip" || routes[1].pushType != "alert" {
		t.Fatalf("routes=%+v", routes)
	}
}
