package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
	appserver "github.com/kvuua-maker/wifi-secure-call-server/internal/server"
)

const tokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const tokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const callID = "11111111-2222-4333-8444-555555555555"

type pushStub struct{ configured bool }

type v2SMSSender struct {
	calls int
	code  string
}

func (s *v2SMSSender) Send(_ context.Context, _ string, message string) (string, error) {
	s.calls++
	for _, field := range strings.Fields(message) {
		candidate := strings.TrimSuffix(field, ".")
		if len(candidate) == 6 && candidate[0] >= '0' && candidate[0] <= '9' {
			s.code = candidate
			break
		}
	}
	return "provider-id", nil
}

func (p pushStub) IncomingCall(context.Context, string, string, string, string, time.Time) (apns.Result, error) {
	return apns.Result{Status: http.StatusOK, Reason: "Success"}, nil
}
func (p pushStub) Configured() bool { return p.configured }

type pushAttempt struct {
	role, token, callID, pushType string
}

type pushRecorder struct {
	attempts chan pushAttempt
}

type accountPushAttempt struct {
	platform, token, callID, pushType, accountID string
}

type accountPushRecorder struct {
	attempts chan accountPushAttempt
	mu       sync.Mutex
	result   apns.Result
	err      error
}

func (p *accountPushRecorder) IncomingCall(context.Context, string, string, string, string, time.Time) (apns.Result, error) {
	return apns.Result{Status: http.StatusOK, Reason: "Success"}, nil
}
func (p *accountPushRecorder) IncomingAccountCall(_ context.Context, platform, token, callID, pushType string, _ time.Time, accountID string) (apns.Result, error) {
	p.mu.Lock()
	if p.result.Status == 0 {
		p.result = apns.Result{Status: http.StatusOK, Reason: "Success"}
	}
	result, err := p.result, p.err
	p.mu.Unlock()
	// Sent outside the lock: the channel is buffered, and holding a lock while
	// blocking on it would deadlock a test that drains slowly.
	p.attempts <- accountPushAttempt{platform: platform, token: token, callID: callID, pushType: pushType, accountID: accountID}
	return result, err
}
func (p *accountPushRecorder) Configured() bool { return true }

type pushFailure struct{}

func (pushFailure) IncomingCall(context.Context, string, string, string, string, time.Time) (apns.Result, error) {
	return apns.Result{Status: 410, Reason: "Unregistered", DeadToken: true}, errors.New("APNs rejected token")
}
func (pushFailure) Configured() bool { return true }

func (p *pushRecorder) IncomingCall(_ context.Context, role, token, callID, pushType string, _ time.Time) (apns.Result, error) {
	p.attempts <- pushAttempt{role: role, token: token, callID: callID, pushType: pushType}
	return apns.Result{Status: http.StatusOK, Reason: "Success"}, nil
}
func (p *pushRecorder) Configured() bool { return true }

func fixture(t *testing.T) (*httptest.Server, *calls.Store, string) {
	t.Helper()
	dir := t.TempDir()
	devicesStore, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	callStore := calls.New(30*time.Second, 10*time.Second)
	srv := appserver.New(tokenA, tokenB, callStore, devicesStore, pushStub{})
	return httptest.NewServer(srv.Handler()), callStore, dir
}
func request(t *testing.T, server, method, path, token string, body any) *http.Response {
	t.Helper()
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest(method, server+path, bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func createBody() map[string]string {
	return map[string]string{"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "callID": callID}
}
func mutationBody(id string) map[string]string { return map[string]string{"requestID": id} }

func TestHealth(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	resp := request(t, srv.URL, "GET", "/v1/health", "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	var value map[string]any
	json.NewDecoder(resp.Body).Decode(&value)
	if value["ok"] != true || value["apnsConfigured"] != false {
		t.Fatal(value)
	}
}

func TestSMSDisabledKeepsExistingV2SessionsAndRoutesAvailable(t *testing.T) {
	dir := t.TempDir()
	accountStore, err := accounts.Open(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	sender := &v2SMSSender{}
	const pepper = "0123456789abcdef0123456789abcdef"
	enabled, err := phoneauth.New(accountStore, sender, pepper, 100)
	if err != nil {
		t.Fatal(err)
	}
	start, err := enabled.Start(context.Background(), "10000000-0000-4000-8000-000000000001", "+380501234567", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	account, err := enabled.Verify("10000000-0000-4000-8000-000000000002", start.VerificationID, sender.code, "10000000-0000-4000-8000-000000000003", "iOS")
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := phoneauth.New(accountStore, nil, pepper, 100)
	if err != nil {
		t.Fatal(err)
	}
	deviceStore, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(appserver.NewWithV2(tokenA, tokenB, calls.New(30*time.Second, 0), deviceStore, pushStub{}, disabled).Handler())
	defer srv.Close()

	startResponse := request(t, srv.URL, http.MethodPost, "/v2/auth/phone/start", "", map[string]string{"requestID": "10000000-0000-4000-8000-000000000004", "phoneNumber": "+14155550123"})
	if startResponse.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("phone start status=%d", startResponse.StatusCode)
	}
	startResponse.Body.Close()
	if sender.calls != 1 {
		t.Fatalf("unexpected SMS calls=%d", sender.calls)
	}

	refreshResponse := request(t, srv.URL, http.MethodPost, "/v2/auth/refresh", "", map[string]string{"refreshToken": account.RefreshToken, "deviceID": account.DeviceID})
	if refreshResponse.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d", refreshResponse.StatusCode)
	}
	var refreshed struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(refreshResponse.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	refreshResponse.Body.Close()

	meResponse := request(t, srv.URL, http.MethodGet, "/v2/me", refreshed.AccessToken, nil)
	if meResponse.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d", meResponse.StatusCode)
	}
	var me map[string]string
	if err := json.NewDecoder(meResponse.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	meResponse.Body.Close()
	if me["accountID"] != account.Account.AccountID || me["deviceID"] != account.DeviceID {
		t.Fatalf("me=%v", me)
	}
	registration := map[string]any{
		"requestID": "10000000-0000-4000-8000-000000000008", "deviceID": account.DeviceID, "platform": "iOS",
		"pushType": "alert", "token": "aabbccdd", "installationGeneration": 1, "environment": "production",
		"capabilities": map[string]bool{"voipPush": true, "alertPush": true, "notificationsAuthorized": true, "microphoneReady": true},
	}
	registrationResponse := request(t, srv.URL, http.MethodPost, "/v2/devices/register", refreshed.AccessToken, registration)
	if registrationResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("device registration status=%d", registrationResponse.StatusCode)
	}
	registrationResponse.Body.Close()
	devicesForAccount := disabled.DevicesForAccount(account.Account.AccountID)
	if len(devicesForAccount) != 1 || devicesForAccount[0].AlertToken != "aabbccdd" {
		t.Fatalf("account device not registered: %+v", devicesForAccount)
	}
	registration["deviceID"] = "99999999-0000-4000-8000-000000000009"
	foreignResponse := request(t, srv.URL, http.MethodPost, "/v2/devices/register", refreshed.AccessToken, registration)
	if foreignResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign device status=%d", foreignResponse.StatusCode)
	}
	foreignResponse.Body.Close()
	registration["deviceID"] = account.DeviceID
	registration["platform"] = "watchOS"
	platformResponse := request(t, srv.URL, http.MethodPost, "/v2/devices/register", refreshed.AccessToken, registration)
	if platformResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("platform mismatch status=%d", platformResponse.StatusCode)
	}
	platformResponse.Body.Close()

	watchStart := request(t, srv.URL, http.MethodPost, "/v2/watch-link/start", "", map[string]string{"requestID": "10000000-0000-4000-8000-000000000005", "deviceID": "10000000-0000-4000-8000-000000000006", "platform": "watchOS"})
	if watchStart.StatusCode != http.StatusOK {
		t.Fatalf("watch start status=%d", watchStart.StatusCode)
	}
	var link map[string]any
	if err := json.NewDecoder(watchStart.Body).Decode(&link); err != nil {
		t.Fatal(err)
	}
	watchStart.Body.Close()
	claim := request(t, srv.URL, http.MethodPost, "/v2/watch-link/claim", refreshed.AccessToken, map[string]string{"requestID": "10000000-0000-4000-8000-000000000007", "code": link["code"].(string)})
	if claim.StatusCode != http.StatusNoContent {
		t.Fatalf("watch claim status=%d", claim.StatusCode)
	}
	claim.Body.Close()
}

type accountCallFixture struct {
	server                       *httptest.Server
	auth                         *phoneauth.Service
	accountID, iPhoneID, watchID string
	iPhoneToken, watchToken      string
	store                        *accountcalls.Store
	push                         *accountPushRecorder
}

func newAccountCallFixture(t *testing.T) accountCallFixture {
	t.Helper()
	dir := t.TempDir()
	accountStore, err := accounts.Open(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	sender := &v2SMSSender{}
	auth, err := phoneauth.New(accountStore, sender, "0123456789abcdef0123456789abcdef", 100)
	if err != nil {
		t.Fatal(err)
	}
	started, err := auth.Start(context.Background(), "21000000-0000-4000-8000-000000000001", "+380501234567", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	phone, err := auth.Verify("21000000-0000-4000-8000-000000000002", started.VerificationID, sender.code, "21000000-0000-4000-8000-000000000003", "iOS")
	if err != nil {
		t.Fatal(err)
	}
	phoneIdentity, err := auth.Authenticate(phone.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	link, err := auth.WatchStart("21000000-0000-4000-8000-000000000004", "21000000-0000-4000-8000-000000000005", "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.WatchClaim(phoneIdentity, "21000000-0000-4000-8000-000000000006", link.Code); err != nil {
		t.Fatal(err)
	}
	watch, err := auth.WatchStatus(link.LinkID, link.LinkSecret)
	if err != nil {
		t.Fatal(err)
	}
	watchIdentity, err := auth.Authenticate(watch.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	for _, registration := range []struct {
		identity    phoneauth.Identity
		kind, token string
	}{
		{phoneIdentity, "alert", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{phoneIdentity, "voip", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		{watchIdentity, "alert", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		{watchIdentity, "voip", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
	} {
		if err := auth.RegisterDevice(registration.identity, phoneauth.DeviceRegistration{RequestID: "22000000-0000-4000-8000-000000000001", DeviceID: registration.identity.DeviceID, Platform: registration.identity.Platform, PushType: registration.kind, Token: registration.token, InstallationGeneration: 1, Environment: "production", Capabilities: capabilities}); err != nil {
			t.Fatal(err)
		}
	}
	legacyDevices, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	push := &accountPushRecorder{attempts: make(chan accountPushAttempt, 4)}
	store := accountcalls.New(30 * time.Second)
	app := appserver.NewWithV2Calls(tokenA, tokenB, calls.New(30*time.Second, 0), legacyDevices, push, auth, store)
	return accountCallFixture{server: httptest.NewServer(app.Handler()), auth: auth, accountID: phone.Account.AccountID, iPhoneID: phone.DeviceID, watchID: watchIdentity.DeviceID, iPhoneToken: phone.AccessToken, watchToken: watch.AccessToken, store: store, push: push}
}

func TestV2DevicesAreAccountScopedSanitizedAndCallReady(t *testing.T) {
	fixture := newAccountCallFixture(t)
	defer fixture.server.Close()
	response := request(t, fixture.server.URL, http.MethodGet, "/v2/devices", fixture.iPhoneToken, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var raw []map[string]any
	if err := json.NewDecoder(response.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if len(raw) != 2 {
		t.Fatalf("devices=%#v", raw)
	}
	seen := map[string]bool{}
	for _, device := range raw {
		id, _ := device["deviceID"].(string)
		seen[id] = true
		if device["callReady"] != true {
			t.Fatalf("not ready: %#v", device)
		}
		for _, secret := range []string{"alertToken", "voipToken", "capabilities", "accessToken", "refreshToken"} {
			if _, exists := device[secret]; exists {
				t.Fatalf("device response exposed %s", secret)
			}
		}
	}
	if !seen[fixture.iPhoneID] || !seen[fixture.watchID] {
		t.Fatalf("wrong devices=%#v", raw)
	}
}

func TestV2SameAccountCallPermissionsMediaTokensAndWatchPush(t *testing.T) {
	fixture := newAccountCallFixture(t)
	defer fixture.server.Close()
	call := "23000000-0000-4000-8000-000000000001"
	create := map[string]string{"requestID": "23000000-0000-4000-8000-000000000002", "callID": call, "targetDeviceID": fixture.watchID}
	response := request(t, fixture.server.URL, http.MethodPost, "/v2/calls", fixture.iPhoneToken, create)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d", response.StatusCode)
	}
	var caller accountcalls.View
	if err := json.NewDecoder(response.Body).Decode(&caller); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if caller.LocalSide != accountcalls.SideCaller || caller.State != accountcalls.Ringing || !caller.CreatedNew || caller.MediaToken != "" {
		t.Fatalf("caller create=%+v", caller)
	}
	select {
	case attempt := <-fixture.push.attempts:
		if attempt.platform != "watchOS" || attempt.pushType != "alert" || attempt.accountID != fixture.accountID || attempt.callID != call {
			t.Fatalf("push=%+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("account push not attempted")
	}

	accept := request(t, fixture.server.URL, http.MethodPost, "/v2/calls/"+call+"/accept", fixture.watchToken, mutationBody("23000000-0000-4000-8000-000000000003"))
	if accept.StatusCode != http.StatusOK {
		t.Fatalf("accept status=%d", accept.StatusCode)
	}
	var callee accountcalls.View
	if err := json.NewDecoder(accept.Body).Decode(&callee); err != nil {
		t.Fatal(err)
	}
	accept.Body.Close()
	callerResponse := request(t, fixture.server.URL, http.MethodGet, "/v2/calls/"+call, fixture.iPhoneToken, nil)
	if err := json.NewDecoder(callerResponse.Body).Decode(&caller); err != nil {
		t.Fatal(err)
	}
	callerResponse.Body.Close()
	if caller.LocalSide != accountcalls.SideCaller || callee.LocalSide != accountcalls.SideCallee || caller.MediaToken == "" || callee.MediaToken == "" || caller.MediaToken == callee.MediaToken {
		t.Fatalf("caller=%+v callee=%+v", caller, callee)
	}
	if !fixture.store.ValidateMedia(call, "caller", caller.MediaToken) || fixture.store.ValidateMedia(call, "callee", caller.MediaToken) {
		t.Fatal("media token side isolation failed")
	}

	callerAccept := request(t, fixture.server.URL, http.MethodPost, "/v2/calls/"+call+"/accept", fixture.iPhoneToken, mutationBody("23000000-0000-4000-8000-000000000004"))
	if callerAccept.StatusCode == http.StatusOK {
		t.Fatal("caller accepted")
	}
	callerAccept.Body.Close()
	end := request(t, fixture.server.URL, http.MethodPost, "/v2/calls/"+call+"/end", fixture.iPhoneToken, mutationBody("23000000-0000-4000-8000-000000000005"))
	if end.StatusCode != http.StatusOK {
		t.Fatalf("end status=%d", end.StatusCode)
	}
	end.Body.Close()
}

func TestV2IPhonePushPreferenceAndDeadTokenInvalidationAreAccountScoped(t *testing.T) {
	fixture := newAccountCallFixture(t)
	defer fixture.server.Close()
	call := "25000000-0000-4000-8000-000000000001"
	body := map[string]string{"requestID": "25000000-0000-4000-8000-000000000002", "callID": call, "targetDeviceID": fixture.iPhoneID}
	response := request(t, fixture.server.URL, http.MethodPost, "/v2/calls", fixture.watchToken, body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d", response.StatusCode)
	}
	select {
	case attempt := <-fixture.push.attempts:
		if attempt.platform != "iOS" || attempt.pushType != "voip" || attempt.token != strings.Repeat("b", 64) {
			t.Fatalf("iPhone push=%+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("iPhone push not attempted")
	}

	dead := newAccountCallFixture(t)
	defer dead.server.Close()
	dead.push.result = apns.Result{Status: http.StatusGone, Reason: "Unregistered", DeadToken: true}
	dead.push.err = errors.New("dead token")
	deadCall := "25000000-0000-4000-8000-000000000003"
	response = request(t, dead.server.URL, http.MethodPost, "/v2/calls", dead.iPhoneToken, map[string]string{"requestID": "25000000-0000-4000-8000-000000000004", "callID": deadCall, "targetDeviceID": dead.watchID})
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("dead-token create status=%d", response.StatusCode)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		device, ok := dead.auth.DeviceForAccount(dead.accountID, dead.watchID)
		if ok && device.AlertToken == "" {
			if device.VoIPToken == "" {
				t.Fatal("dead alert invalidated Watch VoIP token")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("dead account token was not invalidated")
}

func TestV2CallTargetMustBelongToAuthenticatedAccountAndNoSelfCall(t *testing.T) {
	fixture := newAccountCallFixture(t)
	defer fixture.server.Close()
	for name, target := range map[string]string{"self": fixture.iPhoneID, "foreign": "24000000-0000-4000-8000-000000000009"} {
		t.Run(name, func(t *testing.T) {
			body := map[string]string{"requestID": "24000000-0000-4000-8000-000000000001", "callID": "24000000-0000-4000-8000-000000000002", "targetDeviceID": target}
			response := request(t, fixture.server.URL, http.MethodPost, "/v2/calls", fixture.iPhoneToken, body)
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("status=%d", response.StatusCode)
			}
		})
	}
}

func TestMediaRouterRejectsAmbiguousOrMissingPeerShape(t *testing.T) {
	fixture := newAccountCallFixture(t)
	defer fixture.server.Close()
	for _, path := range []string{"/media?callID=" + callID, "/media?callID=" + callID + "&role=A&side=caller"} {
		response := request(t, fixture.server.URL, http.MethodGet, path, tokenA, nil)
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s status=%d", path, response.StatusCode)
		}
	}
}

func TestDeploymentPreservesProductionConfigAndExplicitlyRestarts(t *testing.T) {
	script, err := os.ReadFile("../deploy/install-vps.sh")
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	for _, forbidden := range []string{"APNS_ENABLED=false", "APNS_KEY_ID=\\n", "server.env.new", "enable --now"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("deployment contains forbidden production-config behavior: %q", forbidden)
		}
	}
	for _, required := range []string{"systemctl restart wifi-secure-call.service", "production server.env is missing", "WSC_EXPECTED_BUILD", "running process does not match the staged binary"} {
		if !strings.Contains(text, required) {
			t.Fatalf("deployment safety check missing: %q", required)
		}
	}
}
func TestDeviceRegistrationAndAuth(t *testing.T) {
	srv, _, dir := fixture(t)
	defer srv.Close()
	body := map[string]any{"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "A", "token": tokenA, "platform": "watchOS", "pushType": "alert", "installationID": callID, "installationGeneration": 1, "environment": "production", "capabilities": map[string]bool{"alertPush": true, "voipPush": false, "notificationsAuthorized": true, "microphoneReady": true}}
	resp := request(t, srv.URL, "POST", "/v1/devices/register", tokenA, body)
	if resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
	data, err := os.ReadFile(filepath.Join(dir, "devices.json"))
	if err != nil || !bytes.Contains(data, []byte(tokenA)) {
		t.Fatal("registration not persisted")
	}
	bad := request(t, srv.URL, "POST", "/v1/devices/register", "wrong", body)
	if bad.StatusCode != 401 {
		t.Fatal(bad.StatusCode)
	}
	bad.Body.Close()
}

func TestLegacyTokenMigratesToAlertToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	legacy := `{"A":{"role":"A","token":"` + tokenA + `","platform":"watchOS","updatedAt":"2026-09-21T01:02:03Z"}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := devices.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := store.Get("A")
	if !ok || value.TokenFor("alert", "production") != tokenA || value.TokenFor("voip", "production") != "" {
		t.Fatalf("legacy migration failed: %+v", value)
	}
	persisted, _ := os.ReadFile(path)
	if bytes.Contains(persisted, []byte(`"token":"`+tokenA+`"`)) || !bytes.Contains(persisted, []byte(`"alertToken":"`+tokenA+`"`)) {
		t.Fatal("legacy token was not persisted as alert token")
	}
}

func TestAlertAndVoIPTokensCoexistWithoutCrossRoleOverwrite(t *testing.T) {
	store, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	aAlert, aVoIP, bVoIP := strings.Repeat("a", 64), strings.Repeat("c", 64), strings.Repeat("b", 64)
	caps := devices.Capabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	if err := store.Register("A", "watchOS", "alert", aAlert, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("A", "watchOS", "voip", aVoIP, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("B", "iOS", "voip", bVoIP, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	a, _ := store.Get("A")
	b, _ := store.Get("B")
	if a.TokenFor("alert", "production") != aAlert || a.TokenFor("voip", "production") != aVoIP {
		t.Fatalf("A tokens overwritten: %+v", a)
	}
	if b.TokenFor("voip", "production") != bVoIP || b.TokenFor("alert", "production") != "" {
		t.Fatalf("role isolation failed: %+v", b)
	}
}

func TestIPhoneIncomingPrefersVoIPToken(t *testing.T) {
	dir := t.TempDir()
	deviceStore, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	bAlert, bVoIP := strings.Repeat("d", 64), strings.Repeat("b", 64)
	caps := devices.Capabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	if err := deviceStore.Register("B", "iOS", "alert", bAlert, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Register("B", "iOS", "voip", bVoIP, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	recorder := &pushRecorder{attempts: make(chan pushAttempt, 1)}
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, calls.New(30*time.Second, 10*time.Second), deviceStore, recorder).Handler())
	defer srv.Close()
	resp := request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody())
	resp.Body.Close()
	select {
	case attempt := <-recorder.attempts:
		if attempt.role != "B" || attempt.token != bVoIP || attempt.pushType != "voip" || attempt.callID != callID {
			t.Fatalf("unexpected push attempt: %+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("push not attempted")
	}
	select {
	case attempt := <-recorder.attempts:
		t.Fatalf("unexpected duplicate push attempt: %+v", attempt)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchIncomingPrefersAlertToken(t *testing.T) {
	deviceStore, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	aAlert, aVoIP := strings.Repeat("a", 64), strings.Repeat("c", 64)
	caps := devices.Capabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	if err := deviceStore.Register("A", "watchOS", "alert", aAlert, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Register("A", "watchOS", "voip", aVoIP, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	recorder := &pushRecorder{attempts: make(chan pushAttempt, 2)}
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, calls.New(30*time.Second, 10*time.Second), deviceStore, recorder).Handler())
	defer srv.Close()
	resp := request(t, srv.URL, "POST", "/v1/calls", tokenB, createBody())
	resp.Body.Close()
	select {
	case attempt := <-recorder.attempts:
		if attempt.role != "A" || attempt.token != aAlert || attempt.pushType != "alert" || attempt.callID != callID {
			t.Fatalf("unexpected push attempt: %+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("push not attempted")
	}
	select {
	case attempt := <-recorder.attempts:
		t.Fatalf("unexpected duplicate push attempt: %+v", attempt)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchIncomingFallsBackToVoIPWhenAlertMissing(t *testing.T) {
	deviceStore, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	aVoIP := strings.Repeat("c", 64)
	caps := devices.Capabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	if err := deviceStore.Register("A", "watchOS", "voip", aVoIP, callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	recorder := &pushRecorder{attempts: make(chan pushAttempt, 2)}
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, calls.New(30*time.Second, 10*time.Second), deviceStore, recorder).Handler())
	defer srv.Close()
	resp := request(t, srv.URL, "POST", "/v1/calls", tokenB, createBody())
	resp.Body.Close()
	select {
	case attempt := <-recorder.attempts:
		if attempt.role != "A" || attempt.token != aVoIP || attempt.pushType != "voip" || attempt.callID != callID {
			t.Fatalf("unexpected push attempt: %+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("push not attempted")
	}
	select {
	case attempt := <-recorder.attempts:
		t.Fatalf("unexpected duplicate push attempt: %+v", attempt)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestWatchLiveReadyUsesAlertPath(t *testing.T) {
	base := devices.Registration{
		Role:       "A",
		Platform:   "watchOS",
		AlertToken: strings.Repeat("a", 64),
		VoIPToken:  strings.Repeat("c", 64),
		Capabilities: devices.Capabilities{
			AlertPush:               true,
			VoIPPush:                true,
			NotificationsAuthorized: true,
			MicrophoneReady:         true,
		},
	}
	if !base.LiveReady() {
		t.Fatal("complete Watch alert path is not ready")
	}
	missingToken := base
	missingToken.AlertToken = ""
	if missingToken.LiveReady() {
		t.Fatal("Watch without alert token reported ready")
	}
	unauthorized := base
	unauthorized.Capabilities.NotificationsAuthorized = false
	if unauthorized.LiveReady() {
		t.Fatal("Watch without notification authorization reported ready")
	}
}

func TestIOSLiveReadyStillUsesVoIPPath(t *testing.T) {
	base := devices.Registration{
		Role:       "B",
		Platform:   "iOS",
		AlertToken: strings.Repeat("d", 64),
		VoIPToken:  strings.Repeat("b", 64),
		Capabilities: devices.Capabilities{
			AlertPush:               true,
			VoIPPush:                true,
			NotificationsAuthorized: false,
			MicrophoneReady:         true,
		},
	}
	if !base.LiveReady() {
		t.Fatal("complete iOS VoIP path is not ready")
	}
	missingToken := base
	missingToken.VoIPToken = ""
	if missingToken.LiveReady() {
		t.Fatal("iOS without VoIP token reported ready")
	}
	missingCapability := base
	missingCapability.Capabilities.VoIPPush = false
	if missingCapability.LiveReady() {
		t.Fatal("iOS without VoIP capability reported ready")
	}
}
func TestNotificationDiagnosticsAuthAndValidation(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	body := map[string]any{
		"requestID":   "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"role":        "B",
		"platform":    "iOS",
		"event":       "notification_permission",
		"status":      "authorized",
		"tokenPrefix": "",
		"tokenLength": 0,
	}
	resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
	body["role"] = "A"
	bad := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatal(bad.StatusCode)
	}
	bad.Body.Close()
}

func TestWatchBackgroundDiagnosticEventsAreExactAndBounded(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	events := []string{
		"watch_background_notification_received",
		"watch_background_callkit_handoff",
		"duplicate_incoming_suppressed",
		"watch_alert_action_received",
		"watch_notification_capabilities_refreshed",
	}
	for _, event := range events {
		body := map[string]any{
			"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			"role":      "A",
			"platform":  "watchOS",
			"event":     event,
			"status":    "success",
			"callID":    "11111111-2222-4333-8444-555555555555",
		}
		resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenA, body)
		if resp.StatusCode != http.StatusNoContent {
			resp.Body.Close()
			t.Fatalf("event %s status %d", event, resp.StatusCode)
		}
		resp.Body.Close()
	}
	unknown := map[string]any{
		"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"role":      "A",
		"platform":  "watchOS",
		"event":     "watch_background_unknown",
		"status":    "success",
	}
	resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenA, unknown)
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("unknown event status %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestOutgoingEndRaceDiagnosticEventsAreExactAndBounded(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	events := []string{
		"callkit_end_action_received",
		"system_end_reconcile_started",
		"system_end_reconcile_result",
		"system_end_preserved_after_remote_accept",
		"system_end_duplicate_preserved_during_connecting",
	}
	for _, event := range events {
		body := map[string]any{
			"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			"role":      "B",
			"platform":  "iOS",
			"event":     event,
			"status":    "success",
			"callID":    "11111111-2222-4333-8444-555555555555",
		}
		resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
		if resp.StatusCode != http.StatusNoContent {
			resp.Body.Close()
			t.Fatalf("event %s status %d", event, resp.StatusCode)
		}
		resp.Body.Close()
	}
}

func TestCallKitErrorDiagnosticIsAcceptedAndBounded(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	body := map[string]any{
		"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"role":      "B", "platform": "iOS", "event": "callkit_error", "status": "failed",
		"stage": "reportIncoming", "errorDomain": "com.apple.CallKit.error.incomingcall", "errorCode": 4,
	}
	resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
	body["errorDomain"] = strings.Repeat("x", 129)
	bad := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatal(bad.StatusCode)
	}
	bad.Body.Close()
}

func TestRuntimeAudioDiagnosticsAreAcceptedAndBounded(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	base := map[string]any{
		"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"role":      "B", "platform": "iOS", "callID": callID,
	}
	for _, event := range []string{
		"start_call_entered", "microphone_permission", "callkit_start_requested",
		"callkit_start_approved", "server_call_create_started", "server_call_create_succeeded",
		"new_call_blocked", "previous_terminal_reset",
		"audio_session_configured", "callkit_did_activate", "callkit_did_deactivate",
		"audio_engine_start_attempt", "audio_engine_start_success", "voice_processing_enabled",
		"input_format", "output_format", "capture_source_connected", "first_mic_buffer",
		"first_network_audio_frame_generated", "first_network_audio_frame_sent",
		"first_remote_audio_frame_received", "first_playback_buffer_scheduled",
		"media_connect_started", "media_connect_succeeded", "media_disconnected",
		"reconnect_started", "reconnect_succeeded", "reconnect_failed",
	} {
		body := make(map[string]any, len(base)+2)
		for key, value := range base {
			body[key] = value
		}
		body["event"] = event
		body["status"] = "success"
		resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("event %s: %d", event, resp.StatusCode)
		}
		resp.Body.Close()
	}

	for _, event := range []string{"server_call_create_failed", "call_state_poll_failure", "first_capture_conversion_failure", "first_network_audio_frame_send_failure"} {
		failure := make(map[string]any, len(base)+5)
		for key, value := range base {
			failure[key] = value
		}
		failure["event"] = event
		failure["status"] = "failed"
		failure["errorDomain"] = "NSURLErrorDomain"
		failure["errorCode"] = -1009
		resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, failure)
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("event %s: %d", event, resp.StatusCode)
		}
		resp.Body.Close()
	}

	bad := map[string]any{
		"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "B", "platform": "iOS",
		"callID": "not-a-uuid", "event": "audio_engine_start_success", "status": "success",
	}
	resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()

	bad["callID"] = callID
	bad["status"] = strings.Repeat("x", 257)
	resp = request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, bad)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuntimeDiagnosticRejectsSecretAndAudioPayloadFields(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	body := map[string]any{
		"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "B", "platform": "iOS",
		"callID": callID, "event": "first_network_audio_frame_sent", "status": "bytes=640",
		"mediaToken": "must-not-be-accepted", "audioPayload": "must-not-be-accepted",
	}
	resp := request(t, srv.URL, "POST", "/v1/devices/diagnostics", tokenB, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
}
func TestCreateAndIdempotentCreate(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	first := request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody())
	if first.StatusCode != 200 {
		t.Fatal(first.StatusCode)
	}
	first.Body.Close()
	second := request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody())
	if second.StatusCode != 200 {
		t.Fatal(second.StatusCode)
	}
	defer second.Body.Close()
	var view calls.View
	json.NewDecoder(second.Body).Decode(&view)
	if view.CallID != callID || view.State != calls.Ringing {
		t.Fatal(view)
	}
}

func TestDuplicateCreateSubmitsExactlyOnePush(t *testing.T) {
	deviceStore, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	caps := devices.Capabilities{VoIPPush: true, MicrophoneReady: true}
	if err = deviceStore.Register("B", "iOS", "voip", strings.Repeat("b", 64), callID, 1, "production", caps); err != nil {
		t.Fatal(err)
	}
	recorder := &pushRecorder{attempts: make(chan pushAttempt, 2)}
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, calls.New(30*time.Second, 0), deviceStore, recorder).Handler())
	defer srv.Close()
	request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody()).Body.Close()
	request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody()).Body.Close()
	select {
	case <-recorder.attempts:
	case <-time.After(time.Second):
		t.Fatal("push not submitted")
	}
	select {
	case <-recorder.attempts:
		t.Fatal("duplicate create submitted a second push")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAPNsFailureBecomesAuthoritativeTerminalState(t *testing.T) {
	deviceStore, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = deviceStore.Register("B", "iOS", "voip", strings.Repeat("b", 64), callID, 1, "production", devices.Capabilities{VoIPPush: true, MicrophoneReady: true}); err != nil {
		t.Fatal(err)
	}
	store := calls.New(30*time.Second, 0)
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, store, deviceStore, pushFailure{}).Handler())
	defer srv.Close()
	request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody()).Body.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		view, _ := store.Get(callID, "A")
		if view.State == calls.Expired {
			if view.TerminalReason != "delivery_failed:Unregistered" || view.DeliveryStatus != "submission_failed:Unregistered" {
				t.Fatalf("unexpected delivery state: %+v", view)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("APNs failure did not terminate ringing call")
}

func TestMutationIdempotencyRejectsParameterMismatch(t *testing.T) {
	store := calls.New(30*time.Second, 0)
	_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	requestID := "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"
	if _, applied, err := store.Mutate(callID, requestID, "B", calls.Accepted); err != nil || !applied {
		t.Fatalf("accept failed: %v", err)
	}
	if _, _, err := store.Mutate(callID, requestID, "B", calls.Ended); err == nil || !strings.Contains(err.Error(), "idempotency conflict") {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestConditionalTokenInvalidationCannotDeleteNewerToken(t *testing.T) {
	store, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldToken, newToken := strings.Repeat("a", 64), strings.Repeat("b", 64)
	caps := devices.Capabilities{VoIPPush: true, MicrophoneReady: true}
	if err = store.Register("A", "watchOS", "voip", oldToken, callID, 7, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err = store.Register("A", "watchOS", "voip", newToken, callID, 7, "production", caps); err != nil {
		t.Fatal(err)
	}
	if err = store.Invalidate("A", "voip", callID, 7, oldToken); err != nil {
		t.Fatal(err)
	}
	value, _ := store.Get("A")
	if value.TokenFor("voip", "production") != newToken {
		t.Fatal("stale invalidation removed newer token")
	}
	if err = store.Invalidate("A", "voip", callID, 7, newToken); err != nil {
		t.Fatal(err)
	}
	value, _ = store.Get("A")
	if value.TokenFor("voip", "production") != "" {
		t.Fatal("current token was not invalidated")
	}
}

func TestStrictBearerRolePlatformAndJSONLimits(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	raw, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/calls", strings.NewReader(`{}`))
	raw.Header.Set("Authorization", tokenA)
	resp, err := http.DefaultClient.Do(raw)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("raw bearer accepted: %d", resp.StatusCode)
	}
	body := map[string]any{"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "B", "token": strings.Repeat("b", 64), "platform": "watchOS", "pushType": "alert"}
	resp = request(t, srv.URL, "POST", "/v1/devices/register", tokenB, body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("role/platform mismatch accepted: %d", resp.StatusCode)
	}
	trailing, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/calls", strings.NewReader(`{"requestID":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","callID":"`+callID+`"}{}`))
	trailing.Header.Set("Authorization", "Bearer "+tokenA)
	trailing.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(trailing)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing JSON accepted: %d", resp.StatusCode)
	}
	oversized, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/calls", strings.NewReader(strings.Repeat("x", 5000)))
	oversized.Header.Set("Authorization", "Bearer "+tokenA)
	oversized.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(oversized)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status: %d", resp.StatusCode)
	}
}

func TestCorruptedDeviceStateFailsClosedAndEnvironmentDoesNotMix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":2,"devices":{"A":{"role":"A"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := devices.Open(path); err == nil {
		t.Fatal("corrupted state accepted")
	}
	store, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	if err = store.Register("A", "watchOS", "voip", token, callID, 1, "development", devices.Capabilities{}); err != nil {
		t.Fatal(err)
	}
	value, _ := store.Get("A")
	if value.TokenFor("voip", "production") != "" || value.TokenFor("voip", "development") != token {
		t.Fatal("APNs environments mixed")
	}
}
func TestCallViewExpiresAtUsesWholeSecondRFC3339WithoutChangingTimeout(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	base := time.Date(2026, time.September, 21, 2, 15, 0, 123456789, time.UTC)
	now := base
	store.SetClock(func() time.Time { return now })
	view, _, err := store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		ExpiresAt string `json:"expiresAt"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	want := base.Add(30 * time.Second).UTC().Truncate(time.Second)
	parsed, err := time.Parse(time.RFC3339, wire.ExpiresAt)
	if err != nil {
		t.Fatalf("expiresAt is not RFC3339: %q: %v", wire.ExpiresAt, err)
	}
	if strings.Contains(wire.ExpiresAt, ".") {
		t.Fatalf("expiresAt contains fractional seconds: %q", wire.ExpiresAt)
	}
	if !parsed.Equal(want) || !view.ExpiresAt.Equal(want) {
		t.Fatalf("expiresAt = %s, want %s", wire.ExpiresAt, want.Format(time.RFC3339))
	}
	if !view.RingExpiresAt.Equal(base.Add(30 * time.Second)) {
		t.Fatalf("precise ring deadline changed: %s", view.RingExpiresAt)
	}

	now = base.Add(30*time.Second - time.Nanosecond)
	beforeExpiry, _ := store.Get(callID, "A")
	if beforeExpiry.State != calls.Ringing {
		t.Fatalf("call expired before precise internal deadline: %s", beforeExpiry.State)
	}
	now = base.Add(30 * time.Second)
	atExpiry, _ := store.Get(callID, "A")
	if atExpiry.State != calls.Expired {
		t.Fatalf("call did not expire at precise internal deadline: %s", atExpiry.State)
	}
}
func TestAcceptRejectCancelAndExpiration(t *testing.T) {
	for _, tc := range []struct {
		name, action, token string
		want                calls.State
	}{{"accept", "accept", tokenB, calls.Accepted}, {"reject", "reject", tokenB, calls.Rejected}, {"cancel", "cancel", tokenA, calls.Cancelled}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := fixture(t)
			defer srv.Close()
			registration := map[string]any{"requestID": "99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "B", "token": strings.Repeat("b", 64), "platform": "iOS", "pushType": "voip", "installationID": callID, "installationGeneration": 1, "environment": "production", "capabilities": map[string]bool{"voipPush": true, "microphoneReady": true}}
			registered := request(t, srv.URL, "POST", "/v1/devices/register", tokenB, registration)
			registered.Body.Close()
			if registered.StatusCode != http.StatusNoContent {
				t.Fatal(registered.StatusCode)
			}
			request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody()).Body.Close()
			resp := request(t, srv.URL, "POST", "/v1/calls/"+callID+"/"+tc.action, tc.token, mutationBody("bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"))
			defer resp.Body.Close()
			var view calls.View
			json.NewDecoder(resp.Body).Decode(&view)
			if view.State != tc.want {
				t.Fatal(view)
			}
		})
	}
	store := calls.New(time.Second, 10*time.Second)
	now := time.Now()
	store.SetClock(func() time.Time { return now })
	_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	now = now.Add(2 * time.Second)
	view, _ := store.Get(callID, "A")
	if view.State != calls.Expired {
		t.Fatal(view.State)
	}
}
func TestAcceptCancelRaceHasOneWinner(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
	}()
	go func() {
		defer wg.Done()
		_, _, _ = store.Mutate(callID, "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa", "A", calls.Cancelled)
	}()
	wg.Wait()
	view, _ := store.Get(callID, "A")
	if view.State != calls.Accepted && view.State != calls.Cancelled {
		t.Fatal(view.State)
	}
}
func TestInvalidBearerToken(t *testing.T) {
	srv, _, _ := fixture(t)
	defer srv.Close()
	resp := request(t, srv.URL, "POST", "/v1/calls", "invalid", createBody())
	defer resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}
func TestAcceptedMediaTokensRemainValidUntilTerminalState(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	now := time.Date(2026, time.September, 21, 3, 27, 24, 0, time.UTC)
	store.SetClock(func() time.Time { return now })
	_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	_, _, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
	a, _ := store.Get(callID, "A")
	b, _ := store.Get(callID, "B")
	if !store.ValidateMedia(callID, "A", a.MediaToken) {
		t.Fatal("correct A token rejected")
	}
	if !store.ValidateMedia(callID, "B", b.MediaToken) {
		t.Fatal("correct B token rejected")
	}
	if store.ValidateMedia(callID, "B", a.MediaToken) || store.ValidateMedia(callID, "A", b.MediaToken) {
		t.Fatal("role token isolation failed")
	}
	if store.ValidateMedia(callID, "A", "wrong-token") || store.ValidateMedia("bad", "A", a.MediaToken) {
		t.Fatal("wrong token or call ID accepted")
	}

	now = now.Add(41 * time.Second)
	if !store.ValidateMedia(callID, "A", a.MediaToken) || !store.ValidateMedia(callID, "B", b.MediaToken) {
		t.Fatal("accepted call lost media authorization after old expiry plus grace")
	}
	_, _, _ = store.Mutate(callID, "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa", "A", calls.Ended)
	if store.ValidateMedia(callID, "A", a.MediaToken) || store.ValidateMedia(callID, "B", b.MediaToken) {
		t.Fatal("ended call authorized media")
	}
}

func TestNonAcceptedStatesRejectMedia(t *testing.T) {
	for _, target := range []calls.State{calls.Rejected, calls.Cancelled, calls.Expired} {
		t.Run(string(target), func(t *testing.T) {
			store := calls.New(30*time.Second, 10*time.Second)
			now := time.Date(2026, time.September, 21, 3, 27, 24, 0, time.UTC)
			store.SetClock(func() time.Time { return now })
			_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
			switch target {
			case calls.Rejected:
				_, _, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Rejected)
			case calls.Cancelled:
				_, _, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "A", calls.Cancelled)
			case calls.Expired:
				now = now.Add(30 * time.Second)
				view, _ := store.Get(callID, "A")
				if view.State != calls.Expired {
					t.Fatalf("ringing timeout not preserved: %s", view.State)
				}
			}
			if store.ValidateMedia(callID, "A", "any-token") || store.ValidateMedia(callID, "B", "any-token") {
				t.Fatalf("%s call authorized media", target)
			}
		})
	}
}
func TestWebSocketRelayAndNoAudioPersistence(t *testing.T) {
	srv, store, dir := fixture(t)
	defer srv.Close()
	_, _, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	_, _, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
	a, _ := store.Get(callID, "A")
	b, _ := store.Get(callID, "B")
	base := "ws" + strings.TrimPrefix(srv.URL, "http") + "/media?callID=" + callID + "&role="
	dial := func(role, token string) *websocket.Conn {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer "+token)
		conn, resp, err := websocket.DefaultDialer.Dial(base+role, headers)
		if err != nil {
			if resp != nil {
				t.Log(resp.Status)
			}
			t.Fatal(err)
		}
		return conn
	}
	connA := dial("A", a.MediaToken)
	defer connA.Close()
	connB := dial("B", b.MediaToken)
	defer connB.Close()
	raw, _ := hex.DecodeString(strings.ReplaceAll(callID, "-", ""))
	packet := append([]byte{1, 1}, raw...)
	packet = append(packet, make([]byte, 16)...)
	packet = append(packet, make([]byte, 640)...)
	if err := connA.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		t.Fatal(err)
	}
	connB.SetReadDeadline(time.Now().Add(time.Second))
	kind, got, err := connB.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(got, packet) {
		t.Fatal("A to B relay failed")
	}
	if err := connB.WriteMessage(websocket.BinaryMessage, packet); err != nil {
		t.Fatal(err)
	}
	connA.SetReadDeadline(time.Now().Add(time.Second))
	kind, got, err = connA.ReadMessage()
	if err != nil || kind != websocket.BinaryMessage || !bytes.Equal(got, packet) {
		t.Fatal("B to A relay failed")
	}
	invalid := append([]byte(nil), packet...)
	invalid[2] ^= 0xff
	if err := connA.WriteMessage(websocket.BinaryMessage, invalid); err != nil {
		t.Fatal(err)
	}
	connB.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := connB.ReadMessage(); err == nil {
		t.Fatal("invalid packet was relayed")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name()), "audio") {
			t.Fatal("audio persisted")
		}
	}
}
