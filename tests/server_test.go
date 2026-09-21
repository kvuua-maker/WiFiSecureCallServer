package tests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	appserver "github.com/kvuua-maker/wifi-secure-call-server/internal/server"
)

const tokenA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const tokenB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const callID = "11111111-2222-4333-8444-555555555555"

type pushStub struct{ configured bool }

func (p pushStub) IncomingCall(context.Context, string, string, string, string) error { return nil }
func (p pushStub) Configured() bool                                                   { return p.configured }

type pushAttempt struct {
	role, token, callID, pushType string
}

type pushRecorder struct {
	attempts chan pushAttempt
}

func (p *pushRecorder) IncomingCall(_ context.Context, role, token, callID, pushType string) error {
	p.attempts <- pushAttempt{role: role, token: token, callID: callID, pushType: pushType}
	return nil
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
func TestDeviceRegistrationAndAuth(t *testing.T) {
	srv, _, dir := fixture(t)
	defer srv.Close()
	body := map[string]string{"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "A", "token": "abc123", "platform": "watchOS", "pushType": "alert"}
	resp := request(t, srv.URL, "POST", "/v1/devices/register", tokenA, body)
	if resp.StatusCode != 204 {
		t.Fatal(resp.StatusCode)
	}
	resp.Body.Close()
	data, err := os.ReadFile(filepath.Join(dir, "devices.json"))
	if err != nil || !bytes.Contains(data, []byte("abc123")) {
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
	legacy := `{"A":{"role":"A","token":"legacy-alert","platform":"watchOS","updatedAt":"2026-09-21T01:02:03Z"}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := devices.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	value, ok := store.Get("A")
	if !ok || value.TokenFor("alert") != "legacy-alert" || value.TokenFor("voip") != "" {
		t.Fatalf("legacy migration failed: %+v", value)
	}
	persisted, _ := os.ReadFile(path)
	if bytes.Contains(persisted, []byte(`"token":"legacy-alert"`)) || !bytes.Contains(persisted, []byte(`"alertToken":"legacy-alert"`)) {
		t.Fatal("legacy token was not persisted as alert token")
	}
}

func TestAlertAndVoIPTokensCoexistWithoutCrossRoleOverwrite(t *testing.T) {
	store, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register("A", "watchOS", "alert", "a-alert"); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("A", "watchOS", "voip", "a-voip"); err != nil {
		t.Fatal(err)
	}
	if err := store.Register("B", "iOS", "voip", "b-voip"); err != nil {
		t.Fatal(err)
	}
	a, _ := store.Get("A")
	b, _ := store.Get("B")
	if a.TokenFor("alert") != "a-alert" || a.TokenFor("voip") != "a-voip" {
		t.Fatalf("A tokens overwritten: %+v", a)
	}
	if b.TokenFor("voip") != "b-voip" || b.TokenFor("alert") != "" {
		t.Fatalf("role isolation failed: %+v", b)
	}
}

func TestLiveCallPrefersCalleeVoIPToken(t *testing.T) {
	dir := t.TempDir()
	deviceStore, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Register("B", "iOS", "alert", "b-alert"); err != nil {
		t.Fatal(err)
	}
	if err := deviceStore.Register("B", "iOS", "voip", "b-voip"); err != nil {
		t.Fatal(err)
	}
	recorder := &pushRecorder{attempts: make(chan pushAttempt, 1)}
	srv := httptest.NewServer(appserver.New(tokenA, tokenB, calls.New(30*time.Second, 10*time.Second), deviceStore, recorder).Handler())
	defer srv.Close()
	resp := request(t, srv.URL, "POST", "/v1/calls", tokenA, createBody())
	resp.Body.Close()
	select {
	case attempt := <-recorder.attempts:
		if attempt.role != "B" || attempt.token != "b-voip" || attempt.pushType != "voip" || attempt.callID != callID {
			t.Fatalf("unexpected push attempt: %+v", attempt)
		}
	case <-time.After(time.Second):
		t.Fatal("push not attempted")
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
		"audio_session_configured", "callkit_did_activate", "callkit_did_deactivate",
		"audio_engine_start_attempt", "audio_engine_start_success", "voice_processing_enabled",
		"input_format", "output_format", "first_mic_buffer",
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
func TestCallViewExpiresAtUsesWholeSecondRFC3339WithoutChangingTimeout(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	base := time.Date(2026, time.September, 21, 2, 15, 0, 123456789, time.UTC)
	now := base
	store.SetClock(func() time.Time { return now })
	view, err := store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
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
	store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	now = now.Add(2 * time.Second)
	view, _ := store.Get(callID, "A")
	if view.State != calls.Expired {
		t.Fatal(view.State)
	}
}
func TestAcceptCancelRaceHasOneWinner(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
	}()
	go func() {
		defer wg.Done()
		store.Mutate(callID, "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa", "A", calls.Cancelled)
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
	store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	_, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
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
	_, _ = store.Mutate(callID, "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa", "A", calls.Ended)
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
			_, _ = store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
			switch target {
			case calls.Rejected:
				_, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Rejected)
			case calls.Cancelled:
				_, _ = store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "A", calls.Cancelled)
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
	store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
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
