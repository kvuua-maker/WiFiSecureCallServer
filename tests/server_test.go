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

func (p pushStub) IncomingCall(context.Context, string, string, string) error { return nil }
func (p pushStub) Configured() bool                                           { return p.configured }

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
	body := map[string]string{"requestID": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "role": "A", "token": "abc123", "platform": "watchOS"}
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
func TestMediaTokenBindingWrongRoleAndExpiry(t *testing.T) {
	store := calls.New(30*time.Second, 10*time.Second)
	now := time.Now()
	store.SetClock(func() time.Time { return now })
	store.Create(callID, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "A")
	accepted, _ := store.Mutate(callID, "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff", "B", calls.Accepted)
	a, _ := store.Get(callID, "A")
	if !store.ValidateMedia(callID, "A", a.MediaToken) || store.ValidateMedia(callID, "B", a.MediaToken) || store.ValidateMedia("bad", "A", a.MediaToken) {
		t.Fatal("media binding failed")
	}
	if accepted.MediaToken == a.MediaToken {
		t.Fatal("role tokens must differ")
	}
	now = now.Add(41 * time.Second)
	if store.ValidateMedia(callID, "A", a.MediaToken) {
		t.Fatal("expired token accepted")
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
		t.Fatal("relay failed")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Name()), "audio") {
			t.Fatal("audio persisted")
		}
	}
}
