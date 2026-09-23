package accountmedia

import (
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
)

const (
	mediaCall    = "11111111-2222-4333-8444-555555555555"
	mediaAccount = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	mediaCaller  = "11111111-1111-4111-8111-111111111111"
	mediaCallee  = "22222222-2222-4222-8222-222222222222"
)

func acceptedStore(t *testing.T) (*accountcalls.Store, string, string) {
	t.Helper()
	store := accountcalls.New(30 * time.Second)
	if _, _, err := store.Create(mediaCall, "33333333-3333-4333-8333-333333333333", mediaAccount, mediaCaller, mediaCallee); err != nil {
		t.Fatal(err)
	}
	callee, _, err := store.Mutate(mediaCall, "44444444-4444-4444-8444-444444444444", mediaAccount, mediaCallee, accountcalls.Accepted)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := store.Get(mediaCall, mediaAccount, mediaCaller)
	if err != nil {
		t.Fatal(err)
	}
	return store, caller.MediaToken, callee.MediaToken
}

func dialPeer(t *testing.T, base, side, token string) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	url := "ws" + strings.TrimPrefix(base, "http") + "?callID=" + mediaCall + "&side=" + side + "&protocolVersion=2"
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	return websocket.DefaultDialer.Dial(url, header)
}

func TestCallerAndCalleeTokensAreSideBound(t *testing.T) {
	store, callerToken, calleeToken := acceptedStore(t)
	server := httptest.NewServer(New(store))
	defer server.Close()

	if conn, response, err := dialPeer(t, server.URL, "callee", callerToken); err == nil {
		conn.Close()
		t.Fatal("caller token connected as callee")
	} else if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-side response=%v err=%v", response, err)
	}
	if conn, response, err := dialPeer(t, server.URL, "caller", calleeToken); err == nil {
		conn.Close()
		t.Fatal("callee token connected as caller")
	} else if response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-side response=%v err=%v", response, err)
	}
}

func TestBothSidesPeerReadyAndBidirectionalRelay(t *testing.T) {
	store, callerToken, calleeToken := acceptedStore(t)
	hub := New(store)
	server := httptest.NewServer(hub)
	defer server.Close()

	caller, _, err := dialPeer(t, server.URL, "caller", callerToken)
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	callee, _, err := dialPeer(t, server.URL, "callee", calleeToken)
	if err != nil {
		t.Fatal(err)
	}
	defer callee.Close()
	_ = caller.SetReadDeadline(time.Now().Add(time.Second))
	_ = callee.SetReadDeadline(time.Now().Add(time.Second))
	for name, conn := range map[string]*websocket.Conn{"caller": caller, "callee": callee} {
		kind, packet, err := conn.ReadMessage()
		if err != nil || kind != websocket.BinaryMessage || len(packet) != controlPacketSize || packet[1] != 3 {
			t.Fatalf("%s peer ready kind=%d len=%d err=%v", name, kind, len(packet), err)
		}
	}

	callerPacket := audioPacket(t, 1, 0x11)
	if err := caller.WriteMessage(websocket.BinaryMessage, callerPacket); err != nil {
		t.Fatal(err)
	}
	_, relayed, err := callee.ReadMessage()
	if err != nil || string(relayed) != string(callerPacket) {
		t.Fatalf("caller->callee relay len=%d err=%v", len(relayed), err)
	}
	calleePacket := audioPacket(t, 1, 0x22)
	if err := callee.WriteMessage(websocket.BinaryMessage, calleePacket); err != nil {
		t.Fatal(err)
	}
	_, relayed, err = caller.ReadMessage()
	if err != nil || string(relayed) != string(calleePacket) {
		t.Fatalf("callee->caller relay len=%d err=%v", len(relayed), err)
	}

	hub.CloseCall(mediaCall, "ended")
	if store.IsAccepted(mediaCall) != true {
		t.Fatal("hub close mutated call store")
	}
}

func audioPacket(t *testing.T, sequence uint64, fill byte) []byte {
	t.Helper()
	packet := make([]byte, audioPacketSize)
	packet[0], packet[1] = 1, 1
	raw, err := hex.DecodeString(strings.ReplaceAll(mediaCall, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	copy(packet[2:18], raw)
	binary.BigEndian.PutUint64(packet[18:26], sequence)
	for index := 34; index < len(packet); index++ {
		packet[index] = fill
	}
	return packet
}
