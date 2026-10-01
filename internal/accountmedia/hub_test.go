package accountmedia

import (
	"encoding/binary"
	"encoding/hex"
	"net"
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
	url := "ws" + strings.TrimPrefix(base, "http") + "?callID=" + mediaCall + "&side=" + side + "&protocolVersion=1"
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	return websocket.DefaultDialer.Dial(url, header)
}

func testHTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}

func TestCallerAndCalleeTokensAreSideBound(t *testing.T) {
	store, callerToken, calleeToken := acceptedStore(t)
	server := testHTTPServer(t, New(store))
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
	server := testHTTPServer(t, hub)
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

func encryptedAudioPacket(t *testing.T, side string, sequence uint64, fill byte) []byte {
	t.Helper()
	packet := make([]byte, encryptedAudioPacketSize)
	packet[0], packet[1] = 2, 1
	raw, err := hex.DecodeString(strings.ReplaceAll(mediaCall, "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	copy(packet[2:18], raw)
	if side == "caller" {
		packet[18] = 1
	} else {
		packet[18] = 2
	}
	binary.BigEndian.PutUint32(packet[19:23], 1)
	binary.BigEndian.PutUint64(packet[23:31], sequence)
	binary.BigEndian.PutUint64(packet[31:39], sequence*20_000)
	binary.BigEndian.PutUint32(packet[39:43], 1)
	binary.BigEndian.PutUint64(packet[43:51], sequence)
	for index := 51; index < len(packet); index++ {
		packet[index] = fill
	}
	return packet
}

func TestMediaPacketVersionsAreStrictAndOpaque(t *testing.T) {
	legacy := audioPacket(t, 1, 0x33)
	encrypted := encryptedAudioPacket(t, "caller", 2, 0x44)
	if !validPacket(legacy, mediaCall, "caller", 1) {
		t.Fatal("valid legacy packet rejected")
	}
	if !validPacket(encrypted, mediaCall, "caller", 2) {
		t.Fatal("valid encrypted packet rejected")
	}
	if validPacket(legacy, mediaCall, "caller", 2) || validPacket(encrypted, mediaCall, "caller", 1) {
		t.Fatal("media protocol downgrade accepted")
	}
	wrongDirection := append([]byte(nil), encrypted...)
	wrongDirection[18] = 2
	if validPacket(wrongDirection, mediaCall, "caller", 2) {
		t.Fatal("wrong direction accepted")
	}
	oversized := append(encrypted, 0)
	if validPacket(oversized, mediaCall, "caller", 2) {
		t.Fatal("oversized frame accepted")
	}
}

func TestOutboundOverflowKeepsNewestBoundedAudioWithoutClosingPeer(t *testing.T) {
	p := &peer{outbound: make(chan []byte, 2), control: make(chan []byte, 1), done: make(chan struct{})}
	if !p.enqueueLatest([]byte{1}) || !p.enqueueLatest([]byte{2}) || !p.enqueueLatest([]byte{3}) {
		t.Fatal("bounded newest-frame enqueue failed")
	}
	if got := <-p.outbound; len(got) != 1 || got[0] != 2 {
		t.Fatalf("oldest frame was not dropped: %v", got)
	}
	if got := <-p.outbound; len(got) != 1 || got[0] != 3 {
		t.Fatalf("newest frame missing: %v", got)
	}
	select {
	case <-p.done:
		t.Fatal("short overflow closed authenticated peer")
	default:
	}
}

func TestPeerReadyHasPriorityOverCongestedAudioForBothPeers(t *testing.T) {
	h := New(nil)
	caller := &peer{callID: mediaCall, side: "caller", outbound: make(chan []byte, 2), control: make(chan []byte, 1), done: make(chan struct{})}
	callee := &peer{callID: mediaCall, side: "callee", outbound: make(chan []byte, 2), control: make(chan []byte, 1), done: make(chan struct{})}
	h.peers[mediaCall] = map[string]*peer{"caller": caller, "callee": callee}
	for _, p := range []*peer{caller, callee} {
		p.enqueueLatest([]byte{1})
		p.enqueueLatest([]byte{2})
	}
	h.sendPeerReady(mediaCall)
	for _, p := range []*peer{caller, callee} {
		p.enqueueLatest([]byte{3})
		select {
		case ready := <-p.control:
			if len(ready) != controlPacketSize || ready[1] != 3 {
				t.Fatalf("invalid ready packet: %v", ready)
			}
		default:
			t.Fatal("peer-ready was lost behind audio")
		}
	}
}

func TestClosedAndReplacedPeerCannotConsumeNewTraffic(t *testing.T) {
	h := New(nil)
	old := &peer{callID: mediaCall, side: "caller", epoch: "old", outbound: make(chan []byte, 1), control: make(chan []byte, 1), done: make(chan struct{})}
	newPeer := &peer{callID: mediaCall, side: "caller", epoch: "new", outbound: make(chan []byte, 1), control: make(chan []byte, 1), done: make(chan struct{})}
	h.peers[mediaCall] = map[string]*peer{"caller": newPeer}
	close(old.done)
	if old.enqueueLatest([]byte{1}) || old.enqueueControl([]byte{2}) {
		t.Fatal("closed replaced peer accepted traffic")
	}
	h.remove(old)
	if h.peers[mediaCall]["caller"] != newPeer {
		t.Fatal("removing old peer removed replacement")
	}
}
