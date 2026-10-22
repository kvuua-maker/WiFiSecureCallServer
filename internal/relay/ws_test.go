package relay

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func testServer(t *testing.T, hub *Hub) (*httptest.Server, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("/relay", func(w http.ResponseWriter, r *http.Request) {
		ServeWS(hub, "account-1", r.URL.Query().Get("role"), w, r, logger)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, "ws" + strings.TrimPrefix(server.URL, "http") + "/relay"
}

func dialRole(t *testing.T, url, role string) *websocket.Conn {
	t.Helper()
	conn, response, err := websocket.DefaultDialer.Dial(url+"?role="+role, nil)
	if err != nil {
		t.Fatalf("dial %s: %v", role, err)
	}
	if response != nil {
		_ = response.Body.Close()
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestWatchCommandWaitsForThePhone(t *testing.T) {
	hub := New(time.Minute, 4)
	_, url := testServer(t, hub)

	watch := dialRole(t, url, "watch")
	if err := watch.WriteJSON(Message{Type: "dial", RequestID: "r1", Number: "+380501234567"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var reply Message
	if err := watch.ReadJSON(&reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	if reply.Type != "queued" || reply.RequestID != "r1" {
		t.Fatalf("reply = %+v", reply)
	}

	// The phone connects later and must receive the command immediately.
	iphone := dialRole(t, url, "iphone")
	_ = iphone.SetReadDeadline(time.Now().Add(3 * time.Second))
	var delivered Message
	if err := iphone.ReadJSON(&delivered); err != nil {
		t.Fatalf("the backlog was not delivered: %v", err)
	}
	if delivered.Type != "dial" || delivered.Number != "+380501234567" {
		t.Fatalf("delivered = %+v", delivered)
	}

	if err := iphone.WriteJSON(Message{Type: "delivered", RequestID: "r1"}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(hub.Pending("account-1")) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the acknowledged command is still queued")
}

func TestConnectedPhoneReceivesTheCommandImmediately(t *testing.T) {
	hub := New(time.Minute, 4)
	_, url := testServer(t, hub)

	iphone := dialRole(t, url, "iphone")
	// Attach is asynchronous with respect to the handshake; wait until the hub
	// reports a connection by observing that a command is delivered rather than queued.
	watch := dialRole(t, url, "watch")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := watch.WriteJSON(Message{Type: "dial", RequestID: "r2", Number: "+380501234567"}); err != nil {
			t.Fatalf("write: %v", err)
		}
		var reply Message
		_ = watch.SetReadDeadline(time.Now().Add(time.Second))
		if err := watch.ReadJSON(&reply); err == nil && reply.Type == "delivered" {
			_ = iphone.SetReadDeadline(time.Now().Add(2 * time.Second))
			var delivered Message
			if err := iphone.ReadJSON(&delivered); err != nil {
				t.Fatalf("delivery announced but not sent: %v", err)
			}
			if delivered.Number != "+380501234567" {
				t.Fatalf("delivered = %+v", delivered)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("a connected phone never took the command")
}
