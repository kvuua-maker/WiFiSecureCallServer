package relay

import (
	"testing"
	"time"
)

func TestQueuedCommandSurvivesUntilThePhoneConnects(t *testing.T) {
	hub := New(time.Minute, 4)
	now := time.Now()
	hub.now = func() time.Time { return now }

	if delivered := hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"}); delivered {
		t.Fatal("a command with no connected phone must be queued, not delivered")
	}
	pending := hub.Pending("account-1")
	if len(pending) != 1 || pending[0].Number != "+380501234567" {
		t.Fatalf("pending = %+v", pending)
	}
}

func TestDuplicateRequestIsNotQueuedTwice(t *testing.T) {
	hub := New(time.Minute, 4)
	hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"})
	hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"})
	if pending := hub.Pending("account-1"); len(pending) != 1 {
		t.Fatalf("the same request must be stored once, got %d", len(pending))
	}
}

func TestAckRemovesTheCommand(t *testing.T) {
	hub := New(time.Minute, 4)
	hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"})
	hub.Ack("account-1", "r1")
	if pending := hub.Pending("account-1"); len(pending) != 0 {
		t.Fatalf("pending = %+v", pending)
	}
}

func TestCommandsExpire(t *testing.T) {
	hub := New(30*time.Second, 4)
	now := time.Now()
	hub.now = func() time.Time { return now }
	hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"})

	now = now.Add(31 * time.Second)
	if pending := hub.Pending("account-1"); len(pending) != 0 {
		t.Fatalf("an expired command must not be delivered: %+v", pending)
	}
}

func TestQueueIsBoundedPerAccount(t *testing.T) {
	hub := New(time.Minute, 2)
	for _, id := range []string{"r1", "r2", "r3"} {
		hub.Enqueue("account-1", Command{RequestID: id, Number: "+380501234567"})
	}
	pending := hub.Pending("account-1")
	if len(pending) != 2 {
		t.Fatalf("queue = %d, want 2", len(pending))
	}
	if pending[0].RequestID != "r2" || pending[1].RequestID != "r3" {
		t.Fatalf("the newest commands must survive, got %+v", pending)
	}
}

func TestAccountsAreIsolated(t *testing.T) {
	hub := New(time.Minute, 4)
	hub.Enqueue("account-1", Command{RequestID: "r1", Number: "+380501234567"})
	if pending := hub.Pending("account-2"); len(pending) != 0 {
		t.Fatalf("account-2 must not see account-1's command: %+v", pending)
	}
}
