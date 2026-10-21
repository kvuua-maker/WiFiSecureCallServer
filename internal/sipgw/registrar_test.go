package sipgw

import (
	"testing"
	"time"
)

func TestRegistrarStoresAndRefreshes(t *testing.T) {
	reg := NewRegistrar()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	reg.Register("alice", Contact{URI: "sip:alice@192.0.2.10:5000"}, time.Minute, now)

	contact, ok := reg.Lookup("alice", now.Add(30*time.Second))
	if !ok || contact.URI != "sip:alice@192.0.2.10:5000" {
		t.Fatalf("lookup = %+v, ok=%v", contact, ok)
	}
	if _, ok := reg.Lookup("alice", now.Add(2*time.Minute)); ok {
		t.Fatal("an expired contact was returned")
	}
}

func TestRegistrarPrefersTheFreshestContact(t *testing.T) {
	reg := NewRegistrar()
	now := time.Now()
	reg.Register("alice", Contact{URI: "sip:alice@first"}, time.Minute, now)
	reg.Register("alice", Contact{URI: "sip:alice@second"}, time.Minute, now.Add(time.Second))
	contact, ok := reg.Lookup("alice", now.Add(2*time.Second))
	if !ok {
		t.Fatal("no contact")
	}
	if contact.URI != "sip:alice@second" {
		t.Fatalf("chose %q", contact.URI)
	}
}

func TestRegistrarUnregisterOnZeroTTL(t *testing.T) {
	reg := NewRegistrar()
	now := time.Now()
	reg.Register("alice", Contact{URI: "sip:alice@a"}, time.Minute, now)
	reg.Register("alice", Contact{URI: "sip:alice@a"}, 0, now)
	if _, ok := reg.Lookup("alice", now); ok {
		t.Fatal("a zero TTL registration must remove the binding")
	}
}

func TestRegistrarPrunesExpired(t *testing.T) {
	reg := NewRegistrar()
	now := time.Now()
	reg.Register("alice", Contact{URI: "sip:alice@a"}, 10*time.Millisecond, now)
	reg.Register("bob", Contact{URI: "sip:bob@b"}, time.Hour, now)
	time.Sleep(20 * time.Millisecond)
	removed := reg.Prune(now.Add(time.Second))
	if removed != 1 {
		t.Fatalf("pruned %d, want 1", removed)
	}
	if snapshot := reg.Snapshot(now.Add(time.Second)); len(snapshot) != 1 || snapshot[0].User != "bob" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestRegistrarSnapshotReportsSecondsLeft(t *testing.T) {
	reg := NewRegistrar()
	now := time.Now()
	reg.Register("alice", Contact{URI: "sip:alice@a"}, 2*time.Minute, now)
	reg.Register("alice", Contact{URI: "sip:alice@b"}, 2*time.Minute, now)
	snapshot := reg.Snapshot(now)
	if len(snapshot) != 2 {
		t.Fatalf("snapshot has %d rows", len(snapshot))
	}
	for _, row := range snapshot {
		if row.SecondsLeft < 119 || row.SecondsLeft > 120 {
			t.Fatalf("secondsLeft = %d", row.SecondsLeft)
		}
	}
	if snapshot[0].URI > snapshot[1].URI {
		t.Fatal("snapshot is not sorted")
	}
}
