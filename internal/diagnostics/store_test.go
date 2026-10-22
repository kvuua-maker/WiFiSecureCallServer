package diagnostics

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(t.TempDir(), "diagnostics.json"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store
}

func TestAppendAndReadBack(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	records := []Record{
		{Timestamp: now, Device: "d1", Category: "CALLKIT", Step: "start_call_requested", Status: "success"},
		{Timestamp: now.Add(time.Second), Device: "d1", Category: "MEDIA", Step: "audio_engine_started", Status: "error", Error: "code 20"},
	}
	if err := store.Append(records); err != nil {
		t.Fatalf("Append: %v", err)
	}
	read, err := store.Read(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(read) != 2 {
		t.Fatalf("read %d records", len(read))
	}
	if read[1].Error != "code 20" {
		t.Fatalf("error field lost: %+v", read[1])
	}
}

func TestFiltersAndLimit(t *testing.T) {
	store := newStore(t)
	now := time.Now().UTC()
	for i := 0; i < 30; i++ {
		status := "success"
		if i%3 == 0 {
			status = "error"
		}
		_ = store.Append([]Record{{
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			Device:    "d1", Category: "PUSH", Step: "alert_push_received", Status: status,
		}})
	}
	errors, err := store.Read(Filter{Category: "PUSH", Status: "error", Limit: 100})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(errors) != 10 {
		t.Fatalf("expected 10 errors, got %d", len(errors))
	}
	limited, _ := store.Read(Filter{Limit: 5})
	if len(limited) != 5 {
		t.Fatalf("limit ignored: %d", len(limited))
	}
	// The newest records must survive the limit.
	if !limited[len(limited)-1].Timestamp.After(limited[0].Timestamp) {
		t.Fatal("records are not ordered oldest first")
	}
}

func TestSanitisesControlCharactersAndLength(t *testing.T) {
	store := newStore(t)
	long := make([]byte, 2000)
	for i := range long {
		long[i] = 'a'
	}
	_ = store.Append([]Record{{Device: "d1", Category: "NETWORK", Step: "x", Status: "ok", Details: "line\nbreak\x00" + string(long)}})
	read, _ := store.Read(Filter{Limit: 1})
	if len(read) != 1 {
		t.Fatal("record lost")
	}
	if len(read[0].Details) > 512 {
		t.Fatalf("details not truncated: %d", len(read[0].Details))
	}
	if containsNewline(read[0].Details) {
		t.Fatal("control characters survived")
	}
}

func containsNewline(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r == 0 {
			return true
		}
	}
	return false
}

func TestReadMissingFileIsEmpty(t *testing.T) {
	store := newStore(t)
	_ = os.Remove(store.Path())
	records, err := store.Read(Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("expected none, got %d", len(records))
	}
}

func TestSummaryGroupsByCategoryAndStatus(t *testing.T) {
	summary := Summary([]Record{
		{Category: "CALLKIT", Status: "success"},
		{Category: "CALLKIT", Status: "error"},
		{Category: "MEDIA", Status: "success"},
	})
	if summary["CALLKIT"]["success"] != 1 || summary["CALLKIT"]["error"] != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary["MEDIA"]["success"] != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}
