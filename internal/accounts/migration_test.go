package accounts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestV1MigrationPreservesAccountDeviceAndSession(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	device := "22222222-2222-4222-8222-222222222222"
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	legacy := map[string]any{"schemaVersion": 1, "accounts": map[string]any{id: Account{AccountID: id, PhoneE164: "+380501234567", CreatedAt: time.Now(), Status: "active"}}, "devices": []Device{{AccountID: id, DeviceID: device, Platform: "iOS"}}, "sessions": map[string]Session{}, "verifications": map[string]Verification{}, "startIdempotency": map[string]StartIdempotency{}, "watchStartIdempotency": map[string]WatchStartIdempotency{}, "watchLinks": map[string]WatchLink{}}
	raw, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	state := store.Snapshot()
	if state.SchemaVersion != 2 || state.Accounts[id].UserID != id || state.Users[id].UserID != id || state.PhoneBindings[id].PhoneE164 == "" || len(state.Devices) != 1 {
		t.Fatalf("migration lost state: %#v", state)
	}
}
