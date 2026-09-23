package accounts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDuplicateActivePhoneFailsValidationAndStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := "11111111-2222-4333-8444-555555555555"
	second := "22222222-2222-4333-8444-555555555555"
	phone := "+380501234567"
	if err := store.Update(func(state *State) error {
		state.Accounts[first] = Account{AccountID: first, PhoneE164: phone, CreatedAt: time.Now(), Status: "active"}
		state.Accounts[second] = Account{AccountID: second, PhoneE164: phone, CreatedAt: time.Now(), Status: "active"}
		return nil
	}); err == nil {
		t.Fatal("duplicate phone transaction accepted")
	}

	state := emptyState()
	state.Accounts[first] = Account{AccountID: first, PhoneE164: phone, CreatedAt: time.Now(), Status: "active"}
	state.Accounts[second] = Account{AccountID: second, PhoneE164: phone, CreatedAt: time.Now(), Status: "active"}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("persisted duplicate phone accepted")
	}
}
