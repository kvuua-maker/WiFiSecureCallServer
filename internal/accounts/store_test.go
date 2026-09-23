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

func TestLegacyDeviceWithoutPushFieldsLoadsAndDuplicateDeviceFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	accountID := "11111111-2222-4333-8444-555555555555"
	deviceID := "22222222-2222-4333-8444-555555555555"
	state := emptyState()
	state.Accounts[accountID] = Account{AccountID: accountID, PhoneE164: "+380501234567", CreatedAt: time.Now(), Status: "active"}
	state.Devices = []Device{{AccountID: accountID, DeviceID: deviceID, Platform: "iOS", CreatedAt: time.Now(), LastSeenAt: time.Now()}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("legacy device rejected: %v", err)
	}
	state.Devices = append(state.Devices, state.Devices[0])
	data, _ = json.Marshal(state)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("duplicate account/device accepted")
	}
}

func TestMalformedAccountDevicePushStateFailsClosed(t *testing.T) {
	accountID := "11111111-2222-4333-8444-555555555555"
	base := emptyState()
	base.Accounts[accountID] = Account{AccountID: accountID, PhoneE164: "+380501234567", CreatedAt: time.Now(), Status: "active"}
	cases := []Device{
		{AccountID: accountID, DeviceID: "not-a-uuid", Platform: "iOS"},
		{AccountID: accountID, DeviceID: "22222222-2222-4333-8444-555555555555", Platform: "other"},
		{AccountID: accountID, DeviceID: "22222222-2222-4333-8444-555555555555", Platform: "iOS", InstallationGeneration: 1, Environment: "invalid", AlertToken: "aa"},
		{AccountID: accountID, DeviceID: "22222222-2222-4333-8444-555555555555", Platform: "iOS", Environment: "production", AlertToken: "not-hex"},
		{AccountID: accountID, DeviceID: "22222222-2222-4333-8444-555555555555", Platform: "iOS", Environment: "production", AlertToken: "aabb"},
		{AccountID: "33333333-2222-4333-8444-555555555555", DeviceID: "22222222-2222-4333-8444-555555555555", Platform: "iOS"},
	}
	for _, device := range cases {
		state := cloneState(base)
		state.Devices = []Device{device}
		if err := validateState(state); err == nil {
			t.Fatalf("invalid device accepted: %+v", device)
		}
	}
}
