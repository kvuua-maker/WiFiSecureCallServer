package phoneauth

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

func recipientFixture(t *testing.T) (*Service, Identity, string, string) {
	t.Helper()
	store, err := accounts.Open(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, nil, strings.Repeat("p", 32), 5)
	if err != nil {
		t.Fatal(err)
	}
	callerUser := "11111111-1111-4111-8111-111111111111"
	targetUser := "22222222-2222-4222-8222-222222222222"
	callerAccount := "33333333-3333-4333-8333-333333333333"
	targetAccount := "44444444-4444-4444-8444-444444444444"
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	err = store.Update(func(state *accounts.State) error {
		state.Users[callerUser] = accounts.User{UserID: callerUser, Username: "caller.user", UsernameDisplay: "Caller.User", CreatedAt: now, Status: "active"}
		state.Users[targetUser] = accounts.User{UserID: targetUser, Username: "target.user", UsernameDisplay: "Target.User", DisplayName: "Target", Email: "private@example.invalid", CreatedAt: now, Status: "active"}
		state.Accounts[callerAccount] = accounts.Account{AccountID: callerAccount, UserID: callerUser, CreatedAt: now, Status: "active"}
		state.Accounts[targetAccount] = accounts.Account{AccountID: targetAccount, UserID: targetUser, CreatedAt: now, Status: "active"}
		state.PhoneBindings["55555555-5555-4555-8555-555555555555"] = accounts.PhoneBinding{BindingID: "55555555-5555-4555-8555-555555555555", UserID: targetUser, PhoneE164: "+380501234567", VerifiedAt: now, Status: "active"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, Identity{UserID: callerUser, AccountID: callerAccount}, targetUser, targetAccount
}

func TestRecipientResolverExactSupportedIdentifiers(t *testing.T) {
	service, caller, targetUser, _ := recipientFixture(t)
	for _, input := range []string{"target.user", "@Target.User", "wsc:user:TARGET.USER", "+380 50-123-(4567)"} {
		resolved, err := service.ResolveRecipient(caller, input)
		if err != nil {
			t.Fatalf("resolve %q: %v", input, err)
		}
		if resolved.UserID != targetUser || resolved.Username != "target.user" || resolved.PublicIdentity != "wsc:user:target.user" {
			t.Fatalf("unsafe/incorrect response for %q: %+v", input, resolved)
		}
		if resolved.DisplayName != "Target" {
			t.Fatalf("display name missing: %+v", resolved)
		}
		if strings.Contains(resolved.PhoneNumber, "+380501234567") || strings.Contains(resolved.PhoneNumber, "private@example.invalid") {
			t.Fatalf("private identity leaked: %+v", resolved)
		}
	}
	phone, err := service.ResolveRecipient(caller, "+380 50-123-(4567)")
	if err != nil || phone.PhoneNumber == "" || phone.PhoneNumber == "+380501234567" {
		t.Fatalf("phone representation is not intentionally safe: %+v err=%v", phone, err)
	}
}

func TestRecipientResolverRejectsAmbiguousAndPrivateIdentifiers(t *testing.T) {
	service, caller, _, _ := recipientFixture(t)
	for _, input := range []string{"0501234567", "050 123-4567", "target@example.invalid", "wsc:other:target.user", "wsc:user:", strings.Repeat("a", 64)} {
		if _, err := service.ResolveRecipient(caller, input); errorCode(err) != "invalid_recipient" {
			t.Fatalf("%q error=%v", input, err)
		}
	}
	for _, input := range []string{"unknown.user", "@unknown.user", "+380501234568"} {
		if _, err := service.ResolveRecipient(caller, input); errorCode(err) != "recipient_not_found" {
			t.Fatalf("%q error=%v", input, err)
		}
	}
	if _, err := service.ResolveRecipient(Identity{}, "target.user"); errorCode(err) != "unauthorized" {
		t.Fatalf("unauthenticated resolver error=%v", err)
	}
}

func TestDevicesForUserCollectsAllActiveAccountsOnly(t *testing.T) {
	service, _, targetUser, firstAccount := recipientFixture(t)
	store := service.store
	secondAccount := "66666666-6666-4666-8666-666666666666"
	otherAccount := "77777777-7777-4777-8777-777777777777"
	now := time.Now().UTC()
	err := store.Update(func(state *accounts.State) error {
		state.Accounts[secondAccount] = accounts.Account{AccountID: secondAccount, UserID: targetUser, CreatedAt: now, Status: "active"}
		state.Users["88888888-8888-4888-8888-888888888888"] = accounts.User{UserID: "88888888-8888-4888-8888-888888888888", Username: "other.user", UsernameDisplay: "other.user", CreatedAt: now, Status: "active"}
		state.Accounts[otherAccount] = accounts.Account{AccountID: otherAccount, UserID: "88888888-8888-4888-8888-888888888888", CreatedAt: now, Status: "active"}
		state.Devices = append(state.Devices,
			accounts.Device{AccountID: firstAccount, DeviceID: "99999999-9999-4999-8999-999999999999", Platform: "iOS", CreatedAt: now, LastSeenAt: now},
			accounts.Device{AccountID: secondAccount, DeviceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Platform: "watchOS", CreatedAt: now, LastSeenAt: now},
			accounts.Device{AccountID: otherAccount, DeviceID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Platform: "iOS", CreatedAt: now, LastSeenAt: now},
		)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	devices := service.DevicesForUser(targetUser)
	if len(devices) != 2 {
		t.Fatalf("devices=%+v", devices)
	}
}

func errorCode(err error) string {
	if typed, ok := err.(*ServiceError); ok {
		return typed.Code
	}
	return ""
}
