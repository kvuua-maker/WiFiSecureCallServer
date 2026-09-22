package phoneauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

const testPepper = "0123456789abcdef0123456789abcdef"
const phoneOne = "+380501234567"
const phoneTwo = "+14155550123"
const deviceOne = "11111111-2222-4333-8444-555555555555"

type fakeSender struct {
	mu       sync.Mutex
	calls    int
	messages []string
}

func (f *fakeSender) Send(_ context.Context, _ string, message string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.messages = append(f.messages, message)
	return "provider-id", nil
}
func (f *fakeSender) code() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return regexp.MustCompile(`[0-9]{6}`).FindString(f.messages[len(f.messages)-1])
}

type testFixture struct {
	svc    *Service
	store  *accounts.Store
	sender *fakeSender
	now    time.Time
	path   string
}

func newFixture(t *testing.T, maxDaily int) *testFixture {
	t.Helper()
	value := &testFixture{now: time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC), path: filepath.Join(t.TempDir(), "accounts.json")}
	var err error
	value.store, err = accounts.Open(value.path)
	if err != nil {
		t.Fatal(err)
	}
	value.sender = &fakeSender{}
	value.svc, err = New(value.store, value.sender, testPepper, maxDaily)
	if err != nil {
		t.Fatal(err)
	}
	value.svc.SetClockForTesting(func() time.Time { return value.now })
	return value
}
func (f *testFixture) advance(d time.Duration) { f.now = f.now.Add(d) }
func (f *testFixture) register(t *testing.T, phone, device string) SessionResult {
	t.Helper()
	start, err := f.svc.Start(context.Background(), newUUID(t), phone, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.svc.Verify(newUUID(t), start.VerificationID, f.sender.code(), device, "iOS")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPhoneValidationOTPAndPersistence(t *testing.T) {
	for _, value := range []string{"380501234567", "+01234567", "+123", "+1234567890123456", "+380 50"} {
		if ValidPhone(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	if !ValidPhone(phoneOne) || !ValidPhone(phoneTwo) {
		t.Fatal("valid E.164 rejected")
	}
	f := newFixture(t, 100)
	result, err := f.svc.Start(context.Background(), newUUID(t), phoneOne, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	challenge := f.store.Snapshot().Verifications[result.VerificationID]
	if len(f.sender.code()) != 6 || result.ExpiresAt.Sub(challenge.CreatedAt) != 10*time.Minute || challenge.ResendAfter.Sub(challenge.CreatedAt) != 120*time.Second {
		t.Fatal("OTP contract mismatch")
	}
	data, _ := os.ReadFile(f.path)
	if strings.Contains(string(data), f.sender.code()) {
		t.Fatal("raw OTP persisted")
	}
	if challenge.OTPHash == "" {
		t.Fatal("OTP HMAC missing")
	}
}

func TestStartIdempotencyAndRateLimits(t *testing.T) {
	f := newFixture(t, 2)
	requestID := newUUID(t)
	first, err := f.svc.Start(context.Background(), requestID, phoneOne, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.Start(context.Background(), requestID, phoneOne, "192.0.2.1")
	if err != nil || second.VerificationID != first.VerificationID || f.sender.calls != 1 {
		t.Fatal("idempotent retry sent twice")
	}
	if _, err := f.svc.Start(context.Background(), requestID, phoneTwo, "192.0.2.1"); errorStatus(err) != 409 {
		t.Fatalf("request conflict: %v", err)
	}
	if _, err := f.svc.Start(context.Background(), newUUID(t), phoneOne, "192.0.2.1"); errorStatus(err) != 429 {
		t.Fatalf("resend limit: %v", err)
	}
	f.advance(121 * time.Second)
	if _, err := f.svc.Start(context.Background(), newUUID(t), phoneTwo, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	f.advance(121 * time.Second)
	if _, err := f.svc.Start(context.Background(), newUUID(t), "+442071838750", "192.0.2.2"); errorStatus(err) != 429 {
		t.Fatalf("global cap: %v", err)
	}
}

func TestPhoneAndIPWindowLimits(t *testing.T) {
	f := newFixture(t, 100)
	if err := f.store.Update(func(state *accounts.State) error {
		for i := 0; i < 20; i++ {
			id, _ := randomUUID()
			phone := "+1415555" + fmtDigits(i, 4)
			state.Verifications[id] = accounts.Verification{VerificationID: id, PhoneE164: phone, SourceIP: "198.51.100.1", CreatedAt: f.now.Add(-time.Minute), ProviderSubmitted: true}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Start(context.Background(), newUUID(t), phoneOne, "198.51.100.1"); errorStatus(err) != 429 {
		t.Fatalf("IP limit: %v", err)
	}

	g := newFixture(t, 100)
	if err := g.store.Update(func(state *accounts.State) error {
		for i := 0; i < 10; i++ {
			id, _ := randomUUID()
			state.Verifications[id] = accounts.Verification{VerificationID: id, PhoneE164: phoneOne, SourceIP: "203.0.113." + fmtDigits(i+1, 1), CreatedAt: g.now.Add(-11 * time.Minute), ProviderSubmitted: true}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.svc.Start(context.Background(), newUUID(t), phoneOne, "203.0.113.200"); errorStatus(err) != 429 {
		t.Fatalf("phone daily limit: %v", err)
	}

	h := newFixture(t, 100)
	if err := h.store.Update(func(state *accounts.State) error {
		for i := 0; i < 3; i++ {
			id, _ := randomUUID()
			state.Verifications[id] = accounts.Verification{VerificationID: id, PhoneE164: phoneOne, SourceIP: "203.0.113." + fmtDigits(i+1, 1), CreatedAt: h.now.Add(-3*time.Minute - time.Duration(i)*time.Minute), ProviderSubmitted: true}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.Start(context.Background(), newUUID(t), phoneOne, "203.0.113.200"); errorStatus(err) != 429 {
		t.Fatalf("phone 10m limit: %v", err)
	}
}

func TestVerificationAttemptsExpiryAndReplay(t *testing.T) {
	f := newFixture(t, 100)
	start, _ := f.svc.Start(context.Background(), newUUID(t), phoneOne, "192.0.2.1")
	for i := 0; i < 5; i++ {
		if _, err := f.svc.Verify(newUUID(t), start.VerificationID, "999999", deviceOne, "iOS"); err == nil {
			t.Fatal("wrong OTP accepted")
		}
	}
	if _, err := f.svc.Verify(newUUID(t), start.VerificationID, f.sender.code(), deviceOne, "iOS"); errorStatus(err) != 429 {
		t.Fatalf("attempt cap: %v", err)
	}
	f.advance(121 * time.Second)
	expiring, _ := f.svc.Start(context.Background(), newUUID(t), phoneTwo, "192.0.2.1")
	f.advance(11 * time.Minute)
	if _, err := f.svc.Verify(newUUID(t), expiring.VerificationID, f.sender.code(), deviceOne, "iOS"); errorStatus(err) != 410 {
		t.Fatalf("expiry: %v", err)
	}
}

func TestAccountsSessionsLogoutAndDeletion(t *testing.T) {
	f := newFixture(t, 100)
	first := f.register(t, phoneOne, deviceOne)
	if len(first.AccessToken) < 40 || len(first.RefreshToken) < 40 {
		t.Fatal("low entropy token")
	}
	data, _ := os.ReadFile(f.path)
	if strings.Contains(string(data), first.AccessToken) || strings.Contains(string(data), first.RefreshToken) {
		t.Fatal("raw token persisted")
	}
	if _, err := f.svc.Authenticate(first.AccessToken); err != nil {
		t.Fatal(err)
	}
	rotated, err := f.svc.Refresh(first.RefreshToken, deviceOne)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.AccessToken == first.AccessToken || rotated.RefreshToken == first.RefreshToken {
		t.Fatal("tokens not rotated")
	}
	if _, err := f.svc.Refresh(first.RefreshToken, deviceOne); err == nil {
		t.Fatal("refresh replay accepted")
	}
	identity, _ := f.svc.Authenticate(rotated.AccessToken)
	if err := f.svc.Logout(identity); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(rotated.AccessToken); err == nil {
		t.Fatal("logout failed")
	}
	f.advance(121 * time.Second)
	second := f.register(t, phoneOne, "22222222-2222-4333-8444-555555555555")
	if second.Account.AccountID != first.Account.AccountID {
		t.Fatal("same phone got a new account")
	}
	f.advance(121 * time.Second)
	other := f.register(t, phoneTwo, deviceOne)
	if other.Account.AccountID == first.Account.AccountID {
		t.Fatal("different phone reused account")
	}
	if len(f.store.Snapshot().Devices) != 3 {
		t.Fatalf("device associations=%d", len(f.store.Snapshot().Devices))
	}
	otherIdentity, _ := f.svc.Authenticate(other.AccessToken)
	if err := f.svc.DeleteAccount(otherIdentity); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.store.Snapshot().Accounts[other.Account.AccountID]; ok {
		t.Fatal("account not deleted")
	}
	f.advance(121 * time.Second)
	recreated := f.register(t, phoneTwo, deviceOne)
	if recreated.Account.AccountID == other.Account.AccountID {
		t.Fatal("deleted AccountID reused")
	}
}

func TestConsumedOTPAndAccessExpiry(t *testing.T) {
	f := newFixture(t, 100)
	start, _ := f.svc.Start(context.Background(), newUUID(t), phoneOne, "192.0.2.1")
	code := f.sender.code()
	result, err := f.svc.Verify(newUUID(t), start.VerificationID, code, deviceOne, "iOS")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Verify(newUUID(t), start.VerificationID, code, deviceOne, "iOS"); err == nil {
		t.Fatal("OTP replay accepted")
	}
	f.advance(16 * time.Minute)
	if _, err := f.svc.Authenticate(result.AccessToken); err == nil {
		t.Fatal("expired access accepted")
	}
}

func TestWatchLinkLifecycle(t *testing.T) {
	f := newFixture(t, 100)
	account := f.register(t, phoneOne, deviceOne)
	identity, _ := f.svc.Authenticate(account.AccessToken)
	watchID := "33333333-2222-4333-8444-555555555555"
	link, err := f.svc.WatchStart(newUUID(t), watchID, "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	if len(link.Code) != 6 || link.ExpiresAt.Sub(f.now) != 5*time.Minute {
		t.Fatal("link contract")
	}
	data, _ := os.ReadFile(f.path)
	if strings.Contains(string(data), link.LinkSecret) {
		t.Fatal("raw link secret persisted")
	}
	pending, _ := f.svc.WatchStatus(link.LinkID, link.LinkSecret)
	if pending.Status != "pending" {
		t.Fatal(pending.Status)
	}
	if err := f.svc.WatchClaim(identity, newUUID(t), "999999"); err == nil {
		t.Fatal("wrong link code accepted")
	}
	if err := f.svc.WatchClaim(identity, newUUID(t), link.Code); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.svc.WatchStatus(link.LinkID, link.LinkSecret)
	if err != nil || claimed.Status != "claimed" || claimed.AccessToken == "" {
		t.Fatalf("claimed=%+v err=%v", claimed, err)
	}
	if _, err := f.svc.WatchStatus(link.LinkID, link.LinkSecret); errorStatus(err) != 409 {
		t.Fatalf("second retrieval: %v", err)
	}
	linked := false
	for _, device := range f.store.Snapshot().Devices {
		if device.AccountID == identity.AccountID && device.DeviceID == strings.ToLower(watchID) {
			linked = true
		}
	}
	if !linked {
		t.Fatal("watch device not linked")
	}
	link2, _ := f.svc.WatchStart(newUUID(t), "44444444-2222-4333-8444-555555555555", "watchOS")
	f.advance(6 * time.Minute)
	expired, _ := f.svc.WatchStatus(link2.LinkID, link2.LinkSecret)
	if expired.Status != "expired" {
		t.Fatal(expired.Status)
	}
}

func TestMalformedPersistenceFailsClosedAndRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := accounts.Open(path); err == nil {
		t.Fatal("malformed state accepted")
	}
	path = filepath.Join(t.TempDir(), "accounts.json")
	store, err := accounts.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := newUUID(t)
	if err := store.Update(func(state *accounts.State) error {
		state.Accounts[id] = accounts.Account{AccountID: id, PhoneE164: phoneOne, CreatedAt: time.Now(), Status: "active"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := accounts.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Snapshot().Accounts[id]; !ok {
		t.Fatal("roundtrip failed")
	}
}

func newUUID(t *testing.T) string {
	t.Helper()
	value, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func errorStatus(err error) int {
	var typed *ServiceError
	if errors.As(err, &typed) {
		return typed.Status
	}
	return 0
}
func fmtDigits(value, width int) string {
	raw := "0000000000" + strconv.Itoa(value)
	return raw[len(raw)-width:]
}
