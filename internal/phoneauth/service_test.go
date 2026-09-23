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

func TestConcurrentVerificationUsesOneAccountPerPhone(t *testing.T) {
	f := newFixture(t, 100)
	code := "123456"
	verificationIDs := []string{newUUID(t), newUUID(t)}
	if err := f.store.Update(func(state *accounts.State) error {
		for _, id := range verificationIDs {
			state.Verifications[id] = accounts.Verification{
				VerificationID: id, PhoneE164: phoneOne, SourceIP: "192.0.2.1",
				OTPHash: f.svc.hmac(id, phoneOne, code), CreatedAt: f.now,
				ExpiresAt: f.now.Add(10 * time.Minute), ResendAfter: f.now.Add(120 * time.Second),
				ProviderAttempted: true, ProviderSubmitted: true,
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	results := make(chan SessionResult, 2)
	errors := make(chan error, 2)
	var group sync.WaitGroup
	for index, id := range verificationIDs {
		group.Add(1)
		go func(index int, id string) {
			defer group.Done()
			device := []string{deviceOne, "22222222-2222-4333-8444-555555555555"}[index]
			result, err := f.svc.Verify(newUUID(t), id, code, device, "iOS")
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(index, id)
	}
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	var accountID string
	count := 0
	for result := range results {
		count++
		if accountID == "" {
			accountID = result.Account.AccountID
		} else if result.Account.AccountID != accountID {
			t.Fatalf("different AccountIDs: %s and %s", accountID, result.Account.AccountID)
		}
	}
	if count != 2 {
		t.Fatalf("successful verifications=%d", count)
	}
	phoneAccounts := 0
	for _, account := range f.store.Snapshot().Accounts {
		if account.PhoneE164 == phoneOne {
			phoneAccounts++
		}
	}
	if phoneAccounts != 1 {
		t.Fatalf("accounts for phone=%d", phoneAccounts)
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

func TestWatchLinkCodeCollisionAndExpiredReuse(t *testing.T) {
	f := newFixture(t, 100)
	codes := []string{"123456", "123456", "654321"}
	index := 0
	f.svc.SetWatchCodeGeneratorForTesting(func() (string, error) {
		value := codes[index]
		index++
		return value, nil
	})
	first, err := f.svc.WatchStart(newUUID(t), "33333333-2222-4333-8444-555555555555", "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.WatchStart(newUUID(t), "44444444-2222-4333-8444-555555555555", "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	if first.Code != "123456" || second.Code != "654321" || index != 3 {
		t.Fatalf("collision was not retried: first=%s second=%s attempts=%d", first.Code, second.Code, index)
	}

	f.advance(6 * time.Minute)
	f.svc.SetWatchCodeGeneratorForTesting(func() (string, error) { return "123456", nil })
	reused, err := f.svc.WatchStart(newUUID(t), "55555555-2222-4333-8444-555555555555", "watchOS")
	if err != nil || reused.Code != "123456" {
		t.Fatalf("expired code blocked reuse: %+v %v", reused, err)
	}
}

func TestWatchClaimRejectsAmbiguousCode(t *testing.T) {
	f := newFixture(t, 100)
	account := f.register(t, phoneOne, deviceOne)
	identity, err := f.svc.Authenticate(account.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	code := "123456"
	if err := f.store.Update(func(state *accounts.State) error {
		for index, id := range []string{"33333333-2222-4333-8444-555555555555", "44444444-2222-4333-8444-555555555555"} {
			device := []string{"55555555-2222-4333-8444-555555555555", "66666666-2222-4333-8444-555555555555"}[index]
			state.WatchLinks[id] = accounts.WatchLink{LinkID: id, DeviceID: device, Platform: "watchOS", CodeHash: f.svc.hmac(id, device, code), SecretHash: tokenHash("secret" + id), CreatedAt: f.now, ExpiresAt: f.now.Add(5 * time.Minute)}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.WatchClaim(identity, newUUID(t), code); errorStatus(err) != 503 {
		t.Fatalf("ambiguous code status=%d err=%v", errorStatus(err), err)
	}
	for _, link := range f.store.Snapshot().WatchLinks {
		if link.ClaimedAt != nil {
			t.Fatal("ambiguous link was claimed")
		}
	}
}

func TestSMSDisabledPreservesExistingSessionsAndWatchLinking(t *testing.T) {
	f := newFixture(t, 100)
	account := f.register(t, phoneOne, deviceOne)
	disabled, err := New(f.store, nil, testPepper, 100)
	if err != nil {
		t.Fatal(err)
	}
	disabled.SetClockForTesting(func() time.Time { return f.now })
	if _, err := disabled.Start(context.Background(), newUUID(t), phoneTwo, "192.0.2.2"); errorStatus(err) != 503 {
		t.Fatalf("disabled sender start status=%d", errorStatus(err))
	}
	identity, err := disabled.Authenticate(account.AccessToken)
	if err != nil || identity.AccountID != account.Account.AccountID {
		t.Fatalf("existing access session failed: %+v %v", identity, err)
	}
	rotated, err := disabled.Refresh(account.RefreshToken, deviceOne)
	if err != nil {
		t.Fatal(err)
	}
	identity, err = disabled.Authenticate(rotated.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	disabled.SetWatchCodeGeneratorForTesting(func() (string, error) { return "123456", nil })
	link, err := disabled.WatchStart(newUUID(t), "33333333-2222-4333-8444-555555555555", "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	if err := disabled.WatchClaim(identity, newUUID(t), link.Code); err != nil {
		t.Fatal(err)
	}
	status, err := disabled.WatchStatus(link.LinkID, link.LinkSecret)
	if err != nil || status.Status != "claimed" || status.AccessToken == "" {
		t.Fatalf("watch link unavailable with SMS disabled: %+v %v", status, err)
	}
}

func TestAccountDeviceRegistrationGenerationAndInvalidation(t *testing.T) {
	f := newFixture(t, 100)
	account := f.register(t, phoneOne, deviceOne)
	identity, err := f.svc.Authenticate(account.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	caps := accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	register := func(pushType, token, invalidated string, generation uint64, environment string) error {
		return f.svc.RegisterDevice(identity, DeviceRegistration{RequestID: newUUID(t), DeviceID: deviceOne, Platform: "iOS", PushType: pushType, Token: token, InvalidatedToken: invalidated, InstallationGeneration: generation, Environment: environment, Capabilities: caps})
	}
	if err := register("alert", "aabb", "", 1, "production"); err != nil {
		t.Fatal(err)
	}
	if err := register("voip", "ccdd", "", 1, "production"); err != nil {
		t.Fatal(err)
	}
	devices := f.svc.DevicesForAccount(identity.AccountID)
	if len(devices) != 1 || devices[0].AlertToken != "aabb" || devices[0].VoIPToken != "ccdd" {
		t.Fatalf("same-generation tokens=%+v", devices)
	}
	if err := register("alert", "1122", "", 2, "production"); err != nil {
		t.Fatal(err)
	}
	devices = f.svc.DevicesForAccount(identity.AccountID)
	if devices[0].AlertToken != "1122" || devices[0].VoIPToken != "" || devices[0].InstallationGeneration != 2 {
		t.Fatalf("higher generation did not clear stale tokens: %+v", devices[0])
	}
	if err := register("alert", "eeff", "", 1, "production"); errorStatus(err) != 409 {
		t.Fatalf("stale generation status=%d", errorStatus(err))
	}
	if err := register("voip", "3344", "", 2, "production"); err != nil {
		t.Fatal(err)
	}
	if err := register("alert", "5566", "", 2, "development"); err != nil {
		t.Fatal(err)
	}
	devices = f.svc.DevicesForAccount(identity.AccountID)
	if devices[0].Environment != "development" || devices[0].AlertToken != "5566" || devices[0].VoIPToken != "" {
		t.Fatalf("environment replacement unsafe: %+v", devices[0])
	}
	if err := register("alert", "not-hex", "", 2, "development"); errorStatus(err) != 400 {
		t.Fatalf("invalid token status=%d", errorStatus(err))
	}
	if err := register("alert", "", "ffff", 2, "development"); err != nil {
		t.Fatal(err)
	}
	if f.svc.DevicesForAccount(identity.AccountID)[0].AlertToken != "5566" {
		t.Fatal("mismatched invalidation erased current token")
	}
	if err := register("alert", "", "5566", 2, "development"); err != nil {
		t.Fatal(err)
	}
	if f.svc.DevicesForAccount(identity.AccountID)[0].AlertToken != "" {
		t.Fatal("matching invalidation did not clear alert token")
	}
}

func TestAccountDeviceIdentityIsolationAndWatchRegistration(t *testing.T) {
	f := newFixture(t, 100)
	first := f.register(t, phoneOne, deviceOne)
	f.advance(121 * time.Second)
	second := f.register(t, phoneTwo, deviceOne)
	firstIdentity, _ := f.svc.Authenticate(first.AccessToken)
	secondIdentity, _ := f.svc.Authenticate(second.AccessToken)
	caps := accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}
	registration := DeviceRegistration{RequestID: newUUID(t), DeviceID: deviceOne, Platform: "iOS", PushType: "voip", Token: "aabb", InstallationGeneration: 1, Environment: "production", Capabilities: caps}
	if err := f.svc.RegisterDevice(firstIdentity, registration); err != nil {
		t.Fatal(err)
	}
	registration.RequestID = newUUID(t)
	registration.Token = "ccdd"
	if err := f.svc.RegisterDevice(secondIdentity, registration); err != nil {
		t.Fatal(err)
	}
	if f.svc.DevicesForAccount(firstIdentity.AccountID)[0].VoIPToken != "aabb" || f.svc.DevicesForAccount(secondIdentity.AccountID)[0].VoIPToken != "ccdd" {
		t.Fatal("same physical device account registrations were not isolated")
	}
	registration.RequestID = newUUID(t)
	registration.DeviceID = "99999999-2222-4333-8444-555555555555"
	if err := f.svc.RegisterDevice(firstIdentity, registration); errorStatus(err) != 403 {
		t.Fatalf("foreign device status=%d", errorStatus(err))
	}
	registration.DeviceID = deviceOne
	registration.Platform = "watchOS"
	if err := f.svc.RegisterDevice(firstIdentity, registration); errorStatus(err) != 403 {
		t.Fatalf("platform mismatch status=%d", errorStatus(err))
	}

	watchID := "33333333-2222-4333-8444-555555555555"
	link, err := f.svc.WatchStart(newUUID(t), watchID, "watchOS")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.WatchClaim(firstIdentity, newUUID(t), link.Code); err != nil {
		t.Fatal(err)
	}
	watchSession, err := f.svc.WatchStatus(link.LinkID, link.LinkSecret)
	if err != nil {
		t.Fatal(err)
	}
	watchIdentity, err := f.svc.Authenticate(watchSession.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RegisterDevice(watchIdentity, DeviceRegistration{RequestID: newUUID(t), DeviceID: watchID, Platform: "watchOS", PushType: "alert", Token: "eeff", InstallationGeneration: 1, Environment: "production", Capabilities: caps}); err != nil {
		t.Fatal(err)
	}
	watchFound := false
	for _, device := range f.svc.DevicesForAccount(firstIdentity.AccountID) {
		if device.DeviceID == watchID && device.AlertToken == "eeff" {
			watchFound = true
		}
	}
	if !watchFound {
		t.Fatal("Watch account token not registered")
	}
	if err := f.svc.DeleteAccount(firstIdentity); err != nil {
		t.Fatal(err)
	}
	if len(f.svc.DevicesForAccount(firstIdentity.AccountID)) != 0 || len(f.svc.DevicesForAccount(secondIdentity.AccountID)) != 1 {
		t.Fatal("account deletion crossed device ownership")
	}
}

func TestRateLimitRetryAtUsesActualRollingWindows(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	base := accounts.State{Verifications: map[string]accounts.Verification{}}
	for i, age := range []time.Duration{9 * time.Minute, 8 * time.Minute, 7 * time.Minute} {
		id := fmtDigits(i, 1)
		base.Verifications[id] = accounts.Verification{PhoneE164: phoneOne, SourceIP: "192.0.2." + fmtDigits(i+1, 1), CreatedAt: now.Add(-age), ProviderSubmitted: true}
	}
	limited := rateLimit(base, phoneOne, "198.51.100.1", now, 100)
	if limited == nil || !limited.RetryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("10m retryAt=%v", limited)
	}

	daily := accounts.State{Verifications: map[string]accounts.Verification{}}
	for i := 0; i < 10; i++ {
		id := fmtDigits(i, 2)
		daily.Verifications[id] = accounts.Verification{PhoneE164: phoneOne, SourceIP: "192.0.2." + fmtDigits(i+1, 2), CreatedAt: now.Add(-23*time.Hour + time.Duration(i)*time.Minute), ProviderSubmitted: true}
	}
	limited = rateLimit(daily, phoneOne, "198.51.100.1", now, 100)
	if limited == nil || !limited.RetryAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("24h retryAt=%v", limited)
	}

	ipState := accounts.State{Verifications: map[string]accounts.Verification{}}
	for i := 0; i < 20; i++ {
		id := fmtDigits(i, 2)
		ipState.Verifications[id] = accounts.Verification{PhoneE164: "+1415555" + fmtDigits(i, 4), SourceIP: "203.0.113.1", CreatedAt: now.Add(-59*time.Minute + time.Duration(i)*time.Second), ProviderSubmitted: true}
	}
	limited = rateLimit(ipState, phoneOne, "203.0.113.1", now, 100)
	if limited == nil || !limited.RetryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("hour retryAt=%v", limited)
	}

	globalState := accounts.State{Verifications: map[string]accounts.Verification{
		"one": {PhoneE164: "+14155550101", SourceIP: "192.0.2.10", CreatedAt: now.Add(-23 * time.Hour), ProviderSubmitted: true},
		"two": {PhoneE164: "+14155550102", SourceIP: "192.0.2.11", CreatedAt: now.Add(-22 * time.Hour), ProviderSubmitted: true},
	}}
	limited = rateLimit(globalState, phoneOne, "203.0.113.1", now, 2)
	if limited == nil || !limited.RetryAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("global rolling retryAt=%v", limited)
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
