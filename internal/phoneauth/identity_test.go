package phoneauth

import (
	"context"
	"errors"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/appleauth"
	"path/filepath"
	"testing"
	"time"
)

type fakeAppleVerifier struct {
	subject, email string
	err            error
}

func (f *fakeAppleVerifier) Verify(context.Context, string, string) (appleauth.Claims, error) {
	return appleauth.Claims{Subject: f.subject, Email: f.email, EmailVerified: true}, f.err
}
func TestAppleSubjectStableUserAndZeroPhone(t *testing.T) {
	store, err := accounts.Open(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := New(store, nil, "12345678901234567890123456789012", 5)
	fake := &fakeAppleVerifier{subject: "sub", email: "first@example.com"}
	svc.ConfigureAppleIdentity(fake)
	now := time.Now()
	svc.SetClockForTesting(func() time.Time { return now })
	dev := "22222222-2222-4222-8222-222222222222"
	first, err := svc.AppleSignIn(context.Background(), AppleSignInRequest{RequestID: "11111111-1111-4111-8111-111111111111", DeviceID: dev, Platform: "iOS", IdentityToken: "token", Nonce: "nonce"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Account.PhoneNumber != "" || first.User == nil {
		t.Fatal("Apple user incorrectly requires phone")
	}
	watch, err := svc.AppleSignIn(context.Background(), AppleSignInRequest{
		RequestID: "44444444-4444-4444-8444-444444444444",
		DeviceID:  "55555555-5555-4555-8555-555555555555",
		Platform:  "watchOS", IdentityToken: "watch-token", Nonce: "watch-nonce",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.User.UserID != watch.User.UserID || first.Account.AccountID != watch.Account.AccountID {
		t.Fatal("grouped Watch Apple sign-in created another identity")
	}
	fake.email = "changed@example.com"
	second, err := svc.AppleSignIn(context.Background(), AppleSignInRequest{RequestID: "33333333-3333-4333-8333-333333333333", DeviceID: dev, Platform: "iOS", IdentityToken: "token2", Nonce: "nonce2"})
	if err != nil {
		t.Fatal(err)
	}
	if first.User.UserID != second.User.UserID || first.Account.AccountID != second.Account.AccountID {
		t.Fatal("same Apple subject created another identity")
	}
	if _, err := svc.SetUsername(Identity{UserID: first.User.UserID}, "Valid.Name"); err != nil {
		t.Fatal(err)
	}
	if got, _ := svc.Profile(Identity{UserID: first.User.UserID}); got.PublicIdentity != "wsc:user:valid.name" {
		t.Fatalf("bad public identity %q", got.PublicIdentity)
	}
}

func TestAppleSignInAllowsOnlyIOSAndWatchOS(t *testing.T) {
	for _, test := range []struct {
		platform string
		valid    bool
	}{
		{platform: "iOS", valid: true},
		{platform: "watchOS", valid: true},
		{platform: "macOS", valid: false},
		{platform: "", valid: false},
	} {
		if got := validApplePlatform(test.platform); got != test.valid {
			t.Fatalf("platform %q validity=%v, want %v", test.platform, got, test.valid)
		}
	}

	store, err := accounts.Open(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := New(store, nil, "12345678901234567890123456789012", 5)
	svc.ConfigureAppleIdentity(&fakeAppleVerifier{subject: "sub"})
	_, err = svc.AppleSignIn(context.Background(), AppleSignInRequest{
		RequestID: "11111111-1111-4111-8111-111111111111",
		DeviceID:  "22222222-2222-4222-8222-222222222222",
		Platform:  "arbitrary", IdentityToken: "token", Nonce: "nonce",
	})
	if errorStatus(err) != 400 {
		t.Fatalf("arbitrary Apple platform status=%d", errorStatus(err))
	}
}

func TestAppleVerificationFailureCodeIsSafelyPropagated(t *testing.T) {
	store, err := accounts.Open(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := New(store, nil, "12345678901234567890123456789012", 5)
	svc.ConfigureAppleIdentity(&fakeAppleVerifier{err: &appleauth.VerificationError{Code: appleauth.FailureNonce}})
	_, err = svc.AppleSignIn(context.Background(), AppleSignInRequest{
		RequestID: "11111111-1111-4111-8111-111111111111",
		DeviceID:  "22222222-2222-4222-8222-222222222222",
		Platform:  "iOS", IdentityToken: "token", Nonce: "nonce",
	})
	var serviceError *ServiceError
	if !errors.As(err, &serviceError) || serviceError.Status != 401 || serviceError.Code != string(appleauth.FailureNonce) {
		t.Fatalf("unexpected safe failure: %#v", err)
	}
}
