package phoneauth

import (
	"context"
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
