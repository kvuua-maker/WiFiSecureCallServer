package devicekeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
)

const (
	testUserID   = "11111111-1111-4111-8111-111111111111"
	testDeviceID = "22222222-2222-4222-8222-222222222222"
	testRequest  = "33333333-3333-4333-8333-333333333333"
)

func signedRegistration(t *testing.T, requestID, deviceID string, version uint64) (Registration, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agreement := make([]byte, 32)
	if _, err = rand.Read(agreement); err != nil {
		t.Fatal(err)
	}
	value := Registration{RequestID: requestID, DeviceID: deviceID, SigningPublicKey: base64.StdEncoding.EncodeToString(publicKey), AgreementPublicKey: base64.StdEncoding.EncodeToString(agreement), KeyVersion: version, ProtocolVersion: 2}
	value.ProofSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, ProofMessage(value)))
	return value, privateKey
}

func TestAuthenticatedRegistrationPersistenceIdempotencyAndReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	registration, _ := signedRegistration(t, testRequest, testDeviceID, 1)
	bundle, created, err := store.Register(testUserID, testDeviceID, registration)
	if err != nil || !created || bundle.DeviceID != testDeviceID {
		t.Fatalf("register bundle=%+v created=%v err=%v", bundle, created, err)
	}
	if _, created, err = store.Register(testUserID, testDeviceID, registration); err != nil || created {
		t.Fatalf("idempotent created=%v err=%v", created, err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reloaded.ForDevice(testUserID, testDeviceID); !ok || got != bundle {
		t.Fatalf("reloaded=%+v ok=%v", got, ok)
	}
	changed, _ := signedRegistration(t, "44444444-4444-4444-8444-444444444444", testDeviceID, 2)
	if _, _, err = reloaded.Register(testUserID, testDeviceID, changed); ErrorCode(err) != "key_changed" {
		t.Fatalf("changed err=%v", err)
	}
	if _, _, err = reloaded.Register("55555555-5555-4555-8555-555555555555", testDeviceID, registration); ErrorCode(err) != "device_not_owned" && ErrorCode(err) != "idempotency_conflict" {
		t.Fatalf("owner err=%v", err)
	}
}

func TestMalformedAndInvalidProofAreRejected(t *testing.T) {
	store := NewMemory()
	registration, _ := signedRegistration(t, testRequest, testDeviceID, 1)
	registration.AgreementPublicKey = base64.StdEncoding.EncodeToString([]byte("short"))
	if _, _, err := store.Register(testUserID, testDeviceID, registration); ErrorCode(err) != "invalid_device_key" {
		t.Fatalf("malformed err=%v", err)
	}
	registration, _ = signedRegistration(t, testRequest, testDeviceID, 1)
	registration.ProofSignature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, _, err := store.Register(testUserID, testDeviceID, registration); ErrorCode(err) != "invalid_key_proof" {
		t.Fatalf("proof err=%v", err)
	}
}
