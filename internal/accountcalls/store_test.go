package accountcalls

import (
	"testing"
	"time"
)

const (
	testAccount = "11111111-1111-4111-8111-111111111111"
	testCaller  = "22222222-2222-4222-8222-222222222222"
	testCallee  = "33333333-3333-4333-8333-333333333333"
	testCall    = "44444444-4444-4444-8444-444444444444"
)

func createTestCall(t *testing.T, store *Store) View {
	t.Helper()
	view, created, err := store.Create(testCall, "55555555-5555-4555-8555-555555555555", testAccount, testCaller, testCallee)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	return view
}

func TestSameAccountDifferentDevicesAndParticipantViews(t *testing.T) {
	store := New(30 * time.Second)
	caller := createTestCall(t, store)
	if caller.LocalSide != SideCaller || caller.State != Ringing {
		t.Fatalf("caller view=%+v", caller)
	}
	callee, err := store.Get(testCall, testAccount, testCallee)
	if err != nil || callee.LocalSide != SideCallee {
		t.Fatalf("callee view=%+v err=%v", callee, err)
	}
	if _, err := store.Get(testCall, testAccount, "66666666-6666-4666-8666-666666666666"); err == nil {
		t.Fatal("third device accessed call")
	}
	if _, _, err := store.Create("77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", testAccount, testCaller, testCaller); err == nil {
		t.Fatal("same caller and callee device accepted")
	}
}

func TestMutationPermissionsTokensAndPeerReady(t *testing.T) {
	store := New(30 * time.Second)
	createTestCall(t, store)
	if _, _, err := store.Mutate(testCall, "55555555-5555-4555-8555-555555555556", testAccount, testCaller, Accepted); err == nil {
		t.Fatal("caller accepted")
	}
	callee, applied, err := store.Mutate(testCall, "55555555-5555-4555-8555-555555555557", testAccount, testCallee, Accepted)
	if err != nil || !applied || callee.MediaToken == "" {
		t.Fatalf("accept=%+v applied=%v err=%v", callee, applied, err)
	}
	caller, err := store.Get(testCall, testAccount, testCaller)
	if err != nil || caller.MediaToken == "" || caller.MediaToken == callee.MediaToken {
		t.Fatalf("independent tokens caller=%q callee=%q err=%v", caller.MediaToken, callee.MediaToken, err)
	}
	if !store.ValidateMedia(testCall, "caller", caller.MediaToken) || !store.ValidateMedia(testCall, "callee", callee.MediaToken) {
		t.Fatal("correct media token rejected")
	}
	if store.ValidateMedia(testCall, "caller", callee.MediaToken) || store.ValidateMedia(testCall, "callee", caller.MediaToken) {
		t.Fatal("opposite-side token accepted")
	}
	if store.MediaPeerJoined(testCall, "caller", "one") {
		t.Fatal("one peer reported ready")
	}
	if !store.MediaPeerJoined(testCall, "callee", "two") {
		t.Fatal("two peers not ready")
	}
	ready, _ := store.Get(testCall, testAccount, testCaller)
	if !ready.PeerReady {
		t.Fatal("participant view missing peer ready")
	}
	if _, _, err := store.Mutate(testCall, "55555555-5555-4555-8555-555555555558", testAccount, testCaller, Ended); err != nil {
		t.Fatal(err)
	}
	if store.ValidateMedia(testCall, "caller", caller.MediaToken) {
		t.Fatal("terminal call authorized media")
	}
}

func TestCallerCancelCalleeRejectAndMutationIdempotency(t *testing.T) {
	store := New(30 * time.Second)
	createTestCall(t, store)
	if _, _, err := store.Mutate(testCall, "55555555-5555-4555-8555-555555555559", testAccount, testCallee, Cancelled); err == nil {
		t.Fatal("callee cancelled")
	}
	view, applied, err := store.Mutate(testCall, "55555555-5555-4555-8555-555555555560", testAccount, testCaller, Cancelled)
	if err != nil || !applied || view.State != Cancelled {
		t.Fatalf("cancel=%+v applied=%v err=%v", view, applied, err)
	}
	view, applied, err = store.Mutate(testCall, "55555555-5555-4555-8555-555555555560", testAccount, testCaller, Cancelled)
	if err != nil || applied || view.MutationApplied == nil || *view.MutationApplied {
		t.Fatalf("duplicate mutation=%+v applied=%v err=%v", view, applied, err)
	}

	rejectStore := New(30 * time.Second)
	createTestCall(t, rejectStore)
	if _, _, err := rejectStore.Mutate(testCall, "55555555-5555-4555-8555-555555555561", testAccount, testCaller, Rejected); err == nil {
		t.Fatal("caller rejected")
	}
	if view, _, err := rejectStore.Mutate(testCall, "55555555-5555-4555-8555-555555555562", testAccount, testCallee, Rejected); err != nil || view.State != Rejected {
		t.Fatalf("reject=%+v err=%v", view, err)
	}
}

func TestCreateIdempotencyAndOneActiveCallPerDevice(t *testing.T) {
	store := New(30 * time.Second)
	first := createTestCall(t, store)
	duplicate, created, err := store.Create(testCall, "55555555-5555-4555-8555-555555555555", testAccount, testCaller, testCallee)
	if err != nil || created || duplicate.CallID != first.CallID {
		t.Fatalf("duplicate=%+v created=%v err=%v", duplicate, created, err)
	}
	if _, _, err := store.Create("77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", testAccount, testCaller, "99999999-9999-4999-8999-999999999999"); err == nil {
		t.Fatal("busy caller entered second call")
	}
	if _, _, err := store.Create("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", testAccount, "99999999-9999-4999-8999-999999999999", testCallee); err == nil {
		t.Fatal("busy callee entered second call")
	}
	if _, _, err := store.Create(testCall, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", testAccount, testCaller, testCallee); err == nil {
		t.Fatal("existing callID accepted")
	}
}

func securePackage(side Side, device string) KeyPackage {
	return KeyPackage{ProtocolVersion: 2, KeyEpoch: 1, CallID: testCall,
		UserID: "99999999-9999-4999-8999-999999999999", DeviceID: device, Side: side,
		EphemeralPublicKey: "opaque-public", Signature: "opaque-signature"}
}

func TestSecureAccountCallRequiresBothBoundPackagesAndProtocolTwo(t *testing.T) {
	store := New(30 * time.Second)
	callerPackage := securePackage(SideCaller, testCaller)
	created, fresh, err := store.CreateSecure(testCall, "55555555-5555-4555-8555-555555555570", testAccount, callerPackage.UserID, testCaller, testCallee, callerPackage)
	if err != nil || !fresh || created.CallerKeyPackage == nil || store.RequiredMediaProtocol(testCall) != 2 {
		t.Fatalf("secure create=%+v fresh=%v err=%v protocol=%d", created, fresh, err, store.RequiredMediaProtocol(testCall))
	}
	if _, _, err = store.Mutate(testCall, "55555555-5555-4555-8555-555555555571", testAccount, testCallee, Accepted); err == nil {
		t.Fatal("secure call accepted without callee package")
	}
	calleePackage := securePackage(SideCallee, testCallee)
	accepted, applied, err := store.MutateSecure(testCall, "55555555-5555-4555-8555-555555555572", testAccount, testCallee, Accepted, &calleePackage)
	if err != nil || !applied || accepted.CalleeKeyPackage == nil || accepted.MediaToken == "" {
		t.Fatalf("secure accept=%+v applied=%v err=%v", accepted, applied, err)
	}
	if store.RequiredMediaProtocol(testCall) != 2 {
		t.Fatal("secure media protocol downgraded")
	}
}

func TestLegacyAndSecureIdempotencyCannotChangeModeOrPackages(t *testing.T) {
	legacy := New(30 * time.Second)
	createTestCall(t, legacy)
	packageValue := securePackage(SideCallee, testCallee)
	if _, _, err := legacy.MutateSecure(testCall, "55555555-5555-4555-8555-555555555573", testAccount, testCallee, Accepted, &packageValue); err == nil {
		t.Fatal("legacy call accepted with secure package")
	}
	if legacy.RequiredMediaProtocol(testCall) != 1 { t.Fatal("legacy protocol changed") }

	secure := New(30 * time.Second)
	caller := securePackage(SideCaller, testCaller)
	if _, _, err := secure.CreateSecure(testCall, "55555555-5555-4555-8555-555555555574", testAccount, caller.UserID, testCaller, testCallee, caller); err != nil { t.Fatal(err) }
	changed := caller; changed.KeyEpoch = 2
	if _, _, err := secure.CreateSecure(testCall, "55555555-5555-4555-8555-555555555574", testAccount, caller.UserID, testCaller, testCallee, changed); err == nil {
		t.Fatal("idempotent create replaced caller package")
	}
}

func TestRingExpiryDeliveryFailureAndTerminalGC(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	store := New(time.Second)
	store.SetClock(func() time.Time { return now })
	createTestCall(t, store)
	now = now.Add(2 * time.Second)
	view, err := store.Get(testCall, testAccount, testCaller)
	if err != nil || view.State != Expired || view.TerminalReason != "ring_timeout" {
		t.Fatalf("expired=%+v err=%v", view, err)
	}

	delivery := New(30 * time.Second)
	createTestCall(t, delivery)
	delivery.FailDelivery(testCall, "BadDeviceToken")
	view, err = delivery.Get(testCall, testAccount, testCaller)
	if err != nil || view.State != Expired || view.DeliveryStatus == "" {
		t.Fatalf("delivery failure=%+v err=%v", view, err)
	}

	now = now.Add(11 * time.Minute)
	store.SetClock(func() time.Time { return now })
	_, _, _ = store.Create("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", testAccount, "ffffffff-ffff-4fff-8fff-ffffffffffff", "12121212-1212-4212-8212-121212121212")
	if _, err := store.Get(testCall, testAccount, testCaller); err == nil {
		t.Fatal("terminal call not garbage collected")
	}
}
