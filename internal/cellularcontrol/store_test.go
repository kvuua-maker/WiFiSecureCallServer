package cellularcontrol

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testPhone = "+380501234567"

func participants() (Participant, Participant) {
	return Participant{
		UserID: "11111111-1111-4111-8111-111111111111", AccountID: "22222222-2222-4222-8222-222222222222",
		DeviceID: "33333333-3333-4333-8333-333333333333", Platform: "watchOS",
	}, Participant{
		UserID: "11111111-1111-4111-8111-111111111111", AccountID: "22222222-2222-4222-8222-222222222222",
		DeviceID: "44444444-4444-4444-8444-444444444444", Platform: "iOS",
	}
}

func TestCreateIsSameOwnerWatchToIPhoneAndIdempotent(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	view, created, err := store.Create(id, source, target, testPhone)
	if err != nil || !created || view.State != DeliveryPending || view.DeliveryStatus != "pending" || !view.SameOwnerAuthorized {
		t.Fatalf("create view=%+v created=%v err=%v", view, created, err)
	}
	duplicate, created, err := store.Create(id, source, target, testPhone)
	if err != nil || created || duplicate.RequestID != id {
		t.Fatalf("duplicate view=%+v created=%v err=%v", duplicate, created, err)
	}
	changedTarget := target
	changedTarget.DeviceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	duplicate, created, err = store.Create(id, source, changedTarget, testPhone)
	if err != nil || created || duplicate.RequestID != id {
		t.Fatalf("retargeted retry view=%+v created=%v err=%v", duplicate, created, err)
	}
	existing, found, err := store.ExistingCreate(id, source, testPhone)
	if err != nil || !found || existing.RequestID != id {
		t.Fatalf("existing retry view=%+v found=%v err=%v", existing, found, err)
	}
	if _, _, err = store.Create(id, source, target, "+380671234567"); errorCode(err) != "request_conflict" {
		t.Fatalf("changed parameters error=%v", err)
	}
	if _, found, err = store.ExistingCreate(id, source, "+380671234567"); found || errorCode(err) != "request_conflict" {
		t.Fatalf("changed retry found=%v error=%v", found, err)
	}
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || contains(string(encoded), testPhone) || contains(string(encoded), "phoneNumber") {
		t.Fatalf("public view leaked phone: %s", encoded)
	}
}

func TestCreateRejectsCrossUserAndWrongPlatforms(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	target.UserID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	if _, _, err := store.Create("55555555-5555-4555-8555-555555555555", source, target, testPhone); errorCode(err) != "invalid_request" {
		t.Fatalf("cross-user err=%v", err)
	}
	target.UserID = source.UserID
	source.Platform = "iOS"
	if _, _, err := store.Create("66666666-6666-4666-8666-666666666666", source, target, testPhone); errorCode(err) != "invalid_request" {
		t.Fatalf("non-watch source err=%v", err)
	}
}

func TestOnlySnapshottedParticipantsCanReadOrMutate(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	outsider := target
	outsider.DeviceID = "99999999-9999-4999-8999-999999999999"
	if _, err := store.Get(id, outsider); errorCode(err) != "request_not_participant" {
		t.Fatalf("outsider get err=%v", err)
	}
	if _, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", source, ReceiptBackground); errorCode(err) != "request_not_participant" {
		t.Fatalf("source receive err=%v", err)
	}
	if _, err := store.Cancel(id, "77777777-7777-4777-8777-777777777777", target); errorCode(err) != "request_not_participant" {
		t.Fatalf("target cancel err=%v", err)
	}
}

func TestReceiveDeliveryAndAtomicClaimAllowExactlyOneStart(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if view, err := store.MarkDelivery(id, true); err != nil || view.DeliveryStatus != "submission_accepted" || view.State != DeliveryPending {
		t.Fatalf("delivery view=%+v err=%v", view, err)
	}
	if view, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptForeground); err != nil || view.State != IPhoneActionRequired || view.ReceiptContext != ReceiptForeground {
		t.Fatalf("receive view=%+v err=%v", view, err)
	}

	var winners atomic.Int32
	var wg sync.WaitGroup
	for index := 0; index < 32; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			mutation := mutationID(index)
			grant, err := store.ClaimStart(id, mutation, target)
			if err == nil && grant.PhoneNumber != "" {
				if grant.PhoneNumber != testPhone || grant.MutationApplied == nil || !*grant.MutationApplied {
					t.Errorf("unsafe grant=%+v", grant)
				}
				winners.Add(1)
			}
		}(index)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
	view, err := store.Get(id, target)
	if err != nil || view.State != IPhoneStartAuthorized {
		t.Fatalf("post-claim view=%+v err=%v", view, err)
	}
}

func TestDuplicateStartMutationNeverReleasesPhoneTwice(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	mutation := "66666666-6666-4666-8666-666666666666"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Receive(id, "77777777-7777-4777-8777-777777777777", target, ReceiptBackground); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimStart(id, mutation, target)
	if err != nil || first.PhoneNumber != testPhone || first.MutationApplied == nil || !*first.MutationApplied {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	duplicate, err := store.ClaimStart(id, mutation, target)
	if err != nil || duplicate.PhoneNumber != "" || duplicate.MutationApplied == nil || *duplicate.MutationApplied {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	if view, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target); err != nil || view.State != IPhoneBackgroundStartAttempted {
		t.Fatalf("start attempted view=%+v err=%v", view, err)
	}
	if view, err := store.MarkStartResult(id, "99999999-9999-4999-8999-999999999999", target, StartAccepted, "", nil); err != nil || view.State != SystemStartAccepted || view.StartResult != StartAccepted {
		t.Fatalf("start result view=%+v err=%v", view, err)
	}
}

func TestBackgroundPublicStartErrorIsSafeVisibleAndImmutable(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	received, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptBackground)
	if err != nil || received.State != IPhoneBackgroundReceived || received.ReceiptContext != ReceiptBackground || received.ReceivedAt == nil {
		t.Fatalf("received=%+v err=%v", received, err)
	}
	grant, err := store.ClaimStart(id, "77777777-7777-4777-8777-777777777777", target)
	if err != nil || grant.PhoneNumber != testPhone {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
	store.mu.Lock()
	phoneAfterClaim := store.controls[id].phoneNumber
	store.mu.Unlock()
	if phoneAfterClaim != "" {
		t.Fatal("phone remained after claim")
	}
	attempted, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target)
	if err != nil || attempted.State != IPhoneBackgroundStartAttempted || attempted.ReceivedAt == nil || attempted.StartAttemptedAt == nil {
		t.Fatalf("attempted=%+v err=%v", attempted, err)
	}
	code := 7
	failed, err := store.MarkStartResult(id, "99999999-9999-4999-8999-999999999999", target, StartError, SafePublicErrorDomain, &code)
	if err != nil || failed.State != PublicStartError || failed.StartResult != StartError || failed.SafeErrorDomain != SafePublicErrorDomain || failed.SafeErrorCode == nil || *failed.SafeErrorCode != code || failed.ReceivedAt == nil || failed.StartAttemptedAt == nil || failed.StartResultAt == nil {
		t.Fatalf("failed=%+v err=%v", failed, err)
	}
	encoded, err := json.Marshal(failed)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(encoded), testPhone) || contains(string(encoded), "localizedDescription") {
		t.Fatalf("unsafe public result: %s", encoded)
	}
	duplicate, err := store.MarkStartResult(id, "99999999-9999-4999-8999-999999999999", target, StartError, SafePublicErrorDomain, &code)
	if err != nil || duplicate.MutationApplied == nil || *duplicate.MutationApplied || duplicate.State != PublicStartError {
		t.Fatalf("duplicate=%+v err=%v", duplicate, err)
	}
	if _, err := store.MarkStartResult(id, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", target, StartAccepted, "", nil); errorCode(err) != "system_start_result_already_reported" {
		t.Fatalf("conflicting result err=%v", err)
	}
}

func TestReceiptContextIsFirstObservedAndValidated(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptContext("invented")); errorCode(err) != "invalid_request" {
		t.Fatalf("invalid context err=%v", err)
	}
	first, err := store.Receive(id, "77777777-7777-4777-8777-777777777777", target, ReceiptBackground)
	if err != nil || first.ReceiptContext != ReceiptBackground {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := store.Receive(id, "88888888-8888-4888-8888-888888888888", target, ReceiptForeground)
	if err != nil || second.ReceiptContext != ReceiptBackground || second.MutationApplied == nil || *second.MutationApplied {
		t.Fatalf("second=%+v err=%v", second, err)
	}
}

func TestInactiveReceiptUsesBackgroundAttemptPath(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	received, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptInactive)
	if err != nil || received.State != IPhoneBackgroundReceived || received.ReceiptContext != ReceiptInactive {
		t.Fatalf("received=%+v err=%v", received, err)
	}
	if _, err := store.ClaimStart(id, "77777777-7777-4777-8777-777777777777", target); err != nil {
		t.Fatal(err)
	}
	attempted, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target)
	if err != nil || attempted.State != IPhoneBackgroundStartAttempted {
		t.Fatalf("attempted=%+v err=%v", attempted, err)
	}
}

func TestCancellationBeforeStartAndHonestSemanticsAfterAuthorization(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	first := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(first, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	cancelled, err := store.Cancel(first, "66666666-6666-4666-8666-666666666666", source)
	if err != nil || cancelled.State != Cancelled || cancelled.TerminalReason != "cancelled_before_system_start" {
		t.Fatalf("cancel=%+v err=%v", cancelled, err)
	}

	second := "77777777-7777-4777-8777-777777777777"
	if _, _, err := store.Create(second, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Receive(second, "88888888-8888-4888-8888-888888888888", target, ReceiptForeground); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimStart(second, "99999999-9999-4999-8999-999999999999", target); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel(second, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", source); errorCode(err) != "system_start_already_authorized" {
		t.Fatalf("post-start cancel err=%v", err)
	}
}

func TestTTLExpiresAndRedactsWithoutFurtherRequest(t *testing.T) {
	store := New(20 * time.Millisecond)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkDelivery(id, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	view, err := store.Get(id, source)
	if err != nil || view.State != Expired || view.TerminalReason != "background_execution_not_observed" {
		t.Fatalf("expired view=%+v err=%v", view, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.controls[id].phoneNumber != "" {
		t.Fatal("phone remained after expiry")
	}
}

func TestUnsubmittedRequestExpiryIsNotReportedAsMissedBackgroundExecution(t *testing.T) {
	store := New(20 * time.Millisecond)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	view, err := store.Get(id, target)
	if err != nil || view.State != Expired || view.TerminalReason != "request_expired" {
		t.Fatalf("expired view=%+v err=%v", view, err)
	}
}

func TestAttemptWithoutPublicResultExpiresDistinctly(t *testing.T) {
	store := New(20 * time.Millisecond)
	store.startResultGrace = 20 * time.Millisecond
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptBackground); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimStart(id, "77777777-7777-4777-8777-777777777777", target); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	view, err := store.Get(id, source)
	if err != nil || view.State != Expired || view.TerminalReason != "public_start_result_not_observed" {
		t.Fatalf("expired attempt view=%+v err=%v", view, err)
	}
}

func TestClaimNearOriginalExpiryHasBoundedResultReportingGrace(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	store.startResultGrace = 30 * time.Second
	base := time.Now().UTC()
	now := base
	store.now = func() time.Time { return now }
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	now = base.Add(time.Minute - time.Millisecond)
	if _, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptBackground); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimStart(id, "77777777-7777-4777-8777-777777777777", target); err != nil {
		t.Fatal(err)
	}
	now = base.Add(time.Minute + time.Second)
	if view, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target); err != nil || view.State != IPhoneBackgroundStartAttempted {
		t.Fatalf("attempt after original expiry view=%+v err=%v", view, err)
	}
	if view, err := store.MarkStartResult(id, "99999999-9999-4999-8999-999999999999", target, StartAccepted, "", nil); err != nil || view.State != SystemStartAccepted {
		t.Fatalf("result after original expiry view=%+v err=%v", view, err)
	}
}

func TestLateDeliveryResultCannotOverwriteProgressOrTerminalResult(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Receive(id, "66666666-6666-4666-8666-666666666666", target, ReceiptBackground); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimStart(id, "77777777-7777-4777-8777-777777777777", target); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkStartAttempted(id, "88888888-8888-4888-8888-888888888888", target); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkStartResult(id, "99999999-9999-4999-8999-999999999999", target, StartAccepted, "", nil); err != nil {
		t.Fatal(err)
	}
	view, err := store.MarkDelivery(id, false)
	if err != nil || view.State != SystemStartAccepted || view.DeliveryStatus != "submission_failed" {
		t.Fatalf("late delivery view=%+v err=%v", view, err)
	}
}

func TestDeliveryFailureClearsPhoneAndCannotBeClaimed(t *testing.T) {
	store := New(time.Minute)
	defer store.Close()
	source, target := participants()
	id := "55555555-5555-4555-8555-555555555555"
	if _, _, err := store.Create(id, source, target, testPhone); err != nil {
		t.Fatal(err)
	}
	view, err := store.MarkDelivery(id, false)
	if err != nil || view.State != FailedSafe || view.DeliveryStatus != "submission_failed" {
		t.Fatalf("failed delivery view=%+v err=%v", view, err)
	}
	if _, err := store.ClaimStart(id, "66666666-6666-4666-8666-666666666666", target); errorCode(err) != "request_not_ready" {
		t.Fatalf("claim after failure err=%v", err)
	}
	preserved, err := store.Cancel(id, "77777777-7777-4777-8777-777777777777", source)
	if err != nil || preserved.State != FailedSafe || preserved.TerminalReason != "iphone_delivery_failed" || preserved.MutationApplied == nil || *preserved.MutationApplied {
		t.Fatalf("cancel after failure view=%+v err=%v", preserved, err)
	}
}

func errorCode(err error) string {
	if value, ok := err.(*Error); ok {
		return value.Code
	}
	return ""
}

func contains(value, fragment string) bool {
	return len(fragment) > 0 && stringsContains(value, fragment)
}

func stringsContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func mutationID(index int) string {
	const alphabet = "0123456789abcdef"
	byteValue := alphabet[index%len(alphabet)]
	return "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa" + string(byteValue)
}
