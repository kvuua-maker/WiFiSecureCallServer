package usercalls

import (
	"sync"
	"testing"
	"time"
)

const (
	callerUser    = "11111111-1111-4111-8111-111111111111"
	callerAccount = "22222222-2222-4222-8222-222222222222"
	callerDevice  = "33333333-3333-4333-8333-333333333333"
	targetUser    = "44444444-4444-4444-8444-444444444444"
	targetAccount = "55555555-5555-4555-8555-555555555555"
	targetDeviceA = "66666666-6666-4666-8666-666666666666"
	targetDeviceB = "77777777-7777-4777-8777-777777777777"
	testCall      = "88888888-8888-4888-8888-888888888888"
	testRequest   = "99999999-9999-4999-8999-999999999999"
)

func callerParticipant() Participant {
	return Participant{UserID: callerUser, AccountID: callerAccount, DeviceID: callerDevice}
}

func targetParticipant(device string) Participant {
	return Participant{UserID: targetUser, AccountID: targetAccount, DeviceID: device}
}

func createTwoTargetCall(t *testing.T, store *Store) View {
	t.Helper()
	view, targets, created, err := store.Create(
		testCall, testRequest, callerParticipant(), targetUser,
		PublicCaller{Username: "caller.user", DisplayName: "Caller", PublicIdentity: "wsc:user:caller.user"},
		[]Target{{AccountID: targetAccount, DeviceID: targetDeviceA, Platform: "iOS"}, {AccountID: targetAccount, DeviceID: targetDeviceB, Platform: "watchOS"}},
	)
	if err != nil || !created || len(targets) != 2 {
		t.Fatalf("create view=%+v targets=%d created=%v err=%v", view, len(targets), created, err)
	}
	return view
}

func TestCreateSnapshotAuthorizationAndIdempotency(t *testing.T) {
	store := New(30 * time.Second)
	first := createTwoTargetCall(t, store)
	if first.State != Ringing || first.LocalSide != SideCaller {
		t.Fatalf("caller view=%+v", first)
	}
	duplicate, targets, created, err := store.Create(
		testCall, testRequest, callerParticipant(), targetUser,
		PublicCaller{Username: "ignored"},
		[]Target{{AccountID: targetAccount, DeviceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Platform: "iOS"}},
	)
	if err != nil || created || len(targets) != 0 || duplicate.CallID != testCall {
		t.Fatalf("duplicate=%+v targets=%v created=%v err=%v", duplicate, targets, created, err)
	}
	if _, err := store.Get(testCall, targetParticipant("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")); ErrorCode(err) != "call_not_participant" {
		t.Fatalf("later device accessed snapshot: %v", err)
	}
	if _, err := store.Get(testCall, Participant{UserID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", AccountID: targetAccount, DeviceID: targetDeviceA}); ErrorCode(err) != "call_not_participant" {
		t.Fatalf("unrelated user accessed call: %v", err)
	}
	if _, _, _, err := store.Create("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", testRequest, callerParticipant(), targetUser, PublicCaller{}, nil); ErrorCode(err) != "idempotency_conflict" {
		t.Fatalf("changed idempotency parameters: %v", err)
	}
	if _, _, _, err := store.Create("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", callerParticipant(), callerUser, PublicCaller{}, []Target{{AccountID: targetAccount, DeviceID: targetDeviceA}}); ErrorCode(err) != "self_call_not_allowed" {
		t.Fatalf("self call accepted: %v", err)
	}
}

func TestFirstAnswerWinsAndMediaIsCallerToWinnerOnly(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	winner, applied, err := store.Mutate(testCall, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", targetParticipant(targetDeviceA), Accepted)
	if err != nil || !applied || winner.State != Accepted || winner.LegState != LegAccepted || winner.MediaToken == "" {
		t.Fatalf("winner=%+v applied=%v err=%v", winner, applied, err)
	}
	caller, err := store.Get(testCall, callerParticipant())
	if err != nil || caller.MediaToken == "" || caller.MediaToken == winner.MediaToken {
		t.Fatalf("caller token invalid caller=%q winner=%q err=%v", caller.MediaToken, winner.MediaToken, err)
	}
	loser, applied, err := store.Mutate(testCall, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", targetParticipant(targetDeviceB), Accepted)
	if err != nil || applied || loser.LegState != LegAnsweredElsewhere || loser.MediaToken != "" {
		t.Fatalf("loser=%+v applied=%v err=%v", loser, applied, err)
	}
	if store.ValidateMedia(testCall, "callee", loser.MediaToken) || !store.ValidateMedia(testCall, "callee", winner.MediaToken) || !store.ValidateMedia(testCall, "caller", caller.MediaToken) {
		t.Fatal("media authorization did not remain caller/winner only")
	}
	if _, _, err := store.Mutate(testCall, "cccccccc-cccc-4ccc-8ccc-cccccccccccc", targetParticipant(targetDeviceB), Ended); ErrorCode(err) != "call_not_participant" {
		t.Fatalf("loser ended winner: %v", err)
	}
	if _, _, err := store.Mutate(testCall, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", targetParticipant(targetDeviceA), Ended); err != nil {
		t.Fatalf("winner could not end: %v", err)
	}
	if store.ValidateMedia(testCall, "caller", caller.MediaToken) || store.ValidateMedia(testCall, "callee", winner.MediaToken) {
		t.Fatal("ended call retained media authorization")
	}
}

func TestConcurrentAcceptChoosesExactlyOneImmutableWinner(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	type outcome struct {
		participant Participant
		view        View
		applied     bool
		err         error
	}
	start := make(chan struct{})
	results := make(chan outcome, 2)
	var wait sync.WaitGroup
	for index, participant := range []Participant{targetParticipant(targetDeviceA), targetParticipant(targetDeviceB)} {
		wait.Add(1)
		go func(index int, participant Participant) {
			defer wait.Done()
			<-start
			request := "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee" + string(rune('0'+index))
			view, applied, err := store.Mutate(testCall, request, participant, Accepted)
			results <- outcome{participant: participant, view: view, applied: applied, err: err}
		}(index, participant)
	}
	close(start)
	wait.Wait()
	close(results)
	winners := 0
	var winner Participant
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.applied {
			winners++
			winner = result.participant
			if result.view.MediaToken == "" || result.view.LegState != LegAccepted {
				t.Fatalf("winner missing token: %+v", result.view)
			}
		} else if result.view.MediaToken != "" || result.view.LegState != LegAnsweredElsewhere {
			t.Fatalf("loser received private winner state: %+v", result.view)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d", winners)
	}
	again, applied, err := store.Mutate(testCall, "ffffffff-ffff-4fff-8fff-ffffffffffff", winner, Accepted)
	if err != nil || applied || again.LegState != LegAccepted || again.MediaToken == "" {
		t.Fatalf("winner was not immutable/idempotent: %+v applied=%v err=%v", again, applied, err)
	}
}

func TestPerDeviceRejectPreservesOtherLegAndAllRejectTerminates(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	first, applied, err := store.Mutate(testCall, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", targetParticipant(targetDeviceA), Rejected)
	if err != nil || !applied || first.State != Ringing || first.LegState != LegRejected {
		t.Fatalf("first reject=%+v applied=%v err=%v", first, applied, err)
	}
	second, applied, err := store.Mutate(testCall, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2", targetParticipant(targetDeviceB), Rejected)
	if err != nil || !applied || second.State != Rejected || second.TerminalReason != "all_targets_rejected" {
		t.Fatalf("second reject=%+v applied=%v err=%v", second, applied, err)
	}
	duplicate, applied, err := store.Mutate(testCall, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2", targetParticipant(targetDeviceB), Rejected)
	if err != nil || applied || duplicate.State != Rejected {
		t.Fatalf("duplicate reject=%+v applied=%v err=%v", duplicate, applied, err)
	}
}

func TestPartialAndTotalDeliveryFailureAreIndependent(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	if applied, terminal := store.SetDelivery(testCall, targetAccount, targetDeviceA, false, "BadDeviceToken"); !applied || terminal {
		t.Fatalf("partial delivery failure applied=%v terminal=%v", applied, terminal)
	}
	view, _ := store.Get(testCall, callerParticipant())
	if view.State != Ringing {
		t.Fatalf("partial failure killed call: %+v", view)
	}
	if applied, terminal := store.SetDelivery(testCall, targetAccount, targetDeviceB, true, ""); !applied || terminal {
		t.Fatalf("accepted delivery applied=%v terminal=%v", applied, terminal)
	}
	view, _ = store.Get(testCall, callerParticipant())
	if view.State != Ringing || view.DeliveryStatus != "submission_accepted" {
		t.Fatalf("accepted delivery changed answer state: %+v", view)
	}

	allFail := New(30 * time.Second)
	createTwoTargetCall(t, allFail)
	allFail.SetDelivery(testCall, targetAccount, targetDeviceA, false, "BadDeviceToken")
	_, terminal := allFail.SetDelivery(testCall, targetAccount, targetDeviceB, false, "Unregistered")
	view, _ = allFail.Get(testCall, callerParticipant())
	if !terminal || view.State != Expired || view.TerminalReason != "delivery_failed" {
		t.Fatalf("all delivery failure=%+v terminal=%v", view, terminal)
	}
}

func TestBusyTargetFallbackAndCallerCancel(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	otherCaller := Participant{UserID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AccountID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", DeviceID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
	view, targets, created, err := store.Create(
		"dddddddd-dddd-4ddd-8ddd-dddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", otherCaller, targetUser,
		PublicCaller{Username: "other"},
		[]Target{{AccountID: targetAccount, DeviceID: targetDeviceA}, {AccountID: targetAccount, DeviceID: "ffffffff-ffff-4fff-8fff-ffffffffffff"}},
	)
	if err != nil || !created || len(targets) != 1 || targets[0].DeviceID != "ffffffff-ffff-4fff-8fff-ffffffffffff" || view.State != Ringing {
		t.Fatalf("busy fallback view=%+v targets=%+v created=%v err=%v", view, targets, created, err)
	}
	cancelled, applied, err := store.Mutate(testCall, "abababab-abab-4bab-8bab-abababababab", callerParticipant(), Cancelled)
	if err != nil || !applied || cancelled.State != Cancelled {
		t.Fatalf("cancel=%+v applied=%v err=%v", cancelled, applied, err)
	}
	callee, _ := store.Get(testCall, targetParticipant(targetDeviceB))
	if callee.LegState != LegCancelled {
		t.Fatalf("callee did not reconcile cancel: %+v", callee)
	}
}

func TestTimeoutRejectsLateAcceptAndDuplicateCreateReturnsTerminalState(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	store := New(30 * time.Second)
	store.SetClock(func() time.Time { return now })
	createTwoTargetCall(t, store)
	now = now.Add(31 * time.Second)
	if _, _, err := store.Mutate(testCall, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3", targetParticipant(targetDeviceA), Accepted); ErrorCode(err) != "call_expired" {
		t.Fatalf("late accept error=%v", err)
	}
	view, _, created, err := store.Create(testCall, testRequest, callerParticipant(), targetUser, PublicCaller{}, nil)
	if err != nil || created || view.State != Expired || view.TerminalReason != "ring_timeout" {
		t.Fatalf("terminal idempotency view=%+v created=%v err=%v", view, created, err)
	}
}
