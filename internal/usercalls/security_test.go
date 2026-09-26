package usercalls

import (
	"sync"
	"testing"
	"time"
)

func TestRejectAfterWinnerCannotTerminateAcceptedCall(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	winner, _, err := store.Mutate(testCall, "30303030-3030-4030-8030-303030303030", targetParticipant(targetDeviceA), Accepted)
	if err != nil || winner.MediaToken == "" {
		t.Fatalf("winner=%+v err=%v", winner, err)
	}
	loser, applied, err := store.Mutate(testCall, "31313131-3131-4131-8131-313131313131", targetParticipant(targetDeviceB), Rejected)
	if err != nil || applied || loser.State != Accepted || loser.LegState != LegAnsweredElsewhere || loser.MediaToken != "" {
		t.Fatalf("loser reject=%+v applied=%v err=%v", loser, applied, err)
	}
	stillAccepted, err := store.Get(testCall, callerParticipant())
	if err != nil || stillAccepted.State != Accepted || stillAccepted.MediaToken == "" {
		t.Fatalf("accepted call was damaged: %+v err=%v", stillAccepted, err)
	}
}

func TestCallerCancelIsWholeCallAndLateAcceptCannotWin(t *testing.T) {
	store := New(30 * time.Second)
	createTwoTargetCall(t, store)
	cancelRequest := "32323232-3232-4232-8232-323232323232"
	view, applied, err := store.Mutate(testCall, cancelRequest, callerParticipant(), Cancelled)
	if err != nil || !applied || view.State != Cancelled {
		t.Fatalf("cancel=%+v applied=%v err=%v", view, applied, err)
	}
	duplicate, applied, err := store.Mutate(testCall, cancelRequest, callerParticipant(), Cancelled)
	if err != nil || applied || duplicate.State != Cancelled {
		t.Fatalf("duplicate cancel=%+v applied=%v err=%v", duplicate, applied, err)
	}
	if _, _, err := store.Mutate(testCall, "33333333-3333-4333-8333-333333333333", targetParticipant(targetDeviceA), Accepted); ErrorCode(err) != "answered_elsewhere" {
		t.Fatalf("late accept error=%v", err)
	}
}

func TestConcurrentDeliveryFailuresCannotOverrideWinner(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		store := New(30 * time.Second)
		createTwoTargetCall(t, store)
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _, _ = store.Mutate(testCall, "34343434-3434-4434-8434-343434343434", targetParticipant(targetDeviceA), Accepted)
		}()
		go func() {
			defer wait.Done()
			<-start
			store.SetDelivery(testCall, targetAccount, targetDeviceB, false, "Unregistered")
		}()
		close(start)
		wait.Wait()
		view, err := store.Get(testCall, callerParticipant())
		if err != nil || view.State != Accepted || view.MediaToken == "" {
			t.Fatalf("iteration=%d view=%+v err=%v", iteration, view, err)
		}
	}
}

func TestWinnerOnlyCanEndAndCallerCanEnd(t *testing.T) {
	for _, ender := range []Participant{targetParticipant(targetDeviceA), callerParticipant()} {
		store := New(30 * time.Second)
		createTwoTargetCall(t, store)
		if _, _, err := store.Mutate(testCall, "35353535-3535-4535-8535-353535353535", targetParticipant(targetDeviceA), Accepted); err != nil {
			t.Fatal(err)
		}
		ended, applied, err := store.Mutate(testCall, "36363636-3636-4636-8636-363636363636", ender, Ended)
		if err != nil || !applied || ended.State != Ended || ended.MediaToken != "" {
			t.Fatalf("ender=%+v ended=%+v applied=%v err=%v", ender, ended, applied, err)
		}
	}
}
