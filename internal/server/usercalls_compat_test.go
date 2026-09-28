package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
)

func TestV3SkipsDeviceBusyInExistingV2Call(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	legacyCallID := "37373737-3737-4737-8737-373737373737"
	_, _, err := fixture.accountCalls.Create(
		legacyCallID,
		"38383838-3838-4838-8838-383838383838",
		fixture.targetIOS.Account.AccountID,
		fixture.targetIOS.DeviceID,
		"39393939-3939-4939-8939-393939393939",
	)
	if err != nil {
		t.Fatal(err)
	}

	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "40404040-4040-4040-8040-404040404040", "41414141-4141-4141-8141-414141414141", fixture.targetUserID))
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", response.Code, response.Body.String())
	}
	_ = waitForPushes(t, fixture.push, 1)
	time.Sleep(50 * time.Millisecond)
	pushes := fixture.push.snapshot()
	if len(pushes) != 1 || pushes[0].platform != "watchOS" {
		t.Fatalf("busy device was not isolated: %+v", pushes)
	}
}

func TestV2AndV3CallIDNamespacesCannotCollide(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	callID := "42424242-4242-4242-8242-424242424242"
	if _, _, err := fixture.accountCalls.Create(
		callID,
		"43434343-4343-4343-8343-434343434343",
		fixture.targetIOS.Account.AccountID,
		fixture.targetIOS.DeviceID,
		fixture.targetWatch.DeviceID,
	); err != nil {
		t.Fatal(err)
	}

	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, fixtureCreateBody(t, fixture, "44444444-4444-4444-8444-444444444444", callID, fixture.targetUserID))
	if response.Code != http.StatusConflict {
		t.Fatalf("cross-store collision status=%d body=%q", response.Code, response.Body.String())
	}
	if !fixture.accountCalls.HasCall(callID) || fixture.server.userCalls.HasCall(callID) {
		t.Fatal("call ID collision entered both media validators")
	}
}

func TestV2StoreBusyHelperPreservesTerminalAvailability(t *testing.T) {
	store := accountcalls.New(30 * time.Second)
	if store.DeviceBusy("45454545-4545-4545-8545-454545454545") {
		t.Fatal("empty V2 store reported a busy device")
	}
}
