package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

func TestV3FanoutIncludesReadyDevicesAcrossEveryActiveTargetAccount(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	secondAccountID := "20202020-2020-4020-8020-202020202020"
	secondDeviceID := "21212121-2121-4121-8121-212121212121"
	secondToken := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	now := time.Now().UTC()
	if err := fixture.accountStore.Update(func(state *accounts.State) error {
		state.Accounts[secondAccountID] = accounts.Account{
			AccountID: secondAccountID, UserID: fixture.targetUserID,
			CreatedAt: now, Status: "active",
		}
		state.Devices = append(state.Devices, accounts.Device{
			AccountID: secondAccountID, DeviceID: secondDeviceID, Platform: "watchOS",
			AlertToken: secondToken, Environment: "production", InstallationGeneration: 1,
			Capabilities: accounts.DeviceCapabilities{
				AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true,
			},
			CreatedAt: now, LastSeenAt: now,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	callID := "22222222-2222-4222-8222-222222222222"
	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, map[string]string{
		"requestID": "23232323-2323-4323-8323-232323232323",
		"callID":    callID, "targetUserID": fixture.targetUserID,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", response.Code, response.Body.String())
	}
	pushes := waitForPushes(t, fixture.push, 3)
	accountsSeen := map[string]bool{}
	for _, push := range pushes {
		accountsSeen[push.accountID] = true
	}
	if !accountsSeen[fixture.targetIOS.Account.AccountID] || !accountsSeen[secondAccountID] {
		t.Fatalf("fanout accounts=%v", accountsSeen)
	}
}

func TestV3ExcludesNonReadyDevicesWithoutBlockingReadySibling(t *testing.T) {
	fixture := newUserCallFixture(t, nil)
	now := time.Now().UTC()
	if err := fixture.accountStore.Update(func(state *accounts.State) error {
		state.Devices = append(state.Devices,
			accounts.Device{AccountID: fixture.targetIOS.Account.AccountID, DeviceID: "26262626-2626-4626-8626-262626262626", Platform: "watchOS", AlertToken: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", Environment: "production", InstallationGeneration: 1, Capabilities: accounts.DeviceCapabilities{AlertPush: true, NotificationsAuthorized: false, MicrophoneReady: true}, CreatedAt: now, LastSeenAt: now},
		)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/calls", fixture.caller.AccessToken, map[string]string{
		"requestID": "27272727-2727-4727-8727-272727272727",
		"callID":    "28282828-2828-4828-8828-282828282828", "targetUserID": fixture.targetUserID,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", response.Code, response.Body.String())
	}
	pushes := waitForPushes(t, fixture.push, 2)
	if len(pushes) != 2 {
		t.Fatalf("ready sibling fanout=%+v", pushes)
	}
}
