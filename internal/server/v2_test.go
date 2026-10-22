package server

import (
	"strings"
	"testing"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

func TestAccountDeviceCallReadyMatchesProvenPlatformRoutes(t *testing.T) {
	ready := accounts.Device{Environment: "production", Capabilities: accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}, AlertToken: strings.Repeat("a", 64), VoIPToken: strings.Repeat("b", 64)}
	ready.Platform = "iOS"
	if !accountDeviceCallReady(ready) {
		t.Fatal("ready iOS device rejected")
	}
	missingVoIP := ready
	missingVoIP.VoIPToken = ""
	if accountDeviceCallReady(missingVoIP) {
		t.Fatal("iOS without VoIP token reported ready")
	}
	ready.Platform = "watchOS"
	if !accountDeviceCallReady(ready) {
		t.Fatal("ready Watch device rejected")
	}
	unauthorized := ready
	unauthorized.Capabilities.NotificationsAuthorized = false
	if accountDeviceCallReady(unauthorized) {
		t.Fatal("notification-disabled Watch reported ready")
	}
	nonProduction := ready
	nonProduction.Environment = "development"
	if accountDeviceCallReady(nonProduction) {
		t.Fatal("non-production device reported ready")
	}
}

func TestAccountIncomingPushSelectionPreservesPlatformPreferences(t *testing.T) {
	device := accounts.Device{Environment: "production", Capabilities: accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true}, AlertToken: strings.Repeat("a", 64), VoIPToken: strings.Repeat("b", 64)}
	device.Platform = "iOS"
	if token, kind := selectAccountIncomingPush(device); token != device.VoIPToken || kind != "voip" {
		t.Fatalf("iOS selection token=%q kind=%q", token, kind)
	}
	device.VoIPToken = ""
	if token, kind := selectAccountIncomingPush(device); token != device.AlertToken || kind != "alert" {
		t.Fatalf("iOS fallback token=%q kind=%q", token, kind)
	}
	device.Platform, device.VoIPToken = "watchOS", strings.Repeat("b", 64)
	if token, kind := selectAccountIncomingPush(device); token != device.AlertToken || kind != "alert" {
		t.Fatalf("Watch selection token=%q kind=%q", token, kind)
	}
	device.AlertToken = ""
	if token, kind := selectAccountIncomingPush(device); token != device.VoIPToken || kind != "voip" {
		t.Fatalf("Watch fallback token=%q kind=%q", token, kind)
	}
}

func TestCompanionIPhonesWakesOnlyTheOwnersProductionIPhones(t *testing.T) {
	watch := accounts.Device{AccountID: "account-1", DeviceID: "watch-1", Platform: "watchOS"}
	watch.Environment = "production"
	iphone := accounts.Device{AccountID: "account-1", DeviceID: "phone-1", Platform: "iOS", VoIPToken: strings.Repeat("b", 64)}
	iphone.Environment = "production"
	iphone.Capabilities = accounts.DeviceCapabilities{VoIPPush: true}

	otherAccount := iphone
	otherAccount.AccountID = "account-2"
	otherAccount.DeviceID = "phone-2"

	noCapability := iphone
	noCapability.DeviceID = "phone-3"
	noCapability.Capabilities = accounts.DeviceCapabilities{}

	development := iphone
	development.DeviceID = "phone-4"
	development.Environment = "development"

	noToken := iphone
	noToken.DeviceID = "phone-5"
	noToken.VoIPToken = ""

	companions := companionIPhones(
		[]accounts.Device{watch, iphone, otherAccount, noCapability, development, noToken},
		watch,
	)
	if len(companions) != 1 || companions[0].DeviceID != "phone-1" {
		t.Fatalf("companions = %+v, want only phone-1", companions)
	}
}

func TestCompanionIPhonesIgnoresACallAddressedToAnIPhone(t *testing.T) {
	iphone := accounts.Device{AccountID: "account-1", DeviceID: "phone-1", Platform: "iOS", VoIPToken: strings.Repeat("b", 64)}
	iphone.Environment = "production"
	iphone.Capabilities = accounts.DeviceCapabilities{VoIPPush: true}
	if companions := companionIPhones([]accounts.Device{iphone}, iphone); len(companions) != 0 {
		t.Fatalf("an iPhone call must not wake itself, got %+v", companions)
	}
}

func TestCallAttemptNeedsOnlyAPushToken(t *testing.T) {
	watch := accounts.Device{Platform: "watchOS", AlertToken: strings.Repeat("a", 64)}
	watch.Environment = "production"
	watch.Capabilities = accounts.DeviceCapabilities{MicrophoneReady: true, AlertPush: true}

	// Notifications were never authorised, so listing must not call it ready…
	if accountDeviceCallReady(watch) {
		t.Fatal("a watch without notification authorisation must not be listed as ready")
	}
	// …but a call to it must still be attempted, because an alert token exists.
	if !accountDeviceCallAttemptable(watch) {
		t.Fatal("a watch with an alert token must be callable")
	}

	noToken := watch
	noToken.AlertToken = ""
	if accountDeviceCallAttemptable(noToken) {
		t.Fatal("a watch with no token must not be attempted")
	}

	development := watch
	development.Environment = "development"
	if accountDeviceCallAttemptable(development) {
		t.Fatal("a development device must not be attempted")
	}
}
