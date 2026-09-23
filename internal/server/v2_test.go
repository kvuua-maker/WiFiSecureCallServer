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
