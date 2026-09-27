package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/cellularcontrol"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
)

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type remoteControlPushFake struct {
	mu       sync.Mutex
	requests []remoteControlPush
	result   apns.Result
	err      error
}

type remoteControlPush struct {
	requestID, accountID string
	expiresAt            time.Time
}

func (f *remoteControlPushFake) Configured() bool { return true }
func (f *remoteControlPushFake) IncomingCall(context.Context, string, string, string, string, time.Time) (apns.Result, error) {
	return apns.Result{Status: http.StatusOK}, nil
}
func (f *remoteControlPushFake) RemoteCellularControl(_ context.Context, _ string, requestID string, expiresAt time.Time, accountID string) (apns.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, remoteControlPush{requestID: requestID, accountID: accountID, expiresAt: expiresAt})
	result := f.result
	if result.Status == 0 {
		result.Status = http.StatusOK
	}
	return result, f.err
}
func (f *remoteControlPushFake) snapshot() []remoteControlPush {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]remoteControlPush(nil), f.requests...)
}

func prepareRemoteControlFixture(t *testing.T) (userCallFixture, *remoteControlPushFake) {
	t.Helper()
	fixture := newUserCallFixture(t, nil)
	identity, err := fixture.auth.Authenticate(fixture.targetIOS.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	err = fixture.auth.RegisterDevice(identity, phoneauth.DeviceRegistration{
		RequestID: "a1111111-1111-4111-8111-111111111111", DeviceID: fixture.targetIOS.DeviceID,
		Platform: "iOS", PushType: "alert", Token: strings.Repeat("c", 64), InstallationGeneration: 1,
		Environment: "production", Capabilities: accounts.DeviceCapabilities{VoIPPush: true, AlertPush: true, NotificationsAuthorized: true, MicrophoneReady: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	fake := &remoteControlPushFake{}
	fixture.server.apns = fake
	return fixture, fake
}

func decodeCellularControlView(t *testing.T, responseBody []byte) cellularcontrol.View {
	t.Helper()
	var view cellularcontrol.View
	if err := json.Unmarshal(responseBody, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func waitForRemotePush(t *testing.T, fake *remoteControlPushFake, count int) []remoteControlPush {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if values := fake.snapshot(); len(values) >= count {
			return values
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("push count=%d want=%d", len(fake.snapshot()), count)
	return nil
}

func TestRemoteCellularTargetSelectionRequiresReadyIPhoneAndPrefersSameAccount(t *testing.T) {
	now := time.Now()
	source := phoneauth.Identity{AccountID: "11111111-1111-4111-8111-111111111111"}
	watchOnly := []accounts.Device{{
		AccountID: source.AccountID, DeviceID: "22222222-2222-4222-8222-222222222222", Platform: "watchOS",
		Environment: "production", AlertToken: strings.Repeat("a", 64),
		Capabilities: accounts.DeviceCapabilities{AlertPush: true, NotificationsAuthorized: true}, LastSeenAt: now,
	}}
	if _, ok := selectRemoteCellularIPhone(source, watchOnly); ok {
		t.Fatal("non-iOS target selected")
	}

	otherAccount := accounts.Device{
		AccountID: "33333333-3333-4333-8333-333333333333", DeviceID: "44444444-4444-4444-8444-444444444444", Platform: "iOS",
		Environment: "production", AlertToken: strings.Repeat("b", 64),
		Capabilities: accounts.DeviceCapabilities{AlertPush: true, NotificationsAuthorized: true}, LastSeenAt: now,
	}
	sameAccount := otherAccount
	sameAccount.AccountID = source.AccountID
	sameAccount.DeviceID = "55555555-5555-4555-8555-555555555555"
	sameAccount.LastSeenAt = now.Add(-time.Hour)
	selected, ok := selectRemoteCellularIPhone(source, append(watchOnly, otherAccount, sameAccount))
	if !ok || selected.DeviceID != sameAccount.DeviceID {
		t.Fatalf("selected=%+v ok=%v", selected, ok)
	}
}

func TestRemoteCellularControlSameOwnerWatchToIPhoneLifecycle(t *testing.T) {
	fixture, fake := prepareRemoteControlFixture(t)
	if fixture.targetWatch.Account.AccountID != fixture.targetIOS.Account.AccountID || fixture.targetWatch.User.UserID != fixture.targetIOS.User.UserID {
		t.Fatal("fixture is not same-owner linked Watch/iPhone")
	}
	controlID := "b1111111-1111-4111-8111-111111111111"
	phone := "+380501234567"
	var logs synchronizedBuffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": phone})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", created.Code, created.Body.String())
	}
	view := decodeCellularControlView(t, created.Body.Bytes())
	if view.State != cellularcontrol.DeliveryPending || !view.SameOwnerAuthorized || view.TargetPlatform != "iOS" || view.SourcePlatform != "watchOS" {
		t.Fatalf("create view=%+v", view)
	}
	pushes := waitForRemotePush(t, fake, 1)
	if pushes[0].requestID != controlID || pushes[0].accountID != fixture.targetIOS.Account.AccountID || pushes[0].expiresAt.IsZero() {
		t.Fatalf("push=%+v", pushes[0])
	}
	if strings.Contains(logs.String(), phone) {
		t.Fatal("phone appeared in ordinary logs")
	}

	received := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/receive", fixture.targetIOS.AccessToken, map[string]string{"requestID": "c1111111-1111-4111-8111-111111111111"})
	if received.Code != http.StatusOK || decodeCellularControlView(t, received.Body.Bytes()).State != cellularcontrol.IPhoneActionRequired {
		t.Fatalf("receive status=%d body=%q", received.Code, received.Body.String())
	}
	start := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start", fixture.targetIOS.AccessToken, map[string]string{"requestID": "d1111111-1111-4111-8111-111111111111"})
	if start.Code != http.StatusOK {
		t.Fatalf("start status=%d body=%q", start.Code, start.Body.String())
	}
	var grant cellularcontrol.StartGrant
	if err := json.Unmarshal(start.Body.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.State != cellularcontrol.IPhoneStartAuthorized || grant.PhoneNumber != phone || grant.MutationApplied == nil || !*grant.MutationApplied {
		t.Fatalf("grant=%+v", grant)
	}
	duplicate := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start", fixture.targetIOS.AccessToken, map[string]string{"requestID": "d1111111-1111-4111-8111-111111111111"})
	var duplicateGrant cellularcontrol.StartGrant
	if duplicate.Code != http.StatusOK || json.Unmarshal(duplicate.Body.Bytes(), &duplicateGrant) != nil || duplicateGrant.PhoneNumber != "" || duplicateGrant.MutationApplied == nil || *duplicateGrant.MutationApplied {
		t.Fatalf("duplicate status=%d grant=%+v", duplicate.Code, duplicateGrant)
	}
	started := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-requested", fixture.targetIOS.AccessToken, map[string]string{"requestID": "e1111111-1111-4111-8111-111111111111"})
	if started.Code != http.StatusOK || decodeCellularControlView(t, started.Body.Bytes()).State != cellularcontrol.IPhoneStartRequested {
		t.Fatalf("started status=%d body=%q", started.Code, started.Body.String())
	}
}

func TestRemoteCellularControlRejectsCrossUserArbitraryTargetAndInvalidInputs(t *testing.T) {
	fixture, _ := prepareRemoteControlFixture(t)
	controlID := "b1111111-1111-4111-8111-111111111111"
	wrongPlatform := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetIOS.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": "+380501234567"})
	if wrongPlatform.Code != http.StatusForbidden {
		t.Fatalf("iOS source status=%d", wrongPlatform.Code)
	}
	arbitrary := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": "+380501234567", "targetDeviceID": fixture.unrelated.DeviceID})
	if arbitrary.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary target status=%d", arbitrary.Code)
	}
	invalid := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": "0501234567"})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid phone status=%d", invalid.Code)
	}
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": "+380501234567"})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d", created.Code)
	}
	outsider := performUserRequest(t, fixture.server, http.MethodGet, "/v3/cellular-controls/"+controlID, fixture.unrelated.AccessToken, nil)
	if outsider.Code != http.StatusForbidden {
		t.Fatalf("cross-user get status=%d body=%q", outsider.Code, outsider.Body.String())
	}
}

func TestRemoteCellularControlCreateIsIdempotentAndCancelDoesNotTerminateCarrierCall(t *testing.T) {
	fixture, fake := prepareRemoteControlFixture(t)
	controlID := "b1111111-1111-4111-8111-111111111111"
	body := map[string]string{"requestID": controlID, "phoneNumber": "+380501234567"}
	for index := 0; index < 2; index++ {
		response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, body)
		if response.Code != http.StatusOK {
			t.Fatalf("create %d status=%d", index, response.Code)
		}
	}
	if got := len(waitForRemotePush(t, fake, 1)); got != 1 {
		t.Fatalf("push count=%d", got)
	}
	cancelled := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/cancel", fixture.targetWatch.AccessToken, map[string]string{"requestID": "c1111111-1111-4111-8111-111111111111"})
	if cancelled.Code != http.StatusOK || decodeCellularControlView(t, cancelled.Body.Bytes()).State != cellularcontrol.Cancelled {
		t.Fatalf("cancel status=%d body=%q", cancelled.Code, cancelled.Body.String())
	}
}
