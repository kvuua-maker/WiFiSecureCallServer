package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
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

	received := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/receive", fixture.targetIOS.AccessToken, map[string]string{"requestID": "c1111111-1111-4111-8111-111111111111", "receiptContext": "background"})
	receivedView := decodeCellularControlView(t, received.Body.Bytes())
	if received.Code != http.StatusOK || receivedView.State != cellularcontrol.IPhoneBackgroundReceived || receivedView.ReceiptContext != cellularcontrol.ReceiptBackground {
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
	attempted := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-attempted", fixture.targetIOS.AccessToken, map[string]string{"requestID": "e1111111-1111-4111-8111-111111111111"})
	if attempted.Code != http.StatusOK || decodeCellularControlView(t, attempted.Body.Bytes()).State != cellularcontrol.IPhoneBackgroundStartAttempted {
		t.Fatalf("attempted status=%d body=%q", attempted.Code, attempted.Body.String())
	}
	accepted := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-result", fixture.targetIOS.AccessToken, map[string]any{"requestID": "f1111111-1111-4111-8111-111111111111", "result": "accepted"})
	acceptedView := decodeCellularControlView(t, accepted.Body.Bytes())
	if accepted.Code != http.StatusOK || acceptedView.State != cellularcontrol.SystemStartAccepted || acceptedView.StartResult != cellularcontrol.StartAccepted {
		t.Fatalf("accepted status=%d body=%q", accepted.Code, accepted.Body.String())
	}
	watchView := performUserRequest(t, fixture.server, http.MethodGet, "/v3/cellular-controls/"+controlID, fixture.targetWatch.AccessToken, nil)
	if watchView.Code != http.StatusOK || decodeCellularControlView(t, watchView.Body.Bytes()).State != cellularcontrol.SystemStartAccepted || strings.Contains(watchView.Body.String(), phone) {
		t.Fatalf("watch view status=%d body=%q", watchView.Code, watchView.Body.String())
	}
}

func TestRemoteCellularControlPublicStartErrorIsSafeAndWatchVisible(t *testing.T) {
	fixture, _ := prepareRemoteControlFixture(t)
	controlID := "b2222222-2222-4222-8222-222222222222"
	phone := "+380501234567"
	created := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, map[string]string{"requestID": controlID, "phoneNumber": phone})
	if created.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%q", created.Code, created.Body.String())
	}
	invalidContext := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/receive", fixture.targetIOS.AccessToken, map[string]string{"requestID": "c2222222-2222-4222-8222-222222222222", "receiptContext": "invented"})
	if invalidContext.Code != http.StatusBadRequest {
		t.Fatalf("invalid context status=%d body=%q", invalidContext.Code, invalidContext.Body.String())
	}
	received := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/receive", fixture.targetIOS.AccessToken, map[string]string{"requestID": "d2222222-2222-4222-8222-222222222222", "receiptContext": "background"})
	if received.Code != http.StatusOK {
		t.Fatalf("receive status=%d body=%q", received.Code, received.Body.String())
	}
	claimed := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start", fixture.targetIOS.AccessToken, map[string]string{"requestID": "e2222222-2222-4222-8222-222222222222"})
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim status=%d body=%q", claimed.Code, claimed.Body.String())
	}
	attempted := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-attempted", fixture.targetIOS.AccessToken, map[string]string{"requestID": "f2222222-2222-4222-8222-222222222222"})
	if attempted.Code != http.StatusOK {
		t.Fatalf("attempt status=%d body=%q", attempted.Code, attempted.Body.String())
	}
	unsafe := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-result", fixture.targetIOS.AccessToken, map[string]any{
		"requestID": "a2222222-2222-4222-8222-222222222222", "result": "error", "safeErrorDomain": "tel.380501234567", "safeErrorCode": 7,
	})
	if unsafe.Code != http.StatusBadRequest {
		t.Fatalf("unsafe result status=%d body=%q", unsafe.Code, unsafe.Body.String())
	}
	result := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/start-result", fixture.targetIOS.AccessToken, map[string]any{
		"requestID": "b3333333-3333-4333-8333-333333333333", "result": "error", "safeErrorDomain": "PublicCellularAPI", "safeErrorCode": 7,
	})
	view := decodeCellularControlView(t, result.Body.Bytes())
	if result.Code != http.StatusOK || view.State != cellularcontrol.PublicStartError || view.StartResult != cellularcontrol.StartError || view.SafeErrorDomain != cellularcontrol.SafePublicErrorDomain || view.SafeErrorCode == nil || *view.SafeErrorCode != 7 || view.ReceivedAt == nil || view.StartAttemptedAt == nil || view.StartResultAt == nil {
		t.Fatalf("result status=%d view=%+v", result.Code, view)
	}
	watch := performUserRequest(t, fixture.server, http.MethodGet, "/v3/cellular-controls/"+controlID, fixture.targetWatch.AccessToken, nil)
	if watch.Code != http.StatusOK || strings.Contains(watch.Body.String(), phone) || strings.Contains(watch.Body.String(), "tel.380501234567") {
		t.Fatalf("unsafe Watch view status=%d body=%q", watch.Code, watch.Body.String())
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
	response := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, body)
	if response.Code != http.StatusOK {
		t.Fatalf("create status=%d", response.Code)
	}
	if err := fixture.auth.InvalidateAccountDeviceToken(
		fixture.targetIOS.Account.AccountID, fixture.targetIOS.DeviceID, "alert", strings.Repeat("c", 64), 1,
	); err != nil {
		t.Fatal(err)
	}
	retry := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls", fixture.targetWatch.AccessToken, body)
	if retry.Code != http.StatusOK || decodeCellularControlView(t, retry.Body.Bytes()).RequestID != controlID {
		t.Fatalf("retry after eligibility changed status=%d body=%q", retry.Code, retry.Body.String())
	}
	waitForRemotePush(t, fake, 1)
	time.Sleep(25 * time.Millisecond)
	if got := len(fake.snapshot()); got != 1 {
		t.Fatalf("push count=%d", got)
	}
	cancelled := performUserRequest(t, fixture.server, http.MethodPost, "/v3/cellular-controls/"+controlID+"/cancel", fixture.targetWatch.AccessToken, map[string]string{"requestID": "c1111111-1111-4111-8111-111111111111"})
	if cancelled.Code != http.StatusOK || decodeCellularControlView(t, cancelled.Body.Bytes()).State != cellularcontrol.Cancelled {
		t.Fatalf("cancel status=%d body=%q", cancelled.Code, cancelled.Body.String())
	}
}

func TestRemoteCellularControlCreationCriticalSectionCoversCheckSelectionAndCreate(t *testing.T) {
	source, err := os.ReadFile("cellularcontrol.go")
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(source, []byte("func (s *Server) createCellularControl"))
	if start < 0 {
		t.Fatal("create handler not found")
	}
	endMarker := []byte("\n}\n\nfunc (s *Server) getCellularControl")
	endOffset := bytes.Index(source[start:], endMarker)
	if endOffset < 0 {
		t.Fatal("create handler not found")
	}
	body := source[start : start+endOffset]
	lock := bytes.Index(body, []byte("s.cellularControlCreationMu.Lock()"))
	deferredUnlock := bytes.Index(body, []byte("defer s.cellularControlCreationMu.Unlock()"))
	existing := bytes.Index(body, []byte("s.cellularControls.ExistingCreate("))
	selection := bytes.Index(body, []byte("selectRemoteCellularIPhone("))
	create := bytes.Index(body, []byte("s.cellularControls.Create("))
	if !(lock >= 0 && lock < deferredUnlock && deferredUnlock < existing && existing < selection && selection < create) {
		t.Fatalf("creation critical-section order lock=%d defer=%d existing=%d selection=%d create=%d", lock, deferredUnlock, existing, selection, create)
	}
}
