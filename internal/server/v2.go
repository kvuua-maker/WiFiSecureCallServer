package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
)

type identityKeyType string

const identityKey identityKeyType = "v2Identity"

func (s *Server) registerV2() {
	s.mux.HandleFunc("POST /v2/auth/phone/start", s.phoneStart)
	s.mux.HandleFunc("POST /v2/auth/phone/verify", s.phoneVerify)
	s.mux.HandleFunc("POST /v2/auth/refresh", s.refresh)
	s.mux.HandleFunc("POST /v2/auth/logout", s.v2Auth(s.logout))
	s.mux.HandleFunc("GET /v2/me", s.v2Auth(s.me))
	s.mux.HandleFunc("DELETE /v2/account", s.v2Auth(s.deleteAccount))
	s.mux.HandleFunc("POST /v2/watch-link/start", s.watchLinkStart)
	s.mux.HandleFunc("POST /v2/watch-link/claim", s.v2Auth(s.watchLinkClaim))
	s.mux.HandleFunc("POST /v2/watch-link/status", s.watchLinkStatus)
	s.mux.HandleFunc("POST /v2/devices/register", s.v2Auth(s.v2RegisterDevice))
	s.mux.HandleFunc("GET /v2/devices", s.v2Auth(s.v2Devices))
	s.mux.HandleFunc("POST /v2/diagnostics/log", s.v2Auth(s.diagnosticsLog))
	s.mux.HandleFunc("GET /v2/diagnostics/read", s.v2Auth(s.diagnosticsRead))
	s.mux.HandleFunc("POST /v2/calls", s.v2Auth(s.v2CreateCall))
	s.mux.HandleFunc("GET /v2/calls/{id}", s.v2Auth(s.v2GetCall))
	s.mux.HandleFunc("POST /v2/calls/{id}/{action}", s.v2Auth(s.v2MutateCall))
}

type v2DeviceSummary struct {
	DeviceID   string    `json:"deviceID"`
	Platform   string    `json:"platform"`
	CallReady  bool      `json:"callReady"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

func (s *Server) v2Devices(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	devices := s.phoneAuth.DevicesForAccount(identity.AccountID)
	result := make([]v2DeviceSummary, 0, len(devices))
	for _, device := range devices {
		result = append(result, v2DeviceSummary{DeviceID: device.DeviceID, Platform: device.Platform, CallReady: accountDeviceCallReady(device), LastSeenAt: device.LastSeenAt})
	}
	writeJSON(w, http.StatusOK, result)
}

// accountDeviceCallAttemptable is the weaker test used when a call is placed: the
// device must be able to receive a push, but it does not have to look fully ready.
func accountDeviceCallAttemptable(device accounts.Device) bool {
	if device.Environment != "production" || !device.Capabilities.MicrophoneReady {
		return false
	}
	switch device.Platform {
	case "iOS":
		return device.VoIPToken != ""
	case "watchOS":
		return device.AlertToken != ""
	default:
		return false
	}
}

func accountDeviceCallReady(device accounts.Device) bool {
	if device.Environment != "production" || !device.Capabilities.MicrophoneReady {
		return false
	}
	if device.Platform == "iOS" {
		return device.VoIPToken != "" && device.Capabilities.VoIPPush
	}
	if device.Platform == "watchOS" {
		return device.AlertToken != "" && device.Capabilities.AlertPush && device.Capabilities.NotificationsAuthorized
	}
	return false
}

type v2CallCreateRequest struct{ RequestID, CallID, TargetDeviceID string }
type v2CallMutationRequest struct{ RequestID string }

func (s *Server) v2CreateCall(w http.ResponseWriter, r *http.Request) {
	if s.accountCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "account calls unavailable")
		return
	}
	var body v2CallCreateRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !validID(body.CallID) || !validID(body.TargetDeviceID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	identity := identityFrom(r.Context())
	target, ok := s.phoneAuth.DeviceForAccount(identity.AccountID, body.TargetDeviceID)
	if !ok || strings.EqualFold(target.DeviceID, identity.DeviceID) {
		writeError(w, http.StatusForbidden, "target device unavailable")
		return
	}
	// Readiness decides which device a client prefers when choosing a target. It
	// must not decide whether a call is attempted at all: a stale capability flag
	// (token uploaded before notifications were allowed, a rotated push token) used
	// to make a reachable device look unringable, and the caller saw "calling" and
	// then nothing. Attempt when a usable token exists and let delivery report.
	if !accountDeviceCallAttemptable(target) {
		writeError(w, http.StatusConflict, "target device has no push token")
		return
	}
	s.callCreationMu.Lock()
	if s.userCalls != nil && (s.userCalls.HasCall(body.CallID) || s.userCalls.DeviceBusy(identity.DeviceID) || s.userCalls.DeviceBusy(target.DeviceID)) {
		s.callCreationMu.Unlock()
		writeError(w, http.StatusConflict, "device already has an active call")
		return
	}
	view, createdNew, err := s.accountCalls.Create(body.CallID, body.RequestID, identity.AccountID, identity.DeviceID, target.DeviceID)
	s.callCreationMu.Unlock()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !createdNew {
		if current, currentErr := s.accountCalls.Get(view.CallID, identity.AccountID, identity.DeviceID); currentErr == nil {
			view = current
		}
		writeJSON(w, http.StatusOK, view)
		return
	}
	slog.Info("account call created", "callID", view.CallID, "callerAccountID", identity.AccountID, "callerDeviceID", identity.DeviceID, "calleeDeviceID", target.DeviceID)
	s.recordDiagnostic(target.DeviceID, "SIGNALING", "call_created_on_server", "success",
		"platform="+target.Platform+" callerLocal="+strconv.FormatBool(target.Platform == "watchOS"), nil)
	token, pushType := selectAccountIncomingPush(target)
	if token == "" {
		s.accountCalls.FailDelivery(view.CallID, "device_token_missing")
		if current, currentErr := s.accountCalls.Get(view.CallID, identity.AccountID, identity.DeviceID); currentErr == nil {
			view = current
		}
		writeJSON(w, http.StatusOK, view)
		return
	}
	slog.Info("account APNs delivery attempted", "callID", view.CallID, "platform", target.Platform, "pushType", pushType, "tokenLength", len(token))
	s.recordDiagnostic(target.DeviceID, "SERVER", "apns_send_attempted", "info", "platform="+target.Platform+" pushType="+pushType, nil)
	go s.deliverAccountIncoming(view, target, token, pushType, identity.AccountID)
	// A call aimed at a watch also wakes the iPhone it belongs to. The phone is
	// where CallKit and PushKit actually run when the wrist is down, and it is the
	// phone that hands the call to the watch over WatchConnectivity; without this
	// the watch would have to be awake on its own, which it cannot be.
	if target.Platform == "watchOS" {
		go s.wakeCompanionIPhones(view, target, identity.AccountID)
	}
	writeJSON(w, http.StatusOK, view)
}

func selectAccountIncomingPush(device accounts.Device) (string, string) {
	if device.Environment != "production" {
		return "", ""
	}
	if device.Platform == "watchOS" {
		if device.AlertToken != "" && device.Capabilities.AlertPush && device.Capabilities.NotificationsAuthorized {
			return device.AlertToken, "alert"
		}
		if device.VoIPToken != "" && device.Capabilities.VoIPPush {
			return device.VoIPToken, "voip"
		}
		return "", "alert"
	}
	if device.Platform == "iOS" {
		if device.VoIPToken != "" && device.Capabilities.VoIPPush {
			return device.VoIPToken, "voip"
		}
		if device.AlertToken != "" && device.Capabilities.AlertPush && device.Capabilities.NotificationsAuthorized {
			return device.AlertToken, "alert"
		}
		return "", "voip"
	}
	return "", ""
}

func (s *Server) deliverAccountIncoming(view accountcalls.View, device accounts.Device, token, pushType, accountID string) {
	if !s.accountCalls.IsRinging(view.CallID) {
		return
	}
	sender, ok := s.apns.(apns.AccountSender)
	if !ok {
		s.accountCalls.FailDelivery(view.CallID, "account_push_unavailable")
		return
	}
	deadline := view.RingExpiresAt
	if deadline.IsZero() || deadline.After(time.Now().Add(8*time.Second)) {
		deadline = time.Now().Add(8 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	result, err := sender.IncomingAccountCall(ctx, device.Platform, token, view.CallID, pushType, view.RingExpiresAt, accountID)
	if err != nil {
		reason := result.Reason
		if reason == "" {
			reason = "unavailable"
		}
		s.accountCalls.FailDelivery(view.CallID, reason)
		if s.accountMedia != nil {
			s.accountMedia.CloseCall(view.CallID, "delivery failed")
		}
		if result.DeadToken {
			_ = s.phoneAuth.InvalidateAccountDeviceToken(accountID, device.DeviceID, pushType, token, device.InstallationGeneration)
		}
		slog.Warn("account APNs submission failed", "callID", view.CallID, "status", result.Status, "reason", result.Reason)
		s.recordDiagnostic(device.DeviceID, "SERVER", "apns_send_failed", "error",
			"status="+strconv.Itoa(result.Status)+" pushType="+pushType, errors.New(reason))
		return
	}
	s.accountCalls.SetDelivery(view.CallID, "submission_accepted")
	slog.Info("account APNs submission accepted", "callID", view.CallID, "status", result.Status, "apnsID", result.APNSID)
	s.recordDiagnostic(device.DeviceID, "SERVER", "apns_send_success", "success",
		"status="+strconv.Itoa(result.Status)+" pushType="+pushType, nil)
	s.recordDiagnostic(device.DeviceID, "SERVER", "apns_response_code", "info",
		"code="+strconv.Itoa(result.Status), nil)
}

func (s *Server) v2GetCall(w http.ResponseWriter, r *http.Request) {
	if s.accountCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "account calls unavailable")
		return
	}
	identity := identityFrom(r.Context())
	view, err := s.accountCalls.Get(r.PathValue("id"), identity.AccountID, identity.DeviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "call not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) v2MutateCall(w http.ResponseWriter, r *http.Request) {
	if s.accountCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "account calls unavailable")
		return
	}
	var body v2CallMutationRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var target accountcalls.State
	switch r.PathValue("action") {
	case "accept":
		target = accountcalls.Accepted
	case "reject":
		target = accountcalls.Rejected
	case "cancel":
		target = accountcalls.Cancelled
	case "end":
		target = accountcalls.Ended
	default:
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	identity := identityFrom(r.Context())
	view, _, err := s.accountCalls.Mutate(r.PathValue("id"), body.RequestID, identity.AccountID, identity.DeviceID, target)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			writeError(w, http.StatusRequestTimeout, "cancelled")
		} else {
			writeError(w, http.StatusConflict, err.Error())
		}
		return
	}
	if view.State == accountcalls.Ended || view.State == accountcalls.Cancelled || view.State == accountcalls.Rejected || view.State == accountcalls.Expired {
		if s.accountMedia != nil {
			s.accountMedia.CloseCall(view.CallID, string(view.State))
		}
	}
	writeJSON(w, http.StatusOK, view)
}

type v2DeviceCapabilities struct {
	VoIPPush                bool
	AlertPush               bool
	NotificationsAuthorized bool
	MicrophoneReady         bool
}

type v2DeviceRegistrationRequest struct {
	RequestID, DeviceID, Platform, PushType, Token, InvalidatedToken, Environment string
	InstallationGeneration                                                        uint64
	Capabilities                                                                  v2DeviceCapabilities
}

func (s *Server) v2RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var body v2DeviceRegistrationRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid device registration")
		return
	}
	err := s.phoneAuth.RegisterDevice(identityFrom(r.Context()), phoneauth.DeviceRegistration{
		RequestID: body.RequestID, DeviceID: body.DeviceID, Platform: body.Platform, PushType: body.PushType,
		Token: body.Token, InvalidatedToken: body.InvalidatedToken, InstallationGeneration: body.InstallationGeneration,
		Environment: body.Environment, Capabilities: accounts.DeviceCapabilities{
			VoIPPush: body.Capabilities.VoIPPush, AlertPush: body.Capabilities.AlertPush,
			NotificationsAuthorized: body.Capabilities.NotificationsAuthorized, MicrophoneReady: body.Capabilities.MicrophoneReady,
		},
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type phoneStartRequest struct{ RequestID, PhoneNumber string }

func (s *Server) phoneStart(w http.ResponseWriter, r *http.Request) {
	if s.phoneAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "SMS provider disabled")
		return
	}
	var body phoneStartRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.Start(r.Context(), body.RequestID, body.PhoneNumber, sourceIP(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type phoneVerifyRequest struct{ RequestID, VerificationID, Code, DeviceID, Platform string }

func (s *Server) phoneVerify(w http.ResponseWriter, r *http.Request) {
	if s.phoneAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "phone authentication unavailable")
		return
	}
	var body phoneVerifyRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.Verify(body.RequestID, body.VerificationID, body.Code, body.DeviceID, body.Platform)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type refreshRequest struct{ RefreshToken, DeviceID string }

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	if s.phoneAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "phone authentication unavailable")
		return
	}
	var body refreshRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.Refresh(body.RefreshToken, body.DeviceID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.phoneAuth.Logout(identityFrom(r.Context())); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"accountID": id.AccountID, "phoneNumber": id.PhoneE164, "deviceID": id.DeviceID, "platform": id.Platform})
}

type deleteAccountRequest struct{ Confirm string }

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	var body deleteAccountRequest
	if err := decode(w, r, &body); err != nil || body.Confirm != "DELETE" {
		writeError(w, http.StatusBadRequest, "invalid confirmation")
		return
	}
	if err := s.phoneAuth.DeleteAccount(identityFrom(r.Context())); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type watchStartRequest struct{ RequestID, DeviceID, Platform string }

func (s *Server) watchLinkStart(w http.ResponseWriter, r *http.Request) {
	if s.phoneAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "phone authentication unavailable")
		return
	}
	var body watchStartRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.WatchStart(body.RequestID, body.DeviceID, body.Platform)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"linkID": result.LinkID, "linkSecret": result.LinkSecret, "code": result.Code, "expiresAt": result.ExpiresAt})
}

type watchClaimRequest struct{ RequestID, Code string }

func (s *Server) watchLinkClaim(w http.ResponseWriter, r *http.Request) {
	var body watchClaimRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if err := s.phoneAuth.WatchClaim(identityFrom(r.Context()), body.RequestID, body.Code); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type watchStatusRequest struct{ LinkID, LinkSecret string }

func (s *Server) watchLinkStatus(w http.ResponseWriter, r *http.Request) {
	if s.phoneAuth == nil {
		writeError(w, http.StatusServiceUnavailable, "phone authentication unavailable")
		return
	}
	var body watchStatusRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.WatchStatus(body.LinkID, body.LinkSecret)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) v2Auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.phoneAuth == nil {
			writeError(w, http.StatusServiceUnavailable, "phone authentication unavailable")
			return
		}
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || strings.Count(header, " ") != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		identity, err := s.phoneAuth.Authenticate(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			writeServiceError(w, err)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), identityKey, identity)))
	}
}

func identityFrom(ctx context.Context) phoneauth.Identity {
	value, _ := ctx.Value(identityKey).(phoneauth.Identity)
	return value
}

func writeServiceError(w http.ResponseWriter, err error) {
	if typed, ok := err.(*phoneauth.ServiceError); ok {
		payload := map[string]any{"error": typed.Code}
		if !typed.RetryAt.IsZero() {
			payload["retryAt"] = typed.RetryAt
		}
		writeJSON(w, typed.Status, payload)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal error")
}

func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	if ip == nil {
		return "unknown"
	}
	return ip.String()
}

// companionIPhones selects the iPhones that should be woken for a call addressed
// to a watch: same account, production, a VoIP token and the capability to use it.
func companionIPhones(devices []accounts.Device, target accounts.Device) []accounts.Device {
	var companions []accounts.Device
	for _, device := range devices {
		if device.AccountID != target.AccountID || device.DeviceID == target.DeviceID {
			continue
		}
		if device.Platform != "iOS" || device.Environment != "production" {
			continue
		}
		if device.VoIPToken == "" || !device.Capabilities.VoIPPush {
			continue
		}
		companions = append(companions, device)
	}
	return companions
}

// wakeCompanionIPhones sends the same incoming-call push to the iPhones of the
// account that owns the watch the call was addressed to.
//
// Delivery to the watch is unaffected: this is an additional wake-up, not a
// replacement, so a wrist that is awake still rings on its own. Failures here are
// logged and ignored, because the call itself is already ringing.
func (s *Server) wakeCompanionIPhones(view accountcalls.View, target accounts.Device, accountID string) {
	if target.AccountID == "" || s.phoneAuth == nil {
		return
	}
	sender, ok := s.apns.(apns.AccountSender)
	if !ok {
		return
	}
	companions := companionIPhones(s.phoneAuth.DevicesForAccount(target.AccountID), target)
	for _, device := range companions {
		device := device
		go func() {
			deadline := view.RingExpiresAt
			if deadline.IsZero() || deadline.After(time.Now().Add(8*time.Second)) {
				deadline = time.Now().Add(8 * time.Second)
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			result, err := sender.IncomingAccountCall(ctx, device.Platform, device.VoIPToken, view.CallID, "voip", view.RingExpiresAt, accountID)
			if err != nil {
				slog.Warn("companion iPhone wake failed", "callID", view.CallID, "deviceID", device.DeviceID, "status", result.Status, "reason", result.Reason)
				return
			}
			slog.Info("companion iPhone woken for a watch call", "callID", view.CallID, "deviceID", device.DeviceID)
		}()
	}
}
