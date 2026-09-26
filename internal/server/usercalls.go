package server

import (
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/usercalls"
)

type recipientResolveRequest struct {
	Recipient string
}

type userCallCreateRequest struct {
	RequestID, CallID, TargetUserID string
}

type userCallRoute struct {
	target                 usercalls.Target
	token, pushType        string
	installationGeneration uint64
	lastSeenAt             time.Time
}

func (s *Server) resolveRecipient(w http.ResponseWriter, r *http.Request) {
	var body recipientResolveRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid_recipient")
		return
	}
	result, err := s.phoneAuth.ResolveRecipient(identityFrom(r.Context()), body.Recipient)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) createUserCall(w http.ResponseWriter, r *http.Request) {
	if s.userCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "call_failed")
		return
	}
	var body userCallCreateRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !validID(body.CallID) || !validID(body.TargetUserID) {
		writeError(w, http.StatusBadRequest, "invalid_recipient")
		return
	}
	identity := identityFrom(r.Context())
	if strings.EqualFold(identity.UserID, body.TargetUserID) {
		writeError(w, http.StatusConflict, "self_call_not_allowed")
		return
	}
	targetRecipient, err := s.phoneAuth.RecipientForUserID(body.TargetUserID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	callerRecipient, err := s.phoneAuth.RecipientForUserID(identity.UserID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	routes := eligibleUserCallRoutes(s.phoneAuth.DevicesForUser(targetRecipient.UserID))
	s.callCreationMu.Lock()
	if s.accountCalls != nil {
		if s.accountCalls.HasCall(body.CallID) {
			s.callCreationMu.Unlock()
			writeError(w, http.StatusConflict, "idempotency_conflict")
			return
		}
		if s.accountCalls.DeviceBusy(identity.DeviceID) {
			s.callCreationMu.Unlock()
			writeError(w, http.StatusConflict, "call_failed")
			return
		}
		available := routes[:0]
		for _, route := range routes {
			if !s.accountCalls.DeviceBusy(route.target.DeviceID) {
				available = append(available, route)
			}
		}
		routes = available
	}
	targets := make([]usercalls.Target, 0, len(routes))
	for _, route := range routes {
		targets = append(targets, route.target)
	}
	participant := userCallParticipant(identity)
	caller := usercalls.PublicCaller{Username: callerRecipient.Username, DisplayName: callerRecipient.DisplayName, PublicIdentity: callerRecipient.PublicIdentity}
	view, selected, createdNew, err := s.userCalls.Create(body.CallID, body.RequestID, participant, targetRecipient.UserID, caller, targets)
	s.callCreationMu.Unlock()
	if err != nil {
		writeUserCallError(w, err)
		return
	}
	if !createdNew {
		writeJSON(w, http.StatusOK, view)
		return
	}
	selectedKeys := make(map[string]bool, len(selected))
	for _, target := range selected {
		selectedKeys[target.AccountID+"\x00"+target.DeviceID] = true
	}
	for _, route := range routes {
		if selectedKeys[route.target.AccountID+"\x00"+route.target.DeviceID] {
			slog.Info("user call APNs delivery attempted", "callID", view.CallID, "platform", route.target.Platform, "pushType", route.pushType)
			go s.deliverUserIncoming(view, route, caller)
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) getUserCall(w http.ResponseWriter, r *http.Request) {
	if s.userCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "call_failed")
		return
	}
	identity := identityFrom(r.Context())
	view, err := s.userCalls.Get(r.PathValue("id"), userCallParticipant(identity))
	if err != nil {
		writeUserCallError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) mutateUserCall(w http.ResponseWriter, r *http.Request) {
	if s.userCalls == nil {
		writeError(w, http.StatusServiceUnavailable, "call_failed")
		return
	}
	var body v2CallMutationRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var action usercalls.State
	switch r.PathValue("action") {
	case "accept":
		action = usercalls.Accepted
	case "reject":
		action = usercalls.Rejected
	case "cancel":
		action = usercalls.Cancelled
	case "end":
		action = usercalls.Ended
	default:
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	view, _, err := s.userCalls.Mutate(r.PathValue("id"), body.RequestID, userCallParticipant(identityFrom(r.Context())), action)
	if err != nil {
		writeUserCallError(w, err)
		return
	}
	if view.State == usercalls.Ended || view.State == usercalls.Cancelled || view.State == usercalls.Rejected || view.State == usercalls.Expired {
		if s.accountMedia != nil {
			s.accountMedia.CloseCall(view.CallID, string(view.State))
		}
	}
	writeJSON(w, http.StatusOK, view)
}

func eligibleUserCallRoutes(devices []accounts.Device) []userCallRoute {
	byDevice := map[string]userCallRoute{}
	for _, device := range devices {
		if !userCallDeviceReady(device) {
			continue
		}
		token, pushType := selectAccountIncomingPush(device)
		if token == "" {
			continue
		}
		deviceID := strings.ToLower(device.DeviceID)
		candidate := userCallRoute{
			target: usercalls.Target{AccountID: strings.ToLower(device.AccountID), DeviceID: deviceID, Platform: device.Platform},
			token:  token, pushType: pushType, installationGeneration: device.InstallationGeneration, lastSeenAt: device.LastSeenAt,
		}
		prior, exists := byDevice[deviceID]
		if !exists || candidate.lastSeenAt.After(prior.lastSeenAt) || candidate.lastSeenAt.Equal(prior.lastSeenAt) && candidate.target.AccountID < prior.target.AccountID {
			byDevice[deviceID] = candidate
		}
	}
	keys := make([]string, 0, len(byDevice))
	for key := range byDevice {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]userCallRoute, 0, len(keys))
	for _, key := range keys {
		result = append(result, byDevice[key])
	}
	return result
}

func userCallDeviceReady(device accounts.Device) bool {
	if device.Environment != "production" || !device.Capabilities.MicrophoneReady {
		return false
	}
	switch device.Platform {
	case "iOS":
		return device.VoIPToken != "" && device.Capabilities.VoIPPush || device.AlertToken != "" && device.Capabilities.AlertPush && device.Capabilities.NotificationsAuthorized
	case "watchOS":
		return device.AlertToken != "" && device.Capabilities.AlertPush && device.Capabilities.NotificationsAuthorized
	default:
		return false
	}
}

func (s *Server) deliverUserIncoming(view usercalls.View, route userCallRoute, caller usercalls.PublicCaller) {
	if !s.userCalls.TargetRinging(view.CallID, route.target.AccountID, route.target.DeviceID) {
		return
	}
	sender, ok := s.apns.(apns.UserCallSender)
	if !ok {
		_, terminal := s.userCalls.SetDelivery(view.CallID, route.target.AccountID, route.target.DeviceID, false, "push_unavailable")
		if terminal && s.accountMedia != nil {
			s.accountMedia.CloseCall(view.CallID, "delivery failed")
		}
		return
	}
	deadline := view.RingExpiresAt
	if deadline.IsZero() || deadline.After(time.Now().Add(8*time.Second)) {
		deadline = time.Now().Add(8 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	result, err := sender.IncomingUserCall(ctx, route.target.Platform, route.token, view.CallID, route.pushType, view.RingExpiresAt, route.target.AccountID, caller.Username, caller.DisplayName)
	if err != nil {
		reason := result.Reason
		if reason == "" {
			reason = "unavailable"
		}
		_, terminal := s.userCalls.SetDelivery(view.CallID, route.target.AccountID, route.target.DeviceID, false, reason)
		if result.DeadToken {
			_ = s.phoneAuth.InvalidateAccountDeviceToken(route.target.AccountID, route.target.DeviceID, route.pushType, route.token, route.installationGeneration)
		}
		if terminal && s.accountMedia != nil {
			s.accountMedia.CloseCall(view.CallID, "delivery failed")
		}
		slog.Warn("user call APNs submission failed", "callID", view.CallID, "platform", route.target.Platform, "status", result.Status, "reason", result.Reason)
		return
	}
	s.userCalls.SetDelivery(view.CallID, route.target.AccountID, route.target.DeviceID, true, "")
	slog.Info("user call APNs submission accepted", "callID", view.CallID, "platform", route.target.Platform, "status", result.Status, "apnsID", result.APNSID)
}

func userCallParticipant(identity phoneauth.Identity) usercalls.Participant {
	return usercalls.Participant{UserID: strings.ToLower(identity.UserID), AccountID: strings.ToLower(identity.AccountID), DeviceID: strings.ToLower(identity.DeviceID)}
}

func writeUserCallError(w http.ResponseWriter, err error) {
	code := usercalls.ErrorCode(err)
	status := http.StatusConflict
	switch code {
	case "invalid_recipient":
		status = http.StatusBadRequest
	case "recipient_not_found", "call_not_participant":
		status = http.StatusNotFound
	case "call_expired":
		status = http.StatusGone
	case "":
		code, status = "call_failed", http.StatusInternalServerError
	}
	writeError(w, status, code)
}
