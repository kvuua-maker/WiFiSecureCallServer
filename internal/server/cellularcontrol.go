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
	"github.com/kvuua-maker/wifi-secure-call-server/internal/cellularcontrol"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
)

type cellularControlCreateRequest struct {
	RequestID   string
	PhoneNumber string
}

type cellularControlMutationRequest struct {
	RequestID string
}

type cellularControlReceiveRequest struct {
	RequestID      string
	ReceiptContext cellularcontrol.ReceiptContext
}

type cellularControlStartResultRequest struct {
	RequestID       string
	Result          cellularcontrol.StartResult
	SafeErrorDomain string
	SafeErrorCode   *int
}

func (s *Server) createCellularControl(w http.ResponseWriter, r *http.Request) {
	if s.cellularControls == nil {
		writeError(w, http.StatusServiceUnavailable, "control_unavailable")
		return
	}
	var body cellularControlCreateRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !phoneauth.ValidPhone(body.PhoneNumber) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	identity := identityFrom(r.Context())
	source, ok := s.authenticatedWatchParticipant(identity)
	if !ok {
		writeError(w, http.StatusForbidden, "same_owner_required")
		return
	}
	s.cellularControlCreationMu.Lock()
	defer s.cellularControlCreationMu.Unlock()
	if existing, found, err := s.cellularControls.ExistingCreate(body.RequestID, source, body.PhoneNumber); err != nil {
		writeCellularControlError(w, err)
		return
	} else if found {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	targetDevice, ok := selectRemoteCellularIPhone(identity, s.phoneAuth.DevicesForUser(identity.UserID))
	if !ok {
		writeError(w, http.StatusConflict, "iphone_unavailable")
		return
	}
	target := cellularcontrol.Participant{UserID: identity.UserID, AccountID: targetDevice.AccountID, DeviceID: targetDevice.DeviceID, Platform: targetDevice.Platform}
	view, created, err := s.cellularControls.Create(body.RequestID, source, target, body.PhoneNumber)
	if err != nil {
		writeCellularControlError(w, err)
		return
	}
	if created {
		slog.Info("remote cellular control created", "requestID", view.RequestID, "sourcePlatform", source.Platform, "targetPlatform", target.Platform)
		go s.deliverRemoteCellularControl(view, targetDevice)
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) getCellularControl(w http.ResponseWriter, r *http.Request) {
	if s.cellularControls == nil {
		writeError(w, http.StatusServiceUnavailable, "control_unavailable")
		return
	}
	view, err := s.cellularControls.Get(r.PathValue("id"), cellularControlParticipant(identityFrom(r.Context())))
	if err != nil {
		writeCellularControlError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) mutateCellularControl(w http.ResponseWriter, r *http.Request) {
	if s.cellularControls == nil {
		writeError(w, http.StatusServiceUnavailable, "control_unavailable")
		return
	}
	id := r.PathValue("id")
	participant := cellularControlParticipant(identityFrom(r.Context()))
	switch r.PathValue("action") {
	case "receive":
		var body cellularControlReceiveRequest
		if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !cellularcontrol.ValidReceiptContext(body.ReceiptContext) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		view, err := s.cellularControls.Receive(id, body.RequestID, participant, body.ReceiptContext)
		if err != nil {
			writeCellularControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case "start":
		var body cellularControlMutationRequest
		if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		grant, err := s.cellularControls.ClaimStart(id, body.RequestID, participant)
		if err != nil {
			writeCellularControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, grant)
	case "start-attempted":
		var body cellularControlMutationRequest
		if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		view, err := s.cellularControls.MarkStartAttempted(id, body.RequestID, participant)
		if err != nil {
			writeCellularControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case "start-result":
		var body cellularControlStartResultRequest
		if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !validCellularStartResult(body) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		view, err := s.cellularControls.MarkStartResult(id, body.RequestID, participant, body.Result, body.SafeErrorDomain, body.SafeErrorCode)
		if err != nil {
			writeCellularControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	case "cancel":
		var body cellularControlMutationRequest
		if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		view, err := s.cellularControls.Cancel(id, body.RequestID, participant)
		if err != nil {
			writeCellularControlError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, view)
	default:
		writeError(w, http.StatusNotFound, "unknown_action")
	}
}

func validCellularStartResult(body cellularControlStartResultRequest) bool {
	switch body.Result {
	case cellularcontrol.StartAccepted:
		return body.SafeErrorDomain == "" && body.SafeErrorCode == nil
	case cellularcontrol.StartError:
		return cellularcontrol.ValidSafeErrorDomain(body.SafeErrorDomain) && body.SafeErrorCode != nil && *body.SafeErrorCode >= -2147483648 && *body.SafeErrorCode <= 2147483647
	default:
		return false
	}
}

func (s *Server) authenticatedWatchParticipant(identity phoneauth.Identity) (cellularcontrol.Participant, bool) {
	if identity.UserID == "" || identity.AccountID == "" || identity.DeviceID == "" || identity.Platform != "watchOS" {
		return cellularcontrol.Participant{}, false
	}
	device, ok := s.phoneAuth.DeviceForAccount(identity.AccountID, identity.DeviceID)
	if !ok || device.Platform != "watchOS" {
		return cellularcontrol.Participant{}, false
	}
	return cellularControlParticipant(identity), true
}

func cellularControlParticipant(identity phoneauth.Identity) cellularcontrol.Participant {
	return cellularcontrol.Participant{UserID: strings.ToLower(identity.UserID), AccountID: strings.ToLower(identity.AccountID), DeviceID: strings.ToLower(identity.DeviceID), Platform: identity.Platform}
}

func selectRemoteCellularIPhone(source phoneauth.Identity, devices []accounts.Device) (accounts.Device, bool) {
	candidates := make([]accounts.Device, 0)
	for _, device := range devices {
		// Remote cellular control uses a silent background notification. Visible
		// alert authorization is not required for that APNs delivery class.
		if device.Platform != "iOS" || device.Environment != "production" || device.AlertToken == "" || !device.Capabilities.AlertPush {
			continue
		}
		candidates = append(candidates, device)
	}
	sort.Slice(candidates, func(i, j int) bool {
		iSame := strings.EqualFold(candidates[i].AccountID, source.AccountID)
		jSame := strings.EqualFold(candidates[j].AccountID, source.AccountID)
		if iSame != jSame {
			return iSame
		}
		if !candidates[i].LastSeenAt.Equal(candidates[j].LastSeenAt) {
			return candidates[i].LastSeenAt.After(candidates[j].LastSeenAt)
		}
		if candidates[i].AccountID != candidates[j].AccountID {
			return candidates[i].AccountID < candidates[j].AccountID
		}
		return candidates[i].DeviceID < candidates[j].DeviceID
	})
	if len(candidates) == 0 {
		return accounts.Device{}, false
	}
	return candidates[0], true
}

func (s *Server) deliverRemoteCellularControl(view cellularcontrol.View, target accounts.Device) {
	sender, ok := s.apns.(apns.RemoteCellularControlSender)
	if !ok {
		_, _ = s.cellularControls.MarkDelivery(view.RequestID, false)
		return
	}
	deadline := view.ExpiresAt
	if deadline.After(time.Now().Add(8 * time.Second)) {
		deadline = time.Now().Add(8 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	result, err := sender.RemoteCellularControl(ctx, target.AlertToken, view.RequestID, view.ExpiresAt, target.AccountID)
	accepted := err == nil && result.Status/100 == 2
	_, _ = s.cellularControls.MarkDelivery(view.RequestID, accepted)
	if result.DeadToken {
		_ = s.phoneAuth.InvalidateAccountDeviceToken(target.AccountID, target.DeviceID, "alert", target.AlertToken, target.InstallationGeneration)
	}
	if accepted {
		slog.Info("remote cellular control APNs submission accepted", "requestID", view.RequestID, "platform", target.Platform, "status", result.Status, "apnsID", result.APNSID)
		return
	}
	reason := result.Reason
	if reason == "" {
		reason = "unavailable"
	}
	slog.Warn("remote cellular control APNs submission failed", "requestID", view.RequestID, "platform", target.Platform, "status", result.Status, "reason", reason)
}

func writeCellularControlError(w http.ResponseWriter, err error) {
	if typed, ok := err.(*cellularcontrol.Error); ok {
		writeError(w, typed.Status, typed.Code)
		return
	}
	writeError(w, http.StatusInternalServerError, "control_failed")
}
