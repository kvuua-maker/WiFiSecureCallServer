package server

import (
	"net/http"
	"strings"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/devicekeys"
)

func (s *Server) registerDeviceKey(w http.ResponseWriter, r *http.Request) {
	if s.deviceKeys == nil {
		writeError(w, http.StatusServiceUnavailable, "device_keys_unavailable")
		return
	}
	var body devicekeys.Registration
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid_device_key")
		return
	}
	identity := identityFrom(r.Context())
	bundle, _, err := s.deviceKeys.Register(identity.UserID, identity.DeviceID, body)
	if err != nil {
		writeDeviceKeyError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) getDeviceKeys(w http.ResponseWriter, r *http.Request) {
	if s.deviceKeys == nil {
		writeError(w, http.StatusServiceUnavailable, "device_keys_unavailable")
		return
	}
	userID := strings.ToLower(r.PathValue("userID"))
	if !validID(userID) {
		writeError(w, http.StatusBadRequest, "invalid_recipient")
		return
	}
	if _, err := s.phoneAuth.RecipientForUserID(userID); err != nil {
		writeServiceError(w, err)
		return
	}
	active := map[string]bool{}
	for _, device := range s.phoneAuth.DevicesForUser(userID) {
		active[strings.ToLower(device.DeviceID)] = true
	}
	writeJSON(w, http.StatusOK, s.deviceKeys.ForUser(userID, active))
}

func writeDeviceKeyError(w http.ResponseWriter, err error) {
	code := devicekeys.ErrorCode(err)
	status := http.StatusBadRequest
	switch code {
	case "device_not_owned":
		status = http.StatusForbidden
	case "idempotency_conflict", "key_changed":
		status = http.StatusConflict
	case "":
		code, status = "device_key_failed", http.StatusInternalServerError
	}
	writeError(w, status, code)
}
