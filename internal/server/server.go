package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/media"
)

type Server struct {
	tokenA, tokenB string
	calls          *calls.Store
	devices        *devices.Store
	apns           apns.Sender
	media          *media.Hub
	mux            *http.ServeMux
}

func New(tokenA, tokenB string, callStore *calls.Store, deviceStore *devices.Store, push apns.Sender) *Server {
	s := &Server{tokenA: tokenA, tokenB: tokenB, calls: callStore, devices: deviceStore, apns: push}
	s.media = media.New(callStore)
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/devices/register", s.auth(s.register))
	s.mux.HandleFunc("POST /v1/devices/diagnostics", s.auth(s.notificationDiagnostics))
	s.mux.HandleFunc("POST /v1/calls", s.auth(s.create))
	s.mux.HandleFunc("GET /v1/calls/{id}", s.auth(s.get))
	s.mux.HandleFunc("POST /v1/calls/{id}/{action}", s.auth(s.mutate))
	s.mux.Handle("/media", s.media)
	return s
}
func (s *Server) Handler() http.Handler { return securityHeaders(s.mux) }
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "apnsConfigured": s.apns.Configured()})
}

type registerRequest struct{ RequestID, Role, Token, Platform, PushType string }

type notificationDiagnosticRequest struct {
	RequestID, Role, Platform, Event, Status, TokenPrefix string
	Stage, ErrorDomain                                    string
	CallID                                                string
	TokenLength, ErrorCode                                int
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	role := roleFrom(r.Context())
	var body registerRequest
	if decode(r, &body) != nil {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
	if body.PushType == "" {
		body.PushType = "alert"
	}
	if !validID(body.RequestID) || body.Role != role || (body.PushType != "alert" && body.PushType != "voip") {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
	if body.Token == "" {
		if err := s.devices.Invalidate(role, body.PushType); err != nil {
			writeError(w, http.StatusBadRequest, "invalid registration")
			return
		}
		slog.Info("push token invalidated", "role", role, "platform", body.Platform, "pushType", body.PushType)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.devices.Register(role, body.Platform, body.PushType, body.Token); err != nil {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
	prefix := body.Token
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	slog.Info("APNs device registered", "role", role, "platform", body.Platform, "pushType", body.PushType, "tokenPrefix", prefix, "tokenLength", len(body.Token))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) notificationDiagnostics(w http.ResponseWriter, r *http.Request) {
	role := roleFrom(r.Context())
	var body notificationDiagnosticRequest
	allowedEvents := map[string]bool{
		"notification_permission":                true,
		"apns_registration_started":              true,
		"apns_registration_succeeded":            true,
		"apns_registration_failed":               true,
		"callkit_error":                          true,
		"start_call_entered":                     true,
		"microphone_permission":                  true,
		"callkit_start_requested":                true,
		"callkit_start_approved":                 true,
		"server_call_create_started":             true,
		"server_call_create_succeeded":           true,
		"server_call_create_failed":              true,
		"new_call_blocked":                       true,
		"previous_terminal_reset":                true,
		"audio_session_configured":               true,
		"callkit_did_activate":                   true,
		"callkit_did_deactivate":                 true,
		"audio_engine_start_attempt":             true,
		"audio_engine_start_success":             true,
		"audio_engine_start_failure":             true,
		"voice_processing_enabled":               true,
		"input_format":                           true,
		"output_format":                          true,
		"first_mic_buffer":                       true,
		"capture_source_connected":               true,
		"first_capture_conversion_failure":       true,
		"first_network_audio_frame_generated":    true,
		"first_network_audio_frame_sent":         true,
		"first_network_audio_frame_send_failure": true,
		"first_remote_audio_frame_received":      true,
		"first_playback_buffer_scheduled":        true,
		"first_playback_failure":                 true,
		"media_connect_started":                  true,
		"media_connect_succeeded":                true,
		"media_connect_failed":                   true,
		"media_disconnected":                     true,
		"reconnect_started":                      true,
		"reconnect_succeeded":                    true,
		"reconnect_failed":                       true,
	}
	if decode(r, &body) != nil || !validID(body.RequestID) || body.Role != role || !allowedEvents[body.Event] || len(body.Status) > 256 || len(body.TokenPrefix) > 8 || body.TokenLength < 0 || body.TokenLength > 512 || len(body.Stage) > 32 || len(body.ErrorDomain) > 128 || (body.CallID != "" && !validID(body.CallID)) {
		writeError(w, http.StatusBadRequest, "invalid diagnostics")
		return
	}
	if body.Event == "callkit_error" && (body.Stage == "" || body.ErrorDomain == "") {
		writeError(w, http.StatusBadRequest, "invalid diagnostics")
		return
	}
	errorEvent := body.Event == "callkit_error" || body.Event == "voice_processing_enabled" || body.Event == "audio_engine_start_failure" || body.Event == "first_capture_conversion_failure" || body.Event == "first_network_audio_frame_send_failure" || body.Event == "first_playback_failure" || body.Event == "media_connect_failed" || body.Event == "media_disconnected" || body.Event == "server_call_create_failed"
	if !errorEvent && (body.Stage != "" || body.ErrorDomain != "" || body.ErrorCode != 0) {
		writeError(w, http.StatusBadRequest, "invalid diagnostics")
		return
	}
	if body.Event == "callkit_error" {
		slog.Warn("CallKit error diagnostic", "role", role, "platform", body.Platform, "callID", body.CallID, "stage", body.Stage, "domain", body.ErrorDomain, "code", body.ErrorCode)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if body.Event != "notification_permission" && body.Event != "apns_registration_started" && body.Event != "apns_registration_succeeded" && body.Event != "apns_registration_failed" {
		slog.Info("runtime diagnostic", "role", role, "platform", body.Platform, "callID", body.CallID, "event", body.Event, "status", body.Status, "domain", body.ErrorDomain, "code", body.ErrorCode)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	slog.Info("notification registration diagnostic", "role", role, "platform", body.Platform, "event", body.Event, "status", body.Status, "tokenPrefix", body.TokenPrefix, "tokenLength", body.TokenLength)
	w.WriteHeader(http.StatusNoContent)
}

type createRequest struct {
	RequestID string `json:"requestID"`
	CallID    string `json:"callID"`
}

func (s *Server) create(w http.ResponseWriter, r *http.Request) {
	var body createRequest
	if decode(r, &body) != nil || !validID(body.RequestID) || !validID(body.CallID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	view, err := s.calls.Create(strings.ToLower(body.CallID), body.RequestID, roleFrom(r.Context()))
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	slog.Info("call created", "callID", view.CallID, "caller", view.Caller, "callee", view.Callee, "state", view.State)
	if device, ok := s.devices.Get(view.Callee); ok {
		pushType := "voip"
		token := device.TokenFor(pushType)
		if token == "" {
			pushType = "alert"
			token = device.TokenFor(pushType)
		}
		if token == "" {
			slog.Warn("APNs delivery skipped", "callID", view.CallID, "role", view.Callee, "reason", "device_token_missing")
			writeJSON(w, http.StatusOK, view)
			return
		}
		prefix := token
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		slog.Info("APNs delivery attempted", "callID", view.CallID, "role", view.Callee, "platform", device.Platform, "pushType", pushType, "tokenPrefix", prefix, "tokenLength", len(token))
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := s.apns.IncomingCall(ctx, view.Callee, token, view.CallID, pushType); err != nil {
				slog.Warn("APNs delivery failed", "status", "delivery_failed")
			}
		}()
	} else {
		slog.Warn("APNs delivery skipped", "callID", view.CallID, "role", view.Callee, "reason", "device_token_missing")
	}
	writeJSON(w, http.StatusOK, view)
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	view, err := s.calls.Get(strings.ToLower(r.PathValue("id")), roleFrom(r.Context()))
	if err != nil {
		writeError(w, http.StatusNotFound, "call not found")
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type mutationRequest struct {
	RequestID string `json:"requestID"`
}

func (s *Server) mutate(w http.ResponseWriter, r *http.Request) {
	var body mutationRequest
	if decode(r, &body) != nil || !validID(body.RequestID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var target calls.State
	switch r.PathValue("action") {
	case "accept":
		target = calls.Accepted
	case "reject":
		target = calls.Rejected
	case "cancel":
		target = calls.Cancelled
	case "end":
		target = calls.Ended
	default:
		writeError(w, http.StatusNotFound, "unknown action")
		return
	}
	view, err := s.calls.Mutate(strings.ToLower(r.PathValue("id")), body.RequestID, roleFrom(r.Context()), target)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
}

type contextKey string

const roleKey contextKey = "role"

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		role := ""
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.tokenA)) == 1 {
			role = "A"
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.tokenB)) == 1 {
			role = "B"
		}
		if role == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), roleKey, role)))
	}
}
func roleFrom(ctx context.Context) string { value, _ := ctx.Value(roleKey).(string); return value }
func decode(r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
func validID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range strings.ToLower(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

var _ = errors.New
