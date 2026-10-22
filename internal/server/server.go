package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountcalls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/accountmedia"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/calls"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/devices"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/diagnostics"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/media"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/relay"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/usercalls"
)

type Server struct {
	callCreationMu    sync.Mutex
	tokenA, tokenB    string
	calls             *calls.Store
	devices           *devices.Store
	apns              apns.Sender
	media             *media.Hub
	mux               *http.ServeMux
	phoneAuth         *phoneauth.Service
	accountCalls      *accountcalls.Store
	userCalls         *usercalls.Store
	accountMedia      *accountmedia.Hub
	relay             *relay.Hub
	diagnostics       *diagnostics.Store
	diagnosticsRateMu sync.Mutex
	diagnosticsRate   map[string]time.Time
}

func New(tokenA, tokenB string, callStore *calls.Store, deviceStore *devices.Store, push apns.Sender) *Server {
	return NewWithV2(tokenA, tokenB, callStore, deviceStore, push, nil)
}

func NewWithV2(tokenA, tokenB string, callStore *calls.Store, deviceStore *devices.Store, push apns.Sender, auth *phoneauth.Service) *Server {
	var accountCallStore *accountcalls.Store
	if auth != nil {
		accountCallStore = accountcalls.New(30 * time.Second)
	}
	return NewWithV2Calls(tokenA, tokenB, callStore, deviceStore, push, auth, accountCallStore)
}

func NewWithV2Calls(tokenA, tokenB string, callStore *calls.Store, deviceStore *devices.Store, push apns.Sender, auth *phoneauth.Service, accountCallStore *accountcalls.Store) *Server {
	var userCallStore *usercalls.Store
	if auth != nil {
		userCallStore = usercalls.New(30 * time.Second)
	}
	return NewWithCallStores(tokenA, tokenB, callStore, deviceStore, push, auth, accountCallStore, userCallStore)
}

func NewWithCallStores(tokenA, tokenB string, callStore *calls.Store, deviceStore *devices.Store, push apns.Sender, auth *phoneauth.Service, accountCallStore *accountcalls.Store, userCallStore *usercalls.Store) *Server {
	s := &Server{tokenA: tokenA, tokenB: tokenB, calls: callStore, devices: deviceStore, apns: push, phoneAuth: auth, accountCalls: accountCallStore, userCalls: userCallStore}
	s.media = media.New(callStore)
	if accountCallStore != nil || userCallStore != nil {
		s.accountMedia = accountmedia.New(combinedCallValidator{account: accountCallStore, user: userCallStore})
	}
	s.relay = relay.New(10*time.Minute, 8)
	// Diagnostics must never block the product: if the log directory cannot be
	// opened, the server runs without them rather than refusing to start.
	path := os.Getenv("WSC_DIAGNOSTICS_PATH")
	if path == "" {
		path = "/var/log/wifisecurecall/diagnostics.json"
	}
	if store, err := diagnostics.New(path); err == nil {
		s.diagnostics = store
	} else {
		slog.Warn("diagnostics disabled", "path", path, "error", err)
	}
	s.mux = http.NewServeMux()
	s.mux.HandleFunc("GET /v1/health", s.health)
	s.mux.HandleFunc("POST /v1/devices/register", s.auth(s.register))
	s.mux.HandleFunc("POST /v1/devices/diagnostics", s.auth(s.notificationDiagnostics))
	s.mux.HandleFunc("POST /v1/calls", s.auth(s.create))
	s.mux.HandleFunc("GET /v1/calls/{id}", s.auth(s.get))
	s.mux.HandleFunc("POST /v1/calls/{id}/{action}", s.auth(s.mutate))
	s.mux.HandleFunc("/media", s.serveMedia)
	s.registerV2()
	s.registerV3()
	// The relay is the fallback for a dial command WatchConnectivity could not
	// deliver, so it lives beside the account routes and uses the same identity.
	s.mux.HandleFunc("GET /v1/relay", s.v2Auth(s.relaySocket))
	return s
}
func (s *Server) Handler() http.Handler { return securityHeaders(s.recoverPanics(s.mux)) }

// recoverPanics keeps one broken handler from taking the process down, and leaves
// a record behind so the failure is visible in the diagnostics feed.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				s.recordDiagnostic("server", "SERVER", "go_routine_panic", "error", r.URL.Path, fmt.Errorf("%v", value))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// recordDiagnostic writes one server-side event. It is best effort and never
// blocks the caller on a full disk.
func (s *Server) recordDiagnostic(device, category, step, status, details string, err error) {
	if s.diagnostics == nil {
		return
	}
	record := diagnostics.Record{
		Timestamp: time.Now().UTC(),
		Device:    device,
		Category:  category,
		Step:      step,
		Status:    status,
		Details:   details,
	}
	if err != nil {
		record.Error = err.Error()
	}
	go func() {
		if writeErr := s.diagnostics.Append([]diagnostics.Record{record}); writeErr != nil {
			slog.Warn("diagnostics write failed", "error", writeErr)
		}
	}()
}
func (s *Server) Shutdown() {
	s.media.CloseAll("server restart")
	if s.accountMedia != nil {
		s.accountMedia.CloseAll("server restart")
	}
}

func (s *Server) serveMedia(w http.ResponseWriter, r *http.Request) {
	role, side := r.URL.Query().Get("role"), r.URL.Query().Get("side")
	if (role == "A" || role == "B") && side == "" {
		s.media.ServeHTTP(w, r)
		return
	}
	if role == "" && (side == string(accountcalls.SideCaller) || side == string(accountcalls.SideCallee)) && s.accountMedia != nil {
		s.accountMedia.ServeHTTP(w, r)
		return
	}
	http.Error(w, "invalid media participant", http.StatusBadRequest)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	_, a := s.devices.Get("A")
	_, b := s.devices.Get("B")
	readyA, readyB := false, false
	if value, ok := s.devices.Get("A"); ok {
		readyA = value.LiveReady()
	}
	if value, ok := s.devices.Get("B"); ok {
		readyB = value.LiveReady()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "apnsConfigured": s.apns.Configured(), "build": buildIdentity(), "mediaReady": true, "roleAReady": a && readyA, "roleBReady": b && readyB})
}

type registerCapabilities struct {
	VoIPPush                bool `json:"voipPush"`
	AlertPush               bool `json:"alertPush"`
	NotificationsAuthorized bool `json:"notificationsAuthorized"`
	MicrophoneReady         bool `json:"microphoneReady"`
}
type registerRequest struct {
	RequestID, Role, Token, InvalidatedToken, Platform, PushType, InstallationID, Environment string
	InstallationGeneration                                                                    uint64
	Capabilities                                                                              registerCapabilities
}

type notificationDiagnosticRequest struct {
	RequestID, Role, Platform, Event, Status, TokenPrefix string
	Stage, ErrorDomain                                    string
	CallID                                                string
	TokenLength, ErrorCode                                int
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	role := roleFrom(r.Context())
	var body registerRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid registration")
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
		if err := s.devices.Invalidate(role, body.PushType, body.InstallationID, body.InstallationGeneration, body.InvalidatedToken); err != nil {
			writeError(w, http.StatusBadRequest, "invalid registration")
			return
		}
		slog.Info("push token invalidated", "role", role, "platform", body.Platform, "pushType", body.PushType)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.devices.Register(role, body.Platform, body.PushType, body.Token, body.InstallationID, body.InstallationGeneration, body.Environment, devices.Capabilities{VoIPPush: body.Capabilities.VoIPPush, AlertPush: body.Capabilities.AlertPush, NotificationsAuthorized: body.Capabilities.NotificationsAuthorized, MicrophoneReady: body.Capabilities.MicrophoneReady}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
	slog.Info("APNs device registered", "role", role, "platform", body.Platform, "pushType", body.PushType, "tokenLength", len(body.Token))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) notificationDiagnostics(w http.ResponseWriter, r *http.Request) {
	role := roleFrom(r.Context())
	var body notificationDiagnosticRequest
	allowedEvents := map[string]bool{
		"notification_permission":                          true,
		"apns_registration_started":                        true,
		"apns_registration_succeeded":                      true,
		"apns_registration_failed":                         true,
		"callkit_error":                                    true,
		"start_call_entered":                               true,
		"microphone_permission":                            true,
		"callkit_start_requested":                          true,
		"callkit_start_approved":                           true,
		"server_call_create_started":                       true,
		"server_call_create_succeeded":                     true,
		"server_call_create_failed":                        true,
		"call_state_poll_failure":                          true,
		"new_call_blocked":                                 true,
		"previous_terminal_reset":                          true,
		"audio_session_configured":                         true,
		"callkit_did_activate":                             true,
		"callkit_did_deactivate":                           true,
		"audio_engine_start_attempt":                       true,
		"audio_engine_start_success":                       true,
		"audio_engine_start_failure":                       true,
		"voice_processing_enabled":                         true,
		"input_format":                                     true,
		"output_format":                                    true,
		"first_mic_buffer":                                 true,
		"capture_source_connected":                         true,
		"first_capture_conversion_failure":                 true,
		"first_network_audio_frame_generated":              true,
		"first_network_audio_frame_sent":                   true,
		"first_network_audio_frame_send_failure":           true,
		"first_remote_audio_frame_received":                true,
		"first_playback_buffer_scheduled":                  true,
		"first_playback_failure":                           true,
		"media_connect_started":                            true,
		"media_connect_succeeded":                          true,
		"media_connect_failed":                             true,
		"media_disconnected":                               true,
		"reconnect_started":                                true,
		"reconnect_succeeded":                              true,
		"reconnect_failed":                                 true,
		"incoming_callkit_reported":                        true,
		"incoming_reconcile_failed":                        true,
		"callkit_action_timeout":                           true,
		"illegal_state_transition":                         true,
		"media_peer_ready":                                 true,
		"terminal_observer_failure":                        true,
		"terminal_mutation_failed":                         true,
		"callkit_end_action_received":                      true,
		"system_end_reconcile_started":                     true,
		"system_end_reconcile_result":                      true,
		"system_end_preserved_after_remote_accept":         true,
		"system_end_duplicate_preserved_during_connecting": true,
		"mute_state_changed":                               true,
		"audio_input_mute":                                 true,
		"audio_route":                                      true,
		"audio_route_changed":                              true,
		"audio_interruption":                               true,
		"capture_watchdog_failed":                          true,
		"first_playback_buffer_rendered":                   true,
		"playback_overflow":                                true,
		"watch_background_notification_received":           true,
		"watch_background_callkit_handoff":                 true,
		"duplicate_incoming_suppressed":                    true,
		"watch_alert_action_received":                      true,
		"watch_notification_capabilities_refreshed":        true,
	}
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid diagnostics")
		return
	}
	if !validID(body.RequestID) || body.Role != role || !allowedEvents[body.Event] || len(body.Status) > 256 || len(body.TokenPrefix) > 8 || body.TokenLength < 0 || body.TokenLength > 512 || len(body.Stage) > 32 || len(body.ErrorDomain) > 128 || (body.CallID != "" && !validID(body.CallID)) {
		writeError(w, http.StatusBadRequest, "invalid diagnostics")
		return
	}
	if body.Event == "callkit_error" && (body.Stage == "" || body.ErrorDomain == "") {
		writeError(w, http.StatusBadRequest, "invalid diagnostics")
		return
	}
	errorEvent := body.Event == "callkit_error" || body.Event == "voice_processing_enabled" || body.Event == "audio_engine_start_failure" || body.Event == "first_capture_conversion_failure" || body.Event == "first_network_audio_frame_send_failure" || body.Event == "first_playback_failure" || body.Event == "media_connect_failed" || body.Event == "media_disconnected" || body.Event == "server_call_create_failed" || body.Event == "call_state_poll_failure"
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
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if !validID(body.RequestID) || !validID(body.CallID) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	view, createdNew, err := s.calls.Create(strings.ToLower(body.CallID), body.RequestID, roleFrom(r.Context()))
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if !createdNew {
		slog.Info("call create reconciled", "callID", view.CallID, "caller", view.Caller, "state", view.State)
		writeJSON(w, http.StatusOK, view)
		return
	}
	slog.Info("call created", "callID", view.CallID, "caller", view.Caller, "callee", view.Callee, "state", view.State)
	if device, ok := s.devices.Get(view.Callee); ok {
		token, pushType := selectIncomingPush(device, view.Callee)
		if token == "" {
			slog.Warn("APNs delivery skipped", "callID", view.CallID, "role", view.Callee, "reason", "device_token_missing")
			s.calls.FailDelivery(view.CallID, "device_token_missing")
			writeJSON(w, http.StatusOK, view)
			return
		}
		slog.Info("APNs delivery attempted", "callID", view.CallID, "role", view.Callee, "platform", device.Platform, "pushType", pushType, "tokenLength", len(token))
		go func(device devices.Registration, token, pushType string) {
			if !s.calls.IsRinging(view.CallID) {
				return
			}
			deadline := view.RingExpiresAt
			if deadline.IsZero() {
				deadline = time.Now().Add(8 * time.Second)
			}
			if deadline.After(time.Now().Add(8 * time.Second)) {
				deadline = time.Now().Add(8 * time.Second)
			}
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			result, err := s.apns.IncomingCall(ctx, view.Callee, token, view.CallID, pushType, view.RingExpiresAt)
			if err != nil {
				reason := result.Reason
				if reason == "" {
					reason = "unavailable"
				}
				s.calls.FailDelivery(view.CallID, reason)
				slog.Warn("APNs submission failed", "callID", view.CallID, "status", result.Status, "reason", result.Reason)
				if result.DeadToken {
					_ = s.devices.Invalidate(view.Callee, pushType, device.InstallationID, device.InstallationGeneration, token)
				}
				return
			}
			s.calls.SetDelivery(view.CallID, "submission_accepted")
			slog.Info("APNs submission accepted", "callID", view.CallID, "status", result.Status, "apnsID", result.APNSID)
		}(device, token, pushType)
	} else {
		slog.Warn("APNs delivery skipped", "callID", view.CallID, "role", view.Callee, "reason", "device_token_missing")
		s.calls.FailDelivery(view.CallID, "device_token_missing")
	}
	writeJSON(w, http.StatusOK, view)
}

func selectIncomingPush(device devices.Registration, calleeRole string) (token, pushType string) {
	preferred := []string{"voip", "alert"}
	if calleeRole == "A" && device.Platform == "watchOS" {
		preferred = []string{"alert", "voip"}
	}
	for _, candidate := range preferred {
		if token := device.TokenFor(candidate, "production"); token != "" {
			return token, candidate
		}
	}
	return "", preferred[0]
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
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	if !validID(body.RequestID) {
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
	view, _, err := s.calls.Mutate(strings.ToLower(r.PathValue("id")), body.RequestID, roleFrom(r.Context()), target)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if view.State == calls.Ended || view.State == calls.Cancelled || view.State == calls.Rejected || view.State == calls.Expired {
		s.media.CloseCall(view.CallID, string(view.State))
	}
	writeJSON(w, http.StatusOK, view)
}

type contextKey string

const roleKey contextKey = "role"

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") || strings.Count(header, " ") != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		token := strings.TrimPrefix(header, "Bearer ")
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
func decode(w http.ResponseWriter, r *http.Request, value any) error {
	if r.ContentLength > 4096 {
		return &http.MaxBytesError{Limit: 4096}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}
func writeDecodeError(w http.ResponseWriter, err error, message string) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	writeError(w, http.StatusBadRequest, message)
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

// embeddedBuild is set from the source commit by the production build command.
// WSC_BUILD remains a development fallback for older deployment tooling.
var embeddedBuild string

func buildIdentity() string {
	if value := strings.TrimSpace(embeddedBuild); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("WSC_BUILD")); value != "" {
		return value
	}
	return "development"
}

// relaySocket hands one authenticated connection to the relay hub.
//
// role=iphone receives queued dial commands, role=watch submits them. The account
// comes from the bearer token, never from the query, so a caller cannot address
// somebody else's queue.
func (s *Server) relaySocket(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	role := r.URL.Query().Get("role")
	relay.ServeWS(s.relay, identity.AccountID, role, w, r, slog.Default())
}
