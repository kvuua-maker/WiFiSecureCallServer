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

type registerRequest struct{ RequestID, Role, Token, Platform string }

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	role := roleFrom(r.Context())
	var body registerRequest
	if decode(r, &body) != nil || body.Role != role {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
	if err := s.devices.Register(devices.Registration{Role: role, Token: body.Token, Platform: body.Platform}); err != nil {
		writeError(w, http.StatusBadRequest, "invalid registration")
		return
	}
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
	if device, ok := s.devices.Get(view.Callee); ok {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := s.apns.IncomingCall(ctx, view.Callee, device.Token, view.CallID); err != nil {
				slog.Warn("APNs delivery failed", "status", "delivery_failed")
			}
		}()
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
