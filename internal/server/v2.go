package server

import (
	"context"
	"net"
	"net/http"
	"strings"

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
