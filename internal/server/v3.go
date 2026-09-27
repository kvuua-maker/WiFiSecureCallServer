package server

import (
	"net/http"
	"strings"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/phoneauth"
)

func (s *Server) registerV3() {
	s.mux.HandleFunc("POST /v3/auth/apple", s.appleSignIn)
	s.mux.HandleFunc("GET /v3/me", s.v2Auth(s.v3Me))
	s.mux.HandleFunc("PUT /v3/me/username", s.v2Auth(s.setUsername))
	s.mux.HandleFunc("GET /v3/me/public-identity", s.v2Auth(s.v3Me))
	s.mux.HandleFunc("POST /v3/phones/start", s.v2Auth(s.phoneBindingStart))
	s.mux.HandleFunc("POST /v3/phones/verify", s.v2Auth(s.phoneBindingVerify))
	s.mux.HandleFunc("DELETE /v3/phones/{id}", s.v2Auth(s.phoneBindingDelete))
	s.mux.HandleFunc("DELETE /v3/account", s.v2Auth(s.deleteAccount))
	s.mux.HandleFunc("POST /v3/recipients/resolve", s.v2Auth(s.resolveRecipient))
	s.mux.HandleFunc("POST /v3/calls", s.v2Auth(s.createUserCall))
	s.mux.HandleFunc("GET /v3/calls/{id}", s.v2Auth(s.getUserCall))
	s.mux.HandleFunc("POST /v3/calls/{id}/{action}", s.v2Auth(s.mutateUserCall))
	s.mux.HandleFunc("POST /v3/cellular-controls", s.v2Auth(s.createCellularControl))
	s.mux.HandleFunc("GET /v3/cellular-controls/{id}", s.v2Auth(s.getCellularControl))
	s.mux.HandleFunc("POST /v3/cellular-controls/{id}/{action}", s.v2Auth(s.mutateCellularControl))
}

type appleSignInRequest struct{ RequestID, DeviceID, Platform, IdentityToken, AuthorizationCode, Nonce, DisplayName, Email string }

func (s *Server) appleSignIn(w http.ResponseWriter, r *http.Request) {
	var body appleSignInRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.AppleSignIn(r.Context(), phoneauth.AppleSignInRequest{RequestID: body.RequestID, DeviceID: body.DeviceID, Platform: body.Platform, IdentityToken: body.IdentityToken, AuthorizationCode: body.AuthorizationCode, Nonce: body.Nonce, DisplayName: body.DisplayName, Email: body.Email})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) v3Me(w http.ResponseWriter, r *http.Request) {
	result, err := s.phoneAuth.Profile(identityFrom(r.Context()))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type usernameRequest struct{ Username string }

func (s *Server) setUsername(w http.ResponseWriter, r *http.Request) {
	var body usernameRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.SetUsername(identityFrom(r.Context()), body.Username)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type bindingStartRequest struct{ RequestID, PhoneNumber string }

func (s *Server) phoneBindingStart(w http.ResponseWriter, r *http.Request) {
	var body bindingStartRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.StartPhoneBinding(r.Context(), identityFrom(r.Context()), body.RequestID, body.PhoneNumber, sourceIP(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

type bindingVerifyRequest struct{ VerificationID, Code string }

func (s *Server) phoneBindingVerify(w http.ResponseWriter, r *http.Request) {
	var body bindingVerifyRequest
	if err := decode(w, r, &body); err != nil {
		writeDecodeError(w, err, "invalid request")
		return
	}
	result, err := s.phoneAuth.VerifyPhoneBinding(identityFrom(r.Context()), body.VerificationID, body.Code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) phoneBindingDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(r.PathValue("id"))
	if err := s.phoneAuth.RemovePhoneBinding(identityFrom(r.Context()), id); err != nil {
		writeServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
