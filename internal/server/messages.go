package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/apns"
	"github.com/kvuua-maker/wifi-secure-call-server/internal/messages"
)

const secureMessageRequestLimit = 128 * 1024

type createConversationRequest struct {
	RequestID    string `json:"requestID"`
	TargetUserID string `json:"targetUserID"`
}

type messageReceiptRequest struct {
	RequestID string `json:"requestID"`
}

type conversationPeer struct {
	UserID         string `json:"userID"`
	Username       string `json:"username"`
	DisplayName    string `json:"displayName,omitempty"`
	PublicIdentity string `json:"publicIdentity"`
}

type conversationResponse struct {
	messages.Conversation
	Peer *conversationPeer `json:"peer,omitempty"`
}

func (s *Server) conversationForUser(conversation messages.Conversation, userID string) conversationResponse {
	response := conversationResponse{Conversation: conversation}
	for _, participant := range conversation.Participants {
		if strings.EqualFold(participant, userID) {
			continue
		}
		if peer, err := s.phoneAuth.RecipientForUserID(participant); err == nil {
			response.Peer = &conversationPeer{
				UserID: peer.UserID, Username: peer.Username,
				DisplayName: peer.DisplayName, PublicIdentity: peer.PublicIdentity,
			}
		}
		break
	}
	return response
}

func (s *Server) createConversation(w http.ResponseWriter, r *http.Request) {
	if s.messages == nil {
		writeError(w, http.StatusServiceUnavailable, "messages_unavailable")
		return
	}
	var body createConversationRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) || !validID(body.TargetUserID) {
		writeError(w, http.StatusBadRequest, "invalid_recipient")
		return
	}
	identity := identityFrom(r.Context())
	if strings.EqualFold(identity.UserID, body.TargetUserID) {
		writeError(w, http.StatusConflict, "self_message_not_allowed")
		return
	}
	if _, err := s.phoneAuth.RecipientForUserID(body.TargetUserID); err != nil {
		writeServiceError(w, err)
		return
	}
	conversation, _, err := s.messages.CreateConversation(body.RequestID, identity.UserID, body.TargetUserID)
	if err != nil {
		writeMessageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.conversationForUser(conversation, identity.UserID))
}

func (s *Server) listConversations(w http.ResponseWriter, r *http.Request) {
	if s.messages == nil {
		writeError(w, http.StatusServiceUnavailable, "messages_unavailable")
		return
	}
	userID := identityFrom(r.Context()).UserID
	conversations := s.messages.Conversations(userID)
	response := make([]conversationResponse, 0, len(conversations))
	for _, conversation := range conversations {
		response = append(response, s.conversationForUser(conversation, userID))
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) listMessages(w http.ResponseWriter, r *http.Request) {
	if s.messages == nil {
		writeError(w, http.StatusServiceUnavailable, "messages_unavailable")
		return
	}
	limit := 30
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(w, http.StatusBadRequest, "invalid_cursor")
			return
		}
		limit = parsed
	}
	page, err := s.messages.Page(r.PathValue("conversationID"), identityFrom(r.Context()).UserID, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeMessageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) sendMessage(w http.ResponseWriter, r *http.Request) {
	if s.messages == nil || s.deviceKeys == nil {
		writeError(w, http.StatusServiceUnavailable, "messages_unavailable")
		return
	}
	var body messages.MessageInput
	if err := decodeSecureMessage(w, r, &body); err != nil {
		writeSecureMessageDecodeError(w, err)
		return
	}
	identity := identityFrom(r.Context())
	conversationID := strings.ToLower(r.PathValue("conversationID"))
	if !validID(conversationID) {
		writeError(w, http.StatusBadRequest, "invalid_message")
		return
	}
	signingBundle, ok := s.deviceKeys.ForDevice(identity.UserID, identity.DeviceID)
	if !ok {
		writeError(w, http.StatusConflict, "device_key_required")
		return
	}
	signingKey, keyErr := base64.StdEncoding.DecodeString(signingBundle.SigningPublicKey)
	signature, signatureErr := base64.StdEncoding.DecodeString(body.Signature)
	if keyErr != nil || signatureErr != nil || len(signingKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(signingKey), messages.SignatureMessage(conversationID, identity.UserID, identity.DeviceID, body), signature) {
		writeError(w, http.StatusBadRequest, "invalid_message_signature")
		return
	}
	conversations := s.messages.Conversations(identity.UserID)
	var recipientUserID string
	for _, conversation := range conversations {
		if conversation.ConversationID != conversationID {
			continue
		}
		for _, participant := range conversation.Participants {
			if !strings.EqualFold(participant, identity.UserID) {
				recipientUserID = participant
			}
		}
		break
	}
	if recipientUserID == "" {
		writeError(w, http.StatusNotFound, "conversation_not_participant")
		return
	}
	required, complete := s.requiredEnvelopeDevices(identity.UserID, identity.DeviceID, recipientUserID)
	if !complete || len(required) == 0 || !matchesEnvelopeDevices(body.Envelopes, required) {
		writeError(w, http.StatusConflict, "recipient_key_unavailable")
		return
	}
	message, created, err := s.messages.Send(conversationID, identity.UserID, identity.DeviceID, body)
	if err != nil {
		writeMessageError(w, err)
		return
	}
	if created {
		go s.deliverSecureMessage(message)
	}
	writeJSON(w, http.StatusOK, message)
}

func (s *Server) markMessageDelivered(w http.ResponseWriter, r *http.Request) {
	s.markMessage(w, r, false)
}

func (s *Server) markMessageRead(w http.ResponseWriter, r *http.Request) {
	s.markMessage(w, r, true)
}

func (s *Server) markMessage(w http.ResponseWriter, r *http.Request, read bool) {
	if s.messages == nil {
		writeError(w, http.StatusServiceUnavailable, "messages_unavailable")
		return
	}
	var body messageReceiptRequest
	if err := decode(w, r, &body); err != nil || !validID(body.RequestID) {
		writeError(w, http.StatusBadRequest, "invalid_receipt")
		return
	}
	identity := identityFrom(r.Context())
	message, _, err := s.messages.Mark(r.PathValue("conversationID"), r.PathValue("messageID"), identity.UserID, identity.DeviceID, read)
	if err != nil {
		writeMessageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, message)
}

func (s *Server) requiredEnvelopeDevices(senderUserID, senderDeviceID, recipientUserID string) (map[string]bool, bool) {
	required := map[string]bool{}
	for _, userID := range []string{recipientUserID, senderUserID} {
		devices := uniqueActiveDevices(s.phoneAuth.DevicesForUser(userID))
		active := make(map[string]bool, len(devices))
		for _, device := range devices {
			active[strings.ToLower(device.DeviceID)] = true
		}
		bundles := s.deviceKeys.ForUser(userID, active)
		if userID == recipientUserID && len(devices) == 0 {
			return nil, false
		}
		if len(bundles) != len(devices) {
			return nil, false
		}
		for _, bundle := range bundles {
			required[strings.ToLower(bundle.DeviceID)] = true
		}
	}
	return required, true
}

func uniqueActiveDevices(values []accounts.Device) []accounts.Device {
	byID := map[string]accounts.Device{}
	for _, value := range values {
		id := strings.ToLower(value.DeviceID)
		if id == "" {
			continue
		}
		prior, exists := byID[id]
		if !exists || value.LastSeenAt.After(prior.LastSeenAt) {
			byID[id] = value
		}
	}
	result := make([]accounts.Device, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	return result
}

func matchesEnvelopeDevices(envelopes []messages.Envelope, required map[string]bool) bool {
	if len(envelopes) != len(required) {
		return false
	}
	seen := map[string]bool{}
	for _, envelope := range envelopes {
		id := strings.ToLower(envelope.DeviceID)
		if !required[id] || seen[id] {
			return false
		}
		seen[id] = true
	}
	return len(seen) == len(required)
}

func (s *Server) deliverSecureMessage(message messages.Message) {
	sender, ok := s.apns.(apns.SecureMessageSender)
	if !ok {
		return
	}
	for _, device := range uniqueActiveDevices(s.phoneAuth.DevicesForUser(message.RecipientUserID)) {
		if device.Environment != "production" || device.AlertToken == "" || !device.Capabilities.AlertPush || !device.Capabilities.NotificationsAuthorized {
			continue
		}
		if device.Platform != "iOS" && device.Platform != "watchOS" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		result, err := sender.SecureMessage(ctx, device.Platform, device.AlertToken, message.ConversationID, message.MessageID, device.AccountID, time.Now().Add(24*time.Hour))
		cancel()
		if err != nil {
			if result.DeadToken {
				_ = s.phoneAuth.InvalidateAccountDeviceToken(device.AccountID, device.DeviceID, "alert", device.AlertToken, device.InstallationGeneration)
			}
			slog.Warn("secure message APNs submission failed", "conversationID", message.ConversationID, "messageID", message.MessageID, "platform", device.Platform, "status", result.Status, "reason", result.Reason)
			continue
		}
		slog.Info("secure message APNs submission accepted", "conversationID", message.ConversationID, "messageID", message.MessageID, "platform", device.Platform, "status", result.Status, "apnsID", result.APNSID)
	}
}

func decodeSecureMessage(w http.ResponseWriter, r *http.Request, value any) error {
	if r.ContentLength > secureMessageRequestLimit {
		return &http.MaxBytesError{Limit: secureMessageRequestLimit}
	}
	r.Body = http.MaxBytesReader(w, r.Body, secureMessageRequestLimit)
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

func writeSecureMessageDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large")
		return
	}
	writeError(w, http.StatusBadRequest, "invalid_message")
}

func writeMessageError(w http.ResponseWriter, err error) {
	code := messages.ErrorCode(err)
	status := http.StatusBadRequest
	switch code {
	case "conversation_not_participant", "message_not_recipient":
		status = http.StatusForbidden
	case "message_not_found":
		status = http.StatusNotFound
	case "idempotency_conflict":
		status = http.StatusConflict
	case "message_rate_limited":
		status = http.StatusTooManyRequests
	case "":
		code, status = "message_failed", http.StatusInternalServerError
	}
	writeError(w, status, code)
}
