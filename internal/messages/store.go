package messages

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Error struct{ Code string }

func (e *Error) Error() string  { return e.Code }
func failure(code string) error { return &Error{Code: code} }
func ErrorCode(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}

type state struct {
	SchemaVersion        int                      `json:"schemaVersion"`
	Conversations        map[string]Conversation  `json:"conversations"`
	Messages             map[string]Message       `json:"messages"`
	ConversationMessages map[string][]string      `json:"conversationMessages"`
	ConversationRequests map[string]string        `json:"conversationRequests"`
	MessageRequests      map[string]requestRecord `json:"messageRequests"`
}
type requestRecord struct {
	MessageID, Parameters string
	CreatedAt             time.Time
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state state
	now   func() time.Time
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: emptyState(), now: time.Now}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.state); err != nil {
		return nil, err
	}
	if s.state.SchemaVersion != SchemaVersion {
		return nil, errors.New("unsupported message schema")
	}
	normalizeState(&s.state)
	if err = validateState(s.state); err != nil {
		return nil, err
	}
	return s, nil
}
func NewMemory() *Store                        { value, _ := Open(""); return value }
func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = now }

func (s *Store) CreateConversation(requestID, ownerUserID, targetUserID string) (Conversation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requestID, ownerUserID, targetUserID = normalize(requestID), normalize(ownerUserID), normalize(targetUserID)
	if !validUUID(requestID) || !validUUID(ownerUserID) || !validUUID(targetUserID) || ownerUserID == targetUserID {
		return Conversation{}, false, failure("invalid_recipient")
	}
	participants := []string{ownerUserID, targetUserID}
	sort.Strings(participants)
	key := strings.Join(participants, "\x00")
	if priorID, ok := s.state.ConversationRequests[requestID]; ok {
		prior, found := s.state.Conversations[priorID]
		if !found || strings.Join(prior.Participants, "\x00") != key {
			return Conversation{}, false, failure("idempotency_conflict")
		}
		return prior, false, nil
	}
	for _, conversation := range s.state.Conversations {
		if strings.Join(conversation.Participants, "\x00") == key {
			return conversation, false, nil
		}
	}
	now := s.now().UTC()
	id, err := newUUID()
	if err != nil {
		return Conversation{}, false, err
	}
	conversation := Conversation{ConversationID: id, Participants: participants, CreatedAt: now, UpdatedAt: now}
	next := cloneState(s.state)
	next.Conversations[id] = conversation
	next.ConversationRequests[requestID] = id
	if err = s.persist(next); err != nil {
		return Conversation{}, false, err
	}
	s.state = next
	return conversation, true, nil
}

func (s *Store) Conversations(userID string) []Conversation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID = normalize(userID)
	result := make([]Conversation, 0)
	for _, value := range s.state.Conversations {
		if contains(value.Participants, userID) {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].UpdatedAt.Equal(result[j].UpdatedAt) {
			return result[i].ConversationID < result[j].ConversationID
		}
		return result[i].UpdatedAt.After(result[j].UpdatedAt)
	})
	return result
}

func (s *Store) Send(conversationID, senderUserID, senderDeviceID string, input MessageInput) (Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conversationID, senderUserID, senderDeviceID = normalize(conversationID), normalize(senderUserID), normalize(senderDeviceID)
	input.MessageID, input.ClientMessageID = normalize(input.MessageID), normalize(input.ClientMessageID)
	conversation, ok := s.state.Conversations[conversationID]
	if !ok || !contains(conversation.Participants, senderUserID) {
		return Message{}, false, failure("conversation_not_participant")
	}
	if !validUUID(input.MessageID) || !validUUID(input.ClientMessageID) || !validUUID(senderDeviceID) {
		return Message{}, false, failure("invalid_message")
	}
	if err := validateInput(input); err != nil {
		return Message{}, false, err
	}
	recipient := conversation.Participants[0]
	if recipient == senderUserID {
		recipient = conversation.Participants[1]
	}
	parameters, _ := json.Marshal(struct {
		Conversation, Sender string
		Input                MessageInput
	}{conversationID, senderUserID + "\x00" + senderDeviceID, input})
	hash := sha256.Sum256(parameters)
	requestKey := senderUserID + "\x00" + input.ClientMessageID
	if prior, ok := s.state.MessageRequests[requestKey]; ok {
		if prior.Parameters != hex.EncodeToString(hash[:]) {
			return Message{}, false, failure("idempotency_conflict")
		}
		message, found := s.state.Messages[prior.MessageID]
		if !found {
			return Message{}, false, failure("message_not_found")
		}
		return message, false, nil
	}
	if _, exists := s.state.Messages[input.MessageID]; exists {
		return Message{}, false, failure("idempotency_conflict")
	}
	now := s.now().UTC()
	sent := 0
	for _, message := range s.state.Messages {
		if message.SenderDeviceID == senderDeviceID && now.Sub(message.CreatedAt) < time.Minute {
			sent++
		}
	}
	if sent >= 60 {
		return Message{}, false, failure("message_rate_limited")
	}
	message := Message{MessageID: input.MessageID, ConversationID: conversationID, ClientMessageID: input.ClientMessageID, SenderUserID: senderUserID, SenderDeviceID: senderDeviceID, RecipientUserID: recipient, CreatedAt: now, ProtocolVersion: input.ProtocolVersion, KeyVersion: input.KeyVersion, Nonce: input.Nonce, Ciphertext: input.Ciphertext, Tag: input.Tag, Envelopes: append([]Envelope(nil), input.Envelopes...), Signature: input.Signature, Receipts: []Receipt{}}
	next := cloneState(s.state)
	next.Messages[message.MessageID] = message
	next.ConversationMessages[conversationID] = append(next.ConversationMessages[conversationID], message.MessageID)
	next.MessageRequests[requestKey] = requestRecord{MessageID: message.MessageID, Parameters: hex.EncodeToString(hash[:]), CreatedAt: now}
	conversation.UpdatedAt = now
	next.Conversations[conversationID] = conversation
	prune(&next, now)
	if err := validateState(next); err != nil {
		return Message{}, false, err
	}
	if err := s.persist(next); err != nil {
		return Message{}, false, err
	}
	s.state = next
	return message, true, nil
}

func (s *Store) Page(conversationID, userID, cursor string, limit int) (Page, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	conversationID, userID = normalize(conversationID), normalize(userID)
	conversation, ok := s.state.Conversations[conversationID]
	if !ok || !contains(conversation.Participants, userID) {
		return Page{}, failure("conversation_not_participant")
	}
	if limit <= 0 {
		limit = 30
	}
	if limit > 100 {
		limit = 100
	}
	start := 0
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return Page{}, failure("invalid_cursor")
		}
		marker := string(raw)
		found := false
		for i, id := range s.state.ConversationMessages[conversationID] {
			if id == marker {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			return Page{}, failure("invalid_cursor")
		}
	}
	ids := s.state.ConversationMessages[conversationID]
	end := start + limit
	if end > len(ids) {
		end = len(ids)
	}
	items := make([]Message, 0, end-start)
	for _, id := range ids[start:end] {
		if value, ok := s.state.Messages[id]; ok {
			items = append(items, value)
		}
	}
	next := ""
	if end < len(ids) && end > 0 {
		next = base64.RawURLEncoding.EncodeToString([]byte(ids[end-1]))
	}
	return Page{Messages: items, NextCursor: next}, nil
}

func (s *Store) Mark(conversationID, messageID, userID, deviceID string, read bool) (Message, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	conversationID, messageID, userID, deviceID = normalize(conversationID), normalize(messageID), normalize(userID), normalize(deviceID)
	conversation, ok := s.state.Conversations[conversationID]
	if !ok || !contains(conversation.Participants, userID) {
		return Message{}, false, failure("conversation_not_participant")
	}
	message, ok := s.state.Messages[messageID]
	if !ok || message.ConversationID != conversationID {
		return Message{}, false, failure("message_not_found")
	}
	if message.RecipientUserID != userID || !validUUID(deviceID) {
		return Message{}, false, failure("message_not_recipient")
	}
	now := s.now().UTC()
	applied := false
	found := false
	for i := range message.Receipts {
		if message.Receipts[i].DeviceID == deviceID {
			found = true
			if message.Receipts[i].DeliveredAt == nil {
				value := now
				message.Receipts[i].DeliveredAt = &value
				applied = true
			}
			if read && message.Receipts[i].ReadAt == nil {
				value := now
				message.Receipts[i].ReadAt = &value
				applied = true
			}
			break
		}
	}
	if !found {
		receipt := Receipt{DeviceID: deviceID}
		value := now
		receipt.DeliveredAt = &value
		if read {
			readAt := now
			receipt.ReadAt = &readAt
		}
		message.Receipts = append(message.Receipts, receipt)
		applied = true
	}
	if !applied {
		return message, false, nil
	}
	next := cloneState(s.state)
	next.Messages[messageID] = message
	if err := s.persist(next); err != nil {
		return Message{}, false, err
	}
	s.state = next
	return message, true, nil
}

func validateInput(input MessageInput) error {
	if input.ProtocolVersion != ProtocolVersion || input.KeyVersion == 0 || len(input.Envelopes) == 0 || len(input.Envelopes) > MaxEnvelopes {
		return failure("invalid_message")
	}
	if _, err := decodeBounded(input.Nonce, 12, 12); err != nil {
		return failure("invalid_message")
	}
	if _, err := decodeBounded(input.Tag, 16, 16); err != nil {
		return failure("invalid_message")
	}
	if _, err := decodeBounded(input.Signature, 64, 64); err != nil {
		return failure("invalid_message")
	}
	if _, err := decodeBounded(input.Ciphertext, 1, MaxCiphertextBytes); err != nil {
		return failure("invalid_message")
	}
	seen := map[string]bool{}
	for _, envelope := range input.Envelopes {
		id := normalize(envelope.DeviceID)
		if !validUUID(id) || seen[id] || envelope.KeyVersion == 0 {
			return failure("invalid_message")
		}
		seen[id] = true
		if _, err := decodeBounded(envelope.EphemeralPublicKey, 32, 32); err != nil {
			return failure("invalid_message")
		}
		if _, err := decodeBounded(envelope.Nonce, 12, 12); err != nil {
			return failure("invalid_message")
		}
		if _, err := decodeBounded(envelope.Tag, 16, 16); err != nil {
			return failure("invalid_message")
		}
		if _, err := decodeBounded(envelope.Ciphertext, 1, 256); err != nil {
			return failure("invalid_message")
		}
	}
	return nil
}
func SignatureMessage(conversationID, senderUserID, senderDeviceID string, input MessageInput) []byte {
	parts := []string{"wsc-message-v1", normalize(conversationID), normalize(input.MessageID), normalize(input.ClientMessageID), normalize(senderUserID), normalize(senderDeviceID), strconv.FormatUint(input.ProtocolVersion, 10), strconv.FormatUint(input.KeyVersion, 10), input.Nonce, input.Ciphertext, input.Tag}
	for _, envelope := range input.Envelopes {
		parts = append(parts, strings.Join([]string{normalize(envelope.DeviceID), strconv.FormatUint(envelope.KeyVersion, 10), envelope.EphemeralPublicKey, envelope.Nonce, envelope.Ciphertext, envelope.Tag}, "|"))
	}
	return []byte(strings.Join(parts, "\n"))
}
func decodeBounded(value string, min, max int) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) < min || len(data) > max {
		return nil, errors.New("invalid encoding")
	}
	return data, nil
}
func emptyState() state {
	return state{SchemaVersion: SchemaVersion, Conversations: map[string]Conversation{}, Messages: map[string]Message{}, ConversationMessages: map[string][]string{}, ConversationRequests: map[string]string{}, MessageRequests: map[string]requestRecord{}}
}
func normalizeState(value *state) {
	if value.Conversations == nil {
		value.Conversations = map[string]Conversation{}
	}
	if value.Messages == nil {
		value.Messages = map[string]Message{}
	}
	if value.ConversationMessages == nil {
		value.ConversationMessages = map[string][]string{}
	}
	if value.ConversationRequests == nil {
		value.ConversationRequests = map[string]string{}
	}
	if value.MessageRequests == nil {
		value.MessageRequests = map[string]requestRecord{}
	}
}
func cloneState(input state) state {
	data, _ := json.Marshal(input)
	result := emptyState()
	_ = json.Unmarshal(data, &result)
	return result
}
func validateState(value state) error {
	if value.SchemaVersion != SchemaVersion {
		return errors.New("invalid message schema")
	}
	for id, c := range value.Conversations {
		if id != c.ConversationID || !validUUID(id) || len(c.Participants) != 2 || !validUUID(c.Participants[0]) || !validUUID(c.Participants[1]) || c.Participants[0] >= c.Participants[1] {
			return errors.New("invalid conversation state")
		}
	}
	for id, m := range value.Messages {
		if id != m.MessageID || !validUUID(id) || value.Conversations[m.ConversationID].ConversationID == "" || m.SenderUserID == m.RecipientUserID {
			return errors.New("invalid message state")
		}
	}
	return nil
}
func prune(value *state, now time.Time) {
	cutoff := now.Add(-Retention)
	for id, m := range value.Messages {
		if m.CreatedAt.Before(cutoff) {
			delete(value.Messages, id)
		}
	}
	for id, ids := range value.ConversationMessages {
		filtered := ids[:0]
		for _, messageID := range ids {
			if _, ok := value.Messages[messageID]; ok {
				filtered = append(filtered, messageID)
			}
		}
		value.ConversationMessages[id] = filtered
	}
	for id, r := range value.MessageRequests {
		if r.CreatedAt.Before(cutoff) {
			delete(value.MessageRequests, id)
		}
	}
}
func (s *Store) persist(value state) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".messages-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
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
func newUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	hexValue := hex.EncodeToString(raw)
	return hexValue[0:8] + "-" + hexValue[8:12] + "-" + hexValue[12:16] + "-" + hexValue[16:20] + "-" + hexValue[20:32], nil
}
