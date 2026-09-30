package devicekeys

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = 2

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

type Registration struct {
	RequestID          string `json:"requestID"`
	DeviceID           string `json:"deviceID"`
	SigningPublicKey   string `json:"signingPublicKey"`
	AgreementPublicKey string `json:"agreementPublicKey"`
	KeyVersion         uint64 `json:"keyVersion"`
	ProtocolVersion    uint64 `json:"protocolVersion"`
	ProofSignature     string `json:"proofSignature"`
}

type Bundle struct {
	DeviceID           string    `json:"deviceID"`
	SigningPublicKey   string    `json:"signingPublicKey"`
	AgreementPublicKey string    `json:"agreementPublicKey"`
	KeyVersion         uint64    `json:"keyVersion"`
	ProtocolVersion    uint64    `json:"protocolVersion"`
	CreatedAt          time.Time `json:"createdAt"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type entry struct {
	Bundle
	UserID string `json:"userID"`
}

type requestRecord struct {
	DeviceID   string    `json:"deviceID"`
	Parameters string    `json:"parameters"`
	CreatedAt  time.Time `json:"createdAt"`
}

type state struct {
	SchemaVersion int                      `json:"schemaVersion"`
	Entries       map[string]entry         `json:"entries"`
	Requests      map[string]requestRecord `json:"requests"`
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
	if s.state.SchemaVersion == 1 {
		migrated := emptyState()
		migrated.Requests = s.state.Requests
		for _, value := range s.state.Entries {
			migrated.Entries[entryKey(value.UserID, value.DeviceID)] = value
		}
		if err = validateState(migrated); err != nil {
			return nil, err
		}
		if err = s.persist(migrated); err != nil {
			return nil, err
		}
		s.state = migrated
	} else if s.state.SchemaVersion != SchemaVersion {
		return nil, errors.New("unsupported device-key schema")
	}
	if s.state.Entries == nil {
		s.state.Entries = map[string]entry{}
	}
	if s.state.Requests == nil {
		s.state.Requests = map[string]requestRecord{}
	}
	if err = validateState(s.state); err != nil {
		return nil, err
	}
	return s, nil
}

func NewMemory() *Store                        { value, _ := Open(""); return value }
func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = now }

func (s *Store) Register(userID, authenticatedDeviceID string, input Registration) (Bundle, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	userID, authenticatedDeviceID = normalize(userID), normalize(authenticatedDeviceID)
	input.RequestID, input.DeviceID = normalize(input.RequestID), normalize(input.DeviceID)
	if !validUUID(input.RequestID) || !validUUID(userID) || !validUUID(authenticatedDeviceID) || input.DeviceID != authenticatedDeviceID || input.KeyVersion == 0 || input.ProtocolVersion != 2 {
		return Bundle{}, false, failure("invalid_device_key")
	}
	signing, err := decodeFixed(input.SigningPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return Bundle{}, false, failure("invalid_device_key")
	}
	if _, err = decodeFixed(input.AgreementPublicKey, 32); err != nil {
		return Bundle{}, false, failure("invalid_device_key")
	}
	signature, err := decodeFixed(input.ProofSignature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(signing), ProofMessage(input), signature) {
		return Bundle{}, false, failure("invalid_key_proof")
	}
	parameters := strings.Join([]string{userID, input.DeviceID, input.SigningPublicKey, input.AgreementPublicKey, strconv.FormatUint(input.KeyVersion, 10), strconv.FormatUint(input.ProtocolVersion, 10)}, "\x00")
	if prior, ok := s.state.Requests[input.RequestID]; ok {
		if prior.DeviceID != input.DeviceID || prior.Parameters != parameters {
			return Bundle{}, false, failure("idempotency_conflict")
		}
		current, ok := s.state.Entries[entryKey(userID, input.DeviceID)]
		if !ok {
			return Bundle{}, false, failure("invalid_device_key")
		}
		return current.Bundle, false, nil
	}
	key := entryKey(userID, input.DeviceID)
	if current, ok := s.state.Entries[key]; ok {
		if current.SigningPublicKey != input.SigningPublicKey || current.AgreementPublicKey != input.AgreementPublicKey || current.KeyVersion != input.KeyVersion || current.ProtocolVersion != input.ProtocolVersion {
			return Bundle{}, false, failure("key_changed")
		}
		next := cloneState(s.state)
		now := s.now().UTC()
		next.Requests[input.RequestID] = requestRecord{DeviceID: input.DeviceID, Parameters: parameters, CreatedAt: now}
		prune(&next, now)
		if err = s.persist(next); err != nil {
			return Bundle{}, false, err
		}
		s.state = next
		return current.Bundle, false, nil
	}
	now := s.now().UTC()
	bundle := Bundle{DeviceID: input.DeviceID, SigningPublicKey: input.SigningPublicKey, AgreementPublicKey: input.AgreementPublicKey, KeyVersion: input.KeyVersion, ProtocolVersion: input.ProtocolVersion, CreatedAt: now, UpdatedAt: now}
	next := cloneState(s.state)
	next.Entries[key] = entry{Bundle: bundle, UserID: userID}
	next.Requests[input.RequestID] = requestRecord{DeviceID: input.DeviceID, Parameters: parameters, CreatedAt: now}
	prune(&next, now)
	if err = validateState(next); err != nil {
		return Bundle{}, false, err
	}
	if err = s.persist(next); err != nil {
		return Bundle{}, false, err
	}
	s.state = next
	return bundle, true, nil
}

func (s *Store) ForUser(userID string, activeDeviceIDs map[string]bool) []Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userID = normalize(userID)
	result := make([]Bundle, 0)
	for _, value := range s.state.Entries {
		if value.UserID == userID && (activeDeviceIDs == nil || activeDeviceIDs[value.DeviceID]) {
			result = append(result, value.Bundle)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DeviceID < result[j].DeviceID })
	return result
}

func (s *Store) ForDevice(userID, deviceID string) (Bundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.state.Entries[entryKey(userID, deviceID)]
	return value.Bundle, ok
}

func ProofMessage(input Registration) []byte {
	return []byte(strings.Join([]string{"wsc-device-key-v1", normalize(input.DeviceID), input.SigningPublicKey, input.AgreementPublicKey, strconv.FormatUint(input.KeyVersion, 10), strconv.FormatUint(input.ProtocolVersion, 10)}, "\n"))
}

func decodeFixed(value string, size int) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) != size {
		return nil, errors.New("invalid key")
	}
	return data, nil
}

func emptyState() state {
	return state{SchemaVersion: SchemaVersion, Entries: map[string]entry{}, Requests: map[string]requestRecord{}}
}
func cloneState(input state) state {
	data, _ := json.Marshal(input)
	result := emptyState()
	_ = json.Unmarshal(data, &result)
	return result
}
func prune(value *state, now time.Time) {
	for id, record := range value.Requests {
		if now.Sub(record.CreatedAt) > 24*time.Hour {
			delete(value.Requests, id)
		}
	}
}
func validateState(value state) error {
	if value.SchemaVersion != SchemaVersion {
		return errors.New("invalid device-key schema")
	}
	for id, item := range value.Entries {
		if id != entryKey(item.UserID, item.DeviceID) || !validUUID(item.DeviceID) || !validUUID(item.UserID) || item.KeyVersion == 0 || item.ProtocolVersion != 2 {
			return errors.New("invalid device-key state")
		}
		if _, err := decodeFixed(item.SigningPublicKey, 32); err != nil {
			return err
		}
		if _, err := decodeFixed(item.AgreementPublicKey, 32); err != nil {
			return err
		}
	}
	return nil
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
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".devicekeys-*.json")
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
func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func entryKey(userID, deviceID string) string {
	return normalize(userID) + "|" + normalize(deviceID)
}
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
func (b Bundle) String() string { return fmt.Sprintf("device-key(%s,v%d)", b.DeviceID, b.KeyVersion) }
