package accounts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const SchemaVersion = 1

type Account struct {
	AccountID string    `json:"accountID"`
	PhoneE164 string    `json:"phoneE164"`
	CreatedAt time.Time `json:"createdAt"`
	Status    string    `json:"status"`
}

type Device struct {
	AccountID  string    `json:"accountID"`
	DeviceID   string    `json:"deviceID"`
	Platform   string    `json:"platform"`
	CreatedAt  time.Time `json:"createdAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

type Session struct {
	SessionID        string     `json:"sessionID"`
	AccountID        string     `json:"accountID"`
	DeviceID         string     `json:"deviceID"`
	Platform         string     `json:"platform"`
	AccessTokenHash  string     `json:"accessTokenHash"`
	AccessExpiresAt  time.Time  `json:"accessExpiresAt"`
	RefreshTokenHash string     `json:"refreshTokenHash"`
	RefreshExpiresAt time.Time  `json:"refreshExpiresAt"`
	CreatedAt        time.Time  `json:"createdAt"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty"`
}

type Verification struct {
	VerificationID    string     `json:"verificationID"`
	PhoneE164         string     `json:"phoneE164"`
	SourceIP          string     `json:"sourceIP"`
	OTPHash           string     `json:"otpHash"`
	CreatedAt         time.Time  `json:"createdAt"`
	ExpiresAt         time.Time  `json:"expiresAt"`
	ResendAfter       time.Time  `json:"resendAfter"`
	Attempts          int        `json:"attempts"`
	ConsumedAt        *time.Time `json:"consumedAt,omitempty"`
	ProviderAttempted bool       `json:"providerAttempted"`
	ProviderSubmitted bool       `json:"providerSubmitted"`
	ProviderMessageID string     `json:"providerMessageID,omitempty"`
}

type StartIdempotency struct {
	RequestID      string    `json:"requestID"`
	PhoneE164      string    `json:"phoneE164"`
	VerificationID string    `json:"verificationID"`
	CreatedAt      time.Time `json:"createdAt"`
}

type WatchStartIdempotency struct {
	RequestID string    `json:"requestID"`
	DeviceID  string    `json:"deviceID"`
	LinkID    string    `json:"linkID"`
	CreatedAt time.Time `json:"createdAt"`
}

type WatchLink struct {
	LinkID      string     `json:"linkID"`
	DeviceID    string     `json:"deviceID"`
	Platform    string     `json:"platform"`
	SecretHash  string     `json:"secretHash"`
	CodeHash    string     `json:"codeHash"`
	CreatedAt   time.Time  `json:"createdAt"`
	ExpiresAt   time.Time  `json:"expiresAt"`
	AccountID   string     `json:"accountID,omitempty"`
	ClaimedAt   *time.Time `json:"claimedAt,omitempty"`
	RetrievedAt *time.Time `json:"retrievedAt,omitempty"`
}

type State struct {
	SchemaVersion         int                              `json:"schemaVersion"`
	Accounts              map[string]Account               `json:"accounts"`
	Devices               []Device                         `json:"devices"`
	Sessions              map[string]Session               `json:"sessions"`
	Verifications         map[string]Verification          `json:"verifications"`
	StartIdempotency      map[string]StartIdempotency      `json:"startIdempotency"`
	WatchStartIdempotency map[string]WatchStartIdempotency `json:"watchStartIdempotency"`
	WatchLinks            map[string]WatchLink             `json:"watchLinks"`
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func emptyState() State {
	return State{SchemaVersion: SchemaVersion, Accounts: map[string]Account{}, Sessions: map[string]Session{}, Verifications: map[string]Verification{}, StartIdempotency: map[string]StartIdempotency{}, WatchStartIdempotency: map[string]WatchStartIdempotency{}, WatchLinks: map[string]WatchLink{}}
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: emptyState()}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, errors.New("invalid account state")
	}
	if err := validateState(state); err != nil {
		return nil, err
	}
	s.state = state
	return s, nil
}

func validateState(s State) error {
	if s.SchemaVersion != SchemaVersion || s.Accounts == nil || s.Sessions == nil || s.Verifications == nil || s.StartIdempotency == nil || s.WatchStartIdempotency == nil || s.WatchLinks == nil {
		return errors.New("unsupported account state schema")
	}
	for id, account := range s.Accounts {
		if id == "" || account.AccountID != id || account.PhoneE164 == "" || account.Status != "active" {
			return errors.New("invalid account state")
		}
	}
	return nil
}

func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	if err := validateState(next); err != nil {
		return err
	}
	if err := s.persist(next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *Store) persist(state State) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".accounts-*.json")
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

func cloneState(in State) State {
	data, _ := json.Marshal(in)
	out := emptyState()
	_ = json.Unmarshal(data, &out)
	return out
}
