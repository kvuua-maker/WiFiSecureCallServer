package devices

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Registration struct {
	Role           string    `json:"role"`
	Platform       string    `json:"platform"`
	Token          string    `json:"token,omitempty"`
	AlertToken     string    `json:"alertToken,omitempty"`
	VoIPToken      string    `json:"voipToken,omitempty"`
	UpdatedAt      time.Time `json:"updatedAt"`
	AlertUpdatedAt time.Time `json:"alertUpdatedAt,omitempty"`
	VoIPUpdatedAt  time.Time `json:"voipUpdatedAt,omitempty"`
}
type Store struct {
	mu     sync.RWMutex
	path   string
	values map[string]Registration
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, values: map[string]Registration{}}
	data, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(data, &s.values) != nil {
			return nil, errors.New("invalid device state")
		}
		migrated := false
		for role, value := range s.values {
			if value.AlertToken == "" && value.Token != "" {
				value.AlertToken = value.Token
				value.AlertUpdatedAt = value.UpdatedAt
				value.Token = ""
				s.values[role] = value
				migrated = true
			}
		}
		if migrated {
			if err := s.persistLocked(); err != nil {
				return nil, err
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Register(role, platform, pushType, token string) error {
	if role != "A" && role != "B" {
		return errors.New("invalid role")
	}
	if pushType != "alert" && pushType != "voip" {
		return errors.New("invalid push type")
	}
	if token == "" || len(token) > 512 {
		return errors.New("invalid token")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	value := s.values[role]
	value.Role = role
	value.Platform = platform
	value.Token = ""
	value.UpdatedAt = now
	if pushType == "voip" {
		value.VoIPToken = token
		value.VoIPUpdatedAt = now
	} else {
		value.AlertToken = token
		value.AlertUpdatedAt = now
	}
	s.values[role] = value
	return s.persistLocked()
}

func (s *Store) Invalidate(role, pushType string) error {
	if pushType != "alert" && pushType != "voip" {
		return errors.New("invalid push type")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[role]
	if !ok {
		return nil
	}
	value.UpdatedAt = time.Now().UTC()
	if pushType == "voip" {
		value.VoIPToken = ""
		value.VoIPUpdatedAt = time.Time{}
	} else {
		value.AlertToken = ""
		value.AlertUpdatedAt = time.Time{}
	}
	s.values[role] = value
	return s.persistLocked()
}

func (r Registration) TokenFor(pushType string) string {
	if pushType == "voip" {
		return r.VoIPToken
	}
	if r.AlertToken != "" {
		return r.AlertToken
	}
	return r.Token
}
func (s *Store) Get(role string) (Registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[role]
	return value, ok
}
func (s *Store) persistLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s.values)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".devices-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, s.path)
}
