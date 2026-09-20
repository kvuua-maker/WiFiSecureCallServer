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
	Role      string    `json:"role"`
	Token     string    `json:"token"`
	Platform  string    `json:"platform"`
	UpdatedAt time.Time `json:"updatedAt"`
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
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Register(value Registration) error {
	if value.Role != "A" && value.Role != "B" {
		return errors.New("invalid role")
	}
	if value.Token == "" || len(value.Token) > 512 {
		return errors.New("invalid token")
	}
	value.UpdatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[value.Role] = value
	return s.persistLocked()
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
