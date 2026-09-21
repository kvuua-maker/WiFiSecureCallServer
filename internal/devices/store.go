package devices

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const schemaVersion = 2

type Capabilities struct {
	VoIPPush                bool `json:"voipPush"`
	AlertPush               bool `json:"alertPush"`
	NotificationsAuthorized bool `json:"notificationsAuthorized"`
	MicrophoneReady         bool `json:"microphoneReady"`
}
type Registration struct {
	Role                   string       `json:"role"`
	Platform               string       `json:"platform"`
	Token                  string       `json:"token,omitempty"`
	AlertToken             string       `json:"alertToken,omitempty"`
	VoIPToken              string       `json:"voipToken,omitempty"`
	UpdatedAt              time.Time    `json:"updatedAt"`
	AlertUpdatedAt         time.Time    `json:"alertUpdatedAt,omitempty"`
	VoIPUpdatedAt          time.Time    `json:"voipUpdatedAt,omitempty"`
	InstallationID         string       `json:"installationID,omitempty"`
	InstallationGeneration uint64       `json:"installationGeneration,omitempty"`
	Environment            string       `json:"environment,omitempty"`
	Capabilities           Capabilities `json:"capabilities,omitempty"`
}
type persistedState struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Devices       map[string]Registration `json:"devices"`
}
type Store struct {
	mu     sync.RWMutex
	path   string
	values map[string]Registration
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, values: map[string]Registration{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedState
	if json.Unmarshal(data, &state) == nil && state.SchemaVersion > 0 {
		if state.SchemaVersion != schemaVersion || state.Devices == nil {
			return nil, errors.New("unsupported device state schema")
		}
		s.values = state.Devices
	} else {
		var legacy map[string]Registration
		if json.Unmarshal(data, &legacy) != nil {
			return nil, errors.New("invalid device state")
		}
		s.values = legacy
		for role, value := range s.values {
			if value.AlertToken == "" && value.Token != "" {
				value.AlertToken = value.Token
				value.AlertUpdatedAt = value.UpdatedAt
				value.Token = ""
			}
			if value.Environment == "" {
				value.Environment = "production"
			}
			if value.InstallationID == "" {
				value.InstallationID = "legacy-" + role
			}
			if value.InstallationGeneration == 0 {
				value.InstallationGeneration = 1
			}
			s.values[role] = value
		}
		if err := s.persist(s.values); err != nil {
			return nil, err
		}
	}
	for role, value := range s.values {
		if err := validateRegistration(role, value); err != nil {
			return nil, errors.New("invalid persisted device state")
		}
	}
	return s, nil
}

func (s *Store) Register(role, platform, pushType, token, installationID string, generation uint64, environment string, capabilities Capabilities) error {
	if rolePlatform(role, platform) == false || (pushType != "alert" && pushType != "voip") || !validToken(token) {
		return errors.New("invalid registration")
	}
	if installationID == "" {
		installationID = "legacy-" + role
	}
	if generation == 0 {
		generation = 1
	}
	if environment == "" {
		environment = "production"
	}
	if environment != "production" && environment != "development" {
		return errors.New("invalid environment")
	}
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.values[role]
	if current.InstallationGeneration > generation {
		return errors.New("stale installation generation")
	}
	if current.InstallationGeneration < generation || (current.InstallationID != "" && current.InstallationID != installationID) || (current.Environment != "" && current.Environment != environment) {
		current = Registration{}
	}
	current.Role = role
	current.Platform = platform
	current.Token = ""
	current.UpdatedAt = now
	current.InstallationID = installationID
	current.InstallationGeneration = generation
	current.Environment = environment
	current.Capabilities = capabilities
	if pushType == "voip" {
		current.VoIPToken = token
		current.VoIPUpdatedAt = now
	} else {
		current.AlertToken = token
		current.AlertUpdatedAt = now
	}
	next := clone(s.values)
	next[role] = current
	if err := s.persist(next); err != nil {
		return err
	}
	s.values = next
	return nil
}

func (s *Store) Invalidate(role, pushType, installationID string, generation uint64, expectedToken string) error {
	if pushType != "alert" && pushType != "voip" {
		return errors.New("invalid push type")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.values[role]
	if !ok {
		return nil
	}
	if installationID != "" && (current.InstallationID != installationID || current.InstallationGeneration != generation) {
		return nil
	}
	if expectedToken != "" && current.TokenFor(pushType, current.Environment) != expectedToken {
		return nil
	}
	current.UpdatedAt = time.Now().UTC()
	if pushType == "voip" {
		current.VoIPToken = ""
		current.VoIPUpdatedAt = time.Time{}
	} else {
		current.AlertToken = ""
		current.AlertUpdatedAt = time.Time{}
	}
	next := clone(s.values)
	next[role] = current
	if err := s.persist(next); err != nil {
		return err
	}
	s.values = next
	return nil
}

func (r Registration) TokenFor(pushType, environment string) string {
	if r.Environment != "" && r.Environment != environment {
		return ""
	}
	if pushType == "voip" {
		return r.VoIPToken
	}
	if r.AlertToken != "" {
		return r.AlertToken
	}
	return r.Token
}
func (r Registration) LiveReady() bool {
	return r.VoIPToken != "" && r.Capabilities.VoIPPush && r.Capabilities.MicrophoneReady
}
func (s *Store) Get(role string) (Registration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[role]
	return value, ok
}

func (s *Store) persist(values map[string]Registration) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(persistedState{SchemaVersion: schemaVersion, Devices: values})
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

func clone(input map[string]Registration) map[string]Registration {
	output := make(map[string]Registration, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
func validToken(value string) bool {
	if value == "" || len(value) > 512 || len(value)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func rolePlatform(role, platform string) bool {
	return role == "A" && platform == "watchOS" || role == "B" && platform == "iOS"
}
func validateRegistration(role string, value Registration) error {
	if !rolePlatform(role, value.Platform) || value.Role != role || value.InstallationGeneration == 0 || (value.Environment != "production" && value.Environment != "development") {
		return errors.New("invalid registration")
	}
	if value.AlertToken != "" && !validToken(value.AlertToken) {
		return errors.New("invalid alert token")
	}
	if value.VoIPToken != "" && !validToken(value.VoIPToken) {
		return errors.New("invalid voip token")
	}
	return nil
}
