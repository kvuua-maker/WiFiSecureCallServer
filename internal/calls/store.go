package calls

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type State string

const (
	Ringing   State = "ringing"
	Accepted  State = "accepted"
	Rejected  State = "rejected"
	Cancelled State = "cancelled"
	Expired   State = "expired"
	Ended     State = "ended"
)

type Call struct {
	ID, Caller, Callee   string
	State                State
	CreatedAt, ExpiresAt time.Time
	tokenA, tokenB       string
	requests             map[string]struct{}
}
type View struct {
	CallID     string    `json:"callID"`
	Caller     string    `json:"caller"`
	Callee     string    `json:"callee"`
	State      State     `json:"state"`
	ExpiresAt  time.Time `json:"expiresAt"`
	MediaToken string    `json:"mediaToken,omitempty"`
}
type Store struct {
	mu                      sync.Mutex
	calls                   map[string]*Call
	createRequests          map[string]string
	ringTimeout, mediaGrace time.Duration
	now                     func() time.Time
}

func New(ringTimeout, mediaGrace time.Duration) *Store {
	return &Store{calls: map[string]*Call{}, createRequests: map[string]string{}, ringTimeout: ringTimeout, mediaGrace: mediaGrace, now: time.Now}
}
func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = now }
func other(role string) string {
	if role == "A" {
		return "B"
	}
	return "A"
}
func (s *Store) Create(id, requestID, caller string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.createRequests[requestID]; ok {
		return s.viewLocked(s.calls[prior], caller), nil
	}
	if existing, ok := s.calls[id]; ok {
		return s.viewLocked(existing, caller), nil
	}
	if caller != "A" && caller != "B" {
		return View{}, errors.New("invalid role")
	}
	now := s.now().UTC()
	call := &Call{ID: id, Caller: caller, Callee: other(caller), State: Ringing, CreatedAt: now, ExpiresAt: now.Add(s.ringTimeout), requests: map[string]struct{}{requestID: {}}}
	s.calls[id] = call
	s.createRequests[requestID] = id
	return s.viewLocked(call, caller), nil
}
func (s *Store) Get(id, role string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.calls[id]
	if !ok {
		return View{}, errors.New("not found")
	}
	s.expireLocked(call)
	return s.viewLocked(call, role), nil
}
func (s *Store) Mutate(id, requestID, role string, target State) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.calls[id]
	if !ok {
		return View{}, errors.New("not found")
	}
	s.expireLocked(call)
	if _, duplicate := call.requests[requestID]; duplicate {
		return s.viewLocked(call, role), nil
	}
	call.requests[requestID] = struct{}{}
	switch target {
	case Accepted:
		if role != call.Callee {
			return View{}, errors.New("only callee may accept")
		}
		if call.State == Ringing {
			call.State = Accepted
			call.tokenA = randomToken()
			call.tokenB = randomToken()
		}
	case Rejected:
		if role != call.Callee {
			return View{}, errors.New("only callee may reject")
		}
		if call.State == Ringing {
			call.State = Rejected
		}
	case Cancelled:
		if role != call.Caller {
			return View{}, errors.New("only caller may cancel")
		}
		if call.State == Ringing {
			call.State = Cancelled
		}
	case Ended:
		if call.State == Accepted {
			call.State = Ended
		}
	default:
		return View{}, errors.New("invalid transition")
	}
	return s.viewLocked(call, role), nil
}
func (s *Store) ValidateMedia(id, role, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.calls[id]
	if !ok || call.State != Accepted || s.now().After(call.ExpiresAt.Add(s.mediaGrace)) {
		return false
	}
	want := call.tokenA
	if role == "B" {
		want = call.tokenB
	} else if role != "A" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}
func (s *Store) expireLocked(call *Call) {
	if call.State == Ringing && !s.now().Before(call.ExpiresAt) {
		call.State = Expired
	}
}
func (s *Store) viewLocked(call *Call, role string) View {
	v := View{CallID: call.ID, Caller: call.Caller, Callee: call.Callee, State: call.State, ExpiresAt: call.ExpiresAt.UTC().Truncate(time.Second)}
	if call.State == Accepted {
		if role == "A" {
			v.MediaToken = call.tokenA
		}
		if role == "B" {
			v.MediaToken = call.tokenB
		}
	}
	return v
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure random unavailable")
	}
	return hex.EncodeToString(b)
}
