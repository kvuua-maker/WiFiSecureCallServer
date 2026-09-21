package calls

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
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
	ID, Caller, Callee             string
	State                          State
	CreatedAt, RingExpiresAt       time.Time
	AcceptedAt, TerminalAt         time.Time
	TerminalReason, DeliveryStatus string
	tokenA, tokenB                 string
	peerEpoch                      map[string]string
}

type View struct {
	CallID          string     `json:"callID"`
	Caller          string     `json:"caller"`
	Callee          string     `json:"callee"`
	State           State      `json:"state"`
	ExpiresAt       time.Time  `json:"expiresAt"` // Build 9 compatibility.
	MediaToken      string     `json:"mediaToken,omitempty"`
	RingExpiresAt   time.Time  `json:"ringExpiresAt,omitempty"`
	AcceptedAt      *time.Time `json:"acceptedAt,omitempty"`
	TerminalAt      *time.Time `json:"terminalAt,omitempty"`
	TerminalReason  string     `json:"terminalReason,omitempty"`
	DeliveryStatus  string     `json:"deliveryStatus,omitempty"`
	PeerReady       bool       `json:"peerReady,omitempty"`
	CreatedNew      bool       `json:"createdNew,omitempty"`
	MutationApplied *bool      `json:"mutationApplied,omitempty"`
}

type idempotencyRecord struct {
	CallID, Role, Operation, Parameters string
	View                                View
	CreatedAt                           time.Time
}
type Store struct {
	mu               sync.Mutex
	calls            map[string]*Call
	createRequests   map[string]idempotencyRecord
	mutationRequests map[string]idempotencyRecord
	ringTimeout      time.Duration
	now              func() time.Time
}

func New(ringTimeout, _ time.Duration) *Store {
	return &Store{calls: map[string]*Call{}, createRequests: map[string]idempotencyRecord{}, mutationRequests: map[string]idempotencyRecord{}, ringTimeout: ringTimeout, now: time.Now}
}
func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = now }
func other(role string) string {
	if role == "A" {
		return "B"
	}
	return "A"
}

func (s *Store) Create(id, requestID, caller string) (View, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	if caller != "A" && caller != "B" {
		return View{}, false, errors.New("invalid role")
	}
	params := id + ":" + caller
	if prior, ok := s.createRequests[requestID]; ok {
		if prior.Role != caller || prior.Parameters != params {
			return View{}, false, errors.New("idempotency conflict")
		}
		view := prior.View
		view.CreatedNew = false
		return view, false, nil
	}
	if existing, ok := s.calls[id]; ok {
		return View{}, false, fmt.Errorf("call ID already exists in state %s", existing.State)
	}
	for _, existing := range s.calls {
		s.expireLocked(existing)
		if (existing.State == Ringing || existing.State == Accepted) && ((existing.Caller == caller && existing.Callee == other(caller)) || (existing.Caller == other(caller) && existing.Callee == caller)) {
			return View{}, false, errors.New("another call is active")
		}
	}
	now := s.now().UTC()
	call := &Call{ID: id, Caller: caller, Callee: other(caller), State: Ringing, CreatedAt: now, RingExpiresAt: now.Add(s.ringTimeout), peerEpoch: map[string]string{}}
	s.calls[id] = call
	view := s.viewLocked(call, caller)
	view.CreatedNew = true
	s.createRequests[requestID] = idempotencyRecord{CallID: id, Role: caller, Operation: "create", Parameters: params, View: view, CreatedAt: now}
	return view, true, nil
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

func (s *Store) Mutate(id, requestID, role string, target State) (View, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	call, ok := s.calls[id]
	if !ok {
		return View{}, false, errors.New("not found")
	}
	s.expireLocked(call)
	operation := string(target)
	key := id + ":" + role + ":" + requestID
	if prior, ok := s.mutationRequests[key]; ok {
		if prior.Operation != operation || prior.Parameters != operation {
			return View{}, false, errors.New("idempotency conflict")
		}
		view := prior.View
		applied := false
		view.MutationApplied = &applied
		return view, false, nil
	}
	if err := validateMutation(call, role, target); err != nil {
		return View{}, false, err
	}
	now := s.now().UTC()
	applied := true
	switch target {
	case Accepted:
		tokenA, err := randomToken()
		if err != nil {
			return View{}, false, err
		}
		tokenB, err := randomToken()
		if err != nil {
			return View{}, false, err
		}
		call.State = Accepted
		call.AcceptedAt = now
		call.tokenA, call.tokenB = tokenA, tokenB
	case Rejected:
		call.State = Rejected
		call.TerminalAt = now
		call.TerminalReason = "rejected"
	case Cancelled:
		call.State = Cancelled
		call.TerminalAt = now
		call.TerminalReason = "cancelled"
	case Ended:
		call.State = Ended
		call.TerminalAt = now
		call.TerminalReason = "ended"
		call.peerEpoch = map[string]string{}
	default:
		return View{}, false, errors.New("invalid transition")
	}
	view := s.viewLocked(call, role)
	view.MutationApplied = &applied
	s.mutationRequests[key] = idempotencyRecord{CallID: id, Role: role, Operation: operation, Parameters: operation, View: view, CreatedAt: now}
	return view, true, nil
}

func validateMutation(call *Call, role string, target State) error {
	switch target {
	case Accepted:
		if role != call.Callee {
			return errors.New("only callee may accept")
		}
		if call.State != Ringing {
			return fmt.Errorf("accept not applicable in state %s", call.State)
		}
	case Rejected:
		if role != call.Callee {
			return errors.New("only callee may reject")
		}
		if call.State != Ringing {
			return fmt.Errorf("reject not applicable in state %s", call.State)
		}
	case Cancelled:
		if role != call.Caller {
			return errors.New("only caller may cancel")
		}
		if call.State != Ringing {
			return fmt.Errorf("cancel not applicable in state %s", call.State)
		}
	case Ended:
		if call.State != Accepted {
			return fmt.Errorf("end not applicable in state %s", call.State)
		}
	default:
		return errors.New("invalid transition")
	}
	return nil
}

func (s *Store) ValidateMedia(id, role, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.calls[id]
	if !ok || call.State != Accepted {
		return false
	}
	want := call.tokenA
	if role == "B" {
		want = call.tokenB
	} else if role != "A" {
		return false
	}
	return len(want) == len(token) && subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

func (s *Store) MediaPeerJoined(id, role, epoch string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call, ok := s.calls[id]
	if !ok || call.State != Accepted || (role != "A" && role != "B") {
		return false
	}
	call.peerEpoch[role] = epoch
	return call.peerEpoch["A"] != "" && call.peerEpoch["B"] != ""
}
func (s *Store) MediaPeerLeft(id, role, epoch string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[id]; call != nil && call.peerEpoch[role] == epoch {
		delete(call.peerEpoch, role)
	}
}
func (s *Store) IsAccepted(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[id]
	return call != nil && call.State == Accepted
}
func (s *Store) IsRinging(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[id]
	if call == nil {
		return false
	}
	s.expireLocked(call)
	return call.State == Ringing
}
func (s *Store) SetDelivery(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[id]; call != nil {
		call.DeliveryStatus = status
	}
}
func (s *Store) FailDelivery(id, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[id]; call != nil && call.State == Ringing {
		call.State = Expired
		call.TerminalAt = s.now().UTC()
		call.TerminalReason = "delivery_failed:" + reason
		call.DeliveryStatus = "submission_failed:" + reason
	}
}

func (s *Store) expireLocked(call *Call) {
	if call.State == Ringing && !s.now().Before(call.RingExpiresAt) {
		call.State = Expired
		call.TerminalAt = s.now().UTC()
		call.TerminalReason = "ring_timeout"
	}
}
func (s *Store) viewLocked(call *Call, role string) View {
	v := View{CallID: call.ID, Caller: call.Caller, Callee: call.Callee, State: call.State, ExpiresAt: call.RingExpiresAt.UTC().Truncate(time.Second), RingExpiresAt: call.RingExpiresAt.UTC(), TerminalReason: call.TerminalReason, DeliveryStatus: call.DeliveryStatus, PeerReady: call.peerEpoch["A"] != "" && call.peerEpoch["B"] != ""}
	if !call.AcceptedAt.IsZero() {
		value := call.AcceptedAt.UTC()
		v.AcceptedAt = &value
	}
	if !call.TerminalAt.IsZero() {
		value := call.TerminalAt.UTC()
		v.TerminalAt = &value
	}
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

func (s *Store) gcLocked() {
	now := s.now()
	for _, call := range s.calls {
		s.expireLocked(call)
	}
	for id, call := range s.calls {
		if !call.TerminalAt.IsZero() && now.Sub(call.TerminalAt) > 10*time.Minute {
			delete(s.calls, id)
		}
	}
	for id, value := range s.createRequests {
		if now.Sub(value.CreatedAt) > 10*time.Minute {
			delete(s.createRequests, id)
		}
	}
	for id, value := range s.mutationRequests {
		if now.Sub(value.CreatedAt) > 10*time.Minute {
			delete(s.mutationRequests, id)
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secure random unavailable: %w", err)
	}
	return hex.EncodeToString(b), nil
}
