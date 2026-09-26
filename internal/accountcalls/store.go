package accountcalls

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

type State string
type Side string

const (
	Ringing   State = "ringing"
	Accepted  State = "accepted"
	Rejected  State = "rejected"
	Cancelled State = "cancelled"
	Expired   State = "expired"
	Ended     State = "ended"

	SideCaller Side = "caller"
	SideCallee Side = "callee"
)

type Call struct {
	ID                                 string
	CallerAccountID, CallerDeviceID    string
	CalleeAccountID, CalleeDeviceID    string
	State                              State
	CreatedAt, RingExpiresAt           time.Time
	AcceptedAt, TerminalAt             time.Time
	TerminalReason, DeliveryStatus     string
	callerMediaToken, calleeMediaToken string
	peerEpoch                          map[Side]string
}

type View struct {
	CallID          string     `json:"callID"`
	LocalSide       Side       `json:"localSide"`
	State           State      `json:"state"`
	ExpiresAt       time.Time  `json:"expiresAt"`
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
	Parameters string
	View       View
	CreatedAt  time.Time
}

type Store struct {
	mu               sync.Mutex
	calls            map[string]*Call
	createRequests   map[string]idempotencyRecord
	mutationRequests map[string]idempotencyRecord
	ringTimeout      time.Duration
	now              func() time.Time
}

func New(ringTimeout time.Duration) *Store {
	return &Store{
		calls: map[string]*Call{}, createRequests: map[string]idempotencyRecord{},
		mutationRequests: map[string]idempotencyRecord{}, ringTimeout: ringTimeout, now: time.Now,
	}
}

func (s *Store) SetClock(now func() time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.now = now }

func (s *Store) Create(callID, requestID, callerAccountID, callerDeviceID, targetDeviceID string) (View, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	callID, requestID = normalize(callID), normalize(requestID)
	callerAccountID, callerDeviceID, targetDeviceID = normalize(callerAccountID), normalize(callerDeviceID), normalize(targetDeviceID)
	if callID == "" || requestID == "" || callerAccountID == "" || callerDeviceID == "" || targetDeviceID == "" || callerDeviceID == targetDeviceID {
		return View{}, false, errors.New("invalid call participants")
	}
	parameters := strings.Join([]string{callID, callerAccountID, callerDeviceID, targetDeviceID}, ":")
	if prior, ok := s.createRequests[requestID]; ok {
		if prior.Parameters != parameters {
			return View{}, false, errors.New("idempotency conflict")
		}
		view := prior.View
		view.CreatedNew = false
		return view, false, nil
	}
	if existing := s.calls[callID]; existing != nil {
		return View{}, false, fmt.Errorf("call ID already exists in state %s", existing.State)
	}
	for _, existing := range s.calls {
		s.expireLocked(existing)
		if existing.State != Ringing && existing.State != Accepted {
			continue
		}
		if existing.CallerDeviceID == callerDeviceID || existing.CalleeDeviceID == callerDeviceID || existing.CallerDeviceID == targetDeviceID || existing.CalleeDeviceID == targetDeviceID {
			return View{}, false, errors.New("device already has an active call")
		}
	}
	now := s.now().UTC()
	call := &Call{ID: callID, CallerAccountID: callerAccountID, CallerDeviceID: callerDeviceID, CalleeAccountID: callerAccountID, CalleeDeviceID: targetDeviceID, State: Ringing, CreatedAt: now, RingExpiresAt: now.Add(s.ringTimeout), peerEpoch: map[Side]string{}}
	s.calls[callID] = call
	view, _ := s.viewLocked(call, callerAccountID, callerDeviceID)
	view.CreatedNew = true
	s.createRequests[requestID] = idempotencyRecord{Parameters: parameters, View: view, CreatedAt: now}
	return view, true, nil
}

func (s *Store) Get(callID, accountID, deviceID string) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil {
		return View{}, errors.New("not found")
	}
	s.expireLocked(call)
	return s.viewLocked(call, normalize(accountID), normalize(deviceID))
}

func (s *Store) Mutate(callID, requestID, accountID, deviceID string, target State) (View, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	callID, requestID, accountID, deviceID = normalize(callID), normalize(requestID), normalize(accountID), normalize(deviceID)
	call := s.calls[callID]
	if call == nil {
		return View{}, false, errors.New("not found")
	}
	s.expireLocked(call)
	side, err := sideFor(call, accountID, deviceID)
	if err != nil {
		return View{}, false, err
	}
	key := strings.Join([]string{callID, accountID, deviceID, requestID}, ":")
	operation := string(target)
	if prior, ok := s.mutationRequests[key]; ok {
		if prior.Parameters != operation {
			return View{}, false, errors.New("idempotency conflict")
		}
		view := prior.View
		applied := false
		view.MutationApplied = &applied
		return view, false, nil
	}
	if err := validateMutation(call, side, target); err != nil {
		return View{}, false, err
	}
	now := s.now().UTC()
	switch target {
	case Accepted:
		callerToken, err := randomToken()
		if err != nil {
			return View{}, false, err
		}
		calleeToken, err := randomToken()
		if err != nil {
			return View{}, false, err
		}
		call.State, call.AcceptedAt = Accepted, now
		call.callerMediaToken, call.calleeMediaToken = callerToken, calleeToken
	case Rejected, Cancelled, Ended:
		call.State, call.TerminalAt, call.TerminalReason = target, now, string(target)
		if target == Ended {
			call.peerEpoch = map[Side]string{}
		}
	default:
		return View{}, false, errors.New("invalid transition")
	}
	view, _ := s.viewLocked(call, accountID, deviceID)
	applied := true
	view.MutationApplied = &applied
	s.mutationRequests[key] = idempotencyRecord{Parameters: operation, View: view, CreatedAt: now}
	return view, true, nil
}

func validateMutation(call *Call, side Side, target State) error {
	switch target {
	case Accepted:
		if side != SideCallee {
			return errors.New("only callee may accept")
		}
		if call.State != Ringing {
			return fmt.Errorf("accept not applicable in state %s", call.State)
		}
	case Rejected:
		if side != SideCallee {
			return errors.New("only callee may reject")
		}
		if call.State != Ringing {
			return fmt.Errorf("reject not applicable in state %s", call.State)
		}
	case Cancelled:
		if side != SideCaller {
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

func (s *Store) ValidateMedia(callID, side, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil || call.State != Accepted {
		return false
	}
	want := call.callerMediaToken
	if side == string(SideCallee) {
		want = call.calleeMediaToken
	} else if side != string(SideCaller) {
		return false
	}
	return len(want) == len(token) && subtle.ConstantTimeCompare([]byte(want), []byte(token)) == 1
}

func (s *Store) MediaPeerJoined(callID, side, epoch string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	value := Side(side)
	if call == nil || call.State != Accepted || value != SideCaller && value != SideCallee {
		return false
	}
	call.peerEpoch[value] = epoch
	return call.peerEpoch[SideCaller] != "" && call.peerEpoch[SideCallee] != ""
}

func (s *Store) MediaPeerLeft(callID, side, epoch string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[normalize(callID)]; call != nil && call.peerEpoch[Side(side)] == epoch {
		delete(call.peerEpoch, Side(side))
	}
}

func (s *Store) HasCall(callID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	_, ok := s.calls[normalize(callID)]
	return ok
}

func (s *Store) DeviceBusy(deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	deviceID = normalize(deviceID)
	for _, call := range s.calls {
		if call.State != Ringing && call.State != Accepted {
			continue
		}
		if call.CallerDeviceID == deviceID || call.CalleeDeviceID == deviceID {
			return true
		}
	}
	return false
}

func (s *Store) IsAccepted(callID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	return call != nil && call.State == Accepted
}
func (s *Store) IsRinging(callID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil {
		return false
	}
	s.expireLocked(call)
	return call.State == Ringing
}
func (s *Store) SetDelivery(callID, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[normalize(callID)]; call != nil {
		call.DeliveryStatus = status
	}
}
func (s *Store) FailDelivery(callID, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.calls[normalize(callID)]; call != nil && call.State == Ringing {
		call.State, call.TerminalAt = Expired, s.now().UTC()
		call.TerminalReason, call.DeliveryStatus = "delivery_failed:"+reason, "submission_failed:"+reason
	}
}

func (s *Store) expireLocked(call *Call) {
	if call.State == Ringing && !s.now().Before(call.RingExpiresAt) {
		call.State, call.TerminalAt, call.TerminalReason = Expired, s.now().UTC(), "ring_timeout"
	}
}

func (s *Store) viewLocked(call *Call, accountID, deviceID string) (View, error) {
	side, err := sideFor(call, accountID, deviceID)
	if err != nil {
		return View{}, err
	}
	v := View{CallID: call.ID, LocalSide: side, State: call.State, ExpiresAt: call.RingExpiresAt.UTC().Truncate(time.Second), RingExpiresAt: call.RingExpiresAt.UTC(), TerminalReason: call.TerminalReason, DeliveryStatus: call.DeliveryStatus, PeerReady: call.peerEpoch[SideCaller] != "" && call.peerEpoch[SideCallee] != ""}
	if !call.AcceptedAt.IsZero() {
		value := call.AcceptedAt.UTC()
		v.AcceptedAt = &value
	}
	if !call.TerminalAt.IsZero() {
		value := call.TerminalAt.UTC()
		v.TerminalAt = &value
	}
	if call.State == Accepted {
		if side == SideCaller {
			v.MediaToken = call.callerMediaToken
		} else {
			v.MediaToken = call.calleeMediaToken
		}
	}
	return v, nil
}

func sideFor(call *Call, accountID, deviceID string) (Side, error) {
	if call.CallerAccountID == accountID && call.CallerDeviceID == deviceID {
		return SideCaller, nil
	}
	if call.CalleeAccountID == accountID && call.CalleeDeviceID == deviceID {
		return SideCallee, nil
	}
	return "", errors.New("not a call participant")
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

func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
