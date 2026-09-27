package cellularcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTTL        = 2 * time.Minute
	terminalRetention = 2 * time.Minute
)

type State string

const (
	DeliveryPending       State = "iphone_delivery_pending"
	IPhoneActionRequired  State = "iphone_action_required"
	IPhoneStartAuthorized State = "iphone_start_authorized"
	IPhoneStartRequested  State = "iphone_start_requested"
	Cancelled             State = "cancelled"
	Expired               State = "expired"
	FailedSafe            State = "failed_safe"
)

type Participant struct {
	UserID, AccountID, DeviceID, Platform string
}

type View struct {
	RequestID           string    `json:"requestID"`
	State               State     `json:"state"`
	CreatedAt           time.Time `json:"createdAt"`
	ExpiresAt           time.Time `json:"expiresAt"`
	DeliveryStatus      string    `json:"deliveryStatus"`
	SourcePlatform      string    `json:"sourcePlatform"`
	TargetPlatform      string    `json:"targetPlatform"`
	SameOwnerAuthorized bool      `json:"sameOwnerAuthorized"`
	MutationApplied     *bool     `json:"mutationApplied,omitempty"`
	TerminalReason      string    `json:"terminalReason,omitempty"`
}

type StartGrant struct {
	View
	PhoneNumber string `json:"phoneNumber,omitempty"`
}

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string { return e.Code }

type control struct {
	requestID, phoneNumber, phoneDigest string
	source, target                      Participant
	state                               State
	createdAt, expiresAt                time.Time
	deliveryStatus, terminalReason      string
	receiveMutations                    map[string]bool
	startMutationID                     string
	startResultMutations                map[string]bool
	cancelMutationID                    string
	timer                               *time.Timer
}

type Store struct {
	mu       sync.Mutex
	ttl      time.Duration
	now      func() time.Time
	controls map[string]*control
	closed   bool
}

func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{ttl: ttl, now: time.Now, controls: map[string]*control{}}
}

func (s *Store) Create(requestID string, source, target Participant, phoneNumber string) (View, bool, error) {
	requestID = normalize(requestID)
	source = normalizeParticipant(source)
	target = normalizeParticipant(target)
	phoneDigest := digest(phoneNumber)
	if requestID == "" || source.UserID == "" || source.AccountID == "" || source.DeviceID == "" || source.Platform != "watchOS" || target.UserID == "" || target.AccountID == "" || target.DeviceID == "" || target.Platform != "iOS" || source.UserID != target.UserID || phoneNumber == "" {
		return View{}, false, failure(400, "invalid_request")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return View{}, false, failure(503, "control_unavailable")
	}
	if existing, ok := s.controls[requestID]; ok {
		s.expireLocked(existing, s.now())
		if existing.source != source || existing.target != target || existing.phoneDigest != phoneDigest {
			return View{}, false, failure(409, "request_conflict")
		}
		return viewLocked(existing, nil), false, nil
	}

	now := s.now().UTC()
	value := &control{
		requestID: requestID, phoneNumber: phoneNumber, phoneDigest: phoneDigest,
		source: source, target: target, state: DeliveryPending,
		createdAt: now, expiresAt: now.Add(s.ttl), deliveryStatus: "pending",
		receiveMutations: map[string]bool{}, startResultMutations: map[string]bool{},
	}
	s.controls[requestID] = value
	value.timer = time.AfterFunc(s.ttl, func() { s.expire(requestID) })
	return viewLocked(value, nil), true, nil
}

func (s *Store) Get(requestID string, participant Participant) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.authorizedLocked(requestID, participant)
	if err != nil {
		return View{}, err
	}
	return viewLocked(value, nil), nil
}

func (s *Store) Receive(requestID, mutationID string, target Participant) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.targetLocked(requestID, target)
	if err != nil {
		return View{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" {
		return View{}, failure(400, "invalid_request")
	}
	if value.receiveMutations[mutationID] {
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.state == Expired {
		return View{}, failure(409, "request_expired")
	}
	if value.state == Cancelled || value.state == FailedSafe {
		return View{}, failure(409, "request_not_available")
	}
	if value.state == DeliveryPending {
		value.state = IPhoneActionRequired
	}
	value.receiveMutations[mutationID] = true
	return viewLocked(value, boolPointer(true)), nil
}

func (s *Store) ClaimStart(requestID, mutationID string, target Participant) (StartGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.targetLocked(requestID, target)
	if err != nil {
		return StartGrant{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" {
		return StartGrant{}, failure(400, "invalid_request")
	}
	if value.startMutationID != "" {
		if value.startMutationID == mutationID {
			return StartGrant{View: viewLocked(value, boolPointer(false))}, nil
		}
		return StartGrant{}, failure(409, "system_start_already_authorized")
	}
	if value.state == Expired {
		return StartGrant{}, failure(409, "request_expired")
	}
	if value.state != IPhoneActionRequired {
		return StartGrant{}, failure(409, "request_not_ready")
	}
	phoneNumber := value.phoneNumber
	if phoneNumber == "" {
		return StartGrant{}, failure(409, "request_not_available")
	}
	value.startMutationID = mutationID
	value.state = IPhoneStartAuthorized
	value.phoneNumber = ""
	return StartGrant{View: viewLocked(value, boolPointer(true)), PhoneNumber: phoneNumber}, nil
}

func (s *Store) MarkStartRequested(requestID, mutationID string, target Participant) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.targetLocked(requestID, target)
	if err != nil {
		return View{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" {
		return View{}, failure(400, "invalid_request")
	}
	if value.startResultMutations[mutationID] {
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.state != IPhoneStartAuthorized && value.state != IPhoneStartRequested {
		return View{}, failure(409, "system_start_not_authorized")
	}
	value.startResultMutations[mutationID] = true
	value.state = IPhoneStartRequested
	s.scheduleCleanupLocked(value, s.now())
	return viewLocked(value, boolPointer(true)), nil
}

func (s *Store) Cancel(requestID, mutationID string, source Participant) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.sourceLocked(requestID, source)
	if err != nil {
		return View{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" {
		return View{}, failure(400, "invalid_request")
	}
	if value.cancelMutationID != "" && value.cancelMutationID == mutationID {
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.state == IPhoneStartAuthorized || value.state == IPhoneStartRequested {
		return View{}, failure(409, "system_start_already_authorized")
	}
	if value.state == Expired {
		return View{}, failure(409, "request_expired")
	}
	if value.state == Cancelled {
		return viewLocked(value, boolPointer(false)), nil
	}
	value.cancelMutationID = mutationID
	value.state = Cancelled
	value.terminalReason = "cancelled_before_system_start"
	value.phoneNumber = ""
	s.scheduleCleanupLocked(value, s.now())
	return viewLocked(value, boolPointer(true)), nil
}

func (s *Store) MarkDelivery(requestID string, accepted bool) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.controls[normalize(requestID)]
	if !ok {
		return View{}, failure(404, "request_not_found")
	}
	s.expireLocked(value, s.now())
	if value.state == Expired || value.state == Cancelled || value.state == IPhoneStartAuthorized || value.state == IPhoneStartRequested {
		return viewLocked(value, boolPointer(false)), nil
	}
	if accepted {
		value.deliveryStatus = "submission_accepted"
		return viewLocked(value, boolPointer(true)), nil
	}
	value.deliveryStatus = "submission_failed"
	if value.state == DeliveryPending {
		value.state = FailedSafe
		value.terminalReason = "iphone_delivery_failed"
		value.phoneNumber = ""
		s.scheduleCleanupLocked(value, s.now())
	}
	return viewLocked(value, boolPointer(true)), nil
}

func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, value := range s.controls {
		value.phoneNumber = ""
		if value.timer != nil {
			value.timer.Stop()
		}
	}
}

func (s *Store) authorizedLocked(requestID string, participant Participant) (*control, error) {
	value, ok := s.controls[normalize(requestID)]
	if !ok {
		return nil, failure(404, "request_not_found")
	}
	s.expireLocked(value, s.now())
	participant = normalizeParticipant(participant)
	if participant != value.source && participant != value.target {
		return nil, failure(403, "request_not_participant")
	}
	return value, nil
}

func (s *Store) sourceLocked(requestID string, participant Participant) (*control, error) {
	value, err := s.authorizedLocked(requestID, participant)
	if err != nil {
		return nil, err
	}
	if normalizeParticipant(participant) != value.source {
		return nil, failure(403, "request_not_participant")
	}
	return value, nil
}

func (s *Store) targetLocked(requestID string, participant Participant) (*control, error) {
	value, err := s.authorizedLocked(requestID, participant)
	if err != nil {
		return nil, err
	}
	if normalizeParticipant(participant) != value.target {
		return nil, failure(403, "request_not_participant")
	}
	return value, nil
}

func (s *Store) expire(requestID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value, ok := s.controls[requestID]; ok {
		s.expireLocked(value, s.now())
	}
}

func (s *Store) expireLocked(value *control, now time.Time) {
	if now.Before(value.expiresAt) || value.state == Cancelled || value.state == FailedSafe || value.state == IPhoneStartRequested {
		return
	}
	value.state = Expired
	value.terminalReason = "request_expired"
	value.phoneNumber = ""
	s.scheduleCleanupLocked(value, now)
}

func (s *Store) scheduleCleanupLocked(value *control, now time.Time) {
	if value.timer != nil {
		value.timer.Stop()
	}
	cleanupAt := value.expiresAt.Add(terminalRetention)
	if minimum := now.Add(terminalRetention); cleanupAt.Before(minimum) {
		cleanupAt = minimum
	}
	requestID := value.requestID
	value.timer = time.AfterFunc(time.Until(cleanupAt), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if current, ok := s.controls[requestID]; ok && current == value {
			delete(s.controls, requestID)
		}
	})
}

func viewLocked(value *control, mutationApplied *bool) View {
	return View{
		RequestID: value.requestID, State: value.state, CreatedAt: value.createdAt, ExpiresAt: value.expiresAt,
		DeliveryStatus: value.deliveryStatus, SourcePlatform: value.source.Platform, TargetPlatform: value.target.Platform,
		SameOwnerAuthorized: value.source.UserID == value.target.UserID, MutationApplied: mutationApplied,
		TerminalReason: value.terminalReason,
	}
}

func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func normalizeParticipant(value Participant) Participant {
	value.UserID = normalize(value.UserID)
	value.AccountID = normalize(value.AccountID)
	value.DeviceID = normalize(value.DeviceID)
	return value
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func boolPointer(value bool) *bool          { return &value }
func failure(status int, code string) error { return &Error{Status: status, Code: code} }
