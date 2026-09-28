package usercalls

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

type State string
type Side string
type LegState string
type DeliveryState string

const (
	Ringing   State = "ringing"
	Accepted  State = "accepted"
	Rejected  State = "rejected"
	Cancelled State = "cancelled"
	Expired   State = "expired"
	Ended     State = "ended"

	SideCaller Side = "caller"
	SideCallee Side = "callee"

	LegRinging           LegState = "ringing"
	LegAccepted          LegState = "accepted"
	LegRejected          LegState = "rejected"
	LegAnsweredElsewhere LegState = "answered_elsewhere"
	LegUnavailable       LegState = "unavailable"
	LegCancelled         LegState = "cancelled"
	LegExpired           LegState = "expired"
	LegEnded             LegState = "ended"

	DeliveryPending  DeliveryState = "pending"
	DeliveryAccepted DeliveryState = "submission_accepted"
	DeliveryFailed   DeliveryState = "submission_failed"
)

type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

func callError(code string) error { return &Error{Code: code} }

type Participant struct {
	UserID, AccountID, DeviceID string
}

type PublicCaller struct {
	Username       string `json:"username"`
	DisplayName    string `json:"displayName,omitempty"`
	PublicIdentity string `json:"publicIdentity"`
}

type KeyPackage struct {
	ProtocolVersion    uint64 `json:"protocolVersion"`
	KeyEpoch           uint64 `json:"keyEpoch"`
	CallID             string `json:"callID"`
	UserID             string `json:"userID"`
	DeviceID           string `json:"deviceID"`
	Side               Side   `json:"side"`
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Signature          string `json:"signature"`
}

type Target struct {
	AccountID string
	DeviceID  string
	Platform  string
}

type TargetLeg struct {
	Target
	DeliveryState  DeliveryState
	DeliveryReason string
	ResponseState  LegState
}

type Call struct {
	ID               string
	Caller           Participant
	CalleeUserID     string
	CallerIdentity   PublicCaller
	Targets          []TargetLeg
	WinnerAccountID  string
	WinnerDeviceID   string
	State            State
	CreatedAt        time.Time
	RingExpiresAt    time.Time
	AcceptedAt       time.Time
	TerminalAt       time.Time
	TerminalReason   string
	CallerKeyPackage *KeyPackage
	CalleeKeyPackage *KeyPackage
	callerToken      string
	calleeToken      string
	peerEpoch        map[Side]string
}

type View struct {
	CallID           string        `json:"callID"`
	CallerUserID     string        `json:"callerUserID"`
	CallerDeviceID   string        `json:"callerDeviceID"`
	CalleeUserID     string        `json:"calleeUserID"`
	CalleeDeviceID   string        `json:"calleeDeviceID,omitempty"`
	LocalSide        Side          `json:"localSide"`
	State            State         `json:"state"`
	LegState         LegState      `json:"legState,omitempty"`
	ExpiresAt        time.Time     `json:"expiresAt"`
	MediaToken       string        `json:"mediaToken,omitempty"`
	RingExpiresAt    time.Time     `json:"ringExpiresAt,omitempty"`
	AcceptedAt       *time.Time    `json:"acceptedAt,omitempty"`
	TerminalAt       *time.Time    `json:"terminalAt,omitempty"`
	TerminalReason   string        `json:"terminalReason,omitempty"`
	DeliveryStatus   string        `json:"deliveryStatus,omitempty"`
	PeerReady        bool          `json:"peerReady,omitempty"`
	CreatedNew       bool          `json:"createdNew,omitempty"`
	MutationApplied  *bool         `json:"mutationApplied,omitempty"`
	Caller           *PublicCaller `json:"caller,omitempty"`
	CallerKeyPackage *KeyPackage   `json:"callerKeyPackage,omitempty"`
	CalleeKeyPackage *KeyPackage   `json:"calleeKeyPackage,omitempty"`
}

type createRecord struct {
	Parameters string
	CallID     string
	CreatedAt  time.Time
}

type mutationRecord struct {
	Operation string
	CreatedAt time.Time
}

type Store struct {
	mu               sync.Mutex
	calls            map[string]*Call
	createRequests   map[string]createRecord
	mutationRequests map[string]mutationRecord
	ringTimeout      time.Duration
	now              func() time.Time
}

func New(ringTimeout time.Duration) *Store {
	return &Store{
		calls: map[string]*Call{}, createRequests: map[string]createRecord{},
		mutationRequests: map[string]mutationRecord{}, ringTimeout: ringTimeout, now: time.Now,
	}
}

func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

func (s *Store) Create(callID, requestID string, caller Participant, targetUserID string, identity PublicCaller, candidates []Target) (View, []Target, bool, error) {
	return s.create(callID, requestID, caller, targetUserID, identity, candidates, nil)
}

func (s *Store) CreateSecure(callID, requestID string, caller Participant, targetUserID string, identity PublicCaller, candidates []Target, keyPackage KeyPackage) (View, []Target, bool, error) {
	return s.create(callID, requestID, caller, targetUserID, identity, candidates, &keyPackage)
}

func (s *Store) create(callID, requestID string, caller Participant, targetUserID string, identity PublicCaller, candidates []Target, keyPackage *KeyPackage) (View, []Target, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	callID, requestID = normalize(callID), normalize(requestID)
	caller = normalizeParticipant(caller)
	targetUserID = normalize(targetUserID)
	if callID == "" || requestID == "" || caller.UserID == "" || caller.AccountID == "" || caller.DeviceID == "" || targetUserID == "" {
		return View{}, nil, false, callError("invalid_recipient")
	}
	if caller.UserID == targetUserID {
		return View{}, nil, false, callError("self_call_not_allowed")
	}
	parameters := strings.Join([]string{callID, caller.UserID, caller.AccountID, caller.DeviceID, targetUserID, keyPackageFingerprint(keyPackage)}, ":")
	if prior, ok := s.createRequests[requestID]; ok {
		if prior.Parameters != parameters {
			return View{}, nil, false, callError("idempotency_conflict")
		}
		call := s.calls[prior.CallID]
		if call == nil {
			return View{}, nil, false, callError("call_not_participant")
		}
		view, err := s.viewLocked(call, caller)
		if err != nil {
			return View{}, nil, false, err
		}
		view.CreatedNew = false
		return view, nil, false, nil
	}
	if s.calls[callID] != nil {
		return View{}, nil, false, callError("idempotency_conflict")
	}
	if s.deviceBusyLocked(caller.DeviceID) {
		return View{}, nil, false, callError("call_failed")
	}
	seen := map[string]bool{}
	legs := make([]TargetLeg, 0, len(candidates))
	selected := make([]Target, 0, len(candidates))
	for _, raw := range candidates {
		target := Target{AccountID: normalize(raw.AccountID), DeviceID: normalize(raw.DeviceID), Platform: raw.Platform}
		if target.AccountID == "" || target.DeviceID == "" || target.DeviceID == caller.DeviceID || seen[target.DeviceID] || s.deviceBusyLocked(target.DeviceID) {
			continue
		}
		seen[target.DeviceID] = true
		legs = append(legs, TargetLeg{Target: target, DeliveryState: DeliveryPending, ResponseState: LegRinging})
		selected = append(selected, target)
	}
	if len(legs) == 0 {
		return View{}, nil, false, callError("recipient_unavailable")
	}
	now := s.now().UTC()
	call := &Call{
		ID: callID, Caller: caller, CalleeUserID: targetUserID, CallerIdentity: identity,
		Targets: legs, State: Ringing, CreatedAt: now, RingExpiresAt: now.Add(s.ringTimeout), CallerKeyPackage: cloneKeyPackage(keyPackage), peerEpoch: map[Side]string{},
	}
	s.calls[callID] = call
	s.createRequests[requestID] = createRecord{Parameters: parameters, CallID: callID, CreatedAt: now}
	view, _ := s.viewLocked(call, caller)
	view.CreatedNew = true
	return view, selected, true, nil
}

func (s *Store) Get(callID string, participant Participant) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil {
		return View{}, callError("call_not_participant")
	}
	s.expireLocked(call)
	return s.viewLocked(call, normalizeParticipant(participant))
}

func (s *Store) Mutate(callID, requestID string, participant Participant, action State) (View, bool, error) {
	return s.mutate(callID, requestID, participant, action, nil)
}

func (s *Store) MutateSecure(callID, requestID string, participant Participant, action State, keyPackage *KeyPackage) (View, bool, error) {
	return s.mutate(callID, requestID, participant, action, keyPackage)
}

func (s *Store) mutate(callID, requestID string, participant Participant, action State, keyPackage *KeyPackage) (View, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	callID, requestID = normalize(callID), normalize(requestID)
	participant = normalizeParticipant(participant)
	call := s.calls[callID]
	if call == nil {
		return View{}, false, callError("call_not_participant")
	}
	s.expireLocked(call)
	side, targetIndex, err := participantFor(call, participant)
	if err != nil {
		return View{}, false, err
	}
	key := strings.Join([]string{callID, participant.AccountID, participant.DeviceID, requestID}, ":")
	operation := string(action) + "\x00" + keyPackageFingerprint(keyPackage)
	if prior, ok := s.mutationRequests[key]; ok {
		if prior.Operation != operation {
			return View{}, false, callError("idempotency_conflict")
		}
		view, viewErr := s.viewLocked(call, participant)
		if viewErr != nil {
			return View{}, false, viewErr
		}
		applied := false
		view.MutationApplied = &applied
		return view, false, nil
	}
	now := s.now().UTC()
	applied := false
	switch action {
	case Accepted:
		if side != SideCallee {
			return View{}, false, callError("call_not_participant")
		}
		if call.State == Expired {
			return View{}, false, callError("call_expired")
		}
		if call.CallerKeyPackage != nil {
			if keyPackage == nil || normalize(keyPackage.CallID) != call.ID || normalize(keyPackage.UserID) != participant.UserID || normalize(keyPackage.DeviceID) != participant.DeviceID || keyPackage.Side != SideCallee || keyPackage.ProtocolVersion != 2 || keyPackage.KeyEpoch == 0 || keyPackage.KeyEpoch != call.CallerKeyPackage.KeyEpoch {
				return View{}, false, callError("invalid_key_package")
			}
		} else if keyPackage != nil {
			return View{}, false, callError("idempotency_conflict")
		}
		if call.State == Accepted {
			if call.WinnerAccountID != participant.AccountID || call.WinnerDeviceID != participant.DeviceID {
				call.Targets[targetIndex].ResponseState = LegAnsweredElsewhere
			}
			break
		}
		if call.State != Ringing || call.Targets[targetIndex].ResponseState != LegRinging || call.Targets[targetIndex].DeliveryState == DeliveryFailed {
			return View{}, false, callError("answered_elsewhere")
		}
		callerToken, tokenErr := randomToken()
		if tokenErr != nil {
			return View{}, false, tokenErr
		}
		calleeToken, tokenErr := randomToken()
		if tokenErr != nil {
			return View{}, false, tokenErr
		}
		call.State, call.AcceptedAt = Accepted, now
		call.CalleeKeyPackage = cloneKeyPackage(keyPackage)
		call.WinnerAccountID, call.WinnerDeviceID = participant.AccountID, participant.DeviceID
		call.callerToken, call.calleeToken = callerToken, calleeToken
		for index := range call.Targets {
			if index == targetIndex {
				call.Targets[index].ResponseState = LegAccepted
			} else if call.Targets[index].ResponseState == LegRinging {
				call.Targets[index].ResponseState = LegAnsweredElsewhere
			}
		}
		applied = true
	case Rejected:
		if side != SideCallee {
			return View{}, false, callError("call_not_participant")
		}
		if call.State == Accepted {
			if call.WinnerAccountID != participant.AccountID || call.WinnerDeviceID != participant.DeviceID {
				call.Targets[targetIndex].ResponseState = LegAnsweredElsewhere
				break
			}
			return View{}, false, callError("answered_elsewhere")
		}
		if call.State == Expired {
			return View{}, false, callError("call_expired")
		}
		if call.State == Rejected || call.Targets[targetIndex].ResponseState == LegRejected {
			break
		}
		if call.State != Ringing || call.Targets[targetIndex].ResponseState != LegRinging {
			return View{}, false, callError("answered_elsewhere")
		}
		call.Targets[targetIndex].ResponseState = LegRejected
		applied = true
		if !hasViableRingingTarget(call) {
			call.State, call.TerminalAt, call.TerminalReason = Rejected, now, "all_targets_rejected"
		}
	case Cancelled:
		if side != SideCaller {
			return View{}, false, callError("call_not_participant")
		}
		if call.State == Cancelled {
			break
		}
		if call.State != Ringing {
			if call.State == Expired {
				return View{}, false, callError("call_expired")
			}
			return View{}, false, callError("call_failed")
		}
		call.State, call.TerminalAt, call.TerminalReason = Cancelled, now, "cancelled"
		for index := range call.Targets {
			if call.Targets[index].ResponseState == LegRinging {
				call.Targets[index].ResponseState = LegCancelled
			}
		}
		applied = true
	case Ended:
		isWinner := side == SideCallee && call.WinnerAccountID == participant.AccountID && call.WinnerDeviceID == participant.DeviceID
		if side != SideCaller && !isWinner {
			return View{}, false, callError("call_not_participant")
		}
		if call.State == Ended {
			break
		}
		if call.State != Accepted {
			return View{}, false, callError("call_failed")
		}
		call.State, call.TerminalAt, call.TerminalReason = Ended, now, "ended"
		call.callerToken, call.calleeToken = "", ""
		call.peerEpoch = map[Side]string{}
		for index := range call.Targets {
			if call.Targets[index].ResponseState == LegAccepted {
				call.Targets[index].ResponseState = LegEnded
			}
		}
		applied = true
	default:
		return View{}, false, callError("call_failed")
	}
	s.mutationRequests[key] = mutationRecord{Operation: operation, CreatedAt: now}
	view, viewErr := s.viewLocked(call, participant)
	if viewErr != nil {
		return View{}, false, viewErr
	}
	view.MutationApplied = &applied
	return view, applied, nil
}

func (s *Store) TargetRinging(callID, accountID, deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil {
		return false
	}
	s.expireLocked(call)
	if call.State != Ringing {
		return false
	}
	index := targetIndex(call, normalize(accountID), normalize(deviceID))
	return index >= 0 && call.Targets[index].ResponseState == LegRinging
}

func (s *Store) SetDelivery(callID, accountID, deviceID string, accepted bool, reason string) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil || call.State != Ringing {
		return false, false
	}
	index := targetIndex(call, normalize(accountID), normalize(deviceID))
	if index < 0 || call.Targets[index].ResponseState != LegRinging || call.Targets[index].DeliveryState != DeliveryPending {
		return false, false
	}
	if accepted {
		call.Targets[index].DeliveryState = DeliveryAccepted
		call.Targets[index].DeliveryReason = ""
		return true, false
	}
	call.Targets[index].DeliveryState = DeliveryFailed
	call.Targets[index].DeliveryReason = safeReason(reason)
	call.Targets[index].ResponseState = LegUnavailable
	if hasViableRingingTarget(call) {
		return true, false
	}
	now := s.now().UTC()
	call.State, call.TerminalAt, call.TerminalReason = Expired, now, "delivery_failed"
	return true, true
}

func (s *Store) ValidateMedia(callID, side, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil || call.State != Accepted {
		return false
	}
	want := call.callerToken
	if side == string(SideCallee) {
		want = call.calleeToken
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

func (s *Store) RequiredMediaProtocol(callID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	if call == nil {
		return 0
	}
	if call.CallerKeyPackage != nil {
		return 2
	}
	return 1
}

func (s *Store) DeviceBusy(deviceID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked()
	return s.deviceBusyLocked(normalize(deviceID))
}

func (s *Store) IsAccepted(callID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	call := s.calls[normalize(callID)]
	return call != nil && call.State == Accepted
}

func (s *Store) viewLocked(call *Call, participant Participant) (View, error) {
	side, index, err := participantFor(call, participant)
	if err != nil {
		return View{}, err
	}
	view := View{
		CallID: call.ID, CallerUserID: call.Caller.UserID, CallerDeviceID: call.Caller.DeviceID,
		CalleeUserID: call.CalleeUserID, CalleeDeviceID: call.WinnerDeviceID, LocalSide: side, State: call.State,
		ExpiresAt: call.RingExpiresAt.UTC().Truncate(time.Second), RingExpiresAt: call.RingExpiresAt.UTC(),
		TerminalReason: call.TerminalReason, DeliveryStatus: deliveryStatus(call),
		PeerReady:        call.peerEpoch[SideCaller] != "" && call.peerEpoch[SideCallee] != "",
		CallerKeyPackage: cloneKeyPackage(call.CallerKeyPackage), CalleeKeyPackage: cloneKeyPackage(call.CalleeKeyPackage),
	}
	if side == SideCallee {
		view.LegState = call.Targets[index].ResponseState
		caller := call.CallerIdentity
		view.Caller = &caller
	}
	if !call.AcceptedAt.IsZero() {
		value := call.AcceptedAt.UTC()
		view.AcceptedAt = &value
	}
	if !call.TerminalAt.IsZero() {
		value := call.TerminalAt.UTC()
		view.TerminalAt = &value
	}
	if call.State == Accepted {
		if side == SideCaller {
			view.MediaToken = call.callerToken
		} else if call.WinnerAccountID == participant.AccountID && call.WinnerDeviceID == participant.DeviceID {
			view.MediaToken = call.calleeToken
		}
	}
	return view, nil
}

func cloneKeyPackage(value *KeyPackage) *KeyPackage {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func keyPackageFingerprint(value *KeyPackage) string {
	if value == nil {
		return "legacy"
	}
	data, _ := json.Marshal(value)
	return string(data)
}

func KeyPackageMessage(value KeyPackage) []byte {
	return []byte(strings.Join([]string{
		"wsc-call-key-v2",
		normalize(value.CallID),
		normalize(value.UserID),
		normalize(value.DeviceID),
		string(value.Side),
		strconv.FormatUint(value.ProtocolVersion, 10),
		strconv.FormatUint(value.KeyEpoch, 10),
		value.EphemeralPublicKey,
	}, "\n"))
}

func participantFor(call *Call, participant Participant) (Side, int, error) {
	if call.Caller == participant {
		return SideCaller, -1, nil
	}
	if participant.UserID != call.CalleeUserID {
		return "", -1, callError("call_not_participant")
	}
	index := targetIndex(call, participant.AccountID, participant.DeviceID)
	if index < 0 {
		return "", -1, callError("call_not_participant")
	}
	return SideCallee, index, nil
}

func targetIndex(call *Call, accountID, deviceID string) int {
	for index := range call.Targets {
		if call.Targets[index].AccountID == accountID && call.Targets[index].DeviceID == deviceID {
			return index
		}
	}
	return -1
}

func (s *Store) deviceBusyLocked(deviceID string) bool {
	for _, call := range s.calls {
		s.expireLocked(call)
		if call.State != Ringing && call.State != Accepted {
			continue
		}
		if call.Caller.DeviceID == deviceID {
			return true
		}
		if call.State == Accepted {
			if call.WinnerDeviceID == deviceID {
				return true
			}
			continue
		}
		for _, leg := range call.Targets {
			if leg.DeviceID == deviceID && leg.ResponseState == LegRinging {
				return true
			}
		}
	}
	return false
}

func hasViableRingingTarget(call *Call) bool {
	for _, leg := range call.Targets {
		if leg.ResponseState == LegRinging && leg.DeliveryState != DeliveryFailed {
			return true
		}
	}
	return false
}

func deliveryStatus(call *Call) string {
	accepted, pending, failed := 0, 0, 0
	for _, leg := range call.Targets {
		switch leg.DeliveryState {
		case DeliveryAccepted:
			accepted++
		case DeliveryFailed:
			failed++
		default:
			pending++
		}
	}
	if accepted > 0 {
		return "submission_accepted"
	}
	if pending > 0 {
		return "pending"
	}
	if failed > 0 {
		return "submission_failed"
	}
	return ""
}

func (s *Store) expireLocked(call *Call) {
	if call.State != Ringing || s.now().Before(call.RingExpiresAt) {
		return
	}
	now := s.now().UTC()
	call.State, call.TerminalAt, call.TerminalReason = Expired, now, "ring_timeout"
	for index := range call.Targets {
		if call.Targets[index].ResponseState == LegRinging {
			call.Targets[index].ResponseState = LegExpired
		}
	}
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
	for id, record := range s.createRequests {
		if now.Sub(record.CreatedAt) > 10*time.Minute {
			delete(s.createRequests, id)
		}
	}
	for id, record := range s.mutationRequests {
		if now.Sub(record.CreatedAt) > 10*time.Minute {
			delete(s.mutationRequests, id)
		}
	}
}

func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func normalizeParticipant(value Participant) Participant {
	return Participant{UserID: normalize(value.UserID), AccountID: normalize(value.AccountID), DeviceID: normalize(value.DeviceID)}
}
func safeReason(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return "unavailable"
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "unavailable"
		}
	}
	return value
}
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func ErrorCode(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return ""
}
