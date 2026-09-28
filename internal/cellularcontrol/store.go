package cellularcontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTTL            = 2 * time.Minute
	startResultGrace      = 30 * time.Second
	terminalRetention     = 2 * time.Minute
	SafePublicErrorDomain = "PublicCellularAPI"
)

type State string

const (
	DeliveryPending                        State = "iphone_delivery_pending"
	IPhoneActionRequired                   State = "iphone_action_required"
	IPhoneBackgroundReceived               State = "iphone_background_received"
	IPhoneNotificationActionReceived       State = "iphone_notification_action_received"
	IPhoneStartAuthorized                  State = "iphone_start_authorized"
	IPhoneBackgroundStartAttempted         State = "iphone_background_start_attempted"
	IPhoneForegroundStartAttempted         State = "iphone_foreground_start_attempted"
	IPhoneNotificationActionStartAttempted State = "iphone_notification_action_start_attempted"
	SystemStartAccepted                    State = "system_start_accepted"
	PublicStartError                       State = "public_start_error"
	Cancelled                              State = "cancelled"
	Expired                                State = "expired"
	FailedSafe                             State = "failed_safe"
)

type ReceiptContext string

const (
	ReceiptForeground             ReceiptContext = "foreground"
	ReceiptBackground             ReceiptContext = "background"
	ReceiptInactive               ReceiptContext = "inactive"
	ReceiptOpenedFromNotification ReceiptContext = "opened_from_notification"
	ReceiptNotificationAction     ReceiptContext = "notification_action"
)

type DeliveryMode string

const (
	SilentBackground   DeliveryMode = "silent_background"
	NotificationAction DeliveryMode = "notification_action"
)

type ApplicationState string

const (
	ApplicationForeground ApplicationState = "foreground"
	ApplicationBackground ApplicationState = "background"
	ApplicationInactive   ApplicationState = "inactive"
	ApplicationUnknown    ApplicationState = "unknown"
)

type StartResult string

const (
	StartAccepted StartResult = "accepted"
	StartError    StartResult = "error"
)

type Participant struct {
	UserID, AccountID, DeviceID, Platform string
}

type View struct {
	RequestID                    string           `json:"requestID"`
	DeliveryMode                 DeliveryMode     `json:"deliveryMode"`
	State                        State            `json:"state"`
	CreatedAt                    time.Time        `json:"createdAt"`
	ExpiresAt                    time.Time        `json:"expiresAt"`
	DeliveryStatus               string           `json:"deliveryStatus"`
	SourcePlatform               string           `json:"sourcePlatform"`
	TargetPlatform               string           `json:"targetPlatform"`
	SameOwnerAuthorized          bool             `json:"sameOwnerAuthorized"`
	MutationApplied              *bool            `json:"mutationApplied,omitempty"`
	TerminalReason               string           `json:"terminalReason,omitempty"`
	ReceiptContext               ReceiptContext   `json:"receiptContext,omitempty"`
	ApplicationState             ApplicationState `json:"applicationState,omitempty"`
	ReceivedAt                   *time.Time       `json:"receivedAt,omitempty"`
	OrdinaryReceivedAt           *time.Time       `json:"ordinaryReceivedAt,omitempty"`
	NotificationActionReceivedAt *time.Time       `json:"notificationActionReceivedAt,omitempty"`
	StartAttemptedAt             *time.Time       `json:"startAttemptedAt,omitempty"`
	StartResultAt                *time.Time       `json:"startResultAt,omitempty"`
	StartResult                  StartResult      `json:"startResult,omitempty"`
	SafeErrorDomain              string           `json:"safeErrorDomain,omitempty"`
	SafeErrorCode                *int             `json:"safeErrorCode,omitempty"`
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
	deliveryMode                        DeliveryMode
	source, target                      Participant
	state                               State
	createdAt, expiresAt                time.Time
	deliveryStatus, terminalReason      string
	receiptContext                      ReceiptContext
	applicationState                    ApplicationState
	receivedAt, ordinaryReceivedAt      time.Time
	notificationActionReceivedAt        time.Time
	startAttemptedAt                    time.Time
	startResultDeadline                 time.Time
	startResultAt                       time.Time
	startResult                         StartResult
	safeErrorDomain                     string
	safeErrorCode                       *int
	receiveMutations                    map[string]receiptMutation
	startMutationID                     string
	startAttemptMutationID              string
	startResultMutationID               string
	cancelMutationID                    string
	timer                               *time.Timer
}

type receiptMutation struct {
	context ReceiptContext
}

type Store struct {
	mu               sync.Mutex
	ttl              time.Duration
	startResultGrace time.Duration
	now              func() time.Time
	controls         map[string]*control
	closed           bool
}

func New(ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{ttl: ttl, startResultGrace: startResultGrace, now: time.Now, controls: map[string]*control{}}
}

func (s *Store) Create(requestID string, source, target Participant, phoneNumber string) (View, bool, error) {
	return s.CreateWithMode(requestID, source, target, phoneNumber, SilentBackground)
}

func (s *Store) CreateWithMode(requestID string, source, target Participant, phoneNumber string, mode DeliveryMode) (View, bool, error) {
	requestID = normalize(requestID)
	source = normalizeParticipant(source)
	target = normalizeParticipant(target)
	phoneDigest := digest(phoneNumber)
	if requestID == "" || source.UserID == "" || source.AccountID == "" || source.DeviceID == "" || source.Platform != "watchOS" || target.UserID == "" || target.AccountID == "" || target.DeviceID == "" || target.Platform != "iOS" || source.UserID != target.UserID || phoneNumber == "" || !ValidDeliveryMode(mode) {
		return View{}, false, failure(400, "invalid_request")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return View{}, false, failure(503, "control_unavailable")
	}
	if existing, ok := s.controls[requestID]; ok {
		s.expireLocked(existing, s.now())
		if existing.source != source || existing.phoneDigest != phoneDigest || existing.deliveryMode != mode {
			return View{}, false, failure(409, "request_conflict")
		}
		return viewLocked(existing, nil), false, nil
	}

	now := s.now().UTC()
	value := &control{
		requestID: requestID, phoneNumber: phoneNumber, phoneDigest: phoneDigest, deliveryMode: mode,
		source: source, target: target, state: DeliveryPending,
		createdAt: now, expiresAt: now.Add(s.ttl), deliveryStatus: "pending",
		receiveMutations: map[string]receiptMutation{},
	}
	s.controls[requestID] = value
	value.timer = time.AfterFunc(s.ttl, func() { s.expire(requestID) })
	return viewLocked(value, nil), true, nil
}

// ExistingCreate makes retries independent of mutable device eligibility while
// preserving the source and destination-number idempotency contract.
func (s *Store) ExistingCreate(requestID string, source Participant, phoneNumber string) (View, bool, error) {
	return s.ExistingCreateWithMode(requestID, source, phoneNumber, SilentBackground)
}

func (s *Store) ExistingCreateWithMode(requestID string, source Participant, phoneNumber string, mode DeliveryMode) (View, bool, error) {
	requestID = normalize(requestID)
	source = normalizeParticipant(source)
	if requestID == "" || source.UserID == "" || source.AccountID == "" || source.DeviceID == "" || source.Platform != "watchOS" || phoneNumber == "" || !ValidDeliveryMode(mode) {
		return View{}, false, failure(400, "invalid_request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return View{}, false, failure(503, "control_unavailable")
	}
	existing, ok := s.controls[requestID]
	if !ok {
		return View{}, false, nil
	}
	s.expireLocked(existing, s.now())
	if existing.source != source || existing.phoneDigest != digest(phoneNumber) || existing.deliveryMode != mode {
		return View{}, false, failure(409, "request_conflict")
	}
	return viewLocked(existing, nil), true, nil
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

func (s *Store) Receive(requestID, mutationID string, target Participant, context ReceiptContext) (View, error) {
	return s.ReceiveWithApplicationState(requestID, mutationID, target, context, applicationStateForReceipt(context))
}

func (s *Store) ReceiveWithApplicationState(requestID, mutationID string, target Participant, context ReceiptContext, applicationState ApplicationState) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.targetLocked(requestID, target)
	if err != nil {
		return View{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" || !ValidReceiptContext(context) || !ValidApplicationState(applicationState) {
		return View{}, failure(400, "invalid_request")
	}
	if existing, ok := value.receiveMutations[mutationID]; ok {
		if existing.context != context {
			return View{}, failure(409, "receipt_mutation_conflict")
		}
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.state == Expired {
		return View{}, failure(409, "request_expired")
	}
	if value.state == Cancelled || value.state == FailedSafe {
		return View{}, failure(409, "request_not_available")
	}
	mutation := receiptMutation{context: context}
	if value.deliveryMode == NotificationAction {
		if context != ReceiptNotificationAction {
			value.receiveMutations[mutationID] = mutation
			if value.ordinaryReceivedAt.IsZero() {
				value.ordinaryReceivedAt = s.now().UTC()
				if value.state == DeliveryPending {
					value.receiptContext = context
					value.applicationState = applicationState
					value.receivedAt = value.ordinaryReceivedAt
				}
			}
			return viewLocked(value, boolPointer(true)), nil
		}
		if value.state != DeliveryPending {
			value.receiveMutations[mutationID] = mutation
			return viewLocked(value, boolPointer(false)), nil
		}
		now := s.now().UTC()
		value.receiptContext = ReceiptNotificationAction
		value.applicationState = applicationState
		value.receivedAt = now
		value.notificationActionReceivedAt = now
		value.state = IPhoneNotificationActionReceived
		value.receiveMutations[mutationID] = mutation
		return viewLocked(value, boolPointer(true)), nil
	}
	if context == ReceiptNotificationAction {
		return View{}, failure(409, "delivery_mode_mismatch")
	}
	if value.state != DeliveryPending {
		value.receiveMutations[mutationID] = mutation
		return viewLocked(value, boolPointer(false)), nil
	}
	value.receiptContext = context
	value.applicationState = applicationState
	value.receivedAt = s.now().UTC()
	value.ordinaryReceivedAt = value.receivedAt
	if context == ReceiptBackground || context == ReceiptInactive {
		value.state = IPhoneBackgroundReceived
	} else {
		value.state = IPhoneActionRequired
	}
	value.receiveMutations[mutationID] = mutation
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
	ready := value.state == IPhoneActionRequired || value.state == IPhoneBackgroundReceived
	if value.deliveryMode == NotificationAction {
		ready = value.state == IPhoneNotificationActionReceived
	}
	if !ready {
		return StartGrant{}, failure(409, "request_not_ready")
	}
	phoneNumber := value.phoneNumber
	if phoneNumber == "" {
		return StartGrant{}, failure(409, "request_not_available")
	}
	value.startMutationID = mutationID
	value.state = IPhoneStartAuthorized
	value.phoneNumber = ""
	now := s.now().UTC()
	value.startResultDeadline = now.Add(s.startResultGrace)
	if value.startResultDeadline.After(value.expiresAt) {
		s.armTimerLocked(value, value.startResultDeadline)
	}
	return StartGrant{View: viewLocked(value, boolPointer(true)), PhoneNumber: phoneNumber}, nil
}

func (s *Store) MarkStartAttempted(requestID, mutationID string, target Participant) (View, error) {
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
	if value.startAttemptMutationID == mutationID {
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.startAttemptMutationID != "" {
		return View{}, failure(409, "system_start_already_attempted")
	}
	if value.state != IPhoneStartAuthorized {
		return View{}, failure(409, "system_start_not_authorized")
	}
	value.startAttemptMutationID = mutationID
	value.startAttemptedAt = s.now().UTC()
	if value.deliveryMode == NotificationAction {
		value.state = IPhoneNotificationActionStartAttempted
	} else if value.receiptContext == ReceiptBackground || value.receiptContext == ReceiptInactive {
		value.state = IPhoneBackgroundStartAttempted
	} else {
		value.state = IPhoneForegroundStartAttempted
	}
	return viewLocked(value, boolPointer(true)), nil
}

func (s *Store) MarkStartResult(requestID, mutationID string, target Participant, result StartResult, safeErrorDomain string, safeErrorCode *int) (View, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.targetLocked(requestID, target)
	if err != nil {
		return View{}, err
	}
	mutationID = normalize(mutationID)
	if mutationID == "" || (result != StartAccepted && result != StartError) {
		return View{}, failure(400, "invalid_request")
	}
	if value.startResultMutationID == mutationID {
		return viewLocked(value, boolPointer(false)), nil
	}
	if value.startResultMutationID != "" {
		return View{}, failure(409, "system_start_result_already_reported")
	}
	if value.state != IPhoneBackgroundStartAttempted && value.state != IPhoneForegroundStartAttempted && value.state != IPhoneNotificationActionStartAttempted {
		return View{}, failure(409, "system_start_not_attempted")
	}
	if result == StartError && (!ValidSafeErrorDomain(safeErrorDomain) || safeErrorCode == nil) {
		return View{}, failure(400, "invalid_request")
	}
	if result == StartAccepted && (safeErrorDomain != "" || safeErrorCode != nil) {
		return View{}, failure(400, "invalid_request")
	}
	value.startResultMutationID = mutationID
	value.startResultAt = s.now().UTC()
	value.startResult = result
	if result == StartAccepted {
		value.state = SystemStartAccepted
	} else {
		value.state = PublicStartError
		value.safeErrorDomain = safeErrorDomain
		code := *safeErrorCode
		value.safeErrorCode = &code
		value.terminalReason = "public_start_error"
	}
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
	if value.state == IPhoneStartAuthorized || value.state == IPhoneBackgroundStartAttempted || value.state == IPhoneForegroundStartAttempted || value.state == IPhoneNotificationActionStartAttempted || value.state == SystemStartAccepted || value.state == PublicStartError {
		return View{}, failure(409, "system_start_already_authorized")
	}
	if value.state == Expired {
		return View{}, failure(409, "request_expired")
	}
	if value.state == FailedSafe {
		return viewLocked(value, boolPointer(false)), nil
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
	if value.deliveryStatus != "pending" {
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
	deadline := value.expiresAt
	if (value.state == IPhoneStartAuthorized || value.state == IPhoneBackgroundStartAttempted || value.state == IPhoneForegroundStartAttempted || value.state == IPhoneNotificationActionStartAttempted) && value.startResultDeadline.After(deadline) {
		deadline = value.startResultDeadline
	}
	if now.Before(deadline) || terminal(value.state) {
		return
	}
	switch value.state {
	case DeliveryPending:
		if value.deliveryMode == NotificationAction && value.deliveryStatus == "submission_accepted" {
			value.terminalReason = "notification_action_not_observed"
		} else if value.deliveryStatus == "submission_accepted" {
			value.terminalReason = "background_execution_not_observed"
		} else {
			value.terminalReason = "request_expired"
		}
	case IPhoneStartAuthorized, IPhoneBackgroundStartAttempted, IPhoneForegroundStartAttempted, IPhoneNotificationActionStartAttempted:
		value.terminalReason = "public_start_result_not_observed"
	default:
		value.terminalReason = "request_expired"
	}
	value.state = Expired
	value.phoneNumber = ""
	s.scheduleCleanupLocked(value, now)
}

func (s *Store) armTimerLocked(value *control, deadline time.Time) {
	if value.timer != nil {
		value.timer.Stop()
	}
	requestID := value.requestID
	value.timer = time.AfterFunc(time.Until(deadline), func() { s.expire(requestID) })
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
		RequestID: value.requestID, DeliveryMode: value.deliveryMode, State: value.state, CreatedAt: value.createdAt, ExpiresAt: value.expiresAt,
		DeliveryStatus: value.deliveryStatus, SourcePlatform: value.source.Platform, TargetPlatform: value.target.Platform,
		SameOwnerAuthorized: value.source.UserID == value.target.UserID, MutationApplied: mutationApplied,
		TerminalReason: value.terminalReason, ReceiptContext: value.receiptContext, ApplicationState: value.applicationState,
		ReceivedAt: timePointer(value.receivedAt), OrdinaryReceivedAt: timePointer(value.ordinaryReceivedAt),
		NotificationActionReceivedAt: timePointer(value.notificationActionReceivedAt), StartAttemptedAt: timePointer(value.startAttemptedAt),
		StartResultAt: timePointer(value.startResultAt),
		StartResult:   value.startResult, SafeErrorDomain: value.safeErrorDomain,
		SafeErrorCode: cloneInt(value.safeErrorCode),
	}
}

func ValidReceiptContext(value ReceiptContext) bool {
	switch value {
	case ReceiptForeground, ReceiptBackground, ReceiptInactive, ReceiptOpenedFromNotification, ReceiptNotificationAction:
		return true
	default:
		return false
	}
}

func ValidDeliveryMode(value DeliveryMode) bool {
	return value == SilentBackground || value == NotificationAction
}

func ValidApplicationState(value ApplicationState) bool {
	switch value {
	case ApplicationForeground, ApplicationBackground, ApplicationInactive, ApplicationUnknown:
		return true
	default:
		return false
	}
}

func applicationStateForReceipt(value ReceiptContext) ApplicationState {
	switch value {
	case ReceiptForeground:
		return ApplicationForeground
	case ReceiptBackground:
		return ApplicationBackground
	case ReceiptInactive:
		return ApplicationInactive
	default:
		return ApplicationUnknown
	}
}

func ValidSafeErrorDomain(value string) bool {
	return value == SafePublicErrorDomain
}

func terminal(state State) bool {
	switch state {
	case Cancelled, Expired, FailedSafe, SystemStartAccepted, PublicStartError:
		return true
	default:
		return false
	}
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func timePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value
	return &copy
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
