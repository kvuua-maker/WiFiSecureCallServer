package phoneauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

var phonePattern = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)
var codePattern = regexp.MustCompile(`^[0-9]{6}$`)

type SMSSender interface {
	Send(context.Context, string, string) (string, error)
}

type ServiceError struct {
	Status  int
	Code    string
	RetryAt time.Time
}

func (e *ServiceError) Error() string { return e.Code }
func tooMany(code string, retry time.Time) *ServiceError {
	return &ServiceError{Status: 429, Code: code, RetryAt: retry}
}
func bad(code string) *ServiceError      { return &ServiceError{Status: 400, Code: code} }
func conflict(code string) *ServiceError { return &ServiceError{Status: 409, Code: code} }
func unauthorized() *ServiceError        { return &ServiceError{Status: 401, Code: "unauthorized"} }

type Service struct {
	store              *accounts.Store
	sender             SMSSender
	pepper             []byte
	maxDaily           int
	now                func() time.Time
	watchCodeGenerator func() (string, error)
	startMu            sync.Mutex
}

type StartResult struct {
	VerificationID string    `json:"verificationID"`
	ExpiresAt      time.Time `json:"expiresAt"`
	ResendAfter    time.Time `json:"resendAfter"`
}
type AccountView struct {
	AccountID   string `json:"accountID"`
	PhoneNumber string `json:"phoneNumber"`
}
type SessionResult struct {
	Account          AccountView `json:"account"`
	DeviceID         string      `json:"deviceID"`
	AccessToken      string      `json:"accessToken"`
	AccessExpiresAt  time.Time   `json:"accessExpiresAt"`
	RefreshToken     string      `json:"refreshToken"`
	RefreshExpiresAt time.Time   `json:"refreshExpiresAt"`
}
type Identity struct{ SessionID, AccountID, DeviceID, Platform, PhoneE164 string }
type WatchStartResult struct {
	LinkID, LinkSecret, Code string
	ExpiresAt                time.Time
}
type WatchStatusResult struct {
	Status           string    `json:"status"`
	AccountID        string    `json:"accountID,omitempty"`
	PhoneNumber      string    `json:"phoneNumber,omitempty"`
	AccessToken      string    `json:"accessToken,omitempty"`
	AccessExpiresAt  time.Time `json:"accessExpiresAt,omitempty"`
	RefreshToken     string    `json:"refreshToken,omitempty"`
	RefreshExpiresAt time.Time `json:"refreshExpiresAt,omitempty"`
}

func New(store *accounts.Store, sender SMSSender, pepper string, maxDaily int) (*Service, error) {
	if store == nil || len(pepper) < 32 || maxDaily <= 0 {
		return nil, errors.New("invalid phone auth configuration")
	}
	return &Service{store: store, sender: sender, pepper: []byte(pepper), maxDaily: maxDaily, now: func() time.Time { return time.Now().UTC() }, watchCodeGenerator: numericCode}, nil
}

func (s *Service) SetClockForTesting(now func() time.Time) { s.now = now }
func (s *Service) SetWatchCodeGeneratorForTesting(generator func() (string, error)) {
	s.watchCodeGenerator = generator
}
func ValidPhone(value string) bool { return phonePattern.MatchString(value) }

func (s *Service) Start(ctx context.Context, requestID, phone, sourceIP string) (StartResult, error) {
	s.startMu.Lock()
	defer s.startMu.Unlock()
	if !validUUID(requestID) || !ValidPhone(phone) {
		return StartResult{}, bad("invalid request")
	}
	if s.sender == nil {
		return StartResult{}, &ServiceError{Status: 503, Code: "SMS provider disabled"}
	}
	now := s.now()
	state := s.store.Snapshot()
	if existing, ok := state.StartIdempotency[strings.ToLower(requestID)]; ok {
		if existing.PhoneE164 != phone {
			return StartResult{}, conflict("requestID conflict")
		}
		challenge, ok := state.Verifications[existing.VerificationID]
		if !ok || !challenge.ProviderSubmitted {
			return StartResult{}, &ServiceError{Status: 503, Code: "SMS submission unavailable"}
		}
		return StartResult{VerificationID: challenge.VerificationID, ExpiresAt: challenge.ExpiresAt, ResendAfter: challenge.ResendAfter}, nil
	}
	if limited := rateLimit(state, phone, sourceIP, now, s.maxDaily); limited != nil {
		return StartResult{}, limited
	}
	verificationID, err := randomUUID()
	if err != nil {
		return StartResult{}, err
	}
	code, err := numericCode()
	if err != nil {
		return StartResult{}, err
	}
	challenge := accounts.Verification{VerificationID: verificationID, PhoneE164: phone, SourceIP: sourceIP, OTPHash: s.hmac(verificationID, phone, code), CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ResendAfter: now.Add(120 * time.Second)}
	err = s.store.Update(func(state *accounts.State) error {
		state.Verifications[verificationID] = challenge
		state.StartIdempotency[strings.ToLower(requestID)] = accounts.StartIdempotency{RequestID: strings.ToLower(requestID), PhoneE164: phone, VerificationID: verificationID, CreatedAt: now}
		prune(state, now)
		return nil
	})
	if err != nil {
		return StartResult{}, err
	}
	_ = s.store.Update(func(state *accounts.State) error {
		value := state.Verifications[verificationID]
		value.ProviderAttempted = true
		state.Verifications[verificationID] = value
		return nil
	})
	messageID, sendErr := s.sender.Send(ctx, phone, fmt.Sprintf("WiFi Secure Call code: %s. Valid 10 min.", code))
	if sendErr != nil {
		return StartResult{}, &ServiceError{Status: 503, Code: "SMS submission failed"}
	}
	if err := s.store.Update(func(state *accounts.State) error {
		value := state.Verifications[verificationID]
		value.ProviderSubmitted = true
		value.ProviderMessageID = messageID
		state.Verifications[verificationID] = value
		return nil
	}); err != nil {
		return StartResult{}, err
	}
	return StartResult{VerificationID: verificationID, ExpiresAt: challenge.ExpiresAt, ResendAfter: challenge.ResendAfter}, nil
}

func (s *Service) Verify(requestID, verificationID, code, deviceID, platform string) (SessionResult, error) {
	if !validUUID(requestID) || !validUUID(verificationID) || !validUUID(deviceID) || platform != "iOS" || !codePattern.MatchString(code) {
		return SessionResult{}, bad("invalid request")
	}
	now := s.now()
	issued, session, err := s.newSession("", deviceID, platform, now)
	if err != nil {
		return SessionResult{}, err
	}
	var resultErr error
	var accountID, phone string
	err = s.store.Update(func(state *accounts.State) error {
		v, ok := state.Verifications[strings.ToLower(verificationID)]
		if !ok || v.VerificationID != strings.ToLower(verificationID) || v.ConsumedAt != nil || !v.ProviderSubmitted {
			resultErr = bad("invalid verification")
			return nil
		}
		if !now.Before(v.ExpiresAt) {
			resultErr = &ServiceError{Status: 410, Code: "verification expired"}
			return nil
		}
		if v.Attempts >= 5 {
			resultErr = tooMany("verification attempts exceeded", v.ExpiresAt)
			return nil
		}
		actual := s.hmac(v.VerificationID, v.PhoneE164, code)
		if subtle.ConstantTimeCompare([]byte(v.OTPHash), []byte(actual)) != 1 {
			v.Attempts++
			state.Verifications[v.VerificationID] = v
			resultErr = bad("invalid verification")
			return nil
		}
		phone = v.PhoneE164
		for _, account := range state.Accounts {
			if account.PhoneE164 == phone && account.Status == "active" {
				accountID = account.AccountID
				break
			}
		}
		if accountID == "" {
			accountID, err = randomUUID()
			if err != nil {
				return err
			}
			state.Accounts[accountID] = accounts.Account{AccountID: accountID, PhoneE164: phone, CreatedAt: now, Status: "active"}
		}
		v.ConsumedAt = &now
		v.Attempts++
		state.Verifications[v.VerificationID] = v
		upsertDevice(state, accountID, deviceID, platform, now)
		session.AccountID = accountID
		state.Sessions[session.SessionID] = session
		return nil
	})
	if err != nil {
		return SessionResult{}, err
	}
	if resultErr != nil {
		return SessionResult{}, resultErr
	}
	issued.Account = AccountView{AccountID: accountID, PhoneNumber: phone}
	issued.DeviceID = deviceID
	return issued, nil
}

func (s *Service) Authenticate(accessToken string) (Identity, error) {
	if accessToken == "" {
		return Identity{}, unauthorized()
	}
	hash := tokenHash(accessToken)
	now := s.now()
	state := s.store.Snapshot()
	for _, session := range state.Sessions {
		if session.RevokedAt == nil && now.Before(session.AccessExpiresAt) && subtle.ConstantTimeCompare([]byte(session.AccessTokenHash), []byte(hash)) == 1 {
			account, ok := state.Accounts[session.AccountID]
			if !ok {
				break
			}
			return Identity{SessionID: session.SessionID, AccountID: session.AccountID, DeviceID: session.DeviceID, Platform: session.Platform, PhoneE164: account.PhoneE164}, nil
		}
	}
	return Identity{}, unauthorized()
}

func (s *Service) Refresh(refreshToken, deviceID string) (SessionResult, error) {
	if refreshToken == "" || !validUUID(deviceID) {
		return SessionResult{}, unauthorized()
	}
	hash := tokenHash(refreshToken)
	state := s.store.Snapshot()
	now := s.now()
	var current accounts.Session
	found := false
	for _, session := range state.Sessions {
		if session.DeviceID == strings.ToLower(deviceID) && session.RevokedAt == nil && now.Before(session.RefreshExpiresAt) && subtle.ConstantTimeCompare([]byte(session.RefreshTokenHash), []byte(hash)) == 1 {
			current = session
			found = true
			break
		}
	}
	if !found {
		return SessionResult{}, unauthorized()
	}
	issued, replacement, err := s.newSession(current.AccountID, current.DeviceID, current.Platform, now)
	if err != nil {
		return SessionResult{}, err
	}
	err = s.store.Update(func(state *accounts.State) error {
		old, ok := state.Sessions[current.SessionID]
		if !ok || old.RevokedAt != nil || subtle.ConstantTimeCompare([]byte(old.RefreshTokenHash), []byte(hash)) != 1 {
			return unauthorized()
		}
		old.RevokedAt = &now
		state.Sessions[old.SessionID] = old
		state.Sessions[replacement.SessionID] = replacement
		return nil
	})
	if err != nil {
		return SessionResult{}, err
	}
	account := state.Accounts[current.AccountID]
	issued.Account = AccountView{AccountID: account.AccountID, PhoneNumber: account.PhoneE164}
	issued.DeviceID = current.DeviceID
	return issued, nil
}

func (s *Service) Logout(identity Identity) error {
	now := s.now()
	return s.store.Update(func(state *accounts.State) error {
		value, ok := state.Sessions[identity.SessionID]
		if !ok {
			return unauthorized()
		}
		value.RevokedAt = &now
		state.Sessions[identity.SessionID] = value
		return nil
	})
}

func (s *Service) DeleteAccount(identity Identity) error {
	return s.store.Update(func(state *accounts.State) error {
		account, ok := state.Accounts[identity.AccountID]
		if !ok {
			return unauthorized()
		}
		delete(state.Accounts, identity.AccountID)
		devices := state.Devices[:0]
		for _, d := range state.Devices {
			if d.AccountID != identity.AccountID {
				devices = append(devices, d)
			}
		}
		state.Devices = devices
		for id, session := range state.Sessions {
			if session.AccountID == identity.AccountID {
				delete(state.Sessions, id)
			}
		}
		for id, link := range state.WatchLinks {
			if link.AccountID == identity.AccountID {
				delete(state.WatchLinks, id)
			}
		}
		for id, v := range state.Verifications {
			if v.PhoneE164 == account.PhoneE164 {
				delete(state.Verifications, id)
			}
		}
		for id, value := range state.StartIdempotency {
			if value.PhoneE164 == account.PhoneE164 {
				delete(state.StartIdempotency, id)
			}
		}
		return nil
	})
}

func (s *Service) WatchStart(requestID, deviceID, platform string) (WatchStartResult, error) {
	if !validUUID(requestID) || !validUUID(deviceID) || platform != "watchOS" {
		return WatchStartResult{}, bad("invalid request")
	}
	now := s.now()
	state := s.store.Snapshot()
	key := strings.ToLower(requestID)
	if idem, ok := state.WatchStartIdempotency[key]; ok {
		if idem.DeviceID != strings.ToLower(deviceID) {
			return WatchStartResult{}, conflict("requestID conflict")
		}
		return WatchStartResult{}, conflict("link start already consumed")
	}
	linkID, err := randomUUID()
	if err != nil {
		return WatchStartResult{}, err
	}
	secret, err := randomToken()
	if err != nil {
		return WatchStartResult{}, err
	}
	var code string
	link := accounts.WatchLink{LinkID: linkID, DeviceID: strings.ToLower(deviceID), Platform: platform, SecretHash: tokenHash(secret), CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	err = s.store.Update(func(state *accounts.State) error {
		for attempt := 0; attempt < 20; attempt++ {
			candidate, generateErr := s.watchCodeGenerator()
			if generateErr != nil {
				return generateErr
			}
			collision := false
			for _, existing := range state.WatchLinks {
				if existing.ClaimedAt == nil && now.Before(existing.ExpiresAt) && subtle.ConstantTimeCompare([]byte(existing.CodeHash), []byte(s.hmac(existing.LinkID, existing.DeviceID, candidate))) == 1 {
					collision = true
					break
				}
			}
			if !collision {
				code = candidate
				break
			}
		}
		if code == "" {
			return &ServiceError{Status: 503, Code: "link code unavailable"}
		}
		link.CodeHash = s.hmac(link.LinkID, link.DeviceID, code)
		state.WatchLinks[linkID] = link
		state.WatchStartIdempotency[key] = accounts.WatchStartIdempotency{RequestID: key, DeviceID: strings.ToLower(deviceID), LinkID: linkID, CreatedAt: now}
		prune(state, now)
		return nil
	})
	if err != nil {
		return WatchStartResult{}, err
	}
	return WatchStartResult{LinkID: linkID, LinkSecret: secret, Code: code, ExpiresAt: link.ExpiresAt}, nil
}

func (s *Service) WatchClaim(identity Identity, requestID, code string) error {
	if !validUUID(requestID) || !codePattern.MatchString(code) {
		return bad("invalid request")
	}
	now := s.now()
	return s.store.Update(func(state *accounts.State) error {
		matched := ""
		matches := 0
		for id, link := range state.WatchLinks {
			if link.ClaimedAt == nil && now.Before(link.ExpiresAt) && subtle.ConstantTimeCompare([]byte(link.CodeHash), []byte(s.hmac(link.LinkID, link.DeviceID, code))) == 1 {
				matched = id
				matches++
			}
		}
		if matches == 0 {
			return bad("invalid link code")
		}
		if matches > 1 {
			return &ServiceError{Status: 503, Code: "ambiguous link code"}
		}
		link := state.WatchLinks[matched]
		link.AccountID = identity.AccountID
		link.ClaimedAt = &now
		state.WatchLinks[matched] = link
		upsertDevice(state, identity.AccountID, link.DeviceID, "watchOS", now)
		return nil
	})
}

func (s *Service) WatchStatus(linkID, secret string) (WatchStatusResult, error) {
	if !validUUID(linkID) || secret == "" {
		return WatchStatusResult{}, bad("invalid request")
	}
	now := s.now()
	state := s.store.Snapshot()
	link, ok := state.WatchLinks[strings.ToLower(linkID)]
	if !ok || subtle.ConstantTimeCompare([]byte(link.SecretHash), []byte(tokenHash(secret))) != 1 {
		return WatchStatusResult{}, unauthorized()
	}
	if !now.Before(link.ExpiresAt) {
		return WatchStatusResult{Status: "expired"}, nil
	}
	if link.ClaimedAt == nil {
		return WatchStatusResult{Status: "pending"}, nil
	}
	if link.RetrievedAt != nil {
		return WatchStatusResult{}, conflict("link session already retrieved")
	}
	issued, session, err := s.newSession(link.AccountID, link.DeviceID, "watchOS", now)
	if err != nil {
		return WatchStatusResult{}, err
	}
	err = s.store.Update(func(state *accounts.State) error {
		current := state.WatchLinks[link.LinkID]
		if current.RetrievedAt != nil {
			return conflict("link session already retrieved")
		}
		current.RetrievedAt = &now
		state.WatchLinks[link.LinkID] = current
		state.Sessions[session.SessionID] = session
		return nil
	})
	if err != nil {
		return WatchStatusResult{}, err
	}
	account := state.Accounts[link.AccountID]
	return WatchStatusResult{Status: "claimed", AccountID: link.AccountID, PhoneNumber: maskPhone(account.PhoneE164), AccessToken: issued.AccessToken, AccessExpiresAt: issued.AccessExpiresAt, RefreshToken: issued.RefreshToken, RefreshExpiresAt: issued.RefreshExpiresAt}, nil
}

func (s *Service) newSession(accountID, deviceID, platform string, now time.Time) (SessionResult, accounts.Session, error) {
	sessionID, err := randomUUID()
	if err != nil {
		return SessionResult{}, accounts.Session{}, err
	}
	access, err := randomToken()
	if err != nil {
		return SessionResult{}, accounts.Session{}, err
	}
	refresh, err := randomToken()
	if err != nil {
		return SessionResult{}, accounts.Session{}, err
	}
	accessExpiry, refreshExpiry := now.Add(15*time.Minute), now.Add(30*24*time.Hour)
	session := accounts.Session{SessionID: sessionID, AccountID: accountID, DeviceID: strings.ToLower(deviceID), Platform: platform, AccessTokenHash: tokenHash(access), AccessExpiresAt: accessExpiry, RefreshTokenHash: tokenHash(refresh), RefreshExpiresAt: refreshExpiry, CreatedAt: now}
	return SessionResult{AccessToken: access, AccessExpiresAt: accessExpiry, RefreshToken: refresh, RefreshExpiresAt: refreshExpiry}, session, nil
}

func upsertDevice(state *accounts.State, accountID, deviceID, platform string, now time.Time) {
	deviceID = strings.ToLower(deviceID)
	for i := range state.Devices {
		if state.Devices[i].AccountID == accountID && state.Devices[i].DeviceID == deviceID {
			state.Devices[i].LastSeenAt = now
			state.Devices[i].Platform = platform
			return
		}
	}
	state.Devices = append(state.Devices, accounts.Device{AccountID: accountID, DeviceID: deviceID, Platform: platform, CreatedAt: now, LastSeenAt: now})
}

func prune(state *accounts.State, now time.Time) {
	for id, value := range state.StartIdempotency {
		if now.Sub(value.CreatedAt) > 24*time.Hour {
			delete(state.StartIdempotency, id)
		}
	}
	for id, value := range state.WatchStartIdempotency {
		if now.Sub(value.CreatedAt) > time.Hour {
			delete(state.WatchStartIdempotency, id)
		}
	}
	for id, value := range state.Verifications {
		if now.Sub(value.CreatedAt) > 48*time.Hour {
			delete(state.Verifications, id)
		}
	}
	for id, value := range state.WatchLinks {
		if now.Sub(value.CreatedAt) > 24*time.Hour {
			delete(state.WatchLinks, id)
		}
	}
}

func (s *Service) hmac(parts ...string) string {
	mac := hmac.New(sha256.New, s.pepper)
	for _, part := range parts {
		mac.Write([]byte{0})
		mac.Write([]byte(part))
	}
	return hex.EncodeToString(mac.Sum(nil))
}
func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func randomToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func numericCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
func randomUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range strings.ToLower(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func maskPhone(phone string) string {
	if len(phone) <= 4 {
		return "••••"
	}
	return phone[:2] + strings.Repeat("•", len(phone)-6) + phone[len(phone)-4:]
}
