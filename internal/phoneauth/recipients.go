package phoneauth

import (
	"strings"
	"unicode"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

type RecipientView struct {
	UserID         string `json:"userID"`
	Username       string `json:"username"`
	DisplayName    string `json:"displayName,omitempty"`
	PublicIdentity string `json:"publicIdentity"`
	PhoneNumber    string `json:"phoneNumber,omitempty"`
}

func (s *Service) ResolveRecipient(identity Identity, value string) (RecipientView, error) {
	if identity.UserID == "" {
		return RecipientView{}, unauthorized()
	}
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return RecipientView{}, bad("invalid_recipient")
	}
	if strings.HasPrefix(value, "wsc:user:") {
		return s.resolveUsername(strings.TrimPrefix(value, "wsc:user:"), "")
	}
	if strings.Contains(value, ":") {
		return RecipientView{}, bad("invalid_recipient")
	}
	if strings.HasPrefix(value, "@") {
		return s.resolveUsername(strings.TrimPrefix(value, "@"), "")
	}
	if strings.HasPrefix(value, "+") || looksLikePhone(value) {
		phone, ok := normalizeRecipientPhone(value)
		if !ok {
			return RecipientView{}, bad("invalid_recipient")
		}
		state := s.store.Snapshot()
		for _, binding := range state.PhoneBindings {
			if binding.Status != "active" || binding.PhoneE164 != phone {
				continue
			}
			user, found := state.Users[binding.UserID]
			if !found || user.Status != "active" {
				break
			}
			return recipientView(user, maskPhone(binding.PhoneE164)), nil
		}
		return RecipientView{}, &ServiceError{Status: 404, Code: "recipient_not_found"}
	}
	return s.resolveUsername(value, "")
}

func (s *Service) RecipientForUserID(userID string) (RecipientView, error) {
	state := s.store.Snapshot()
	user, ok := state.Users[strings.ToLower(strings.TrimSpace(userID))]
	if !ok || user.Status != "active" {
		return RecipientView{}, &ServiceError{Status: 404, Code: "recipient_not_found"}
	}
	return recipientView(user, ""), nil
}

func (s *Service) DevicesForUser(userID string) []accounts.Device {
	state := s.store.Snapshot()
	userID = strings.ToLower(strings.TrimSpace(userID))
	user, ok := state.Users[userID]
	if !ok || user.Status != "active" {
		return nil
	}
	activeAccounts := map[string]bool{}
	for accountID, account := range state.Accounts {
		if account.Status == "active" && strings.EqualFold(account.UserID, userID) {
			activeAccounts[strings.ToLower(accountID)] = true
		}
	}
	result := make([]accounts.Device, 0)
	for _, device := range state.Devices {
		if activeAccounts[strings.ToLower(device.AccountID)] {
			result = append(result, device)
		}
	}
	return result
}

func (s *Service) resolveUsername(value, safePhone string) (RecipientView, error) {
	key := strings.ToLower(strings.TrimSpace(value))
	if !usernamePattern.MatchString(key) || strings.Contains(key, "@") {
		return RecipientView{}, bad("invalid_recipient")
	}
	for _, user := range s.store.Snapshot().Users {
		if user.Status == "active" && strings.EqualFold(user.Username, key) {
			return recipientView(user, safePhone), nil
		}
	}
	return RecipientView{}, &ServiceError{Status: 404, Code: "recipient_not_found"}
}

func recipientView(user accounts.User, phone string) RecipientView {
	return RecipientView{
		UserID: user.UserID, Username: user.Username, DisplayName: safeDisplayName(user.DisplayName),
		PublicIdentity: "wsc:user:" + user.Username, PhoneNumber: phone,
	}
}

func safeDisplayName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len([]rune(value)) > 80 {
		return ""
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return ""
		}
	}
	return value
}

func normalizeRecipientPhone(value string) (string, bool) {
	var builder strings.Builder
	for _, character := range strings.TrimSpace(value) {
		switch {
		case unicode.IsSpace(character), character == '-', character == '(', character == ')':
			continue
		case character == '+' || character >= '0' && character <= '9':
			builder.WriteRune(character)
		default:
			return "", false
		}
	}
	result := builder.String()
	return result, ValidPhone(result)
}

func looksLikePhone(value string) bool {
	hasDigit := false
	for _, character := range value {
		if character >= '0' && character <= '9' {
			hasDigit = true
			continue
		}
		if unicode.IsSpace(character) || character == '-' || character == '(' || character == ')' {
			continue
		}
		return false
	}
	return hasDigit
}
