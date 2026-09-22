package phoneauth

import (
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

func rateLimit(state accounts.State, phone, sourceIP string, now time.Time, globalDaily int) *ServiceError {
	phone10m, phoneDay, ipHour, global := 0, 0, 0, 0
	var latest time.Time
	for _, value := range state.Verifications {
		if value.ProviderSubmitted && now.Sub(value.CreatedAt) < 24*time.Hour {
			global++
		}
		if value.PhoneE164 == phone {
			if value.CreatedAt.After(latest) {
				latest = value.CreatedAt
			}
			if now.Sub(value.CreatedAt) < 10*time.Minute {
				phone10m++
			}
			if now.Sub(value.CreatedAt) < 24*time.Hour {
				phoneDay++
			}
		}
		if value.SourceIP == sourceIP && now.Sub(value.CreatedAt) < time.Hour {
			ipHour++
		}
	}
	if !latest.IsZero() && now.Before(latest.Add(120*time.Second)) {
		return tooMany("resend too soon", latest.Add(120*time.Second))
	}
	if phone10m >= 3 {
		return tooMany("phone rate limit", now.Add(10*time.Minute))
	}
	if phoneDay >= 10 {
		return tooMany("phone daily limit", now.Add(time.Hour))
	}
	if ipHour >= 20 {
		return tooMany("source rate limit", now.Add(time.Hour))
	}
	if global >= globalDaily {
		return tooMany("daily SMS limit", nextUTCDate(now))
	}
	return nil
}

func nextUTCDate(now time.Time) time.Time {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
}
