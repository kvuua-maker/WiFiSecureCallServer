package phoneauth

import (
	"sort"
	"time"

	"github.com/kvuua-maker/wifi-secure-call-server/internal/accounts"
)

func rateLimit(state accounts.State, phone, sourceIP string, now time.Time, globalDaily int) *ServiceError {
	var phone10m, phoneDay, ipHour, global []time.Time
	var latest time.Time
	for _, value := range state.Verifications {
		if value.ProviderSubmitted && now.Sub(value.CreatedAt) < 24*time.Hour {
			global = append(global, value.CreatedAt)
		}
		if value.PhoneE164 == phone {
			if value.CreatedAt.After(latest) {
				latest = value.CreatedAt
			}
			if now.Sub(value.CreatedAt) < 10*time.Minute {
				phone10m = append(phone10m, value.CreatedAt)
			}
			if now.Sub(value.CreatedAt) < 24*time.Hour {
				phoneDay = append(phoneDay, value.CreatedAt)
			}
		}
		if value.SourceIP == sourceIP && now.Sub(value.CreatedAt) < time.Hour {
			ipHour = append(ipHour, value.CreatedAt)
		}
	}
	if !latest.IsZero() && now.Before(latest.Add(120*time.Second)) {
		return tooMany("resend too soon", latest.Add(120*time.Second))
	}
	if retry := rollingRetryAt(phone10m, 3, 10*time.Minute); !retry.IsZero() {
		return tooMany("phone rate limit", retry)
	}
	if retry := rollingRetryAt(phoneDay, 10, 24*time.Hour); !retry.IsZero() {
		return tooMany("phone daily limit", retry)
	}
	if retry := rollingRetryAt(ipHour, 20, time.Hour); !retry.IsZero() {
		return tooMany("source rate limit", retry)
	}
	if retry := rollingRetryAt(global, globalDaily, 24*time.Hour); !retry.IsZero() {
		return tooMany("daily SMS limit", retry)
	}
	return nil
}

func rollingRetryAt(events []time.Time, limit int, window time.Duration) time.Time {
	if limit <= 0 || len(events) < limit {
		return time.Time{}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Before(events[j]) })
	return events[len(events)-limit].Add(window)
}
