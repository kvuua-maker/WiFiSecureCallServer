package sipgw

import (
	"sort"
	"sync"
	"time"
)

// Contact is one registered SIP contact for an address of record.
type Contact struct {
	URI          string
	Source       string
	UserAgent    string
	RegisteredAt time.Time
	ExpiresAt    time.Time
}

// Expired reports whether the registration has lapsed at the given instant.
func (c Contact) Expired(at time.Time) bool { return !c.ExpiresAt.After(at) }

// Registrar stores SIP registrations in memory.
//
// The store is intentionally volatile: a restart makes every device re-register
// within its refresh interval, and nothing about a binding is worth persisting.
type Registrar struct {
	mu        sync.RWMutex
	byUser    map[string]map[string]Contact
	lastPrune time.Time
}

// NewRegistrar returns an empty registrar.
func NewRegistrar() *Registrar {
	return &Registrar{byUser: map[string]map[string]Contact{}}
}

// Register stores or refreshes a binding for user. A ttl of zero removes it,
// which is how a device unregisters itself.
func (r *Registrar) Register(user string, contact Contact, ttl time.Duration, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bindings, ok := r.byUser[user]
	if !ok {
		bindings = map[string]Contact{}
		r.byUser[user] = bindings
	}
	if ttl <= 0 {
		delete(bindings, contact.URI)
		if len(bindings) == 0 {
			delete(r.byUser, user)
		}
		return
	}
	contact.RegisteredAt = now
	contact.ExpiresAt = now.Add(ttl)
	bindings[contact.URI] = contact
}

// Unregister drops every binding of a user.
func (r *Registrar) Unregister(user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byUser, user)
}

// Lookup returns the freshest unexpired contact for user.
func (r *Registrar) Lookup(user string, now time.Time) (Contact, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bindings, ok := r.byUser[user]
	if !ok {
		return Contact{}, false
	}
	var best Contact
	found := false
	for _, contact := range bindings {
		if contact.Expired(now) {
			continue
		}
		if !found || contact.RegisteredAt.After(best.RegisteredAt) {
			best, found = contact, true
		}
	}
	return best, found
}

// Registered reports whether user has at least one live binding.
func (r *Registrar) Registered(user string, now time.Time) bool {
	_, ok := r.Lookup(user, now)
	return ok
}

// Binding is one row of the registry snapshot used by the status endpoint.
type Binding struct {
	User         string    `json:"user"`
	URI          string    `json:"uri"`
	Source       string    `json:"source"`
	UserAgent    string    `json:"userAgent"`
	RegisteredAt time.Time `json:"registeredAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	SecondsLeft  int       `json:"secondsLeft"`
}

// Snapshot lists every live binding, sorted by user.
func (r *Registrar) Snapshot(now time.Time) []Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Binding, 0, len(r.byUser))
	for user, bindings := range r.byUser {
		for _, contact := range bindings {
			if contact.Expired(now) {
				continue
			}
			out = append(out, Binding{
				User:         user,
				URI:          contact.URI,
				Source:       contact.Source,
				UserAgent:    contact.UserAgent,
				RegisteredAt: contact.RegisteredAt,
				ExpiresAt:    contact.ExpiresAt,
				SecondsLeft:  int(contact.ExpiresAt.Sub(now).Seconds()),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].URI < out[j].URI
	})
	return out
}

// Prune removes expired bindings, at most once per second.
func (r *Registrar) Prune(now time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastPrune) < time.Second {
		return 0
	}
	r.lastPrune = now
	removed := 0
	for user, bindings := range r.byUser {
		for uri, contact := range bindings {
			if contact.Expired(now) {
				delete(bindings, uri)
				removed++
			}
		}
		if len(bindings) == 0 {
			delete(r.byUser, user)
		}
	}
	return removed
}
