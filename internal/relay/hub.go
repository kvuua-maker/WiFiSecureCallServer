// Package relay carries a dial command from a watch to its iPhone when
// WatchConnectivity cannot.
//
// The relay is deliberately a queue, not a pipe. WatchConnectivity is the happy
// path: it is encrypted, it needs no infrastructure, and it is the only route
// Apple supports between a watch and its phone. But it is peer to peer through
// iCloud, so it needs both ends awake, and a wrist that is down or a phone in
// low-power mode is exactly when a command goes missing. This package holds the
// command until the phone next connects, which may be minutes later.
//
// It carries one small JSON command per call. No audio, no media, no presence
// beyond what is needed to hand the command over.
package relay

import (
	"sync"
	"time"
)

// Command is one "call this number" instruction.
type Command struct {
	RequestID string    `json:"requestID"`
	Number    string    `json:"number"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Expired reports whether the command is too old to dial.
func (c Command) Expired(now time.Time) bool { return !c.ExpiresAt.After(now) }

// Hub holds one queue per account and at most one connected iPhone per account.
//
// An account is the unit, not a device pair: the watch and the phone already
// authenticate to the same account, and that is the only relationship the server
// needs to be sure the command reaches the right phone.
type Hub struct {
	mu sync.Mutex

	pending map[string][]Command
	iphone  map[string]*session
	seen    map[string]time.Time

	ttl        time.Duration
	maxPending int
	now        func() time.Time
}

// New builds a hub. ttl bounds how long a command may wait; maxPending bounds how
// many commands one account may accumulate, so a stuck sender cannot grow memory.
func New(ttl time.Duration, maxPending int) *Hub {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if maxPending <= 0 {
		maxPending = 8
	}
	return &Hub{
		pending:    map[string][]Command{},
		iphone:     map[string]*session{},
		seen:       map[string]time.Time{},
		ttl:        ttl,
		maxPending: maxPending,
		now:        time.Now,
	}
}

// Enqueue records a command for an account and reports whether a connected iPhone
// took it immediately.
//
// A duplicate request id is accepted but not stored twice: the watch retries over
// WatchConnectivity and over this relay, and both paths must be able to land
// without dialling twice.
func (h *Hub) Enqueue(accountID string, command Command) (delivered bool) {
	if accountID == "" || command.RequestID == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	now := h.now()
	h.sweepLocked(now)

	if _, ok := h.seen[command.RequestID]; ok {
		// Already handled: tell the caller it is delivered so it stops retrying.
		return true
	}
	h.seen[command.RequestID] = now

	if command.CreatedAt.IsZero() {
		command.CreatedAt = now
	}
	command.ExpiresAt = now.Add(h.ttl)

	if connection := h.iphone[accountID]; connection != nil && connection.send(command) {
		return true
	}

	queue := append(h.pending[accountID], command)
	if len(queue) > h.maxPending {
		queue = queue[len(queue)-h.maxPending:]
	}
	h.pending[accountID] = queue
	return false
}

// Ack removes a command once the phone has dialled it.
func (h *Hub) Ack(accountID, requestID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	queue := h.pending[accountID]
	filtered := queue[:0]
	for _, command := range queue {
		if command.RequestID != requestID {
			filtered = append(filtered, command)
		}
	}
	if len(filtered) == 0 {
		delete(h.pending, accountID)
		return
	}
	h.pending[accountID] = filtered
}

// Pending lists what is waiting for an account, oldest first.
func (h *Hub) Pending(accountID string) []Command {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	return append([]Command(nil), h.pending[accountID]...)
}

// attach registers the connected iPhone and returns the backlog, oldest first.
func (h *Hub) attach(accountID string, connection *session) []Command {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sweepLocked(h.now())
	if previous := h.iphone[accountID]; previous != nil && previous != connection {
		previous.close()
	}
	h.iphone[accountID] = connection
	backlog := append([]Command(nil), h.pending[accountID]...)
	delete(h.pending, accountID)
	return backlog
}

func (h *Hub) detach(accountID string, connection *session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.iphone[accountID] == connection {
		delete(h.iphone, accountID)
	}
}

// sweepLocked drops expired commands and forgets request ids that have aged out,
// which is what keeps `seen` from growing for the life of the process.
func (h *Hub) sweepLocked(now time.Time) {
	for accountID, queue := range h.pending {
		kept := queue[:0]
		for _, command := range queue {
			if !command.Expired(now) {
				kept = append(kept, command)
			}
		}
		if len(kept) == 0 {
			delete(h.pending, accountID)
			continue
		}
		h.pending[accountID] = kept
	}
	for requestID, at := range h.seen {
		if now.Sub(at) > h.ttl {
			delete(h.seen, requestID)
		}
	}
}

// Stats reports queue depth for the status endpoint.
func (h *Hub) Stats() (accounts, commands int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, queue := range h.pending {
		if len(queue) > 0 {
			accounts++
			commands += len(queue)
		}
	}
	return accounts, commands
}
