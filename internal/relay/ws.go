package relay

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Message is the JSON envelope both ends speak.
type Message struct {
	Type      string    `json:"type"` // dial | delivered | queued | ack | ping
	RequestID string    `json:"requestID"`
	Number    string    `json:"number,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`
}

const (
	writeWait  = 10 * time.Second
	pongWait   = 70 * time.Second
	pingPeriod = 25 * time.Second
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// The clients are native apps, which send no Origin header. A browser page is
	// not a supported client, so there is no cross-origin surface to protect here
	// and requiring an origin would reject every real caller.
	CheckOrigin: func(r *http.Request) bool { return true },
}

type session struct {
	accountID string
	conn      *websocket.Conn

	mu      sync.Mutex
	closed  bool
	writeMu sync.Mutex
}

func (s *session) send(command Command) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return false
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeWait))
	err := s.conn.WriteJSON(Message{
		Type:      "dial",
		RequestID: command.RequestID,
		Number:    command.Number,
		CreatedAt: command.CreatedAt,
	})
	if err != nil {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		return false
	}
	return true
}

func (s *session) reply(message Message) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeWait))
	_ = s.conn.WriteJSON(message)
}

func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.conn.Close()
}

// ServeWS upgrades one connection and runs it until it closes.
//
// role=iphone receives commands, including the backlog queued while it was away,
// and acknowledges each one. role=watch sends commands and is told whether the
// phone took the command now or whether it was queued.
func ServeWS(hub *Hub, accountID, role string, w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("relay upgrade failed", "error", err)
		return
	}
	s := &session{accountID: accountID, conn: conn}
	defer s.close()

	switch role {
	case "iphone":
		backlog := hub.attach(accountID, s)
		defer hub.detach(accountID, s)
		for _, command := range backlog {
			if !s.send(command) {
				return
			}
		}
		logger.Info("relay iphone attached", "accountID", accountID, "backlog", len(backlog))
		hub.readIPhone(s, logger)
	case "watch":
		logger.Info("relay watch attached", "accountID", accountID)
		hub.readWatch(s, logger)
	default:
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "role must be iphone or watch"),
			time.Now().Add(writeWait))
	}
}

func (h *Hub) readWatch(s *session, logger *slog.Logger) {
	s.conn.SetReadLimit(8 << 10)
	_ = s.conn.SetReadDeadline(time.Now().Add(pongWait))
	s.conn.SetPongHandler(func(string) error {
		return s.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	ping := time.NewTicker(pingPeriod)
	defer ping.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ping.C:
				_ = s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
			}
		}
	}()

	for {
		var message Message
		_ = s.conn.SetReadDeadline(time.Now().Add(pongWait))
		if err := s.conn.ReadJSON(&message); err != nil {
			return
		}
		switch message.Type {
		case "dial":
			if message.Number == "" || message.RequestID == "" {
				s.reply(Message{Type: "ack", RequestID: message.RequestID})
				continue
			}
			delivered := h.Enqueue(s.accountID, Command{
				RequestID: message.RequestID,
				Number:    message.Number,
				CreatedAt: message.CreatedAt,
			})
			status := "queued"
			if delivered {
				status = "delivered"
			}
			s.reply(Message{Type: status, RequestID: message.RequestID})
			logger.Info("relay command accepted", "accountID", s.accountID, "status", status)
		case "ping":
			s.reply(Message{Type: "ack", RequestID: message.RequestID})
		}
	}
}

func (h *Hub) readIPhone(s *session, logger *slog.Logger) {
	s.conn.SetReadLimit(8 << 10)
	_ = s.conn.SetReadDeadline(time.Now().Add(pongWait))
	s.conn.SetPongHandler(func(string) error {
		return s.conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	ping := time.NewTicker(pingPeriod)
	defer ping.Stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ping.C:
				_ = s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait))
			}
		}
	}()

	for {
		var message Message
		_ = s.conn.SetReadDeadline(time.Now().Add(pongWait))
		if err := s.conn.ReadJSON(&message); err != nil {
			return
		}
		if message.Type == "delivered" && message.RequestID != "" {
			h.Ack(s.accountID, message.RequestID)
			logger.Info("relay command delivered", "accountID", s.accountID)
		}
	}
}
