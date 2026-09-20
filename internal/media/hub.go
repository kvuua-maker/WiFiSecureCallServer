package media

import (
	"encoding/binary"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Validator interface {
	ValidateMedia(id, role, token string) bool
}
type Hub struct {
	validator Validator
	upgrader  websocket.Upgrader
	mu        sync.Mutex
	peers     map[string]map[string]*peer
}
type peer struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func New(validator Validator) *Hub {
	return &Hub{validator: validator, upgrader: websocket.Upgrader{HandshakeTimeout: 5 * time.Second, ReadBufferSize: 1024, WriteBufferSize: 1024, CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "" || strings.HasPrefix(r.Header.Get("Origin"), "https://178.105.32.46")
	}}, peers: map[string]map[string]*peer{}}
}
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, role := r.URL.Query().Get("callID"), r.URL.Query().Get("role")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !h.validator.ValidateMedia(id, role, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	p := &peer{conn: conn}
	h.add(id, role, p)
	defer func() { h.remove(id, role, p); conn.Close() }()
	conn.SetReadLimit(2048)
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if kind != websocket.BinaryMessage || !validPacket(data, id) {
			continue
		}
		if destination := h.other(id, role); destination != nil {
			destination.mu.Lock()
			err = destination.conn.WriteMessage(websocket.BinaryMessage, data)
			destination.mu.Unlock()
			if err != nil {
				continue
			}
		}
	}
}
func (h *Hub) add(id, role string, p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[id] == nil {
		h.peers[id] = map[string]*peer{}
	}
	if old := h.peers[id][role]; old != nil {
		old.conn.Close()
	}
	h.peers[id][role] = p
}
func (h *Hub) remove(id, role string, p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[id] != nil && h.peers[id][role] == p {
		delete(h.peers[id], role)
		if len(h.peers[id]) == 0 {
			delete(h.peers, id)
		}
	}
}
func (h *Hub) other(id, role string) *peer {
	h.mu.Lock()
	defer h.mu.Unlock()
	other := "A"
	if role == "A" {
		other = "B"
	}
	return h.peers[id][other]
}
func validPacket(data []byte, id string) bool {
	if len(data) < 34 || len(data) > 674 || data[0] != 1 {
		return false
	}
	if data[1] < 1 || data[1] > 3 {
		return false
	}
	_ = binary.BigEndian.Uint64(data[18:26])
	return uuidString(data[2:18]) == strings.ToLower(id)
}
func uuidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 36)
	j := 0
	for i, v := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[j] = '-'
			j++
		}
		out[j] = hex[v>>4]
		out[j+1] = hex[v&15]
		j += 2
	}
	return string(out)
}
