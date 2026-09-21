package media

import (
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

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

type connectionStats struct {
	binaryMessages    uint64
	validAudioPackets uint64
	invalidPackets    uint64
	audioBytes        uint64
	relayedPackets    uint64
	relayFailures     uint64
	peerMissingCount  uint64
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
	started := time.Now()
	secondPeerPresent := h.add(id, role, p)
	slog.Info("media joined", "callID", id, "role", role)
	if secondPeerPresent {
		slog.Info("media peers paired", "callID", id, "roles", "A,B")
	}
	stats := connectionStats{}
	closeCode := 0
	closeReason := ""
	defer func() {
		h.remove(id, role, p)
		conn.Close()
		slog.Info(
			"media disconnected",
			"callID", id,
			"role", role,
			"durationMilliseconds", time.Since(started).Milliseconds(),
			"binaryMessages", stats.binaryMessages,
			"validAudioPackets", stats.validAudioPackets,
			"audioBytes", stats.audioBytes,
			"invalidPackets", stats.invalidPackets,
			"relayedPackets", stats.relayedPackets,
			"relayFailures", stats.relayFailures,
			"peerMissingCount", stats.peerMissingCount,
			"closeCode", closeCode,
			"closeReason", closeReason,
		)
	}()
	conn.SetReadLimit(2048)
	firstAudioLogged := false
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			var closeError *websocket.CloseError
			if errors.As(err, &closeError) {
				closeCode = closeError.Code
				closeReason = sanitizeCloseReason(closeError.Text)
			}
			return
		}
		if kind != websocket.BinaryMessage {
			stats.invalidPackets++
			continue
		}
		stats.binaryMessages++
		if !validPacket(data, id) {
			stats.invalidPackets++
			continue
		}
		if data[1] == 1 {
			stats.validAudioPackets++
			stats.audioBytes += uint64(len(data) - 34)
			if !firstAudioLogged {
				firstAudioLogged = true
				slog.Info(
					"first valid audio packet received",
					"callID", id,
					"role", role,
					"packetByteLength", len(data),
					"sequence", binary.BigEndian.Uint64(data[18:26]),
					"packetTimestampMicroseconds", binary.BigEndian.Uint64(data[26:34]),
				)
			}
		}
		if destination := h.other(id, role); destination != nil {
			destination.mu.Lock()
			err = destination.conn.WriteMessage(websocket.BinaryMessage, data)
			destination.mu.Unlock()
			if err != nil {
				stats.relayFailures++
				continue
			}
			stats.relayedPackets++
		} else {
			stats.peerMissingCount++
		}
	}
}
func (h *Hub) add(id, role string, p *peer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.peers[id] == nil {
		h.peers[id] = map[string]*peer{}
	}
	if old := h.peers[id][role]; old != nil {
		old.conn.Close()
	}
	h.peers[id][role] = p
	otherRole := "A"
	if role == "A" {
		otherRole = "B"
	}
	return h.peers[id][otherRole] != nil
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

func sanitizeCloseReason(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("-_.:/", r) {
			return r
		}
		return -1
	}, value)
	if len(value) > 64 {
		value = value[:64]
	}
	return value
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
